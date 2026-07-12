import io
import gzip
import json
import logging
import tarfile
import zipfile
from datetime import datetime
from typing import Iterable, Optional

import httpx
from sqlmodel import Session, select

from app.config import RULESET_SOURCES, DATA_DIR
from app.database import engine
from app.models import SnortRule, SyncLog
from app.snort_parser import parse_rule

logger = logging.getLogger("rule_sync")

LOCAL_SAMPLE_RULES_PATH = "app/sample_rules.rules"

# Bir batch'te kaç satır işlensin sonra tek commit yapılsın. Önceki sürümde
# HER satır kendi commit'inde bitiyordu; bu, güvenli ama binlerce satırlık
# gerçek ruleset'lerde (ör. Emerging Threats Open, onbinlerce kural) DAKİKALAR
# sürebiliyordu ve bu da Render gibi platformlarda arka plan görevinin
# tamamlanmadan servisin uykuya geçmesine (ve senkronizasyonun yarıda
# kesilmesine) sebep oluyordu. Şimdi her satır KENDİ SAVEPOINT'inde izole
# ediliyor (bir satır hatası diğerlerini etkilemiyor) ama gerçek commit
# sadece her BATCH_SIZE satırda bir yapılıyor -> onlarca kat daha hızlı.
BATCH_SIZE = 200

# Atlanan satırlardan kaç tanesinin örneğini (sebebiyle birlikte) saklayıp
# kullanıcıya gösterelim. Kullanıcı "benim aradığım kural neden atlandı"
# sorusunu böylece kendi başına teşhis edebilir.
MAX_SKIPPED_SAMPLES = 25


def _download(url: str) -> bytes:
    with httpx.Client(follow_redirects=True, timeout=90.0) as client:
        resp = client.get(url, headers={"User-Agent": "snort-toolkit-sync/1.0"})
        resp.raise_for_status()
        return resp.content


def _iter_rule_lines_from_archive(content: bytes) -> Iterable[str]:
    """.zip, tar.gz, düz .gz ya da düz metin .rules içeriğini otomatik
    algılayıp satır satır kural metnini döndürür.

    ÖNEMLİ DÜZELTME: Önceki sürüm .zip formatını HİÇ desteklemiyordu. Bir
    .zip dosyası yüklendiğinde önce tar olarak açma, sonra düz gzip olarak
    açma denemeleri başarısız oluyor, kod sessizce ham ZIP binary verisini
    'düz metin' sanıp UTF-8'e (hatalı baytları değiştirerek) çevirmeye
    çalışıyordu. Bu durumda hem sonuçlar öngörülemez oluyor (bazı rastgele
    baytlar tesadüfen bir kural gibi ayrıştırılabiliyor) hem de gerçek
    kurallar hiç bulunamıyordu. Şimdi .zip formatı da tıpkı tar.gz gibi
    düzgün şekilde ayrıştırılıyor.
    """
    # 1) ZIP dene (ör. GitHub "Download ZIP", snortrules-snapshot-*.zip)
    if zipfile.is_zipfile(io.BytesIO(content)):
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            for name in zf.namelist():
                if name.endswith(".rules"):
                    with zf.open(name) as f:
                        for line in f.read().decode("utf-8", errors="replace").splitlines():
                            yield line
            return

    # 2) tar.gz dene (snort3/snort2.9 community ruleset'leri bu formattadır)
    try:
        with tarfile.open(fileobj=io.BytesIO(content)) as tar:
            for member in tar.getmembers():
                if member.name.endswith(".rules"):
                    f = tar.extractfile(member)
                    if not f:
                        continue
                    for line in f.read().decode("utf-8", errors="replace").splitlines():
                        yield line
            return
    except tarfile.ReadError:
        pass

    # 3) düz .gz dene (bazı eski/alternatif dağıtımlar tek dosya gzip olabilir)
    try:
        decompressed = gzip.decompress(content)
        for line in decompressed.decode("utf-8", errors="replace").splitlines():
            yield line
        return
    except OSError:
        pass

    # 4) hiçbiri değilse düz metin (.rules / .txt) olduğunu varsay
    for line in content.decode("utf-8", errors="replace").splitlines():
        yield line


def _iter_rule_lines_from_local_sample():
    with open(LOCAL_SAMPLE_RULES_PATH, "r", encoding="utf-8") as f:
        for line in f:
            yield line


def _ingest_lines(
    session: Session,
    lines: Iterable[str],
    snort_version: str,
    ruleset_source: str,
    source_file: Optional[str] = None,
) -> "tuple[int, int, list]":
    """Verilen kural satırlarını parse edip (sid, snort_version) bazında upsert eder.

    Döner: (başarıyla işlenen kural sayısı, atlanan/hatalı satır sayısı,
    atlanan satırlardan örnekler [{'line':..., 'reason':...}]).

    PERFORMANS DÜZELTMESİ: Her satır kendi SAVEPOINT'inde (nested
    transaction) izole edilir — bir satırdaki hata diğerlerini etkilemez,
    tıpkı önceki 'her satır kendi commit'i' yaklaşımı gibi güvenlidir.
    FARK: gerçek disk commit'i sadece her BATCH_SIZE satırda bir yapılır.
    Bu, binlerce/onbinlerce satırlık gerçek ruleset'lerde (ör. Emerging
    Threats Open) senkronizasyonu onlarca kat hızlandırır ve Render gibi
    platformlarda 'işlem çok uzun sürdüğü için arka plan görevi yarıda
    kesiliyor' sorununu doğrudan azaltır.
    """
    ingested = 0
    skipped = 0
    skipped_samples = []

    def _record_skip(raw_line: str, reason: str):
        nonlocal skipped
        skipped += 1
        if len(skipped_samples) < MAX_SKIPPED_SAMPLES:
            skipped_samples.append({"line": raw_line.strip()[:200], "reason": reason})

    for raw_line in lines:
        try:
            parsed = parse_rule(raw_line)
            if not parsed or not parsed.sid:
                continue
        except Exception as e:
            logger.warning("Ayrıştırılamayan satır atlandı: %s", raw_line[:120])
            _record_skip(raw_line, f"parse hatası: {e}")
            continue

        try:
            with session.begin_nested():  # <-- SAVEPOINT: bu satır izole
                options_dump = {
                    "contents": [
                        {
                            "pattern_raw": c.pattern_raw,
                            "nocase": c.nocase,
                            "http_buffer": c.http_buffer,
                            "negated": c.negated,
                        }
                        for c in parsed.contents
                    ],
                    "pcres": [{"regex": p.regex, "flags": p.flags} for p in parsed.pcres],
                    "references": parsed.references,
                    "metadata": parsed.metadata,
                    "flow": parsed.flow,
                }

                existing = session.exec(
                    select(SnortRule).where(
                        SnortRule.sid == parsed.sid, SnortRule.snort_version == snort_version
                    )
                ).first()

                if existing:
                    existing.rev = parsed.rev
                    existing.msg = parsed.msg
                    existing.classtype = parsed.classtype
                    existing.raw_rule = parsed.raw
                    existing.options_json = json.dumps(options_dump)
                    existing.ruleset_source = ruleset_source
                    existing.source_file = source_file
                    existing.synced_at = datetime.utcnow()
                    session.add(existing)
                else:
                    session.add(
                        SnortRule(
                            sid=parsed.sid,
                            snort_version=snort_version,
                            gid=parsed.gid,
                            rev=parsed.rev,
                            msg=parsed.msg,
                            classtype=parsed.classtype,
                            action=parsed.action,
                            protocol=parsed.protocol,
                            src=parsed.src,
                            src_port=parsed.src_port,
                            direction=parsed.direction,
                            dst=parsed.dst,
                            dst_port=parsed.dst_port,
                            raw_rule=parsed.raw,
                            options_json=json.dumps(options_dump),
                            ruleset_source=ruleset_source,
                            source_file=source_file,
                        )
                    )
            ingested += 1
        except Exception as e:
            logger.warning("SID %s işlenemedi, atlandı: %s", getattr(parsed, "sid", "?"), e)
            _record_skip(raw_line, f"db hatası: {e}")
            continue

        if (ingested + skipped) % BATCH_SIZE == 0:
            session.commit()  # <-- Sadece her BATCH_SIZE satırda bir gerçek commit

    session.commit()  # kalan satırları da kaydet
    return ingested, skipped, skipped_samples


def sync_offline_sample(session: Session) -> SyncLog:
    """Ağ erişimi olmayan ortamlarda test için bundle edilmiş örnek kuralları
    yükler. Hem Snort 3.x hem de 2.9 (uricontent) sözdiziminde demo kural
    içerir, böylece çoklu sürüm özelliği internet olmadan da denenebilir."""
    log = SyncLog(status="running", snort_version="3.x,2.9", source_used="offline_sample")
    session.add(log)
    session.commit()
    session.refresh(log)

    try:
        ingested, skipped, samples = _ingest_lines(
            session,
            _iter_rule_lines_from_local_sample(),
            snort_version="3.x",
            ruleset_source="offline-sample",
        )
        with open("app/sample_rules_legacy_29.rules", "r", encoding="utf-8") as f:
            legacy_lines = f.readlines()
        ingested2, skipped2, samples2 = _ingest_lines(
            session, legacy_lines, snort_version="2.9", ruleset_source="offline-sample"
        )
        log.status = "success"
        log.rules_ingested = ingested + ingested2
        log.rules_skipped = skipped + skipped2
        log.skipped_samples = json.dumps((samples + samples2)[:MAX_SKIPPED_SAMPLES])
    except Exception as e:
        logger.exception("Offline örnek yükleme başarısız")
        log.status = "failed"
        log.error = str(e)
    finally:
        log.finished_at = datetime.utcnow()
        session.add(log)
        session.commit()
        session.refresh(log)
    return log


def sync_source(session: Session, source_key: str, existing_log: Optional[SyncLog] = None) -> SyncLog:
    """RULESET_SOURCES içindeki tek bir kaynağı (tek Snort sürümünü) senkronize eder.

    existing_log verilirse (arka plan görevlerinde kullanılır), yeni bir log
    oluşturmak yerine o kayıt güncellenir — böylece çağıran taraf log'u
    hemen (senkronizasyon başlamadan önce) oluşturup id'sini kullanıcıya
    dönebilir, kullanıcı ilerlemeyi bu id üzerinden takip edebilir.
    """
    spec = next((s for s in RULESET_SOURCES if s["key"] == source_key), None)
    if not spec:
        raise ValueError(f"Bilinmeyen kaynak: {source_key}")

    if existing_log is not None:
        log = existing_log
    else:
        log = SyncLog(status="running", snort_version=spec["snort_version"], source_used=spec["label"])
        session.add(log)
        session.commit()
        session.refresh(log)

    try:
        if not spec["url"]:
            raise RuntimeError(
                f"'{spec['label']}' için canlı/ücretsiz bir kaynak yok. "
                f"Lütfen bu sürüm için 'Dosya Yükle' özelliğini kullanın."
            )
        content = _download(spec["url"])
        lines = _iter_rule_lines_from_archive(content)
        ingested, skipped, samples = _ingest_lines(
            session, lines, snort_version=spec["snort_version"], ruleset_source=spec["key"]
        )
        log.status = "success"
        log.rules_ingested = ingested
        log.rules_skipped = skipped
        log.skipped_samples = json.dumps(samples)
    except Exception as e:
        logger.exception("Senkronizasyon başarısız: %s", source_key)
        log.status = "failed"
        log.error = str(e)
    finally:
        log.finished_at = datetime.utcnow()
        session.add(log)
        session.commit()
        session.refresh(log)
    return log


def sync_all_live_sources(session: Session) -> list:
    """url tanımlı olan TÜM kaynakları (tüm canlı Snort sürümlerini) sırayla senkronize eder."""
    results = []
    for spec in RULESET_SOURCES:
        if spec["url"]:
            results.append(sync_source(session, spec["key"]))
    return results


# ---------------------------------------------------------------------------
# ARKA PLAN (background) senkronizasyon görevleri.
#
# ÖNEMLİ: Canlı kaynaklar (özellikle "tüm sürümleri senkronize et") binlerce
# kural indirip işleyebildiği için dakikalarca sürebilir. Bunu doğrudan bir
# HTTP isteği içinde SENKRON yapmak, Render gibi platformlarda proxy'nin
# istek zaman aşımına uğrayıp kullanıcıya "502 Bad Gateway" döndürmesine
# sebep oluyordu (sunucu aslında çalışmaya devam ediyor olsa bile). Bu
# yüzden ağır işler artık arka plan thread'lerinde çalışıyor: HTTP isteği
# ANINDA bir "log_id" ile döner, gerçek iş arka planda devam eder, kullanıcı
# arayüzü bu id'yi periyodik olarak sorgulayarak (polling) ilerlemeyi gösterir.
# ---------------------------------------------------------------------------


def create_running_log(
    snort_version: Optional[str],
    source_used: str,
    file_name: Optional[str] = None,
    is_manual_upload: bool = False,
) -> int:
    """Bir SyncLog kaydını HEMEN 'running' durumunda oluşturup id'sini döner.
    Asıl iş bu id kullanılarak arka planda güncellenir."""
    with Session(engine) as session:
        log = SyncLog(
            status="running",
            snort_version=snort_version,
            source_used=source_used,
            file_name=file_name,
            is_manual_upload=is_manual_upload,
        )
        session.add(log)
        session.commit()
        session.refresh(log)
        return log.id


def run_source_sync_background(log_id: int, source_key: str):
    """Tek bir kaynağı arka planda senkronize edip aynı log satırını günceller."""
    with Session(engine) as session:
        log = session.get(SyncLog, log_id)
        if not log:
            logger.error("Arka plan görevi: log_id %s bulunamadı", log_id)
            return
        try:
            sync_source(session, source_key, existing_log=log)
        except Exception as e:
            logger.exception("Arka plan senkronizasyonu başarısız: %s", source_key)
            log.status = "failed"
            log.error = str(e)
            log.finished_at = datetime.utcnow()
            session.add(log)
            session.commit()


def run_all_sync_background(log_ids_by_key: dict):
    """Tüm canlı kaynakları sırayla, her biri için önceden oluşturulmuş log
    id'lerini güncelleyerek arka planda senkronize eder."""
    with Session(engine) as session:
        for source_key, log_id in log_ids_by_key.items():
            log = session.get(SyncLog, log_id)
            if not log:
                continue
            try:
                sync_source(session, source_key, existing_log=log)
            except Exception as e:
                logger.exception("Arka plan senkronizasyonu başarısız: %s", source_key)
                log.status = "failed"
                log.error = str(e)
                log.finished_at = datetime.utcnow()
                session.add(log)
                session.commit()


def run_upload_background(log_id: int, file_name: str, content: bytes, snort_version: str):
    """Yüklenen dosyayı arka planda işleyip aynı log satırını günceller."""
    with Session(engine) as session:
        log = session.get(SyncLog, log_id)
        if not log:
            logger.error("Arka plan görevi: log_id %s bulunamadı", log_id)
            return
        try:
            lines = _iter_rule_lines_from_archive(content)
            ingested, skipped, samples = _ingest_lines(
                session,
                lines,
                snort_version=snort_version,
                ruleset_source=f"manual-upload:{file_name}",
                source_file=file_name,
            )
            if ingested == 0:
                sample_hint = ""
                if samples:
                    sample_hint = " Örnek atlanan satır: " + samples[0]["line"][:150]
                raise RuntimeError(
                    "Dosyadan hiçbir geçerli Snort kuralı (sid içeren satır) çıkarılamadı. "
                    "Dosya formatı (.rules/.txt/.tar.gz/.zip) veya içeriği hatalı olabilir." + sample_hint
                )
            log.status = "success"
            log.rules_ingested = ingested
            log.rules_skipped = skipped
            log.skipped_samples = json.dumps(samples)
        except Exception as e:
            logger.exception("Arka plan dosya yükleme başarısız: %s", file_name)
            log.status = "failed"
            log.error = str(e)
        finally:
            log.finished_at = datetime.utcnow()
            session.add(log)
            session.commit()


def ingest_uploaded_file(
    session: Session, file_name: str, content: bytes, snort_version: str
) -> SyncLog:
    """ESKİ/KULLANILMAYAN: main.py artık bunun yerine create_running_log +
    run_upload_background (arka plan görevi) kullanıyor. Geriye dönük
    uyumluluk için burada bırakıldı, ama çağrılmıyor."""
    log = SyncLog(
        status="running",
        snort_version=snort_version,
        source_used="manual-upload",
        file_name=file_name,
        is_manual_upload=True,
    )
    session.add(log)
    session.commit()
    session.refresh(log)

    try:
        lines = _iter_rule_lines_from_archive(content)
        ingested, skipped, samples = _ingest_lines(
            session,
            lines,
            snort_version=snort_version,
            ruleset_source=f"manual-upload:{file_name}",
            source_file=file_name,
        )
        if ingested == 0:
            raise RuntimeError(
                "Dosyadan hiçbir geçerli Snort kuralı (sid içeren satır) çıkarılamadı. "
                "Dosyanın .rules formatında olduğundan (ya da içindeki .rules dosyalarını "
                "barındıran bir .tar.gz/.zip olduğundan) emin olun."
            )
        log.status = "success"
        log.rules_ingested = ingested
        log.rules_skipped = skipped
        log.skipped_samples = json.dumps(samples)
    except Exception as e:
        logger.exception("Manuel dosya yükleme başarısız: %s", file_name)
        log.status = "failed"
        log.error = str(e)
    finally:
        log.finished_at = datetime.utcnow()
        session.add(log)
        session.commit()
        session.refresh(log)
    return log
