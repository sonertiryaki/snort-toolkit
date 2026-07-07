import io
import gzip
import json
import logging
import tarfile
from datetime import datetime
from typing import Iterable, Optional

import httpx
from sqlmodel import Session, select

from app.config import RULESET_SOURCES, DATA_DIR
from app.models import SnortRule, SyncLog
from app.snort_parser import parse_rule

logger = logging.getLogger("rule_sync")

LOCAL_SAMPLE_RULES_PATH = "app/sample_rules.rules"


def _download(url: str) -> bytes:
    with httpx.Client(follow_redirects=True, timeout=90.0) as client:
        resp = client.get(url, headers={"User-Agent": "snort-toolkit-sync/1.0"})
        resp.raise_for_status()
        return resp.content


def _iter_rule_lines_from_archive(content: bytes) -> Iterable[str]:
    """tar.gz, düz .gz ya da düz metin .rules içeriğini otomatik algılayıp
    satır satır kural metnini döndürür."""
    # 1) tar.gz dene (snort3/snort2.9 community ruleset'leri bu formattadır)
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

    # 2) düz .gz dene (bazı eski/alternatif dağıtımlar tek dosya gzip olabilir)
    try:
        decompressed = gzip.decompress(content)
        for line in decompressed.decode("utf-8", errors="replace").splitlines():
            yield line
        return
    except OSError:
        pass

    # 3) hiçbiri değilse düz metin (.rules / .txt) olduğunu varsay
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
) -> "tuple[int, int]":
    """Verilen kural satırlarını parse edip (sid, snort_version) bazında upsert eder.

    Döner: (başarıyla işlenen kural sayısı, atlanan/hatalı satır sayısı).

    ÖNEMLİ DÜZELTME: Her satır KENDİ transaction'ında commit edilir ve
    hata durumunda rollback yapılır. Önceki sürümde tek bir commit tüm
    döngünün sonunda yapılıyordu; bu yüzden döngü ortasında oluşan TEK bir
    DB hatası (ör. aynı dosya içinde tekrarlanan bir SID, ya da başka bir
    bütünlük hatası) session'ın transaction'ını 'zehirliyor' ve o
    noktadan sonraki HER satır farklı ve anlamsız hatalarla
    (ör. 'PendingRollbackError') başarısız oluyordu. Bu da 'her seferinde
    başka bir hata alıyorum' ve 'senkronizasyon sadece birkaç kural
    getiriyor' şikayetlerinin gerçek sebebiydi.
    """
    ingested = 0
    skipped = 0
    for raw_line in lines:
        try:
            parsed = parse_rule(raw_line)
            if not parsed or not parsed.sid:
                continue
        except Exception:
            logger.warning("Ayrıştırılamayan satır atlandı: %s", raw_line[:120])
            skipped += 1
            continue

        try:
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
            session.commit()  # <-- Her satır kendi transaction'ında bitiyor
            ingested += 1
        except Exception:
            logger.warning("SID %s işlenemedi, atlandı.", getattr(parsed, "sid", "?"))
            session.rollback()  # <-- Session'ı bir sonraki satır için temiz bırak
            skipped += 1
            continue

    return ingested, skipped


def sync_offline_sample(session: Session) -> SyncLog:
    """Ağ erişimi olmayan ortamlarda test için bundle edilmiş örnek kuralları
    yükler. Hem Snort 3.x hem de 2.9 (uricontent) sözdiziminde demo kural
    içerir, böylece çoklu sürüm özelliği internet olmadan da denenebilir."""
    log = SyncLog(status="running", snort_version="3.x,2.9", source_used="offline_sample")
    session.add(log)
    session.commit()
    session.refresh(log)

    try:
        ingested, skipped = _ingest_lines(
            session,
            _iter_rule_lines_from_local_sample(),
            snort_version="3.x",
            ruleset_source="offline-sample",
        )
        with open("app/sample_rules_legacy_29.rules", "r", encoding="utf-8") as f:
            legacy_lines = f.readlines()
        ingested2, skipped2 = _ingest_lines(
            session, legacy_lines, snort_version="2.9", ruleset_source="offline-sample"
        )
        log.status = "success"
        log.rules_ingested = ingested + ingested2
        log.rules_skipped = skipped + skipped2
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


def sync_source(session: Session, source_key: str) -> SyncLog:
    """RULESET_SOURCES içindeki tek bir kaynağı (tek Snort sürümünü) senkronize eder."""
    spec = next((s for s in RULESET_SOURCES if s["key"] == source_key), None)
    if not spec:
        raise ValueError(f"Bilinmeyen kaynak: {source_key}")

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
        ingested, skipped = _ingest_lines(
            session, lines, snort_version=spec["snort_version"], ruleset_source=spec["key"]
        )
        log.status = "success"
        log.rules_ingested = ingested
        log.rules_skipped = skipped
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


def ingest_uploaded_file(
    session: Session, file_name: str, content: bytes, snort_version: str
) -> SyncLog:
    """Kullanıcının arayüzden yüklediği bir .rules / .txt / .tar.gz dosyasını
    veritabanına işler."""
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
        ingested, skipped = _ingest_lines(
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
                "barındıran bir .tar.gz olduğundan) emin olun."
            )
        log.status = "success"
        log.rules_ingested = ingested
        log.rules_skipped = skipped
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
