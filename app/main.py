import base64
import json
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, select
from sqlalchemy import func, String, cast
from apscheduler.schedulers.background import BackgroundScheduler

from app.database import init_db, get_session, engine
from app.models import SnortRule, SyncLog
from app.config import SYNC_INTERVAL_HOURS, RULESET_SOURCES, SUPPORTED_VERSIONS
from app.rule_sync import (
    sync_offline_sample,
    sync_source,
    sync_all_live_sources,
    ingest_uploaded_file,
)
from app.snort_parser import parse_rule
from app.http_generator import generate_http_request
from app.paloalto_converter import convert_to_palo_alto
from app.pcap_tester import run_pcap_test

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

scheduler = BackgroundScheduler()

# Bir SID sorgulanırken sürüm belirtilmezse hangi sırayla tercih edileceği
VERSION_PREFERENCE = ["3.x", "2.9", "2.8", "2.7", "manual"]


def _scheduled_sync_job():
    with Session(engine) as session:
        results = sync_all_live_sources(session)
        for log in results:
            logger.info(
                "Zamanlanmış senkronizasyon (%s): %s - %s kural",
                log.snort_version, log.status, log.rules_ingested,
            )


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    scheduler.add_job(
        _scheduled_sync_job,
        "interval",
        hours=SYNC_INTERVAL_HOURS,
        id="rule_sync_job",
        replace_existing=True,
    )
    scheduler.start()
    logger.info(
        "Servis başlatıldı. Otomatik senkronizasyon her %s saatte bir tüm sürümler için çalışacak.",
        SYNC_INTERVAL_HOURS,
    )
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(
    title="Snort SID -> Palo Alto Dönüştürücü ve Test Toolkit",
    version="1.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Kaynak / sürüm bilgisi
# ---------------------------------------------------------------------------
@app.get("/api/sources")
def list_sources():
    """Frontend'in senkronizasyon dropdown'ını doldurmak için kaynak listesi."""
    return [
        {
            "key": s["key"],
            "label": s["label"],
            "snort_version": s["snort_version"],
            "live_available": bool(s["url"]),
        }
        for s in RULESET_SOURCES
    ]


# ---------------------------------------------------------------------------
# Senkronizasyon
# ---------------------------------------------------------------------------
@app.post("/api/sync/offline-sample")
def trigger_offline_sync(session: Session = Depends(get_session)):
    log = sync_offline_sample(session)
    return _log_to_dict(log)


@app.post("/api/sync/source/{source_key}")
def trigger_source_sync(source_key: str, session: Session = Depends(get_session)):
    try:
        log = sync_source(session, source_key)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return _log_to_dict(log)


@app.post("/api/sync/all")
def trigger_sync_all(session: Session = Depends(get_session)):
    """url tanımlı olan tüm sürümleri (Snort 3.x + 2.9 community + ET Open) tek seferde senkronize eder."""
    logs = sync_all_live_sources(session)
    return [_log_to_dict(l) for l in logs]


def _log_to_dict(log: SyncLog) -> dict:
    return {
        "status": log.status,
        "rules_ingested": log.rules_ingested,
        "rules_skipped": log.rules_skipped,
        "source_used": log.source_used,
        "snort_version": log.snort_version,
        "file_name": log.file_name,
        "finished_at": log.finished_at,
        "error": log.error,
    }


@app.get("/api/sync/history")
def sync_history(session: Session = Depends(get_session)):
    logs = session.exec(select(SyncLog).order_by(SyncLog.id.desc()).limit(30)).all()
    return logs


# ---------------------------------------------------------------------------
# Manuel dosya yükleme
# ---------------------------------------------------------------------------
@app.post("/api/upload-rules")
async def upload_rules(
    file: UploadFile = File(...),
    snort_version: str = Form(...),
    session: Session = Depends(get_session),
):
    if snort_version not in SUPPORTED_VERSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Geçersiz sürüm '{snort_version}'. Desteklenenler: {SUPPORTED_VERSIONS}",
        )
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Dosya boş.")

    log = ingest_uploaded_file(session, file.filename, content, snort_version)
    if log.status != "success":
        raise HTTPException(status_code=400, detail=log.error or "Yükleme başarısız.")
    return _log_to_dict(log)


# ---------------------------------------------------------------------------
# Genel durum / "son güncelleme" bilgisi
# ---------------------------------------------------------------------------
@app.get("/api/status")
def get_status(session: Session = Depends(get_session)):
    total_rules = session.exec(select(func.count()).select_from(SnortRule)).one()

    by_version = {}
    for v in SUPPORTED_VERSIONS:
        count = session.exec(
            select(func.count()).select_from(SnortRule).where(SnortRule.snort_version == v)
        ).one()
        by_version[v] = count

    last_overall = session.exec(
        select(SyncLog).where(SyncLog.status == "success").order_by(SyncLog.finished_at.desc())
    ).first()

    last_upload = session.exec(
        select(SyncLog)
        .where(SyncLog.is_manual_upload == True, SyncLog.status == "success")  # noqa: E712
        .order_by(SyncLog.finished_at.desc())
    ).first()

    last_per_source = {}
    for spec in RULESET_SOURCES:
        log = session.exec(
            select(SyncLog)
            .where(SyncLog.source_used == spec["label"], SyncLog.status == "success")
            .order_by(SyncLog.finished_at.desc())
        ).first()
        if log:
            last_per_source[spec["key"]] = {
                "label": spec["label"],
                "snort_version": spec["snort_version"],
                "finished_at": log.finished_at,
                "rules_ingested": log.rules_ingested,
                "rules_skipped": log.rules_skipped,
            }

    return {
        "total_rules": total_rules,
        "rules_by_version": by_version,
        "versions": [
            {"snort_version": v, "count": c} for v, c in sorted(by_version.items(), key=lambda kv: -kv[1])
        ],
        "last_update_overall": (
            {
                "finished_at": last_overall.finished_at,
                "source": last_overall.source_used,
                "snort_version": last_overall.snort_version,
                "rules_ingested": last_overall.rules_ingested,
                "rules_skipped": last_overall.rules_skipped,
            }
            if last_overall
            else None
        ),
        "last_manual_upload": (
            {
                "file_name": last_upload.file_name,
                "snort_version": last_upload.snort_version,
                "finished_at": last_upload.finished_at,
                "rules_ingested": last_upload.rules_ingested,
                "rules_skipped": last_upload.rules_skipped,
            }
            if last_upload
            else None
        ),
        "last_per_source": last_per_source,
    }


@app.get("/api/stats/rules")
def get_stats_rules(
    snort_version: str,
    limit: int = 1000,
    offset: int = 0,
    q: Optional[str] = None,
    session: Session = Depends(get_session),
):
    """İstatistik sayfası için: tek bir sürümün TÜM kurallarını (arama filtreli,
    sayfalanabilir) döner. Toplam sayıyı da içerir ki '123 / 4200 gösteriliyor'
    gibi okunabilir bir bilgi verilebilsin."""
    base_query = select(SnortRule).where(SnortRule.snort_version == snort_version)
    if q:
        like = f"%{q}%"
        base_query = base_query.where(
            (SnortRule.msg.ilike(like)) | (cast(SnortRule.sid, String).ilike(like))
        )

    total = session.exec(select(func.count()).select_from(base_query.subquery())).one()
    items = session.exec(base_query.offset(offset).limit(limit)).all()

    return {
        "snort_version": snort_version,
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [{"sid": r.sid, "rev": r.rev, "msg": r.msg, "classtype": r.classtype} for r in items],
    }


# ---------------------------------------------------------------------------
# Kural sorgulama
# ---------------------------------------------------------------------------
@app.get("/api/rules")
def list_rules(limit: int = 50, snort_version: Optional[str] = None, session: Session = Depends(get_session)):
    query = select(SnortRule)
    if snort_version:
        query = query.where(SnortRule.snort_version == snort_version)
    rules = session.exec(query.limit(limit)).all()
    return rules


@app.get("/api/rule/{sid}/versions")
def get_rule_versions(sid: int, session: Session = Depends(get_session)):
    rows = session.exec(select(SnortRule).where(SnortRule.sid == sid)).all()
    if not rows:
        raise HTTPException(status_code=404, detail=f"SID {sid} hiçbir sürümde bulunamadı.")
    return [{"snort_version": r.snort_version, "rev": r.rev, "msg": r.msg} for r in rows]


def _get_rule_or_404(sid: int, session: Session, snort_version: Optional[str] = None) -> SnortRule:
    if snort_version:
        rule = session.exec(
            select(SnortRule).where(SnortRule.sid == sid, SnortRule.snort_version == snort_version)
        ).first()
        if not rule:
            raise HTTPException(
                status_code=404,
                detail=f"SID {sid} için '{snort_version}' sürümünde kayıt bulunamadı.",
            )
        return rule

    rows = {r.snort_version: r for r in session.exec(select(SnortRule).where(SnortRule.sid == sid)).all()}
    if not rows:
        raise HTTPException(
            status_code=404,
            detail=f"SID {sid} veritabanında bulunamadı. Önce bir senkronizasyon/yükleme yapın.",
        )
    for pref in VERSION_PREFERENCE:
        if pref in rows:
            return rows[pref]
    return next(iter(rows.values()))


@app.get("/api/rule/{sid}")
def get_rule(sid: int, snort_version: Optional[str] = None, session: Session = Depends(get_session)):
    return _get_rule_or_404(sid, session, snort_version)


@app.get("/api/rule/{sid}/http")
def get_http_request(sid: int, snort_version: Optional[str] = None, session: Session = Depends(get_session)):
    db_rule = _get_rule_or_404(sid, session, snort_version)
    parsed = parse_rule(db_rule.raw_rule)
    if not parsed:
        raise HTTPException(status_code=500, detail="Kural parse edilemedi.")
    generated = generate_http_request(parsed)
    return {
        "sid": sid,
        "snort_version": db_rule.snort_version,
        "raw_request": generated.raw_request,
        "method": generated.method,
        "uri": generated.uri,
        "headers": generated.headers,
        "notes": generated.notes,
    }


@app.get("/api/rule/{sid}/paloalto")
def get_paloalto(sid: int, snort_version: Optional[str] = None, session: Session = Depends(get_session)):
    db_rule = _get_rule_or_404(sid, session, snort_version)
    parsed = parse_rule(db_rule.raw_rule)
    if not parsed:
        raise HTTPException(status_code=500, detail="Kural parse edilemedi.")
    result = convert_to_palo_alto(parsed)
    return {
        "sid": sid,
        "snort_version": db_rule.snort_version,
        "signature_id": result.signature_id,
        "xml": result.xml,
        "cli_commands": result.cli_commands,
        "warnings": result.warnings,
    }


@app.get("/api/rule/{sid}/test")
def get_test_report(sid: int, snort_version: Optional[str] = None, session: Session = Depends(get_session)):
    db_rule = _get_rule_or_404(sid, session, snort_version)
    parsed = parse_rule(db_rule.raw_rule)
    if not parsed:
        raise HTTPException(status_code=500, detail="Kural parse edilemedi.")

    generated = generate_http_request(parsed)
    report = run_pcap_test(parsed, generated.raw_request)

    return {
        "sid": sid,
        "snort_version": db_rule.snort_version,
        "summary": report.summary,
        "false_positive_rate": report.false_positive_rate,
        "true_positive": {
            "matched": report.true_positive.matched,
            "correct": report.true_positive.correct,
            "detail": report.true_positive.match_result.detail,
        },
        "false_positive_checks": [
            {
                "label": r.label,
                "matched": r.matched,
                "correct": r.correct,
                "detail": r.match_result.detail,
            }
            for r in report.false_positive_checks
        ],
        "pcap_base64": base64.b64encode(report.pcap_bytes).decode("ascii"),
    }


@app.get("/api/rule/{sid}/full-report")
def get_full_report(sid: int, snort_version: Optional[str] = None, session: Session = Depends(get_session)):
    db_rule = _get_rule_or_404(sid, session, snort_version)
    parsed = parse_rule(db_rule.raw_rule)
    if not parsed:
        raise HTTPException(status_code=500, detail="Kural parse edilemedi.")

    generated = generate_http_request(parsed)
    pa = convert_to_palo_alto(parsed)
    report = run_pcap_test(parsed, generated.raw_request)

    return {
        "rule": db_rule,
        "http_request": {"raw_request": generated.raw_request, "notes": generated.notes},
        "palo_alto": {
            "signature_id": pa.signature_id,
            "xml": pa.xml,
            "cli_commands": pa.cli_commands,
            "warnings": pa.warnings,
        },
        "test_report": {
            "summary": report.summary,
            "false_positive_rate": report.false_positive_rate,
            "true_positive_matched": report.true_positive.matched,
            "false_positive_hits": sum(1 for r in report.false_positive_checks if r.matched),
            "false_positive_total": len(report.false_positive_checks),
        },
    }


app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
