import base64
import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, select
from apscheduler.schedulers.background import BackgroundScheduler

from app.database import init_db, get_session, engine
from app.models import SnortRule, SyncLog
from app.config import SYNC_INTERVAL_HOURS
from app.rule_sync import sync_rules
from app.snort_parser import parse_rule
from app.http_generator import generate_http_request
from app.paloalto_converter import convert_to_palo_alto
from app.pcap_tester import run_pcap_test

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

scheduler = BackgroundScheduler()


def _scheduled_sync_job():
    with Session(engine) as session:
        # Canlı ortamda offline sample kullanılmaz; ağ erişimi varsayılır.
        log = sync_rules(session, use_offline_sample=False)
        logger.info("Zamanlanmış senkronizasyon tamamlandı: %s", log.status)


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
    logger.info("Servis başlatıldı. Otomatik senkronizasyon her %s saatte bir çalışacak.", SYNC_INTERVAL_HOURS)
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(
    title="Snort SID -> Palo Alto Dönüştürücü ve Test Toolkit",
    version="1.0.0",
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


@app.post("/api/sync")
def trigger_sync(offline_sample: bool = False, session: Session = Depends(get_session)):
    log = sync_rules(session, use_offline_sample=offline_sample)
    return {
        "status": log.status,
        "rules_ingested": log.rules_ingested,
        "source_used": log.source_used,
        "error": log.error,
    }


@app.get("/api/sync/history")
def sync_history(session: Session = Depends(get_session)):
    logs = session.exec(select(SyncLog).order_by(SyncLog.id.desc()).limit(20)).all()
    return logs


@app.get("/api/rules")
def list_rules(limit: int = 50, session: Session = Depends(get_session)):
    rules = session.exec(select(SnortRule).limit(limit)).all()
    return rules


def _get_rule_or_404(sid: int, session: Session) -> SnortRule:
    rule = session.exec(select(SnortRule).where(SnortRule.sid == sid)).first()
    if not rule:
        raise HTTPException(
            status_code=404,
            detail=f"SID {sid} veritabanında bulunamadı. Önce /api/sync ile senkronizasyon yapın.",
        )
    return rule


@app.get("/api/rule/{sid}")
def get_rule(sid: int, session: Session = Depends(get_session)):
    return _get_rule_or_404(sid, session)


@app.get("/api/rule/{sid}/http")
def get_http_request(sid: int, session: Session = Depends(get_session)):
    db_rule = _get_rule_or_404(sid, session)
    parsed = parse_rule(db_rule.raw_rule)
    if not parsed:
        raise HTTPException(status_code=500, detail="Kural parse edilemedi.")
    generated = generate_http_request(parsed)
    return {
        "sid": sid,
        "raw_request": generated.raw_request,
        "method": generated.method,
        "uri": generated.uri,
        "headers": generated.headers,
        "notes": generated.notes,
    }


@app.get("/api/rule/{sid}/paloalto")
def get_paloalto(sid: int, session: Session = Depends(get_session)):
    db_rule = _get_rule_or_404(sid, session)
    parsed = parse_rule(db_rule.raw_rule)
    if not parsed:
        raise HTTPException(status_code=500, detail="Kural parse edilemedi.")
    result = convert_to_palo_alto(parsed)
    return {
        "sid": sid,
        "signature_id": result.signature_id,
        "xml": result.xml,
        "cli_commands": result.cli_commands,
        "warnings": result.warnings,
    }


@app.get("/api/rule/{sid}/test")
def get_test_report(sid: int, session: Session = Depends(get_session)):
    db_rule = _get_rule_or_404(sid, session)
    parsed = parse_rule(db_rule.raw_rule)
    if not parsed:
        raise HTTPException(status_code=500, detail="Kural parse edilemedi.")

    generated = generate_http_request(parsed)
    report = run_pcap_test(parsed, generated.raw_request)

    return {
        "sid": sid,
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
def get_full_report(sid: int, session: Session = Depends(get_session)):
    """Tek çağrıda tüm iş akışı: kural + HTTP + PAN dönüşümü + test raporu."""
    db_rule = _get_rule_or_404(sid, session)
    parsed = parse_rule(db_rule.raw_rule)
    if not parsed:
        raise HTTPException(status_code=500, detail="Kural parse edilemedi.")

    generated = generate_http_request(parsed)
    pa = convert_to_palo_alto(parsed)
    report = run_pcap_test(parsed, generated.raw_request)

    return {
        "rule": db_rule,
        "http_request": {
            "raw_request": generated.raw_request,
            "notes": generated.notes,
        },
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


# Statik frontend dosyalarını sun (tek servis olarak deploy edilebilsin diye)
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
