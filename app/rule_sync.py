import io
import json
import tarfile
import logging
from datetime import datetime

import httpx
from sqlmodel import Session, select

from app.config import SNORT_RULES_URL, SNORT_RULES_FALLBACK_URL, DATA_DIR
from app.database import engine
from app.models import SnortRule, SyncLog
from app.snort_parser import parse_rule

logger = logging.getLogger("rule_sync")

LOCAL_SAMPLE_RULES_PATH = f"{DATA_DIR}/../app/sample_rules.rules"


def _download(url: str) -> bytes:
    with httpx.Client(follow_redirects=True, timeout=60.0) as client:
        resp = client.get(url, headers={"User-Agent": "snort-toolkit-sync/1.0"})
        resp.raise_for_status()
        return resp.content


def _iter_rule_lines_from_tarball(content: bytes):
    with tarfile.open(fileobj=io.BytesIO(content)) as tar:
        for member in tar.getmembers():
            if member.name.endswith(".rules"):
                f = tar.extractfile(member)
                if not f:
                    continue
                for raw_line in f.read().decode("utf-8", errors="replace").splitlines():
                    yield raw_line


def _iter_rule_lines_from_local_sample():
    with open(LOCAL_SAMPLE_RULES_PATH, "r", encoding="utf-8") as f:
        for line in f:
            yield line


def sync_rules(session: Session, use_offline_sample: bool = False) -> SyncLog:
    log = SyncLog(status="running")
    session.add(log)
    session.commit()
    session.refresh(log)

    ingested = 0
    source_used = "offline_sample"
    try:
        if use_offline_sample:
            lines = _iter_rule_lines_from_local_sample()
        else:
            try:
                content = _download(SNORT_RULES_URL)
                source_used = SNORT_RULES_URL
            except Exception as primary_err:
                logger.warning("Birincil kaynak başarısız (%s), fallback deneniyor", primary_err)
                content = _download(SNORT_RULES_FALLBACK_URL)
                source_used = SNORT_RULES_FALLBACK_URL
            lines = _iter_rule_lines_from_tarball(content)

        for raw_line in lines:
            parsed = parse_rule(raw_line)
            if not parsed or not parsed.sid:
                continue

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

            existing = session.exec(select(SnortRule).where(SnortRule.sid == parsed.sid)).first()
            if existing:
                existing.rev = parsed.rev
                existing.msg = parsed.msg
                existing.classtype = parsed.classtype
                existing.raw_rule = parsed.raw
                existing.options_json = json.dumps(options_dump)
                existing.synced_at = datetime.utcnow()
                session.add(existing)
            else:
                session.add(
                    SnortRule(
                        sid=parsed.sid,
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
                    )
                )
            ingested += 1

        session.commit()
        log.status = "success"
        log.rules_ingested = ingested
        log.source_used = source_used
    except Exception as e:
        logger.exception("Senkronizasyon başarısız")
        log.status = "failed"
        log.error = str(e)
    finally:
        log.finished_at = datetime.utcnow()
        session.add(log)
        session.commit()
        session.refresh(log)

    return log
