from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field


class SnortRule(SQLModel, table=True):
    """Senkronize edilmiş her Snort kuralı için normalize edilmiş kayıt."""

    id: Optional[int] = Field(default=None, primary_key=True)
    sid: int = Field(index=True, unique=True)
    gid: int = Field(default=1)
    rev: int = Field(default=1)
    msg: str = ""
    classtype: Optional[str] = None
    action: str = "alert"
    protocol: str = "tcp"
    src: str = "$EXTERNAL_NET"
    src_port: str = "any"
    direction: str = "->"
    dst: str = "$HOME_NET"
    dst_port: str = "any"
    raw_rule: str = ""
    options_json: str = "{}"  # parse edilmiş option'ların JSON dökümü
    ruleset_source: str = "community"
    synced_at: datetime = Field(default_factory=datetime.utcnow)


class SyncLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None
    status: str = "running"  # running | success | failed
    rules_ingested: int = 0
    source_used: Optional[str] = None
    error: Optional[str] = None
