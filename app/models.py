from datetime import datetime
from typing import Optional
from sqlalchemy import UniqueConstraint
from sqlmodel import SQLModel, Field


class SnortRule(SQLModel, table=True):
    """Senkronize edilmiş her Snort kuralı için normalize edilmiş kayıt.

    ÖNEMLİ: Aynı SID, farklı Snort sürümlerinde (2.7/2.8/2.9/3.x) farklı
    sözdizimiyle (ör. sticky buffer'lar) yayınlanabilir. Bu yüzden benzersizlik
    tek başına 'sid' üzerinde değil, ('sid', 'snort_version') ikilisi
    üzerinde tanımlanır — aynı SID birden fazla sürüm için ayrı satır olarak
    saklanabilir.
    """
    __table_args__ = (UniqueConstraint("sid", "snort_version", name="uq_sid_version"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    sid: int = Field(index=True)
    snort_version: str = Field(default="3.x", index=True)  # "2.7" | "2.8" | "2.9" | "3.x" | "manual"
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
    ruleset_source: str = "community"   # community | et-open | manual-upload:<dosyaadi> | offline-sample
    source_file: Optional[str] = None   # yüklenen/indirilen dosyanın adı (varsa)
    synced_at: datetime = Field(default_factory=datetime.utcnow)


class SyncLog(SQLModel, table=True):
    """Her senkronizasyon veya dosya yükleme işleminin geçmişi.

    Sitedeki 'son güncelleme tarihi' / 'son güncellenen dosya' bilgisi bu
    tablodan üretilir.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None
    status: str = "running"  # running | success | failed
    rules_ingested: int = 0
    rules_skipped: int = 0          # ayrıştırılamayan/hatalı satır sayısı
    skipped_samples: Optional[str] = None  # JSON: [{"line":..., "reason":...}, ...] ilk N örnek
    source_used: Optional[str] = None      # url ya da "manual-upload"
    snort_version: Optional[str] = None    # bu senkronizasyonun etiketlediği sürüm
    file_name: Optional[str] = None        # yüklenen dosyanın adı (elle yüklemede)
    is_manual_upload: bool = False
    error: Optional[str] = None
