import os

DATA_DIR = os.getenv("DATA_DIR", "./data")
os.makedirs(DATA_DIR, exist_ok=True)

# ÖNEMLİ DÜZELTME: Veritabanı dosyası artık DATA_DIR'in İÇİNDE oluşturuluyor.
# Önceki sürümde varsayılan yol './snort_toolkit.db' idi — bu, docker-compose
# içindeki kalıcı disk (volume) olarak tanımlanan './data' klasörünün DIŞINDA
# kalıyordu. Sonuç: container her yeniden oluşturulduğunda (deploy, restart,
# `docker compose up --build`) veritabanı sıfırlanıyordu. Şimdi dosya
# DATA_DIR içinde olduğu için VPS/Oracle gibi kalıcı disk kullanan
# ortamlarda gerçekten kalıcı olacak.
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR}/snort_toolkit.db")

# Kaç saatte bir otomatik senkronizasyon yapılacağı (7/24 canlı servis için)
SYNC_INTERVAL_HOURS = int(os.getenv("SYNC_INTERVAL_HOURS", "6"))

# ---------------------------------------------------------------------------
# Çoklu Snort sürümü kaynakları.
#
# Not (dürüstlük payı): Snort 2.7 / 2.8 gibi çok eski (EOL) sürümler için
# Cisco/Talos artık ücretsiz, kayıtsız bir "community" ruleset yayınlamıyor —
# bu sürümlerin resmi ücretsiz/güncel bir kaynağı yoktur. Bu sürümler için en
# pratik yol, arayüzdeki "Dosya Yükle" özelliğiyle kendi elinizdeki
# .rules dosyalarını sisteme manuel olarak eklemektir (bkz. /api/upload-rules).
#
# "url" alanı olan girdiler otomatik/canlı senkronize edilebilir.
# "url" alanı None olanlar sadece "manuel yükleme" ile beslenir.
# ---------------------------------------------------------------------------
RULESET_SOURCES = [
    {
        "key": "snort3-community",
        "label": "Snort 3 Community Rules (resmi, snort.org)",
        "snort_version": "3.x",
        "url": os.getenv(
            "SNORT3_RULES_URL",
            "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz",
        ),
        "archive_format": "auto",  # tar.gz ya da düz .gz olabilir, otomatik algılanır
    },
    {
        "key": "snort29-community",
        "label": "Snort 2.9 GPLv2 Community Rules (resmi, snort.org)",
        "snort_version": "2.9",
        "url": os.getenv(
            "SNORT29_RULES_URL",
            "https://www.snort.org/downloads/community/community-rules.tar.gz",
        ),
        "archive_format": "auto",
    },
    {
        "key": "et-open-2.9",
        "label": "Emerging Threats Open (2.7/2.8/2.9 ile büyük ölçüde uyumlu)",
        "snort_version": "2.9",
        "url": os.getenv(
            "ET_OPEN_RULES_URL",
            "https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz",
        ),
        "archive_format": "auto",
    },
    {
        # 2.7 ve 2.8 için resmi/ücretsiz canlı kaynak yok (EOL) -> url=None,
        # sadece manuel dosya yüklemesiyle beslenir. Burada tutmamızın amacı,
        # arayüzde bu sürümleri seçenek olarak göstermek ve durumunu şeffafça
        # açıklamaktır.
        "key": "snort28-manual",
        "label": "Snort 2.8 (yalnızca manuel dosya yükleme — canlı kaynak yok)",
        "snort_version": "2.8",
        "url": None,
        "archive_format": "auto",
    },
    {
        "key": "snort27-manual",
        "label": "Snort 2.7 (yalnızca manuel dosya yükleme — canlı kaynak yok)",
        "snort_version": "2.7",
        "url": None,
        "archive_format": "auto",
    },
]

_seen = []
for _s in RULESET_SOURCES:
    if _s["snort_version"] not in _seen:
        _seen.append(_s["snort_version"])
_seen.append("manual")  # dosya yükleme sırasında "diğer/belirsiz sürüm" etiketi olarak kullanılabilir
SUPPORTED_VERSIONS = _seen
