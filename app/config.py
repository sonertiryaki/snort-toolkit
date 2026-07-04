import os

# Resmi Snort 3 community ruleset kaynağı (snort.org).
# Not: snort.org bazı isteklerde User-Agent / oink-code isteyebilir.
# Kurumsal kullanımda kendi Oinkcode'unuzla registered/subscriber feed'e geçebilirsiniz.
SNORT_RULES_URL = os.getenv(
    "SNORT_RULES_URL",
    "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz",
)

# Alternatif/yedek kaynak (GitHub aynası) - birincil kaynak erişilemezse kullanılır.
SNORT_RULES_FALLBACK_URL = os.getenv(
    "SNORT_RULES_FALLBACK_URL",
    "https://raw.githubusercontent.com/thereisnotime/Snort-Rules/master/snort3-community-rules.tar",
)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./snort_toolkit.db")

# Kaç saatte bir otomatik senkronizasyon yapılacağı (7/24 canlı servis için)
SYNC_INTERVAL_HOURS = int(os.getenv("SYNC_INTERVAL_HOURS", "6"))

DATA_DIR = os.getenv("DATA_DIR", "./data")
os.makedirs(DATA_DIR, exist_ok=True)
