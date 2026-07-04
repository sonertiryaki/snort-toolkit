# Snort SID → Palo Alto Dönüştürücü & Test Toolkit

Bir Snort SID girildiğinde:
1. Senkronize edilmiş kural veritabanından kuralı bulur.
2. Kuralı tetikleyecek örnek bir **RAW HTTP isteği** üretir (yalnızca kuralın
   kendi content/pcre desenlerinden — hiçbir gerçek exploit/payload eklenmez).
3. Kuralı **Palo Alto Custom Vulnerability Signature** (XML + `set` CLI komutları) formatına çevirir.
4. Üretilen isteği ve temiz kurumsal trafik havuzunu bir **PCAP**'e yazar, kuralı
   her ikisine karşı simüle ederek **True Positive / False Positive raporu** üretir.

## Mimari

```
frontend/         → tek sayfalık dashboard (statik HTML/CSS/JS, backend'in kendisi servis eder)
app/
  main.py         → FastAPI uygulaması ve API endpoint'leri
  snort_parser.py → Snort kural metnini yapılandırılmış modele çevirir
  rule_sync.py    → snort.org / GitHub kaynağından .tar.gz indirir, DB'ye upsert eder
  http_generator.py → content/pcre desenlerinden sentetik HTTP isteği kurar
  paloalto_converter.py → Snort AND/OR content mantığını PAN-OS And/Or Condition ağacına çevirir
  match_engine.py → basitleştirilmiş content/pcre eşleştirme motoru (TP/FP testi için)
  pcap_tester.py  → scapy ile PCAP üretir, TP + FP havuzunu test eder
  clean_corpus.py → false-positive testi için zararsız örnek kurumsal trafik
  models.py       → SQLModel tabloları (SnortRule, SyncLog)
```

## Yerel çalıştırma

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Tarayıcıda `http://localhost:8000` açın. İlk kullanımda ağ erişiminiz yoksa
(ör. kapalı bir test ortamı) **"Offline demo veri seti ile senkronize et"**
butonuna basın — bu, `app/sample_rules.rules` içindeki 6 örnek kuralı yükler
(sid: 1000001–1000006). Gerçek ortamda **"Canlı kaynaktan senkronize et"**
butonu `snort.org`'un resmi `snort3-community-rules.tar.gz` dosyasını indirir.

## API uç noktaları

| Method | Path | Açıklama |
|---|---|---|
| POST | `/api/sync?offline_sample=true|false` | Kural setini senkronize eder |
| GET  | `/api/rules` | Veritabanındaki kuralları listeler |
| GET  | `/api/rule/{sid}` | Ham Snort kuralını döner |
| GET  | `/api/rule/{sid}/http` | Tetikleyici RAW HTTP isteğini üretir |
| GET  | `/api/rule/{sid}/paloalto` | Palo Alto XML + CLI çıktısını üretir |
| GET  | `/api/rule/{sid}/test` | PCAP tabanlı TP/FP raporu (base64 pcap dahil) |
| GET  | `/api/rule/{sid}/full-report` | Yukarıdakilerin hepsini tek çağrıda döner |

## 7/24 canlıya alma (production deployment)

Bu bir Anthropic/Claude sohbet ortamında barındırılamaz — kodu kendi
sunucunuza/cloud hesabınıza deploy etmeniz gerekir. Üç seçenek:

### Seçenek A — Docker Compose + Caddy (kendi VPS'inizde, otomatik HTTPS)
```bash
# Caddyfile içindeki your-domain.com'u kendi alan adınızla değiştirin
docker compose up -d --build
```
`restart: unless-stopped` ile sunucu yeniden başlasa bile servis otomatik
ayağa kalkar. `SYNC_INTERVAL_HOURS` ortam değişkeniyle otomatik senkronizasyon
sıklığını ayarlayabilirsiniz (varsayılan: 6 saat).

### Seçenek B — Render / Fly.io / Railway (yönetilen PaaS)
Repo'yu GitHub'a pushlayıp bu platformlardan birine bağlayın; hepsi
`Dockerfile`'ı otomatik algılar, otomatik yeniden başlatma ve HTTPS sağlar.
Ek olarak persistent disk (SQLite dosyası için) eklemeyi unutmayın.

### Seçenek C — systemd (çıplak metal / VM)
```ini
# /etc/systemd/system/snort-toolkit.service
[Unit]
Description=Snort to PAN Toolkit
After=network.target

[Service]
WorkingDirectory=/opt/snort-toolkit
ExecStart=/opt/snort-toolkit/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl enable --now snort-toolkit
```

## Önemli sınırlamalar ve doğrulama notları

- **HTTP üreticisi** yalnızca kuralın *kendi içinde zaten yayınlanmış* içerik
  desenlerini kullanır; hiçbir zafiyet/exploit kodu eklemez. `pcre` tabanlı
  kurallarda üretilen metin bazen regex'i tam karşılamayabilir — bu
  durumlar "notes" alanında açıkça belirtilir.
- **Eşleştirme motoru** (`match_engine.py`), gerçek Snort/Snort3 detection
  engine'inin (stream reassembly, preprocessor'lar, `fast_pattern`,
  `flowbits` durum makinesi vb. dahil) tam bir kopyası değildir. Canlıya
  almadan önce üretilen PCAP'i gerçek Snort binary'siyle doğrulamanız önerilir:
  ```bash
  snort -r sid_XXXX_test.pcap -c snort3-community-rules/snort3-community.rules -A alert_fast
  ```
- **Palo Alto context eşlemesi** PAN-OS sürümüne göre değişebilir; canlıya
  almadan önce cihazınızdaki context listesinden doğrulayın
  (`Objects > Custom Objects > Vulnerability > Signature`).
- `clean_corpus.py` içindeki temiz trafik havuzu genel/örnek amaçlıdır;
  gerçek false-positive oranını ölçmek için **kendi kurumsal trafiğinizden**
  anonimleştirilmiş örnekler eklemeniz önerilir.
