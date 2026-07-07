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

## Çoklu Snort sürümü desteği

Aynı SID, farklı Snort sürümlerinde farklı sözdizimiyle (ör. Snort 3'te
`http_uri` sticky buffer, Snort 2.x'te eski `uricontent`) yayınlanabildiği
için veritabanı `(sid, snort_version)` ikilisine göre ayrı satırlar tutar.
Desteklenen sürümler ve kaynakları `app/config.py` içindeki
`RULESET_SOURCES` listesinde tanımlıdır:

| Sürüm | Kaynak | Canlı senkronizasyon |
|---|---|---|
| 3.x | Snort 3 Community Rules (snort.org, resmi) | ✅ |
| 2.9 | Snort 2.9 GPLv2 Community Rules (snort.org, resmi) | ✅ |
| 2.9 | Emerging Threats Open (2.7/2.8/2.9 ile büyük ölçüde uyumlu) | ✅ |
| 2.8 | — (EOL, resmi ücretsiz kaynak yok) | ❌ yalnızca dosya yükleme |
| 2.7 | — (EOL, resmi ücretsiz kaynak yok) | ❌ yalnızca dosya yükleme |

**Dürüstlük notu:** Cisco/Talos, Snort 2.7/2.8 gibi EOL sürümler için artık
ücretsiz/kayıtsız bir community ruleset yayınlamıyor. Bu sürümler için
gerçekçi yol, kendi elinizdeki `.rules` dosyalarını arayüzdeki **"Dosya
Yükleyerek Veritabanını Güncelle"** özelliğiyle sisteme eklemektir.

## Manuel dosya ile veritabanı güncelleme

Arayüzdeki dosya seçiciden `.rules`, `.txt` ya da `.tar.gz`/`.tgz` uzantılı
bir dosya seçip hedef Snort sürümünü belirleyip yükleyebilirsiniz. Sistem
formatı otomatik algılar (tar arşivi / düz gzip / düz metin) ve içindeki
her `sid:` içeren satırı ayrıştırıp veritabanına ekler/günceller.

## Değişiklik notu: scapy kaldırıldı (HTTP 500 düzeltmesi)

Önceki sürüm PCAP üretimi için `scapy` kütüphanesini kullanıyordu. Scapy,
Render gibi minimal/kısıtlı konteyner ortamlarında ağ arayüzü algılama
sırasında beklenmedik exception fırlatabiliyor ve bu da `/api/rule/{sid}/test`
uç noktasında opak bir **HTTP 500** hatasına yol açıyordu. Bu sürümde PCAP
üretimi tamamen `app/pcap_writer.py` içinde, harici bağımlılık olmadan
(sadece Python'ın `struct`/`socket` modülleriyle) yeniden yazıldı — geçerli
Ethernet/IPv4/TCP checksum'larına sahip, standart `.pcap` formatına %100
uyumlu dosyalar üretir. Ayrıca artık herhangi bir sunucu hatası, boş "HTTP
500" yerine gerçek hata mesajını (`Sunucu hatası: ...`) doğrudan arayüzde
gösterir.

## API uç noktaları

| Method | Path | Açıklama |
|---|---|---|
| GET  | `/api/sources` | Tanımlı tüm kaynak/sürümlerin listesi |
| GET  | `/api/status` | Toplam kural sayısı, sürüme göre dağılım, son güncelleme/son yüklenen dosya bilgisi |
| POST | `/api/sync/offline-sample` | Bundle edilmiş demo kuralları (3.x + 2.9) yükler |
| POST | `/api/sync/all` | url tanımlı TÜM canlı kaynakları (3.x, 2.9 community, ET Open) senkronize eder |
| POST | `/api/sync/source/{key}` | Tek bir kaynağı senkronize eder (ör. `snort3-community`) |
| POST | `/api/upload-rules` | (multipart) Manuel `.rules`/`.tar.gz` dosyası yükler, `snort_version` form alanı zorunlu |
| GET  | `/api/sync/history` | Son 30 senkronizasyon/yükleme kaydı |
| GET  | `/api/rules?snort_version=&limit=` | Veritabanındaki kuralları listeler (sürüme göre filtrelenebilir) |
| GET  | `/api/rule/{sid}/versions` | Bu SID'in hangi sürümlerde kayıtlı olduğunu döner |
| GET  | `/api/rule/{sid}?snort_version=` | Ham Snort kuralını döner (sürüm verilmezse otomatik tercih sırası: 3.x → 2.9 → 2.8 → 2.7 → manual) |
| GET  | `/api/rule/{sid}/http?snort_version=` | Tetikleyici RAW HTTP isteğini üretir |
| GET  | `/api/rule/{sid}/paloalto?snort_version=` | Palo Alto XML + CLI çıktısını üretir |
| GET  | `/api/rule/{sid}/test?snort_version=` | PCAP tabanlı TP/FP raporu (base64 pcap dahil) |
| GET  | `/api/rule/{sid}/full-report?snort_version=` | Yukarıdakilerin hepsini tek çağrıda döner |

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
