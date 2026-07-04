"""
Bu modül, bir Snort kuralının SADECE kendi içinde zaten açıkça yayınlanmış
content/pcre desenlerini kullanarak, kuralı tetikleyecek MİNİMAL ve
SENTETİK bir HTTP isteği kurar.

Önemli tasarım kararı: Burada hiçbir gerçek exploit payload'ı, shellcode
veya zafiyet istismar kodu üretilmez. Sadece kuralın "bu string / bu regex
şu buffer'da geçmeli" şeklindeki, kuralı yazan kişi tarafından zaten
herkese açık şekilde yayınlanmış eşleşme kriterleri, o kriterleri
sağlayan en basit metne dönüştürülür (ör. content "cmd.exe" ise URI'ye
"cmd.exe" yerleştirilir). Bu, IPS/IDS QA mühendisliğinde standart bir
"trigger traffic" / "detection test" pratiğidir.
"""
from dataclasses import dataclass
from typing import Optional
from app.snort_parser import ParsedRule, ContentMatch


@dataclass
class GeneratedHttp:
    raw_request: str
    method: str
    uri: str
    headers: dict
    body: str
    notes: list


def _safe_text(b: bytes) -> str:
    """Byte dizisini URI/header'a gömülebilecek, yazdırılabilir bir metne çevirir."""
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        s = b.decode("latin-1", errors="replace")
    # Kontrol karakterlerini görünür placeholder ile değiştir (gerçek isteği bozmamak için)
    return "".join(c if c.isprintable() else f"%{ord(c):02X}" for c in s)


def generate_http_request(rule: ParsedRule, host: str = "victim.example.local") -> GeneratedHttp:
    method = "GET"
    uri_parts = ["/"]
    headers = {
        "Host": host,
        "User-Agent": "Mozilla/5.0 (SnortRuleTester/1.0)",
        "Accept": "*/*",
        "Connection": "close",
    }
    body_parts = []
    notes = []

    negated_skipped = 0

    for c in rule.contents:  # type: ContentMatch
        if c.negated:
            negated_skipped += 1
            continue
        text = _safe_text(c.pattern_bytes)
        buf = c.http_buffer or "http_uri"

        if buf in ("http_uri", "http_raw_uri"):
            uri_parts.append(text)
        elif buf == "http_method":
            method = text.strip().split()[0] if text.strip() else method
        elif buf == "http_header":
            # "Header: value" formatındaysa ayrıştır, değilse ham ekle
            if ":" in text:
                k, _, v = text.partition(":")
                headers[k.strip()] = v.strip()
            else:
                headers.setdefault("X-Rule-Header", text)
        elif buf == "http_user_agent":
            headers["User-Agent"] = text
        elif buf == "http_cookie":
            headers["Cookie"] = text
        elif buf == "http_client_body":
            body_parts.append(text)
            method = "POST"
        else:
            # http buffer belirtilmemiş / genel payload -> URI'ye ekle (en yaygın senaryo)
            uri_parts.append(text)

    if negated_skipped:
        notes.append(
            f"{negated_skipped} adet negatif (!) content koşulu, test isteğinden "
            f"kasıtlı olarak çıkarıldı (bu içerik BULUNMAMALI anlamına geliyordu)."
        )

    if rule.pcres:
        notes.append(
            f"Kuralda {len(rule.pcres)} adet pcre deseni tespit edildi. "
            f"Otomatik metin üretimi regex'ler için tam garanti vermez; "
            f"raporda regex'ler ayrıca listelenir, manuel doğrulama önerilir."
        )

    uri = "".join(uri_parts) if len(uri_parts) > 1 else "/"
    if not uri.startswith("/"):
        uri = "/" + uri

    body = "".join(body_parts)
    if body:
        headers["Content-Length"] = str(len(body.encode("utf-8")))
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    request_line = f"{method} {uri} HTTP/1.1"
    header_lines = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
    raw = f"{request_line}\r\n{header_lines}\r\n\r\n{body}"

    return GeneratedHttp(
        raw_request=raw,
        method=method,
        uri=uri,
        headers=headers,
        body=body,
        notes=notes or ["Kural yalnızca içerik desenlerinden başarıyla türetildi."],
    )
