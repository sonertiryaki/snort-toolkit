"""
Snort -> Palo Alto Networks "Custom Vulnerability Signature" dönüştürücüsü.

ÖNEMLİ NOT (kullanıcıya raporda da gösterilir):
Palo Alto'nun context (bağlam) listesi PAN-OS sürümüne göre değişebilir.
Burada kullanılan context isimleri (http-req-uri-path, http-req-headers, vb.)
en yaygın/stabil olanlardır; canlıya almadan önce cihazınızdaki
"Objects > Custom Objects > Vulnerability > Signature > Context" açılır
listesinden doğrulanması önerilir.

FALSE-POSITIVE NOTU: Her Snort kuralı bir "Custom Vulnerability Signature"a
dönüşmeye uygun değildir. Örneğin FILE-IDENTIFY (dosya imza/magic byte
tespiti) veya POLICY kategorisindeki kurallar, PAN-OS'ta daha doğru şekilde
File Blocking / WildFire profilleriyle karşılanır — bunları zorla IPS
imzasına çevirmek ya yanlış context (ör. HTTP URI'de dosya magic byte'ı
aramak) ya da aşırı genel bir desen yüzünden false-positive riski taşır.
Bu modül böyle durumları SESSİZCE dönüştürmek yerine açıkça uyarır.
"""
from dataclasses import dataclass, field
from typing import Optional
from xml.sax.saxutils import escape
from app.snort_parser import ParsedRule

# Snort content buffer -> Palo Alto pattern-match context eşlemesi.
# NOT: None (buffer belirtilmemiş) burada KASITLI OLARAK yok — çünkü bunu
# otomatik olarak http-req-uri-path'e eşlemek, HTTP'ye özel olmayan
# (ör. dosya imzası, ham TCP payload) kurallarda YANLIŞ ve false-positive'e
# açık bir context üretiyordu. Bu durumlar aşağıda özel olarak ele alınıyor.
CONTEXT_MAP = {
    "http_uri": "http-req-uri-path",
    "http_raw_uri": "http-req-uri-path",
    "http_header": "http-req-headers",
    "http_client_body": "http-req-params",
    "http_method": "http-req-uri-path",
    "http_cookie": "http-req-cookie-header",
    "http_user_agent": "http-req-user-agent-header",
    "http_stat_code": "http-rsp-status-line",
}

SEVERITY_MAP = {
    "attempted-admin": "critical",
    "attempted-user": "high",
    "web-application-attack": "high",
    "trojan-activity": "critical",
    "misc-activity": "low",
    "policy-violation": "low",
    "bad-unknown": "medium",
}

# Bu kategoriler genelde bir "saldırı imzası" değil, bilgi/dosya-tipi/politika
# amaçlıdır; Custom Vulnerability Signature yerine PAN-OS'un başka
# özellikleriyle (File Blocking, WildFire, App-ID) karşılanmalıdır.
POOR_FIT_CLASSTYPES = {"misc-activity", "not-suspicious", "unknown", "protocol-command-decode"}
POOR_FIT_MSG_PREFIXES = ("FILE-IDENTIFY", "POLICY", "INDICATOR-SCAN", "PROTOCOL-")

MIN_SPECIFIC_PATTERN_LENGTH = 4  # bundan kısa/genel desenler FP riski taşır


@dataclass
class PaConversionResult:
    signature_id: int
    xml: str
    cli_commands: list
    warnings: list = field(default_factory=list)
    conversion_confidence: str = "high"  # high | medium | low


def _pa_severity(classtype: Optional[str]) -> str:
    return SEVERITY_MAP.get(classtype or "", "medium")




def _pa_signature_id(sid: int) -> int:
    # PAN-OS custom vulnerability object ID aralığı (klasik): 6800001 - 6900000
    return 6800001 + (sid % 99998)


def convert_to_palo_alto(rule: ParsedRule) -> PaConversionResult:
    warnings = []
    confidence = "high"
    pa_id = _pa_signature_id(rule.sid or 0)
    threat_name = (rule.msg or f"Converted from Snort SID {rule.sid}").strip()[:127]
    severity = _pa_severity(rule.classtype)
    direction = "client2server"  # Snort $EXTERNAL_NET -> $HOME_NET tipik senaryo

    # --- Ön analiz: bu kural gerçekten bir "Custom Vulnerability Signature"
    # olmaya uygun mu? Değilse, sessizce kötü bir imza üretmek yerine
    # açıkça uyarıyoruz (false-positive'lerin en büyük kaynağı budur).
    msg_upper = (rule.msg or "").upper()
    is_poor_fit = (rule.classtype in POOR_FIT_CLASSTYPES) or any(
        msg_upper.startswith(p) for p in POOR_FIT_MSG_PREFIXES
    )
    if is_poor_fit:
        confidence = "low"
        warnings.append(
            f"BU KURAL TİPİ IPS İMZASINA UYGUN DEĞİL: '{rule.msg}' (classtype: "
            f"{rule.classtype}) bir saldırı imzasından çok dosya-tipi/protokol/politika "
            f"bilgisi niteliğinde. PAN-OS'ta bunu Custom Vulnerability Signature olarak "
            f"zorlamak yerine File Blocking profili, WildFire ya da App-ID tabanlı bir "
            f"politika kullanmanız önerilir — aşağıdaki imza yalnızca referans amaçlıdır "
            f"ve canlıya almadan önce dikkatle gözden geçirilmelidir."
        )

    and_entries_xml = []
    cli_commands = []

    base = f"set threats vulnerability custom-vuln-{pa_id}"
    cli_commands.append(f'{base} threatname "{threat_name}"')
    cli_commands.append(f"{base} severity {severity}")
    cli_commands.append(f"{base} direction {direction}")

    usable_contents = [c for c in rule.contents if not c.negated]
    if not usable_contents and not rule.pcres:
        warnings.append(
            "Kuralda pozitif bir content/pcre bulunamadı; sadece flow/metadata "
            "tabanlı bir kural olabilir. Manuel context ataması gerekir."
        )

    # ONEMLI: Snort'ta bir kural icindeki birden fazla content/pcre option'i
    # varsayilan olarak VE (AND) ile birlesir - hepsi eslesmelidir. Bu yuzden
    # her content/pcre kendi "And Condition N" blogunda (icinde tek elemanli
    # bir or-condition ile) yer alir; hepsi ust duzey <and-condition> listesine
    # eklenir. Tek bir or-condition altina toplamak YANLISTIR, cunku PAN-OS'ta
    # bu "herhangi biri yeterli" (OR) anlamina gelir.
    and_idx = 0
    for c in usable_contents:
        and_idx += 1

        if c.http_buffer:
            context = CONTEXT_MAP[c.http_buffer]
        else:
            # ÖNEMLİ DÜZELTME: http_buffer belirtilmemiş bir content (ör. file_data
            # sonrası dosya imzası, ham TCP payload) ARTIK otomatik olarak
            # http-req-uri-path'e eşlenmiyor. Bu yanlış varsayım, HTTP'ye özel
            # olmayan kuralları URI'de arayan, dolayısıyla ya hiç eşleşmeyen ya
            # da rastgele URI'lerle false-positive üreten imzalara sebep oluyordu.
            context = "http-req-uri-path"  # PAN-OS bir context İSTER; en yaygını kullanılıyor
            confidence = "low" if confidence != "low" else confidence
            warnings.append(
                f"content #{and_idx} ('{c.pattern_raw}') herhangi bir http_* buffer'a "
                f"(http_uri, http_header, http_client_body vb.) bağlı değil — muhtemelen "
                f"ham TCP payload'ı, dosya verisi (file_data) ya da başka bir protokol "
                f"alanı hedefleniyor. Bu imza varsayılan olarak 'http-req-uri-path' "
                f"context'ine yerleştirildi ANCAK BU YANLIŞ OLABİLİR — cihazınızda bu "
                f"kural için doğru context'i (ör. ftp-command, smtp-body, ya da dosya "
                f"tipi tespiti gerekiyorsa File Blocking profili) MANUEL olarak seçmeniz "
                f"şiddetle önerilir. Bu haliyle kullanmak false-positive/false-negative "
                f"riski taşır."
            )

        if len(c.pattern_bytes) < MIN_SPECIFIC_PATTERN_LENGTH and not c.nocase:
            confidence = "low" if confidence != "low" else confidence
            warnings.append(
                f"content #{and_idx} ('{c.pattern_raw}') {len(c.pattern_bytes)} byte "
                f"gibi kısa/genel bir desen — meşru trafikte rastgele eşleşme (false "
                f"positive) olasılığı yüksektir. depth/offset/distance/within ile "
                f"daraltılması ya da ek bir content ile birleştirilmesi önerilir."
            )

        try:
            pattern_text = c.pattern_bytes.decode("utf-8")
        except UnicodeDecodeError:
            pattern_text = c.pattern_bytes.decode("latin-1", errors="replace")
            warnings.append(
                f"content #{and_idx} binary veri iceriyor; PAN-OS pattern alanina "
                f"aktarilirken bazi byte'lar kayipsiz yansimayabilir, regex/hex "
                f"biciminde manuel dogrulama onerilir."
            )

        and_entries_xml.append(f"""
      <entry name="And Condition {and_idx}">
        <or-condition>
          <entry name="Or Condition 1">
            <operator>
              <pattern-match>
                <pattern>{escape(pattern_text)}</pattern>
                <context>{context}</context>
                {"<qualifier><entry name='nocase'><value>yes</value></entry></qualifier>" if c.nocase else ""}
              </pattern-match>
            </operator>
          </entry>
        </or-condition>
      </entry>""")

        cli_commands.append(
            f'{base} signature Standard-1 and-condition "And Condition {and_idx}" '
            f'or-condition "Or Condition 1" operator pattern-match pattern "{pattern_text}"'
        )
        cli_commands.append(
            f'{base} signature Standard-1 and-condition "And Condition {and_idx}" '
            f'or-condition "Or Condition 1" operator pattern-match context {context}'
        )

    for p in rule.pcres:
        and_idx += 1
        context = CONTEXT_MAP.get(p.http_buffer, "http-req-uri-path")
        if not p.http_buffer:
            confidence = "low" if confidence != "low" else confidence
        warnings.append(
            f"pcre ('{p.regex}') PAN-OS pattern-match alanina regex olarak "
            f"aktarildi; PCRE ile PAN-OS regex motoru arasinda sozdizim farklari "
            f"olabileceginden test asamasinda ayrica dogrulanmali."
        )
        and_entries_xml.append(f"""
      <entry name="And Condition {and_idx}">
        <or-condition>
          <entry name="Or Condition 1">
            <operator>
              <pattern-match>
                <pattern>{escape(p.regex)}</pattern>
                <context>{context}</context>
              </pattern-match>
            </operator>
          </entry>
        </or-condition>
      </entry>""")
        cli_commands.append(
            f'{base} signature Standard-1 and-condition "And Condition {and_idx}" '
            f'or-condition "Or Condition 1" operator pattern-match pattern "{p.regex}"'
        )
        cli_commands.append(
            f'{base} signature Standard-1 and-condition "And Condition {and_idx}" '
            f'or-condition "Or Condition 1" operator pattern-match context {context}'
        )

    xml = f"""<entry name="custom-vuln-{pa_id}">
  <signature>
    <standard>
      <entry name="Standard-1">
        <and-condition>{"".join(and_entries_xml)}
        </and-condition>
      </entry>
    </standard>
  </signature>
  <threatname>{escape(threat_name)}</threatname>
  <severity>{severity}</severity>
  <direction>{direction}</direction>
  <default-action>
    <alert/>
  </default-action>
  <comment>Converted automatically from Snort SID {rule.sid} (rev {rule.rev}) by Snort-to-PAN Toolkit</comment>
</entry>"""

    cli_commands.append(f"{base} comment \"Converted from Snort SID {rule.sid} rev {rule.rev}\"")

    return PaConversionResult(
        signature_id=pa_id, xml=xml, cli_commands=cli_commands, warnings=warnings,
        conversion_confidence=confidence,
    )
