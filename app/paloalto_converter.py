"""
Snort -> Palo Alto Networks "Custom Vulnerability Signature" dönüştürücüsü.

ÖNEMLİ NOT (kullanıcıya raporda da gösterilir):
Palo Alto'nun context (bağlam) listesi PAN-OS sürümüne göre değişebilir.
Burada kullanılan context isimleri (http-req-uri-path, http-req-headers, vb.)
en yaygın/stabil olanlardır; canlıya almadan önce cihazınızdaki
"Objects > Custom Objects > Vulnerability > Signature > Context" açılır
listesinden doğrulanması önerilir.
"""
from dataclasses import dataclass, field
from typing import Optional
from xml.sax.saxutils import escape
from app.snort_parser import ParsedRule

# Snort content buffer -> Palo Alto pattern-match context eşlemesi
CONTEXT_MAP = {
    "http_uri": "http-req-uri-path",
    "http_raw_uri": "http-req-uri-path",
    "http_header": "http-req-headers",
    "http_client_body": "http-req-params",
    "http_method": "http-req-uri-path",
    "http_cookie": "http-req-cookie-header",
    "http_user_agent": "http-req-user-agent-header",
    "http_stat_code": "http-rsp-status-line",
    None: "http-req-uri-path",  # http_buffer belirtilmemişse en yaygın varsayım
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


@dataclass
class PaConversionResult:
    signature_id: int
    xml: str
    cli_commands: list
    warnings: list = field(default_factory=list)


def _pa_severity(classtype: Optional[str]) -> str:
    return SEVERITY_MAP.get(classtype or "", "medium")


def _pa_signature_id(sid: int) -> int:
    # PAN-OS custom vulnerability object ID aralığı (klasik): 6800001 - 6900000
    return 6800001 + (sid % 99998)


def convert_to_palo_alto(rule: ParsedRule) -> PaConversionResult:
    warnings = []
    pa_id = _pa_signature_id(rule.sid or 0)
    threat_name = (rule.msg or f"Converted from Snort SID {rule.sid}").strip()[:127]
    severity = _pa_severity(rule.classtype)
    direction = "client2server"  # Snort $EXTERNAL_NET -> $HOME_NET tipik senaryo

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
        context = CONTEXT_MAP.get(c.http_buffer, CONTEXT_MAP[None])
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
        context = CONTEXT_MAP.get(p.http_buffer, CONTEXT_MAP[None])
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
        signature_id=pa_id, xml=xml, cli_commands=cli_commands, warnings=warnings
    )
