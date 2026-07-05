"""
Snort 2/3 kural satırlarını parse eden modül.

Bir kural şu genel forma sahiptir:
    action proto src_ip src_port direction dst_ip dst_port ( option1; option2:value; ... )

Bu modül, kuralı hem üst düzey alanlara (sid, msg, classtype, header...)
hem de "content" / "pcre" gibi trafik eşleştirme option'larının
yapılandırılmış bir listesine ayırır. Üretilen yapı, hem HTTP request
üreticisi hem de Palo Alto dönüştürücüsü tarafından kullanılır.
"""
import re
import shlex
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ContentMatch:
    pattern_raw: str            # kuralda yazıldığı haliyle (hex escape'ler dahil)
    pattern_bytes: bytes        # çözülmüş (decoded) байт dizisi
    nocase: bool = False
    http_buffer: Optional[str] = None  # http_uri, http_header, http_client_body, http_method...
    depth: Optional[int] = None
    offset: Optional[int] = None
    distance: Optional[int] = None
    within: Optional[int] = None
    negated: bool = False       # ! content ("bu içermemeli") -> test üretiminde atlanır


@dataclass
class PcreMatch:
    pattern_raw: str
    regex: str
    flags: str
    http_buffer: Optional[str] = None


@dataclass
class ParsedRule:
    raw: str
    action: str = "alert"
    protocol: str = "tcp"
    src: str = "any"
    src_port: str = "any"
    direction: str = "->"
    dst: str = "any"
    dst_port: str = "any"

    sid: Optional[int] = None
    gid: int = 1
    rev: int = 1
    msg: str = ""
    classtype: Optional[str] = None
    metadata: dict = field(default_factory=dict)
    references: list = field(default_factory=list)
    flow: Optional[str] = None

    contents: list = field(default_factory=list)   # list[ContentMatch]
    pcres: list = field(default_factory=list)       # list[PcreMatch]

    is_http: bool = False


_HEX_TOKEN_RE = re.compile(r"\|([0-9A-Fa-f\s]+)\|")


def decode_snort_content(raw: str) -> bytes:
    """`content:"foo|0D 0A|bar"` içindeki hex bloklarını gerçek byte'lara çevirir."""
    out = bytearray()

    def _sub(match: "re.Match[str]"):
        hex_str = re.sub(r"\s+", "", match.group(1))
        return "\x00__HEX__" + hex_str + "__ENDHEX__\x00"

    marked = _HEX_TOKEN_RE.sub(_sub, raw)
    i = 0
    while i < len(marked):
        if marked[i] == "\x00" and marked[i:].startswith("\x00__HEX__"):
            end = marked.index("__ENDHEX__\x00", i)
            hex_part = marked[i + len("\x00__HEX__"): end]
            out += bytes.fromhex(hex_part)
            i = end + len("__ENDHEX__\x00")
        else:
            out += marked[i].encode("latin-1", errors="replace")
            i += 1
    return bytes(out)


def _split_options(options_str: str) -> list:
    """`key:"val;with;semicolons"; key2:val2;` bloğunu güvenli biçimde option'lara böler."""
    options = []
    buf = ""
    in_quotes = False
    escape = False
    for ch in options_str:
        if escape:
            buf += ch
            escape = False
            continue
        if ch == "\\":
            buf += ch
            escape = True
            continue
        if ch == '"':
            in_quotes = not in_quotes
            buf += ch
            continue
        if ch == ";" and not in_quotes:
            if buf.strip():
                options.append(buf.strip())
            buf = ""
            continue
        buf += ch
    if buf.strip():
        options.append(buf.strip())
    return options


def parse_rule(raw_line: str) -> Optional[ParsedRule]:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None

    m = re.match(
        r"^(?P<action>\w+)\s+(?P<proto>\w+)\s+(?P<src>\S+)\s+(?P<sport>\S+)\s+"
        r"(?P<dir>->|<>)\s+(?P<dst>\S+)\s+(?P<dport>\S+)\s*\((?P<options>.*)\)\s*;?\s*$",
        line,
        re.DOTALL,
    )
    if not m:
        return None

    rule = ParsedRule(
        raw=line,
        action=m.group("action"),
        protocol=m.group("proto"),
        src=m.group("src"),
        src_port=m.group("sport"),
        direction=m.group("dir"),
        dst=m.group("dst"),
        dst_port=m.group("dport"),
    )

    pending_negated = False
    for opt in _split_options(m.group("options")):
        if ":" in opt:
            key, _, value = opt.partition(":")
            key = key.strip()
            value = value.strip()
        else:
            key, value = opt.strip(), ""

        negated = value.startswith("!")
        if negated:
            value = value.lstrip("!").strip()

        if key == "sid":
            rule.sid = int(re.sub(r"\D", "", value) or 0)
        elif key == "gid":
            rule.gid = int(value)
        elif key == "rev":
            rule.rev = int(value)
        elif key == "msg":
            rule.msg = value.strip('"')
        elif key == "classtype":
            rule.classtype = value
        elif key == "flow":
            rule.flow = value
        elif key == "reference":
            rule.references.append(value)
        elif key == "metadata":
            for kv in value.split(","):
                kv = kv.strip()
                if " " in kv:
                    k2, v2 = kv.split(" ", 1)
                    rule.metadata[k2.strip()] = v2.strip()
        elif key == "content":
            raw_pattern = value.strip('"')
            content = ContentMatch(
                pattern_raw=raw_pattern,
                pattern_bytes=decode_snort_content(raw_pattern),
                negated=negated,
            )
            rule.contents.append(content)
        elif key == "uricontent":
            raw_pattern = value.strip('"')
            content = ContentMatch(
                pattern_raw=raw_pattern,
                pattern_bytes=decode_snort_content(raw_pattern),
                negated=negated,
                http_buffer="http_uri",
            )
            rule.contents.append(content)
            rule.is_http = True
        elif key == "pcre":
            # pcre:"/regex/flags" ya da http buffer modifier'lı olabilir (Snort3: pcre ile aynı)
            pm = re.match(r'^"?/(?P<regex>.*)/(?P<flags>[A-Za-z]*)"?$', value)
            if pm:
                rule.pcres.append(
                    PcreMatch(pattern_raw=value, regex=pm.group("regex"), flags=pm.group("flags"))
                )
        elif key in (
            "http_uri", "http_raw_uri", "http_header", "http_client_body",
            "http_method", "http_cookie", "http_stat_code", "http_user_agent",
        ):
            if rule.contents:
                rule.contents[-1].http_buffer = key
            if rule.pcres:
                rule.pcres[-1].http_buffer = key
            rule.is_http = True
        elif key == "nocase":
            if rule.contents:
                rule.contents[-1].nocase = True
        elif key == "depth":
            if rule.contents:
                rule.contents[-1].depth = int(value)
        elif key == "offset":
            if rule.contents:
                rule.contents[-1].offset = int(value)
        elif key == "distance":
            if rule.contents:
                rule.contents[-1].distance = int(value)
        elif key == "within":
            if rule.contents:
                rule.contents[-1].within = int(value)
        # diğer option'lar (flowbits, fast_pattern, rawbytes, vb.) şimdilik
        # eşleştirme/HTTP üretimi için kritik değil, sessizce atlanıyor.

    # HTTP tahmini: port 80/443/8080 ya da http_* buffer kullanımı ya da protokol http ise
    if rule.protocol.lower() in ("http", "http2"):
        rule.is_http = True
    if any(p in ("80", "8080", "443", "$HTTP_PORTS") for p in (rule.src_port, rule.dst_port)):
        rule.is_http = True

    return rule
