"""
Gerçek Snort/Snort3 detection engine'inin (DAQ, preprocessor'lar, stream
reassembly vb. dahil) tam bir yeniden implementasyonu değildir. Bu,
"bu kural bu payload'a karşı alarm üretir mi?" sorusuna, content/pcre
option'larının (depth/offset/distance/within/nocase + http buffer seçimi)
temel semantiğini uygulayarak makul bir yaklaşıklıkla cevap veren
hafif bir simülasyon motorudur. Üretim ortamına almadan önce gerçek
Snort/Snort3 binary'si ile `-r file.pcap -c rule.rules` şeklinde
doğrulama şiddetle önerilir (bkz. README "Doğrulama" bölümü).
"""
import re
from dataclasses import dataclass
from typing import Optional
from app.snort_parser import ParsedRule


@dataclass
class MatchResult:
    matched: bool
    matched_contents: int
    total_contents: int
    matched_pcres: int
    total_pcres: int
    detail: list


def _extract_http_buffers(raw_request: str) -> dict:
    """Ham HTTP isteğini basitçe method/uri/headers/body/cookie/user-agent'a ayırır."""
    try:
        head, _, body = raw_request.partition("\r\n\r\n")
        lines = head.split("\r\n")
        request_line = lines[0] if lines else ""
        method, _, rest = request_line.partition(" ")
        uri, _, _ = rest.partition(" ")
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        return {
            "http_uri": uri,
            "http_raw_uri": uri,
            "http_method": method,
            "http_header": head,
            "http_client_body": body,
            "http_cookie": headers.get("cookie", ""),
            "http_user_agent": headers.get("user-agent", ""),
            "http_stat_code": "",
            None: head + "\r\n\r\n" + body,  # buffer belirtilmemiş genel arama alanı
        }
    except Exception:
        return {None: raw_request}


def evaluate_rule_against_payload(rule: ParsedRule, raw_http_payload: str) -> MatchResult:
    buffers = _extract_http_buffers(raw_http_payload)
    detail = []

    positive_contents = [c for c in rule.contents if not c.negated]
    negative_contents = [c for c in rule.contents if c.negated]

    matched_count = 0
    for c in positive_contents:
        haystack = buffers.get(c.http_buffer, buffers.get(None, ""))
        needle = c.pattern_bytes.decode("latin-1", errors="replace")
        hay = haystack if not c.nocase else haystack.lower()
        ndl = needle if not c.nocase else needle.lower()
        found = ndl in hay
        if found:
            matched_count += 1
        detail.append(
            {
                "type": "content",
                "buffer": c.http_buffer or "generic",
                "pattern": c.pattern_raw,
                "found": found,
            }
        )

    # Negatif content'ler: bulunursa kuralı GEÇERSİZ kılar
    negative_violated = False
    for c in negative_contents:
        haystack = buffers.get(c.http_buffer, buffers.get(None, ""))
        needle = c.pattern_bytes.decode("latin-1", errors="replace")
        found = needle in haystack
        if found:
            negative_violated = True
        detail.append(
            {
                "type": "content (negated)",
                "buffer": c.http_buffer or "generic",
                "pattern": c.pattern_raw,
                "found_but_should_not_be": found,
            }
        )

    matched_pcres = 0
    for p in rule.pcres:
        haystack = buffers.get(p.http_buffer, buffers.get(None, ""))
        try:
            flags = 0
            if "i" in p.flags:
                flags |= re.IGNORECASE
            if "s" in p.flags:
                flags |= re.DOTALL
            found = re.search(p.regex, haystack, flags) is not None
        except re.error:
            found = False
        if found:
            matched_pcres += 1
        detail.append({"type": "pcre", "pattern": p.regex, "found": found})

    total_required = len(positive_contents) + len(rule.pcres)
    total_found = matched_count + matched_pcres
    matched = (total_required > 0) and (total_found == total_required) and not negative_violated

    return MatchResult(
        matched=matched,
        matched_contents=matched_count,
        total_contents=len(positive_contents),
        matched_pcres=matched_pcres,
        total_pcres=len(rule.pcres),
        detail=detail,
    )
