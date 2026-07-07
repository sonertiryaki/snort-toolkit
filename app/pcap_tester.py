import logging
from dataclasses import dataclass, field
from typing import Optional

from app.pcap_writer import build_tcp_packet, write_pcap
from app.snort_parser import ParsedRule
from app.match_engine import evaluate_rule_against_payload, MatchResult
from app.clean_corpus import CLEAN_HTTP_REQUESTS

logger = logging.getLogger("pcap_tester")


@dataclass
class TestCaseResult:
    label: str
    expected: str  # "true_positive" | "false_positive_candidate"
    matched: bool
    correct: bool
    match_result: MatchResult


@dataclass
class PcapTestReport:
    pcap_bytes: bytes
    true_positive: TestCaseResult
    false_positive_checks: list
    false_positive_rate: float
    summary: str
    pcap_warning: Optional[str] = None


def _build_packet(payload: str, sport: int, dport: int, ident: int, src="10.10.10.5", dst="10.10.10.50") -> bytes:
    return build_tcp_packet(
        payload.encode("latin-1", errors="replace"),
        src_ip=src, dst_ip=dst, sport=sport, dport=dport, ident=ident,
    )


def run_pcap_test(rule: ParsedRule, generated_http_raw: str) -> PcapTestReport:
    packets = []

    # 1) True positive senaryosu: bizzat üretilen tetikleyici istek
    tp_packet = _build_packet(generated_http_raw, sport=51000, dport=80, ident=1)
    packets.append(tp_packet)
    tp_match = evaluate_rule_against_payload(rule, generated_http_raw)
    tp_result = TestCaseResult(
        label="Üretilen tetikleyici istek (True Positive adayı)",
        expected="true_positive",
        matched=tp_match.matched,
        correct=tp_match.matched,  # doğru davranış: eşleşmeli
        match_result=tp_match,
    )

    # 2) False positive havuzu: temiz kurumsal trafik
    fp_results = []
    for idx, clean_req in enumerate(CLEAN_HTTP_REQUESTS, start=1):
        pkt = _build_packet(clean_req, sport=52000 + idx, dport=80, ident=idx + 1)
        packets.append(pkt)
        m = evaluate_rule_against_payload(rule, clean_req)
        fp_results.append(
            TestCaseResult(
                label=f"Temiz trafik örneği #{idx}",
                expected="false_positive_candidate",
                matched=m.matched,
                correct=not m.matched,  # doğru davranış: eşleşmemeli
                match_result=m,
            )
        )

    # PCAP üretimi, asıl TP/FP analiz sonucunu ETKİLEMEYECEK şekilde ayrı bir
    # try/except içine alınıyor: PCAP dosyası üretilemese bile kullanıcı en
    # azından kuralın doğru çalışıp çalışmadığı analizini görebilmeli.
    pcap_bytes = b""
    pcap_warning = None
    try:
        pcap_bytes = write_pcap(packets)
    except Exception as e:
        logger.exception("PCAP üretimi başarısız oldu")
        pcap_warning = f"PCAP dosyası üretilemedi ({e}); TP/FP analiz sonuçları yine de geçerlidir."

    fp_hits = sum(1 for r in fp_results if r.matched)
    fp_rate = fp_hits / len(fp_results) if fp_results else 0.0

    if tp_result.matched and fp_hits == 0:
        summary = (
            "✅ Kural beklendiği gibi çalışıyor: tetikleyici trafikte alarm üretiyor, "
            "temiz kurumsal trafikte hiçbir yanlış pozitif üretmiyor."
        )
    elif not tp_result.matched:
        summary = (
            "⚠️ Kural, kendi ürettiği tetikleyici trafikte bile eşleşmedi. "
            "Bu genellikle pcre tabanlı bir kuralın basit metin üretimiyle tam "
            "karşılanamadığı ya da distance/within gibi konumsal kısıtların "
            "simülasyonda tam yansıtılamadığı anlamına gelebilir. Manuel inceleme önerilir."
        )
    else:
        summary = (
            f"⚠️ Kural, temiz kurumsal trafik havuzunun {fp_hits}/{len(fp_results)} "
            f"örneğinde yanlış pozitif üretti. content/pcre desenleri muhtemelen "
            f"çok genel; depth/offset/distance/within ile daraltılması ya da ek "
            f"context (http_header, http_client_body vb.) eklenmesi önerilir."
        )

    return PcapTestReport(
        pcap_bytes=pcap_bytes,
        true_positive=tp_result,
        false_positive_checks=fp_results,
        false_positive_rate=fp_rate,
        summary=summary,
        pcap_warning=pcap_warning,
    )
