"""
scapy YERİNE kullanılan, sadece Python standart kütüphanesiyle (struct)
yazılmış minimal Ethernet/IPv4/TCP + PCAP dosya üretici.

Neden: scapy, konteyner ortamlarında (ör. Render gibi minimal/izinli
dosya sistemi olan platformlar) ağ arayüzü algılama/önbellek yazma
sırasında beklenmedik şekilde exception fırlatabiliyor ve bu da
'/api/rule/{sid}/test' uç noktasında HTTP 500'e sebep oluyordu. Bu modül
harici bağımlılık olmadan, standart libpcap dosya formatına uyumlu,
geçerli checksum'lara sahip paketler üretir.
"""
import socket
import struct
import time

LINKTYPE_ETHERNET = 1

_FAKE_SRC_MAC = bytes.fromhex("aa" * 6)
_FAKE_DST_MAC = bytes.fromhex("bb" * 6)

FLAG_PSH_ACK = 0x18


def _checksum(data: bytes) -> int:
    """Standart 16-bit one's complement internet checksum'u (IP/TCP)."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data)//2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _build_ip_header(payload_len: int, src_ip: str, dst_ip: str, ident: int) -> bytes:
    version_ihl = (4 << 4) | 5  # IPv4, 5*4=20 byte header (option yok)
    total_length = 20 + payload_len
    header_no_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,                # ToS
        total_length,
        ident,
        0,                # flags + fragment offset
        64,               # TTL
        socket.IPPROTO_TCP,
        0,                # checksum yer tutucu
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    checksum = _checksum(header_no_checksum)
    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, 0, total_length, ident, 0, 64, socket.IPPROTO_TCP, checksum,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )


def _build_tcp_header(
    payload: bytes, src_ip: str, dst_ip: str, sport: int, dport: int,
    seq: int, ack: int, flags: int,
) -> bytes:
    data_offset = (5 << 4)  # 5*4=20 byte header (option yok)
    header_no_checksum = struct.pack(
        "!HHLLBBHHH",
        sport, dport, seq, ack, data_offset, flags, 65535, 0, 0,
    )
    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0,
        socket.IPPROTO_TCP, len(header_no_checksum) + len(payload),
    )
    checksum = _checksum(pseudo_header + header_no_checksum + payload)
    return struct.pack(
        "!HHLLBBHHH",
        sport, dport, seq, ack, data_offset, flags, 65535, checksum, 0,
    )


def build_tcp_packet(
    payload: bytes,
    src_ip: str = "10.10.10.5",
    dst_ip: str = "10.10.10.50",
    sport: int = 51000,
    dport: int = 80,
    flags: int = FLAG_PSH_ACK,
    ident: int = 1,
    seq: int = 1000,
    ack: int = 1000,
) -> bytes:
    """Tam bir Ethernet+IPv4+TCP çerçevesi (ham bytes) üretir."""
    eth_header = _FAKE_DST_MAC + _FAKE_SRC_MAC + struct.pack("!H", 0x0800)  # IPv4
    tcp_header = _build_tcp_header(payload, src_ip, dst_ip, sport, dport, seq, ack, flags)
    ip_header = _build_ip_header(len(tcp_header) + len(payload), src_ip, dst_ip, ident)
    return eth_header + ip_header + tcp_header + payload


def write_pcap(packets: list) -> bytes:
    """Ham Ethernet çerçevelerinin listesini, geçerli bir .pcap dosyasına
    (Wireshark/tcpdump/Snort ile açılabilir) dönüştürür."""
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)

    base_ts = time.time()
    for i, pkt in enumerate(packets):
        ts = base_ts + i * 0.001
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        out += struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt))
        out += pkt
    return bytes(out)
