"""
协议识别与字段解析模块 —— 李哲

从原始报文中识别 IP / TCP / UDP / ICMP / ARP 协议层，
解析各层字段，提取应用层 payload。
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# 常见服务端端口，用于推断报文方向
SERVER_PORTS = {
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
    1433, 3306, 3389, 5432, 6379, 8080, 8443,
}

# TLS 记录层 ContentType: Handshake = 0x16
TLS_HANDSHAKE = 0x16
TLS_VERSIONS = {0x0300, 0x0301, 0x0302, 0x0303}


def build_flow_id(packet: dict) -> str:
    """
    根据五元组生成流标识。

    Args:
        packet: 单条报文记录

    Returns:
        流标识字符串，格式: "src_ip:src_port->dst_ip:dst_port/protocol"
    """
    src = f"{packet.get('src_ip', '?')}:{packet.get('src_port', '?')}"
    dst = f"{packet.get('dst_ip', '?')}:{packet.get('dst_port', '?')}"
    proto = packet.get("protocol", "?")
    return f"{src}->{dst}/{proto}"


def encode_payload(raw: bytes | None) -> tuple[str, int]:
    """
    将原始 payload 字节转为可读字符串。

    可打印 ASCII 直接保留，其余字节用 \\xNN 转义。

    Returns:
        (payload 字符串, 原始字节长度)
    """
    if not raw:
        return "", 0

    payload_len = len(raw)
    chars: list[str] = []
    for byte in raw:
        if 32 <= byte <= 126:
            chars.append(chr(byte))
        elif byte in (9, 10, 13):
            chars.append(chr(byte))
        else:
            chars.append(f"\\x{byte:02x}")
    return "".join(chars), payload_len


def is_tls_traffic(payload: bytes, src_port: int | None, dst_port: int | None) -> bool:
    """
    基础 TLS 流量识别（不要求解密）。

    检测 TLS 记录层握手特征或常见 TLS 端口上的握手报文。
    """
    if len(payload) >= 3:
        if payload[0] == TLS_HANDSHAKE:
            version = (payload[1] << 8) | payload[2]
            if version in TLS_VERSIONS:
                return True

    tls_ports = {443, 8443, 465, 993, 995}
    if (dst_port in tls_ports or src_port in tls_ports) and len(payload) >= 5:
        if payload[0] == TLS_HANDSHAKE and payload[1] == 0x03:
            return True

    return False


def _format_tcp_flags(tcp_layer) -> str:
    """将 scapy TCP 标志位转为规范字符串，如 S / SA / PA。"""
    flag_map = [
        ("F", "FIN"),
        ("S", "SYN"),
        ("R", "RST"),
        ("P", "PSH"),
        ("A", "ACK"),
        ("U", "URG"),
        ("E", "ECE"),
        ("C", "CWR"),
    ]
    flags = "".join(letter for letter, attr in flag_map if getattr(tcp_layer, attr, 0))
    return flags


def infer_direction(
    src_port: int | None,
    dst_port: int | None,
    flags: str = "",
    protocol: str = "",
) -> str | None:
    """
    推断报文方向。

    - TCP SYN（无 ACK）视为 request
    - TCP SYN+ACK 视为 response
    - 源端口为知名端口时视为 response，目的端口为知名端口时视为 request
    """
    if protocol == "TCP":
        if "S" in flags and "A" not in flags:
            return "request"
        if "S" in flags and "A" in flags:
            return "response"

    if src_port is not None and dst_port is not None:
        src_is_server = src_port in SERVER_PORTS
        dst_is_server = dst_port in SERVER_PORTS
        if dst_is_server and not src_is_server:
            return "request"
        if src_is_server and not dst_is_server:
            return "response"

    return None


def _format_timestamp(packet_time: float | None) -> str:
    """将抓包时间戳格式化为 ISO8601 毫秒精度字符串。"""
    if packet_time is None:
        dt = datetime.now(timezone.utc).astimezone()
    else:
        dt = datetime.fromtimestamp(packet_time).astimezone()
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def _parse_ip_packet(ip_layer, timestamp: str) -> dict | None:
    """解析 IPv4 报文。"""
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = "IP"
    src_port = None
    dst_port = None
    flags = ""
    raw_payload = b""
    transport = ip_layer.payload

    if transport is None:
        return None

    transport_cls = transport.__class__.__name__

    tcp_seq = None
    tcp_ack = None

    if transport_cls == "TCP":
        protocol = "TCP"
        src_port = int(transport.sport)
        dst_port = int(transport.dport)
        flags = _format_tcp_flags(transport)
        tcp_seq = int(transport.seq) if transport.seq is not None else None
        tcp_ack = int(transport.ack) if transport.ack is not None else None
        raw_payload = bytes(transport.payload) if transport.payload else b""
    elif transport_cls == "UDP":
        protocol = "UDP"
        src_port = int(transport.sport)
        dst_port = int(transport.dport)
        raw_payload = bytes(transport.payload) if transport.payload else b""
    elif transport_cls == "ICMP":
        protocol = "ICMP"
        raw_payload = bytes(transport.payload) if transport.payload else b""
    else:
        logger.debug("跳过未支持的 IP 上层协议: %s", transport_cls)
        return None

    payload, payload_len = encode_payload(raw_payload)
    direction = infer_direction(src_port, dst_port, flags, protocol)

    record = {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "direction": direction,
        "flags": flags,
        "payload": payload,
        "payload_len": payload_len,
        "tcp_seq": tcp_seq,
        "tcp_ack": tcp_ack,
    }
    record["flow_id"] = build_flow_id(record)

    if is_tls_traffic(raw_payload, src_port, dst_port):
        logger.debug("识别到 TLS 流量: %s", record["flow_id"])

    return record


def parse_packet(raw_packet) -> dict | None:
    """
    解析单个原始报文为标准化记录。

    Args:
        raw_packet: scapy 抓包返回的原始报文对象

    Returns:
        符合"报文记录格式"的字典；解析失败返回 None
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.l2 import ARP
    except ImportError:
        logger.error("scapy 未安装，无法解析报文")
        return None

    timestamp = _format_timestamp(getattr(raw_packet, "time", None))

    if raw_packet.haslayer(ARP):
        arp = raw_packet[ARP]
        record = {
            "timestamp": timestamp,
            "src_ip": arp.psrc,
            "src_port": None,
            "dst_ip": arp.pdst,
            "dst_port": None,
            "protocol": "ARP",
            "direction": None,
            "flags": "",
            "payload": "",
            "payload_len": 0,
        }
        record["flow_id"] = build_flow_id(record)
        return record

    if raw_packet.haslayer(IP):
        return _parse_ip_packet(raw_packet[IP], timestamp)

    logger.debug("跳过无法识别的报文类型")
    return None
