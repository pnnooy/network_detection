"""
Mock 报文数据生成器 —— 李哲

生成符合 interface_spec.md 要求的 mock_data/mock_packets.json，
覆盖正常流量、SQL注入、XSS、木马特征、暴力破解、端口扫描、异常外联等场景。
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

from .protocol_parser import build_flow_id


def _ts(base: datetime, offset_ms: int) -> str:
    dt = base + timedelta(milliseconds=offset_ms)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def _pkt(
    base: datetime,
    offset_ms: int,
    src_ip: str,
    src_port: int | None,
    dst_ip: str,
    dst_port: int | None,
    protocol: str,
    *,
    direction: str | None = None,
    flags: str = "",
    payload: str = "",
    payload_len: int | None = None,
) -> dict:
    if payload_len is None:
        payload_len = len(payload.encode("utf-8")) if payload else 0

    record = {
        "timestamp": _ts(base, offset_ms),
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "direction": direction,
        "flags": flags,
        "payload": payload,
        "payload_len": payload_len,
    }
    record["flow_id"] = build_flow_id(record)
    return record


def generate_mock_packets() -> list[dict]:
    """生成完整 mock 报文数据集。"""
    base = datetime(2026, 7, 8, 10, 0, 0)
    packets: list[dict] = []
    offset = 0

    def add(pkt: dict) -> None:
        nonlocal offset
        packets.append(pkt)
        offset += 50

    # ------------------------------------------------------------------
    # 1. 正常 HTTP/SSH/FTP 流量 (>=20条)
    # ------------------------------------------------------------------
    normal_http = [
        ("GET /index.html HTTP/1.1", "request", "PA"),
        ("HTTP/1.1 200 OK\r\nContent-Length: 1234", "response", "PA"),
        ("GET /about.html HTTP/1.1", "request", "PA"),
        ("GET /api/users HTTP/1.1", "request", "PA"),
        ("POST /api/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\"}", "request", "PA"),
        ("HTTP/1.1 401 Unauthorized", "response", "PA"),
        ("GET /static/style.css HTTP/1.1", "request", "PA"),
        ("GET /favicon.ico HTTP/1.1", "request", "PA"),
    ]
    for i, (body, direction, flags) in enumerate(normal_http):
        add(_pkt(
            base, offset,
            "192.168.1.10", 51234 + i, "192.168.1.20", 80, "TCP",
            direction=direction, flags=flags, payload=body,
        ))

    normal_ssh = [
        ("SSH-2.0-OpenSSH_8.9", "response", "PA"),
        ("SSH-2.0-OpenSSH_9.0", "request", "PA"),
        ("", "request", "S"),
        ("", "response", "SA"),
    ]
    for i, (body, direction, flags) in enumerate(normal_ssh):
        add(_pkt(
            base, offset,
            "192.168.1.10", 52000 + i, "192.168.1.20", 22, "TCP",
            direction=direction, flags=flags, payload=body,
        ))

    normal_ftp = [
        ("USER anonymous\r\n", "request", "PA"),
        ("331 Please specify the password.\r\n", "response", "PA"),
        ("PASS guest@example.com\r\n", "request", "PA"),
        ("230 Login successful.\r\n", "response", "PA"),
        ("LIST\r\n", "request", "PA"),
        ("150 Here comes the directory listing.\r\n", "response", "PA"),
    ]
    for i, (body, direction, flags) in enumerate(normal_ftp):
        add(_pkt(
            base, offset,
            "192.168.1.10", 53000 + i, "192.168.1.20", 21, "TCP",
            direction=direction, flags=flags, payload=body,
        ))

    # 补充正常 UDP DNS 与 ICMP
    add(_pkt(base, offset, "192.168.1.10", 54001, "8.8.8.8", 53, "UDP",
             direction="request", payload="\x00\x01\x00\x00", payload_len=4))
    add(_pkt(base, offset, "8.8.8.8", 53, "192.168.1.10", 54001, "UDP",
             direction="response", payload="\x00\x01\x81\x80", payload_len=4))
    add(_pkt(base, offset, "192.168.1.10", None, "192.168.1.20", None, "ICMP",
             direction="request", payload="", payload_len=0))
    add(_pkt(base, offset, "192.168.1.20", None, "192.168.1.10", None, "ICMP",
             direction="response", payload="", payload_len=0))

    # ------------------------------------------------------------------
    # 2. SQL 注入特征 (>=5条)
    # ------------------------------------------------------------------
    sql_payloads = [
        "GET /login.php?id=1 UNION SELECT username,password FROM users-- HTTP/1.1",
        "GET /search?q=' OR 1=1-- HTTP/1.1",
        "POST /api/query HTTP/1.1\r\n\r\nSELECT * FROM admin WHERE id=1 UNION SELECT null,version()",
        "GET /product.php?id=1' OR '1'='1 HTTP/1.1",
        "GET /report?sort=1; DROP TABLE users-- HTTP/1.1",
        "GET /item?id=1' OR 1=1 HTTP/1.1",
        "POST /login HTTP/1.1\r\n\r\nusername=admin' OR 1=1--&password=x",
    ]
    for i, body in enumerate(sql_payloads):
        add(_pkt(
            base, offset + 5000,
            "192.168.1.10", 55000 + i, "192.168.1.20", 80, "TCP",
            direction="request", flags="PA", payload=body,
        ))

    # ------------------------------------------------------------------
    # 3. XSS 特征 (>=5条)
    # ------------------------------------------------------------------
    xss_payloads = [
        "GET /comment?text=<script>alert(1)</script> HTTP/1.1",
        "POST /profile HTTP/1.1\r\n\r\nbio=<script>alert(document.cookie)</script>",
        "GET /search?q=<script>alert('xss')</script> HTTP/1.1",
        "POST /feedback HTTP/1.1\r\n\r\nmsg=<SCRIPT>alert(1)</SCRIPT>",
        "GET /page?name=<script>confirm(1)</script> HTTP/1.1",
        "GET /redirect?url=javascript:<script>alert(1)</script> HTTP/1.1",
    ]
    for i, body in enumerate(xss_payloads):
        add(_pkt(
            base, offset + 10000,
            "192.168.1.11", 56000 + i, "192.168.1.20", 80, "TCP",
            direction="request", flags="PA", payload=body,
        ))

    # ------------------------------------------------------------------
    # 4. 木马/恶意命令特征 (>=3条)
    # ------------------------------------------------------------------
    trojan_payloads = [
        "GET /faxsurvey?/bin/cat%20/etc/passwd HTTP/1.1",
        "GET /cgi-bin/test?cmd=/bin/cat%20/etc/passwd HTTP/1.1",
        "GET /faxsurvey?/bin/ls%20-la HTTP/1.1",
        "GET /admin/exec?cmd=/bin/cat%20/etc/shadow HTTP/1.1",
    ]
    for i, body in enumerate(trojan_payloads):
        add(_pkt(
            base, offset + 15000,
            "192.168.1.12", 57000 + i, "192.168.1.20", 80, "TCP",
            direction="request", flags="PA", payload=body,
        ))

    # ------------------------------------------------------------------
    # 5. 暴力破解 — 同一源IP短时间大量连接 SSH 端口 (18条, 60秒内)
    # ------------------------------------------------------------------
    bruteforce_src = "192.168.1.99"
    bruteforce_dst = "192.168.1.20"
    for i in range(18):
        add(_pkt(
            base, 20000 + i * 2000,
            bruteforce_src, 43210 + i, bruteforce_dst, 22, "TCP",
            direction="request", flags="S", payload="", payload_len=0,
        ))
        # 模拟服务端 RST 拒绝
        add(_pkt(
            base, 20000 + i * 2000 + 100,
            bruteforce_dst, 22, bruteforce_src, 43210 + i, "TCP",
            direction="response", flags="RA", payload="", payload_len=0,
        ))

    # Web 登录暴力尝试 (补充 FTP 端口)
    for i in range(5):
        add(_pkt(
            base, 60000 + i * 3000,
            "192.168.1.98", 58000 + i, "192.168.1.20", 21, "TCP",
            direction="request", flags="S", payload="", payload_len=0,
        ))

    # ------------------------------------------------------------------
    # 6. 端口扫描 — 同一源IP访问大量不同目标端口 (25条, 60秒内)
    # ------------------------------------------------------------------
    scan_src = "192.168.1.77"
    scan_dst = "192.168.1.20"
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                  993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8000, 8080,
                  8443, 9200]
    for i, port in enumerate(scan_ports):
        add(_pkt(
            base, 80000 + i * 1500,
            scan_src, 60000 + i, scan_dst, port, "TCP",
            direction="request", flags="S", payload="", payload_len=0,
        ))

    # ------------------------------------------------------------------
    # 7. 内网主机异常外联陌生公网IP (>=3条)
    # ------------------------------------------------------------------
    external_targets = [
        ("203.0.113.99", 443, "request", "PA", "\x16\x03\x01\x00\x05\x01\x00\x00\x01\x03"),
        ("198.51.100.42", 443, "request", "S", ""),
        ("203.0.113.55", 8080, "request", "PA", "GET /beacon HTTP/1.1"),
    ]
    for i, (dst, port, direction, flags, payload) in enumerate(external_targets):
        plen = len(payload.encode("utf-8")) if payload else 0
        add(_pkt(
            base, 120000 + i * 5000,
            "192.168.1.55", 52341 + i, dst, port, "TCP",
            direction=direction, flags=flags, payload=payload, payload_len=plen,
        ))

    # 额外一条正常 HTTPS（不应触发异常外联以外的告警）
    add(_pkt(
        base, 130000,
        "192.168.1.10", 51200, "192.168.1.20", 443, "TCP",
        direction="request", flags="PA",
        payload="\x16\x03\x01\x00\x7f\x01\x00\x00\x7b\x03\x03",
        payload_len=132,
    ))

    packets.sort(key=lambda p: p["timestamp"])
    return packets


def write_mock_packets(output_path: str | Path | None = None) -> Path:
    """生成并写入 mock_packets.json。"""
    if output_path is None:
        output_path = Path(__file__).resolve().parent.parent.parent / "mock_data" / "mock_packets.json"
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    packets = generate_mock_packets()
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(packets, f, ensure_ascii=False, indent=2)

    return output_path


if __name__ == "__main__":
    path = write_mock_packets()
    packets = generate_mock_packets()
    print(f"已生成 {len(packets)} 条 mock 报文 -> {path}")
