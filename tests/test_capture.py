"""数据包捕获模块单元测试 —— 李哲"""

import json
from datetime import datetime
from pathlib import Path

import pytest

from src.capture.mock_generator import generate_mock_packets
from src.capture.protocol_parser import (
    build_flow_id,
    encode_payload,
    infer_direction,
    is_tls_traffic,
    parse_packet,
)
from src.capture.tcp_reassembly import reassemble


class TestProtocolParser:
    """protocol_parser.py 测试"""

    def test_build_flow_id(self):
        pkt = {
            "src_ip": "192.168.1.10",
            "src_port": 51234,
            "dst_ip": "192.168.1.20",
            "dst_port": 80,
            "protocol": "TCP",
        }
        assert build_flow_id(pkt) == "192.168.1.10:51234->192.168.1.20:80/TCP"

    def test_build_flow_id_missing_fields(self):
        pkt = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}
        flow_id = build_flow_id(pkt)
        assert "10.0.0.1" in flow_id
        assert "10.0.0.2" in flow_id

    def test_encode_payload_ascii(self):
        payload, length = encode_payload(b"GET /index.html HTTP/1.1")
        assert payload == "GET /index.html HTTP/1.1"
        assert length == 24

    def test_encode_payload_binary(self):
        raw = b"\x16\x03\x01\x00\x05"
        payload, length = encode_payload(raw)
        assert payload == "\\x16\\x03\\x01\\x00\\x05"
        assert length == 5

    def test_encode_payload_empty(self):
        payload, length = encode_payload(b"")
        assert payload == ""
        assert length == 0

    def test_infer_direction_syn(self):
        assert infer_direction(51234, 80, "S", "TCP") == "request"
        assert infer_direction(80, 51234, "SA", "TCP") == "response"

    def test_infer_direction_server_port(self):
        assert infer_direction(51234, 80, "", "TCP") == "request"
        assert infer_direction(80, 51234, "", "TCP") == "response"

    def test_is_tls_traffic(self):
        tls_hello = bytes([0x16, 0x03, 0x01, 0x00, 0x05])
        assert is_tls_traffic(tls_hello, 52341, 443) is True
        assert is_tls_traffic(b"GET /index.html", 51234, 80) is False

    def test_parse_packet_tcp_with_scapy(self):
        pytest.importorskip("scapy")
        from scapy.all import IP, TCP, Raw, Ether

        pkt = (
            Ether()
            / IP(src="192.168.1.10", dst="192.168.1.20")
            / TCP(sport=51234, dport=80, flags="PA")
            / Raw(load=b"GET /test HTTP/1.1")
        )
        pkt.time = datetime(2026, 7, 8, 10, 0, 0).timestamp()

        record = parse_packet(pkt)
        assert record is not None
        assert record["src_ip"] == "192.168.1.10"
        assert record["dst_ip"] == "192.168.1.20"
        assert record["src_port"] == 51234
        assert record["dst_port"] == 80
        assert record["protocol"] == "TCP"
        assert record["payload"] == "GET /test HTTP/1.1"
        assert record["payload_len"] == 18
        assert record["flow_id"] == "192.168.1.10:51234->192.168.1.20:80/TCP"

    def test_parse_packet_udp_with_scapy(self):
        pytest.importorskip("scapy")
        from scapy.all import IP, UDP, Raw, Ether

        pkt = (
            Ether()
            / IP(src="10.0.0.1", dst="8.8.8.8")
            / UDP(sport=12345, dport=53)
            / Raw(load=b"\x00\x01")
        )
        pkt.time = datetime(2026, 7, 8, 10, 0, 0).timestamp()

        record = parse_packet(pkt)
        assert record is not None
        assert record["protocol"] == "UDP"
        assert record["payload_len"] == 2


class TestTCPReassembly:
    """tcp_reassembly.py 测试"""

    def test_reassemble_merges_payload(self):
        packets = [
            {
                "timestamp": "2026-07-08T10:00:00.000",
                "flow_id": "192.168.1.10:51234->192.168.1.20:80/TCP",
                "src_ip": "192.168.1.10",
                "src_port": 51234,
                "dst_ip": "192.168.1.20",
                "dst_port": 80,
                "protocol": "TCP",
                "flags": "PA",
                "payload": "GET ",
                "payload_len": 4,
            },
            {
                "timestamp": "2026-07-08T10:00:00.100",
                "flow_id": "192.168.1.10:51234->192.168.1.20:80/TCP",
                "src_ip": "192.168.1.10",
                "src_port": 51234,
                "dst_ip": "192.168.1.20",
                "dst_port": 80,
                "protocol": "TCP",
                "flags": "PA",
                "payload": "/index.html HTTP/1.1",
                "payload_len": 20,
            },
        ]
        result = reassemble(packets)
        data_packets = [p for p in result if p.get("payload_len", 0) > 0]
        assert len(data_packets) == 1
        assert data_packets[0]["payload"] == "GET /index.html HTTP/1.1"
        assert data_packets[0]["payload_len"] == 24

    def test_reassemble_preserves_non_tcp(self):
        icmp_pkt = {
            "timestamp": "2026-07-08T10:00:00.000",
            "src_ip": "192.168.1.10",
            "src_port": None,
            "dst_ip": "192.168.1.20",
            "dst_port": None,
            "protocol": "ICMP",
            "flags": "",
            "payload": "",
            "payload_len": 0,
        }
        result = reassemble([icmp_pkt])
        assert len(result) == 1
        assert result[0]["protocol"] == "ICMP"


class TestMockData:
    """mock_packets.json 数据质量测试"""

    REQUIRED_FIELDS = {
        "timestamp", "src_ip", "dst_ip", "protocol", "payload_len",
    }

    @pytest.fixture
    def mock_packets(self):
        return generate_mock_packets()

    def test_mock_packet_count(self, mock_packets):
        assert len(mock_packets) >= 80

    def test_required_fields(self, mock_packets):
        for pkt in mock_packets:
            for field in self.REQUIRED_FIELDS:
                assert field in pkt, f"缺少字段 {field}: {pkt}"

    def test_normal_traffic_count(self, mock_packets):
        normal = [
            p for p in mock_packets
            if p["src_ip"] in ("192.168.1.10",) and p["src_ip"] not in (
                "192.168.1.99", "192.168.1.77", "192.168.1.55"
            )
        ]
        assert len([p for p in mock_packets if p["src_ip"] == "192.168.1.10"]) >= 20

    def test_sql_injection_samples(self, mock_packets):
        sql_hits = [
            p for p in mock_packets
            if "UNION SELECT" in p.get("payload", "") or "' OR 1=1" in p.get("payload", "")
        ]
        assert len(sql_hits) >= 5

    def test_xss_samples(self, mock_packets):
        xss_hits = [p for p in mock_packets if "<script>" in p.get("payload", "").lower()]
        assert len(xss_hits) >= 5

    def test_bruteforce_scenario(self, mock_packets):
        bf = [
            p for p in mock_packets
            if p["src_ip"] == "192.168.1.99" and p["dst_port"] == 22 and p["flags"] == "S"
        ]
        assert len(bf) >= 15

    def test_port_scan_scenario(self, mock_packets):
        scan = [p for p in mock_packets if p["src_ip"] == "192.168.1.77"]
        unique_ports = {p["dst_port"] for p in scan}
        assert len(unique_ports) >= 20

    def test_external_connection_scenario(self, mock_packets):
        external = [p for p in mock_packets if p["src_ip"] == "192.168.1.55"]
        assert len(external) >= 3

    def test_mock_file_exists_and_valid_json(self):
        mock_path = Path(__file__).resolve().parent.parent / "mock_data" / "mock_packets.json"
        if not mock_path.exists():
            from src.capture.mock_generator import write_mock_packets
            write_mock_packets(mock_path)

        with open(mock_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert len(data) > 0


class TestPacketCapture:
    """packet_capture.py 测试"""

    def test_read_pcap_missing_file(self):
        from src.capture.packet_capture import read_pcap

        result = read_pcap("nonexistent_file_12345.pcap")
        assert result == []
