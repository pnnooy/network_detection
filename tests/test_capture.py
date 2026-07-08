"""数据包捕获模块单元测试 —— 李哲"""

import pytest


class TestPacketCapture:
    """packet_capture.py 测试"""

    def test_stub(self):
        """占位测试，Phase3 替换为实际用例"""
        pass


class TestTCPReassembly:
    """tcp_reassembly.py 测试"""

    def test_stub(self):
        pass


class TestProtocolParser:
    """protocol_parser.py 测试"""

    def test_build_flow_id(self):
        from src.capture.protocol_parser import build_flow_id

        pkt = {
            "src_ip": "192.168.1.10",
            "src_port": 51234,
            "dst_ip": "192.168.1.20",
            "dst_port": 80,
            "protocol": "TCP",
        }
        flow_id = build_flow_id(pkt)
        assert flow_id == "192.168.1.10:51234->192.168.1.20:80/TCP"

    def test_build_flow_id_missing_fields(self):
        from src.capture.protocol_parser import build_flow_id

        pkt = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}
        flow_id = build_flow_id(pkt)
        # 不应抛出异常
        assert "10.0.0.1" in flow_id
        assert "10.0.0.2" in flow_id
