"""暴力破解检测单元测试 —— 陈志恒

覆盖：SSH/FTP 暴力破解检出、正常流量不误报、时间窗口边界、
阈值与端口可配置、异常与边界输入、告警格式合规，以及基于
mock_data/mock_packets.json 的端到端场景比对。
"""

import json
from pathlib import Path

import pytest

from src.bruteforce_detect.login_monitor import (
    DEFAULT_THRESHOLD,
    DEFAULT_TIME_WINDOW_SEC,
    detect,
)

# 统一告警格式必填字段（docs/interface_spec.md 3.1）
REQUIRED_ALERT_FIELDS = {
    "alert_id",
    "behavior_id",
    "detector",
    "category",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_network",
    "dst_port",
    "severity",
    "description",
    "evidence",
    "timestamp",
}

MOCK_PATH = Path(__file__).resolve().parents[1] / "mock_data" / "mock_packets.json"


def _syn(src_ip, dst_ip, dst_port, second, sport=40000):
    """构造一条指向登录端口的 SYN 连接尝试报文。"""
    return {
        "timestamp": f"2026-07-08T10:00:{second:02d}.000",
        "flow_id": f"{src_ip}:{sport}->{dst_ip}:{dst_port}/TCP",
        "src_ip": src_ip,
        "src_port": sport,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": "TCP",
        "direction": "request",
        "flags": "S",
        "payload": "",
        "payload_len": 0,
    }


def _burst(src_ip, dst_ip, dst_port, count, start=0, step=1):
    """生成 count 条递增时间的 SYN 报文，源端口逐条递增。"""
    return [
        _syn(src_ip, dst_ip, dst_port, start + i * step, sport=40000 + i)
        for i in range(count)
    ]


class TestBruteforceDetection:
    """核心暴力破解检测逻辑。"""

    def test_ssh_bruteforce_detected(self):
        packets = _burst("192.168.1.99", "192.168.1.20", 22, count=18, step=2)
        alerts = detect(packets)
        assert len(alerts) == 1
        a = alerts[0]
        assert a["detector"] == "bruteforce"
        assert a["src_ip"] == "192.168.1.99"
        assert a["dst_ip"] == "192.168.1.20"
        assert a["dst_port"] == 22
        assert "SSH" in a["description"]
        assert "18" in a["description"]

    def test_ftp_below_threshold_not_detected(self):
        # 5 次 < 默认阈值 10，不应告警
        packets = _burst("192.168.1.98", "192.168.1.20", 21, count=5, start=0, step=3)
        assert detect(packets) == []

    def test_at_threshold_boundary(self):
        # 恰好达到阈值即告警
        packets = _burst("10.0.0.1", "10.0.0.2", 22, count=DEFAULT_THRESHOLD, step=1)
        assert len(detect(packets)) == 1

    def test_just_below_threshold(self):
        packets = _burst("10.0.0.1", "10.0.0.2", 22, count=DEFAULT_THRESHOLD - 1, step=1)
        assert detect(packets) == []

    def test_attempts_spread_beyond_window_not_merged(self):
        # 12 次尝试，每次间隔 10s → 跨度 110s，任意 60s 窗口内不足阈值
        packets = _burst("10.0.0.1", "10.0.0.2", 22, count=12, start=0, step=10)
        assert detect(packets, time_window_sec=60, threshold=10) == []

    def test_dense_window_within_spread_detected(self):
        # 前 15 条集中在 15s 内（应告警），阈值 10、窗口 60
        packets = _burst("10.0.0.1", "10.0.0.2", 22, count=15, start=0, step=1)
        alerts = detect(packets, time_window_sec=60, threshold=10)
        assert len(alerts) == 1

    def test_custom_threshold(self):
        packets = _burst("10.0.0.1", "10.0.0.2", 22, count=4, step=1)
        assert detect(packets) == []  # 默认阈值 10
        assert len(detect(packets, threshold=3)) == 1

    def test_non_login_port_ignored(self):
        # 80 端口不在默认登录端口集合中（正常 Web 浏览不应被判为暴力破解）
        packets = _burst("10.0.0.1", "10.0.0.2", 80, count=30, step=1)
        assert detect(packets) == []

    def test_custom_login_ports(self):
        packets = _burst("10.0.0.1", "10.0.0.2", 8000, count=15, step=1)
        assert detect(packets) == []
        assert len(detect(packets, login_ports={8000})) == 1

    def test_separate_targets_not_merged(self):
        # 同源分别攻击两个目标，各 6 次，均不足阈值 → 不应合并告警
        packets = _burst("10.0.0.1", "10.0.0.2", 22, count=6, start=0, step=1)
        packets += _burst("10.0.0.1", "10.0.0.3", 22, count=6, start=0, step=1)
        assert detect(packets) == []

    def test_two_sources_two_alerts(self):
        packets = _burst("10.0.0.1", "10.0.0.9", 22, count=12, step=1)
        packets += _burst("10.0.0.2", "10.0.0.9", 22, count=12, step=1)
        alerts = detect(packets)
        assert len(alerts) == 2
        assert {a["src_ip"] for a in alerts} == {"10.0.0.1", "10.0.0.2"}


class TestAlertSchema:
    """告警格式合规性。"""

    def test_alert_has_all_required_fields(self):
        packets = _burst("192.168.1.99", "192.168.1.20", 22, count=18, step=2)
        alert = detect(packets)[0]
        assert set(alert.keys()) == REQUIRED_ALERT_FIELDS
        assert alert["detector"] == "bruteforce"
        assert alert["severity"] in {"low", "medium", "high"}
        assert alert["behavior_id"]  # 检测模块已填入 behavior_id
        assert alert["category"] == "暴力破解/非法登录"

    def test_alert_id_and_behavior_id_are_uuid_like(self):
        packets = _burst("192.168.1.99", "192.168.1.20", 22, count=18, step=2)
        alert = detect(packets)[0]
        assert len(alert["alert_id"]) == 36
        assert alert["behavior_id"] == alert["alert_id"]

    def test_severity_scales_with_count(self):
        low = detect(_burst("10.0.0.1", "10.0.0.2", 22, count=12, step=1))[0]
        high = detect(_burst("10.0.0.3", "10.0.0.4", 22, count=25, step=1))[0]
        assert low["severity"] == "medium"
        assert high["severity"] == "high"


class TestRejectionEvidence:
    """结合 RST 响应佐证连接被拒绝。"""

    def test_rejected_connections_counted(self):
        packets = _burst("192.168.1.99", "192.168.1.20", 22, count=12, step=1)
        # 目标对每次尝试回以 RST-ACK（源端口为登录端口 22）
        for i in range(12):
            packets.append({
                "timestamp": f"2026-07-08T10:00:{i:02d}.100",
                "src_ip": "192.168.1.20",
                "src_port": 22,
                "dst_ip": "192.168.1.99",
                "dst_port": 43210 + i,
                "protocol": "TCP",
                "direction": "response",
                "flags": "RA",
                "payload": "",
                "payload_len": 0,
            })
        alert = detect(packets)[0]
        assert "rejected_conn=12" in alert["evidence"]
        assert "拒绝" in alert["description"]
        # RST 响应本身不得被误计为攻击尝试
        assert "12 次连接尝试" in alert["description"]


class TestFallbackCounting:
    """缺失 flags 时按连接(flow_id)退化计数。"""

    def test_counts_by_flow_when_no_syn(self):
        packets = []
        for i in range(12):
            packets.append({
                "timestamp": f"2026-07-08T10:00:{i:02d}.000",
                "flow_id": f"10.0.0.1:{40000 + i}->10.0.0.2:22/TCP",
                "src_ip": "10.0.0.1",
                "src_port": 40000 + i,
                "dst_ip": "10.0.0.2",
                "dst_port": 22,
                "protocol": "TCP",
                "direction": "request",
                "flags": "",  # 无 flags
                "payload": "USER admin",
                "payload_len": 10,
            })
        assert len(detect(packets)) == 1

    def test_same_connection_not_double_counted(self):
        # 同一 flow_id 的多个数据包只算一次连接
        packets = []
        for i in range(30):
            packets.append({
                "timestamp": f"2026-07-08T10:00:{i:02d}.000",
                "flow_id": "10.0.0.1:40000->10.0.0.2:22/TCP",
                "src_ip": "10.0.0.1",
                "src_port": 40000,
                "dst_ip": "10.0.0.2",
                "dst_port": 22,
                "protocol": "TCP",
                "direction": "request",
                "flags": "",
                "payload": f"data {i}",
                "payload_len": 6,
            })
        assert detect(packets) == []  # 只有 1 条连接


class TestEdgeCases:
    """异常与边界输入（不应抛出未捕获异常）。"""

    def test_empty_input(self):
        assert detect([]) == []

    def test_none_like_empty(self):
        assert detect([]) == []

    def test_missing_fields_do_not_crash(self):
        packets = [
            {"timestamp": "2026-07-08T10:00:00.000"},  # 几乎全缺
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},  # 无端口/时间
            {},
        ]
        assert detect(packets) == []

    def test_malformed_records_skipped(self):
        packets = ["not a dict", 123, None]
        packets += _burst("10.0.0.1", "10.0.0.2", 22, count=12, step=1)
        alerts = detect(packets)
        assert len(alerts) == 1

    def test_unparseable_timestamp_does_not_crash(self):
        packets = _burst("10.0.0.1", "10.0.0.2", 22, count=12, step=1)
        packets.append({
            "timestamp": "not-a-timestamp",
            "src_ip": "10.0.0.1", "src_port": 41000,
            "dst_ip": "10.0.0.2", "dst_port": 22,
            "protocol": "TCP", "direction": "request", "flags": "S",
            "payload": "", "payload_len": 0,
        })
        # 不崩溃，仍能对可解析的 12 条尝试告警
        assert len(detect(packets)) == 1


@pytest.fixture(scope="module")
def mock_packets():
    if not MOCK_PATH.exists():
        pytest.skip(f"mock 数据缺失: {MOCK_PATH}")
    with open(MOCK_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


class TestMockData:
    """基于 Phase1 交付的真实 mock 数据端到端比对。"""

    def test_detects_bruteforce(self, mock_packets):
        """mock 数据应检出 SSH×2 + FTP 暴力破解。"""
        alerts = detect(mock_packets)
        # 扩充后：SSH(192.168.1.99:22,18次)+FTP(192.168.1.98:21,10次)+SSH(192.168.1.201:22,12次)=3条
        assert len(alerts) == 3
        ssh_alerts = [a for a in alerts if a["dst_port"] == 22]
        ftp_alerts = [a for a in alerts if a["dst_port"] == 21]
        assert len(ssh_alerts) == 2
        assert len(ftp_alerts) == 1
        ssh_ips = {a["src_ip"] for a in ssh_alerts}
        assert ssh_ips == {"192.168.1.99", "192.168.1.201"}
        assert ftp_alerts[0]["src_ip"] == "192.168.1.98"

    def test_all_alerts_conform_to_schema(self, mock_packets):
        for a in detect(mock_packets):
            assert set(a.keys()) == REQUIRED_ALERT_FIELDS

    def test_normal_ftp_session_not_flagged(self, mock_packets):
        # 正常 FTP 登录会话（192.168.1.10）不应产生告警
        alerts = detect(mock_packets)
        assert all(a["src_ip"] != "192.168.1.10" for a in alerts)
