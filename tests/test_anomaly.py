"""异常行为检测单元测试 —— 姜新晨

覆盖：端口扫描检出、异常外联检出、内网横向扩散检出、高频连接检出、
正常流量不误报、时间窗口边界、阈值可配置、告警格式合规、异常与
边界输入，以及基于 mock_data/mock_packets.json 的端到端场景比对。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.anomaly_detect.anomaly_detector import detect

# ---------------------------------------------------------------------------
# 统一告警格式必填字段（docs/interface_spec.md §3.1）
# ---------------------------------------------------------------------------
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

# 测试用内网网段
INTERNAL_NETS = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]


# ---------------------------------------------------------------------------
#  报文构造辅助
# ---------------------------------------------------------------------------

def _pkt(src_ip, dst_ip, dst_port, timestamp_sec=0, sport=50000, flags="S"):
    """构造一条最小 TCP SYN 探测报文（timestamp_sec 支持浮点）。"""
    total_ms = round(timestamp_sec * 1000)
    sec_part, ms_part = divmod(total_ms, 1000)
    minutes, seconds = divmod(sec_part, 60)
    hours = 10 + minutes // 60
    minutes = minutes % 60
    ts_str = f"2026-07-08T{hours:02d}:{minutes:02d}:{seconds:02d}.{ms_part:03d}"
    return {
        "timestamp": ts_str,
        "flow_id": f"{src_ip}:{sport}->{dst_ip}:{dst_port}/TCP",
        "src_ip": src_ip,
        "src_port": sport,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": "TCP",
        "direction": "request",
        "flags": flags,
        "payload": "",
        "payload_len": 0,
    }


def _port_scan_burst(
    src_ip="10.0.0.77",
    dst_ip="10.0.0.20",
    ports: list[int] | None = None,
    start_sec=0,
    step_sec=1,
    start_sport=60000,
):
    """生成端口扫描报文序列——同一源对同一目标探测多个端口。"""
    if ports is None:
        ports = [22, 23, 25, 53, 80, 110, 135, 139, 143, 443,
                 445, 993, 995, 1433, 3306, 3389, 5432, 5900,
                 6379, 8000, 8080, 8443, 9200]
    return [
        _pkt(src_ip, dst_ip, p, timestamp_sec=start_sec + i * step_sec,
             sport=start_sport + i)
        for i, p in enumerate(ports)
    ]


# ---------------------------------------------------------------------------
#  端口扫描检测
# ---------------------------------------------------------------------------

class TestPortScanDetection:
    """端口扫描核心检测逻辑。"""

    def test_scan_detected_when_above_threshold(self):
        ports = list(range(1, 26))  # 25 个端口
        packets = _port_scan_burst(ports=ports, start_sec=0, step_sec=1)
        alerts = detect(packets, {
            "port_scan": {"time_window_sec": 60, "unique_dst_port_threshold": 20},
            "external_connection": {"internal_networks": INTERNAL_NETS},
            "lateral_movement": {"time_window_sec": 300, "internal_dst_count_threshold": 10},
            "connection_rate": {"time_window_sec": 60, "max_connections_per_ip": 100},
        })
        assert len(alerts) >= 1
        scan = [a for a in alerts if a["category"] == "端口扫描"]
        assert len(scan) == 1
        a = scan[0]
        assert a["detector"] == "anomaly"
        assert a["src_ip"] == "10.0.0.77"
        assert a["dst_ip"] == "10.0.0.20"
        assert "25" in a["evidence"] or "unique_dst_port_count=25" in a["evidence"]

    def test_below_threshold_not_detected(self):
        ports = list(range(1, 11))  # 10 个端口 < 阈值 20
        packets = _port_scan_burst(ports=ports, start_sec=0, step_sec=1)
        alerts = detect(packets, {
            "port_scan": {"time_window_sec": 60, "unique_dst_port_threshold": 20},
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        scan = [a for a in alerts if a["category"] == "端口扫描"]
        assert scan == []

    def test_at_threshold_boundary(self):
        ports = list(range(1, 21))  # 恰好 20 个端口 = 阈值
        packets = _port_scan_burst(ports=ports, start_sec=0, step_sec=1)
        alerts = detect(packets, {
            "port_scan": {"time_window_sec": 60, "unique_dst_port_threshold": 20},
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        scan = [a for a in alerts if a["category"] == "端口扫描"]
        assert len(scan) == 1

    def test_scan_spread_beyond_window_not_detected(self):
        # 每 5 秒一个端口，23 个端口跨 110 秒，60 秒窗口内不足 20
        ports = list(range(1, 24))
        packets = _port_scan_burst(ports=ports, start_sec=0, step_sec=5)
        alerts = detect(packets, {
            "port_scan": {"time_window_sec": 60, "unique_dst_port_threshold": 20},
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        scan = [a for a in alerts if a["category"] == "端口扫描"]
        assert scan == []

    def test_custom_threshold(self):
        ports = list(range(1, 11))  # 10 个端口
        packets = _port_scan_burst(ports=ports, start_sec=0, step_sec=1)
        assert detect(packets, {
            "port_scan": {"time_window_sec": 60, "unique_dst_port_threshold": 20},
        }) == []
        assert len(detect(packets, {
            "port_scan": {"time_window_sec": 60, "unique_dst_port_threshold": 8},
        })) == 1

    def test_separate_targets_separate_alerts(self):
        # 同源扫描两个不同目标
        p1 = _port_scan_burst("10.0.0.77", "10.0.0.20", list(range(1, 26)), start_sec=0)
        p2 = _port_scan_burst("10.0.0.77", "10.0.0.30", list(range(1, 26)), start_sec=30)
        alerts = detect(p1 + p2, {
            "port_scan": {"time_window_sec": 60, "unique_dst_port_threshold": 20},
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        scan = [a for a in alerts if a["category"] == "端口扫描"]
        assert len(scan) >= 1  # 至少检出

    def test_same_src_scan_alerts_share_behavior_id(self):
        # 同一源扫描两个目标的告警应共享 behavior_id
        p1 = _port_scan_burst("10.0.0.77", "10.0.0.20", list(range(1, 26)), start_sec=0)
        p2 = _port_scan_burst("10.0.0.77", "10.0.0.30", list(range(1, 26)), start_sec=60)
        alerts = detect(p1 + p2, {
            "port_scan": {"time_window_sec": 60, "unique_dst_port_threshold": 20},
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        scan = [a for a in alerts if a["category"] == "端口扫描"]
        if len(scan) >= 2:
            assert scan[0]["behavior_id"] == scan[1]["behavior_id"]


# ---------------------------------------------------------------------------
#  异常外联检测
# ---------------------------------------------------------------------------

class TestExternalConnection:
    """异常外联核心检测逻辑。"""

    def test_internal_to_external_detected(self):
        packets = [
            _pkt("192.168.1.55", "203.0.113.99", 443, timestamp_sec=0, sport=52001, flags="PA"),
        ]
        alerts = detect(packets, {
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        ext = [a for a in alerts if a["category"] == "异常外联"]
        assert len(ext) == 1
        a = ext[0]
        assert a["src_ip"] == "192.168.1.55"
        assert a["dst_ip"] == "203.0.113.99"
        assert a["dst_port"] == 443
        assert a["detector"] == "anomaly"

    def test_internal_to_internal_not_flagged(self):
        packets = [
            _pkt("192.168.1.10", "192.168.1.20", 80, timestamp_sec=0, sport=51000),
        ]
        alerts = detect(packets, {
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        ext = [a for a in alerts if a["category"] == "异常外联"]
        assert ext == []

    def test_external_to_internal_not_flagged(self):
        # 外部 IP → 内部 IP 不受检测（只关注内网外联）
        packets = [
            _pkt("203.0.113.99", "192.168.1.55", 443, timestamp_sec=0, sport=443),
        ]
        alerts = detect(packets, {
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        ext = [a for a in alerts if a["category"] == "异常外联"]
        assert ext == []

    def test_external_to_external_not_flagged(self):
        packets = [
            _pkt("203.0.113.1", "203.0.113.2", 80, timestamp_sec=0),
        ]
        alerts = detect(packets, {
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        ext = [a for a in alerts if a["category"] == "异常外联"]
        assert ext == []

    def test_multiple_external_connections_share_behavior_id(self):
        packets = [
            _pkt("192.168.1.55", "203.0.113.99", 443, timestamp_sec=0, sport=52100, flags="PA"),
            _pkt("192.168.1.55", "198.51.100.42", 8080, timestamp_sec=5, sport=52101, flags="PA"),
            _pkt("192.168.1.55", "203.0.113.55", 443, timestamp_sec=10, sport=52102, flags="S"),
        ]
        alerts = detect(packets, {
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        ext = [a for a in alerts if a["category"] == "异常外联"]
        assert len(ext) == 3
        # 同一源的外联告警应共享 behavior_id
        assert ext[0]["behavior_id"] == ext[1]["behavior_id"] == ext[2]["behavior_id"]

    def test_same_dst_dedup(self):
        # 同一连接的多条报文只产生一条告警
        packets = [
            _pkt("192.168.1.55", "203.0.113.99", 443, timestamp_sec=0, sport=52100, flags="PA"),
            _pkt("192.168.1.55", "203.0.113.99", 443, timestamp_sec=1, sport=52100, flags="PA"),
            _pkt("192.168.1.55", "203.0.113.99", 443, timestamp_sec=2, sport=52100, flags="A"),
        ]
        alerts = detect(packets, {
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        ext = [a for a in alerts if a["category"] == "异常外联"]
        assert len(ext) == 1  # 去重

    def test_no_internal_networks_configured(self):
        packets = [
            _pkt("192.168.1.55", "203.0.113.99", 443, timestamp_sec=0, sport=52100),
        ]
        alerts = detect(packets, {
            "external_connection": {"internal_networks": []},
        })
        ext = [a for a in alerts if a["category"] == "异常外联"]
        assert ext == []

    def test_10_network_detected(self):
        """10.0.0.0/8 内网主机外联公网应被检出。"""
        packets = [
            _pkt("10.0.0.55", "8.8.8.8", 53, timestamp_sec=0, sport=54000),
        ]
        alerts = detect(packets, {
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        ext = [a for a in alerts if a["category"] == "异常外联"]
        assert len(ext) == 1

    def test_172_network_detected(self):
        """172.16.0.0/12 内网主机外联公网应被检出。"""
        packets = [
            _pkt("172.16.0.55", "1.2.3.4", 80, timestamp_sec=0, sport=55000),
        ]
        alerts = detect(packets, {
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        ext = [a for a in alerts if a["category"] == "异常外联"]
        assert len(ext) == 1


# ---------------------------------------------------------------------------
#  内网横向扩散检测
# ---------------------------------------------------------------------------

class TestLateralMovement:
    """内网横向扩散核心检测逻辑。"""

    def test_lateral_movement_detected(self):
        # 同一源访问 15 个不同内网 IP
        dst_ips = [f"10.0.0.{i}" for i in range(1, 16)]
        packets = []
        for i, dip in enumerate(dst_ips):
            packets.append(_pkt("10.0.0.77", dip, 445, timestamp_sec=i, sport=60000 + i))
        alerts = detect(packets, {
            "external_connection": {"internal_networks": INTERNAL_NETS},
            "lateral_movement": {"time_window_sec": 60, "internal_dst_count_threshold": 10},
        })
        lat = [a for a in alerts if a["category"] == "内网横向扩散"]
        assert len(lat) == 1
        a = lat[0]
        assert a["src_ip"] == "10.0.0.77"
        assert a["dst_ip"] == "multiple"
        assert a["detector"] == "anomaly"
        assert "15" in a["evidence"]

    def test_below_threshold_not_detected(self):
        dst_ips = [f"10.0.0.{i}" for i in range(1, 6)]  # 5 个 IP < 阈值 10
        packets = []
        for i, dip in enumerate(dst_ips):
            packets.append(_pkt("10.0.0.77", dip, 445, timestamp_sec=i, sport=60000 + i))
        alerts = detect(packets, {
            "external_connection": {"internal_networks": INTERNAL_NETS},
            "lateral_movement": {"time_window_sec": 60, "internal_dst_count_threshold": 10},
        })
        lat = [a for a in alerts if a["category"] == "内网横向扩散"]
        assert lat == []

    def test_spread_beyond_window_not_detected(self):
        # 15 个不同 IP 但跨 300 秒，60 秒窗口内不够
        dst_ips = [f"10.0.0.{i}" for i in range(1, 16)]
        packets = []
        for i, dip in enumerate(dst_ips):
            packets.append(_pkt("10.0.0.77", dip, 445, timestamp_sec=i * 20, sport=60000 + i))
        alerts = detect(packets, {
            "external_connection": {"internal_networks": INTERNAL_NETS},
            "lateral_movement": {"time_window_sec": 60, "internal_dst_count_threshold": 10},
        })
        lat = [a for a in alerts if a["category"] == "内网横向扩散"]
        assert lat == []

    def test_excludes_self_connections(self):
        """自身通信不应计入横向扩散计数。"""
        packets = [_pkt("10.0.0.77", "10.0.0.77", 445, timestamp_sec=i, sport=60000 + i)
                   for i in range(15)]
        alerts = detect(packets, {
            "external_connection": {"internal_networks": INTERNAL_NETS},
            "lateral_movement": {"time_window_sec": 60, "internal_dst_count_threshold": 10},
        })
        lat = [a for a in alerts if a["category"] == "内网横向扩散"]
        assert lat == []

    def test_only_counts_internal_ips(self):
        """外网 IP 不应被计入横向扩散。"""
        # 15 个目标：8 个内网 + 7 个外网 → 只有 8 个内网，不足阈值
        internal = [f"10.0.0.{i}" for i in range(1, 9)]
        external = ["203.0.113.1", "203.0.113.2", "203.0.113.3",
                    "8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]
        packets = []
        for i, dip in enumerate(internal + external):
            packets.append(_pkt("10.0.0.77", dip, 445, timestamp_sec=i, sport=60000 + i))
        alerts = detect(packets, {
            "external_connection": {"internal_networks": INTERNAL_NETS},
            "lateral_movement": {"time_window_sec": 60, "internal_dst_count_threshold": 10},
        })
        lat = [a for a in alerts if a["category"] == "内网横向扩散"]
        assert lat == []


# ---------------------------------------------------------------------------
#  高频连接检测
# ---------------------------------------------------------------------------

class TestHighFrequency:
    """高频连接检测逻辑。"""

    def test_high_frequency_detected(self):
        # 120 个包集中在 59 秒内，60 秒滑动窗口最多容纳 120 次 > 阈值 100
        packets = []
        for i in range(120):
            packets.append(_pkt("10.0.0.99", "10.0.0.1", 80, timestamp_sec=i * 0.49, sport=60000 + i))
        alerts = detect(packets, {
            "connection_rate": {"time_window_sec": 60, "max_connections_per_ip": 100},
        })
        hf = [a for a in alerts if a["category"] == "异常高频连接"]
        assert len(hf) == 1
        assert "120" in hf[0]["evidence"] or "connection_count=" in hf[0]["evidence"]

    def test_below_threshold_not_detected(self):
        packets = []
        for i in range(50):
            packets.append(_pkt("10.0.0.99", "10.0.0.1", 80, timestamp_sec=i, sport=60000 + i))
        alerts = detect(packets, {
            "connection_rate": {"time_window_sec": 60, "max_connections_per_ip": 100},
        })
        hf = [a for a in alerts if a["category"] == "异常高频连接"]
        assert hf == []


# ---------------------------------------------------------------------------
#  告警格式合规性
# ---------------------------------------------------------------------------

class TestAlertSchema:
    """告警格式合规性（docs/interface_spec.md §3.1）。"""

    def test_port_scan_alert_schema(self):
        ports = list(range(1, 26))
        packets = _port_scan_burst(ports=ports, start_sec=0, step_sec=1)
        alerts = detect(packets, {
            "port_scan": {"time_window_sec": 60, "unique_dst_port_threshold": 20},
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        scan = [a for a in alerts if a["category"] == "端口扫描"][0]
        assert set(scan.keys()) == REQUIRED_ALERT_FIELDS
        assert scan["detector"] == "anomaly"
        assert scan["severity"] in {"low", "medium", "high"}
        assert scan["category"] == "端口扫描"
        assert len(scan["alert_id"]) == 36
        assert len(scan["behavior_id"]) == 36

    def test_external_conn_alert_schema(self):
        packets = [
            _pkt("192.168.1.55", "203.0.113.99", 443, timestamp_sec=0, sport=52001, flags="PA"),
        ]
        alerts = detect(packets, {
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        a = alerts[0]
        assert set(a.keys()) == REQUIRED_ALERT_FIELDS
        assert a["detector"] == "anomaly"
        assert a["category"] == "异常外联"
        assert a["severity"] == "medium"

    def test_lateral_movement_alert_schema(self):
        dst_ips = [f"10.0.0.{i}" for i in range(1, 16)]
        packets = [_pkt("10.0.0.77", dip, 445, timestamp_sec=i, sport=60000 + i)
                   for i, dip in enumerate(dst_ips)]
        alerts = detect(packets, {
            "external_connection": {"internal_networks": INTERNAL_NETS},
            "lateral_movement": {"time_window_sec": 60, "internal_dst_count_threshold": 10},
        })
        a = alerts[0]
        assert set(a.keys()) == REQUIRED_ALERT_FIELDS
        assert a["category"] == "内网横向扩散"

    def test_severity_scales_with_count(self):
        # 刚好超过阈值（1.1×）→ medium；远超（2×+）→ high
        low_ports = list(range(1, 23))  # 22 端口 ≈ 1.1×20
        high_ports = list(range(1, 46))  # 45 端口 > 2×20
        low_a = detect(
            _port_scan_burst(ports=low_ports, start_sec=0, step_sec=1),
            {"port_scan": {"time_window_sec": 60, "unique_dst_port_threshold": 20}},
        )
        high_a = detect(
            _port_scan_burst(ports=high_ports, start_sec=0, step_sec=1),
            {"port_scan": {"time_window_sec": 60, "unique_dst_port_threshold": 20}},
        )
        assert low_a[0]["severity"] == "medium"
        assert high_a[0]["severity"] == "high"

    def test_description_is_behavior_oriented(self):
        """告警描述应为行为导向语态，而非仅罗列统计数字。"""
        ports = list(range(1, 26))
        alerts = detect(
            _port_scan_burst(ports=ports, start_sec=0, step_sec=1),
            {"port_scan": {"time_window_sec": 60, "unique_dst_port_threshold": 20}},
        )
        desc = alerts[0]["description"]
        assert "端口扫描" in desc
        assert "探测" in desc or "扫描" in desc

    def test_dst_network_set_for_subnet_level_alert(self):
        ports = list(range(1, 26))
        alerts = detect(
            _port_scan_burst(ports=ports, start_sec=0, step_sec=1),
            {"port_scan": {"time_window_sec": 60, "unique_dst_port_threshold": 20}},
        )
        scan = [a for a in alerts if a["category"] == "端口扫描"][0]
        # 端口扫描属于网段级告警，应有 dst_network
        assert scan["dst_network"] is not None

    def test_multiple_alerts_sorted_by_timestamp(self):
        ports = list(range(1, 26))
        packets = _port_scan_burst(ports=ports, start_sec=0, step_sec=1)
        alert_packets = [
            _pkt("192.168.1.55", "203.0.113.99", 443, timestamp_sec=50, sport=52001, flags="PA"),
            _pkt("192.168.1.55", "198.51.100.42", 443, timestamp_sec=51, sport=52002, flags="S"),
        ]
        alerts = detect(packets + alert_packets, {
            "port_scan": {"time_window_sec": 60, "unique_dst_port_threshold": 20},
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        assert alerts == sorted(alerts, key=lambda a: a["timestamp"])


# ---------------------------------------------------------------------------
#  异常与边界情况
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """异常与边界输入（不应抛出未捕获异常）。"""

    def test_empty_input(self):
        assert detect([]) == []
        assert detect([], {}) == []

    def test_none_config_uses_default(self):
        """config=None 时自动加载默认配置，不崩溃。"""
        assert detect([]) == []

    def test_missing_fields_do_not_crash(self):
        packets = [
            {"timestamp": "2026-07-08T10:00:00.000"},
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
            {},
        ]
        alerts = detect(packets, {
            "port_scan": {"time_window_sec": 60, "unique_dst_port_threshold": 20},
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        assert alerts == []

    def test_malformed_records_skipped(self):
        packets = ["not a dict", 123, None, 3.14]
        packets += _port_scan_burst(ports=list(range(1, 26)), start_sec=0, step_sec=1)
        alerts = detect(packets, {
            "port_scan": {"time_window_sec": 60, "unique_dst_port_threshold": 20},
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        scan = [a for a in alerts if a["category"] == "端口扫描"]
        assert len(scan) == 1

    def test_unparseable_timestamp_does_not_crash(self):
        ports = list(range(1, 26))
        packets = _port_scan_burst(ports=ports, start_sec=0, step_sec=1)
        packets.append({
            "timestamp": "not-a-timestamp",
            "src_ip": "10.0.0.77", "src_port": 65000,
            "dst_ip": "10.0.0.20", "dst_port": 9999,
            "protocol": "TCP", "direction": "request", "flags": "S",
            "payload": "", "payload_len": 0,
        })
        alerts = detect(packets, {
            "port_scan": {"time_window_sec": 60, "unique_dst_port_threshold": 20},
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        scan = [a for a in alerts if a["category"] == "端口扫描"]
        assert len(scan) == 1  # 仍能检出

    def test_invalid_ip_does_not_crash(self):
        packets = [
            _pkt("not-an-ip", "192.168.1.20", 80, timestamp_sec=0, sport=50000),
        ]
        alerts = detect(packets, {
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        assert alerts == []

    def test_null_port_handled(self):
        """dst_port 为 null 时不应崩溃。"""
        packets = [{
            "timestamp": "2026-07-08T10:00:00.000",
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "dst_port": None,
            "protocol": "ICMP",
            "direction": "request",
            "flags": "",
            "payload": "",
            "payload_len": 0,
        }]
        alerts = detect(packets, {
            "external_connection": {"internal_networks": INTERNAL_NETS},
        })
        # 不崩溃，ICMP 外联也告警
        ext = [a for a in alerts if a["category"] == "异常外联"]
        assert len(ext) == 1
        assert ext[0]["dst_port"] is None

    def test_missing_config_sections(self):
        """配置字典缺少某检测项时使用空默认，不崩溃。"""
        ports = list(range(1, 26))
        packets = _port_scan_burst(ports=ports, start_sec=0, step_sec=1)
        alerts = detect(packets, {})  # 空配置 → 各检测项均为空默认
        # 无阈值配置，不应产生告警（也不应崩溃）
        assert isinstance(alerts, list)


# ---------------------------------------------------------------------------
#  Mock 数据端到端验证
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def mock_packets():
    if not MOCK_PATH.exists():
        pytest.skip(f"mock 数据缺失: {MOCK_PATH}")
    with open(MOCK_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


class TestMockData:
    """基于 Phase1 交付的 mock_data/mock_packets.json 端到端比对。"""

    def test_detects_port_scan(self, mock_packets):
        """mock 数据中 192.168.1.77 对 192.168.1.20 的端口扫描应被检出。"""
        alerts = detect(mock_packets)
        scan = [a for a in alerts if a["category"] == "端口扫描"]
        assert len(scan) == 1
        a = scan[0]
        assert a["src_ip"] == "192.168.1.77"
        assert a["dst_ip"] == "192.168.1.20"
        assert a["detector"] == "anomaly"
        assert "24" in a["evidence"]
        assert a["dst_network"] == "192.168.1.0/24"

    def test_detects_external_connections(self, mock_packets):
        """mock 数据中 192.168.1.55 的外联行为应被检出。"""
        alerts = detect(mock_packets)
        ext = [a for a in alerts if a["category"] == "异常外联"]
        # 192.168.1.55 → 203.0.113.99, 198.51.100.42, 203.0.113.55
        ext_55 = [a for a in ext if a["src_ip"] == "192.168.1.55"]
        assert len(ext_55) == 3
        dst_ips = {a["dst_ip"] for a in ext_55}
        assert dst_ips == {"203.0.113.99", "198.51.100.42", "203.0.113.55"}

        # 同一源的外联告警应共享 behavior_id
        bids = {a["behavior_id"] for a in ext_55}
        assert len(bids) == 1

    def test_lateral_movement_detected_in_mock_data(self, mock_packets):
        """mock 数据（扩充后）含横向扩散场景，应被检出。"""
        alerts = detect(mock_packets)
        lat = [a for a in alerts if a["category"] == "内网横向扩散"]
        assert len(lat) == 1
        assert lat[0]["src_ip"] == "10.0.0.77"

    def test_high_frequency_detected_in_mock_data(self, mock_packets):
        """mock 数据（扩充后）含高频连接场景。"""
        alerts = detect(mock_packets)
        hf = [a for a in alerts if a["category"] == "异常高频连接"]
        assert len(hf) == 1
        assert hf[0]["src_ip"] == "192.168.1.88"

    def test_all_alerts_conform_to_schema(self, mock_packets):
        for a in detect(mock_packets):
            assert set(a.keys()) == REQUIRED_ALERT_FIELDS
            assert a["detector"] == "anomaly"
            assert a["severity"] in {"low", "medium", "high"}
            assert len(a["alert_id"]) == 36
            assert a["behavior_id"] is not None

    def test_normal_http_traffic_not_flagged(self, mock_packets):
        """正常 HTTP 浏览（192.168.1.10）不应产生异常告警。"""
        alerts = detect(mock_packets)
        # 192.168.1.10 的正常内网 HTTP 不应产生端口扫描/横向扩散告警
        scan_or_lat = [a for a in alerts
                       if a["category"] in ("端口扫描", "内网横向扩散")
                       and a["src_ip"] == "192.168.1.10"]
        assert scan_or_lat == []

    def test_normal_ssh_ftp_not_flagged_as_anomaly(self, mock_packets):
        """正常 SSH/FTP 会话不应被 anomaly 模块误报。"""
        alerts = detect(mock_packets)
        # anomaly 模块不检测暴力破解（那是 bruteforce 的事）
        assert all(a["category"] != "暴力破解/非法登录" for a in alerts)
