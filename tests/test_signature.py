"""特征匹配引擎单元测试 —— 曾子恒

覆盖：SQL注入检出、XSS regex/literal检出、恶意命令检出、木马通信检出、
协议过滤、窗口聚合、跨窗口拆分、告警格式合规、异常与边界输入，
以及基于 mock_data/mock_packets.json 的端到端场景比对。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.signature_engine.matcher import detect

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


# ---------------------------------------------------------------------------
#  报文构造辅助
# ---------------------------------------------------------------------------

def _pkt(src_ip, dst_ip, dst_port, payload, timestamp_sec=0, sport=50000, protocol="TCP", flags="PA"):
    """构造一条 TCP 报文。"""
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
        "protocol": protocol,
        "direction": "request",
        "flags": flags,
        "payload": payload,
        "payload_len": len(payload.encode("utf-8")),
    }


# ---------------------------------------------------------------------------
#  SQL 注入检测
# ---------------------------------------------------------------------------

class TestSQLInjection:
    """SQL 注入特征检测。"""

    def test_union_select_detected(self):
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "GET /login.php?id=1 UNION SELECT username,password FROM users-- HTTP/1.1",
                 timestamp_sec=0),
        ]
        alerts = detect(packets)
        assert len(alerts) == 1
        a = alerts[0]
        assert a["detector"] == "signature"
        assert a["category"] == "SQL注入"
        assert a["severity"] == "high"
        assert "UNION SELECT" in a["evidence"]

    def test_or_1_eq_1_detected(self):
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "GET /search?q=' OR 1=1-- HTTP/1.1",
                 timestamp_sec=0),
        ]
        alerts = detect(packets)
        assert len(alerts) == 1
        assert alerts[0]["category"] == "SQL注入"

    def test_drop_table_detected(self):
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "GET /report?sort=1; DROP TABLE users-- HTTP/1.1",
                 timestamp_sec=0),
        ]
        alerts = detect(packets)
        assert len(alerts) == 1
        assert alerts[0]["category"] == "SQL注入"
        assert "DROP TABLE" in alerts[0]["evidence"]

    def test_select_star_from_detected(self):
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "POST /api/query HTTP/1.1\r\n\r\nSELECT * FROM admin WHERE id=1",
                 timestamp_sec=0),
        ]
        alerts = detect(packets)
        assert len(alerts) == 1
        a = alerts[0]
        assert a["category"] == "SQL注入"
        assert a["severity"] == "medium"  # SIG-005 is medium

    def test_sql_case_insensitive(self):
        """SQL 注入特征匹配应不区分大小写。"""
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "GET /?q=union select password from users HTTP/1.1",
                 timestamp_sec=0),
        ]
        alerts = detect(packets)
        assert len(alerts) == 1


# ---------------------------------------------------------------------------
#  XSS 检测
# ---------------------------------------------------------------------------

class TestXSS:
    """XSS 特征检测（regex + literal）。"""

    def test_script_tag_detected_by_regex(self):
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "GET /comment?text=<script>alert(1)</script> HTTP/1.1",
                 timestamp_sec=0),
        ]
        alerts = detect(packets)
        assert len(alerts) == 1
        a = alerts[0]
        assert a["category"] == "XSS"
        assert a["detector"] == "signature"

    def test_script_tag_case_insensitive(self):
        """XSS regex 匹配应不区分大小写。"""
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "POST /profile HTTP/1.1\r\n\r\nbio=<SCRIPT>alert(1)</SCRIPT>",
                 timestamp_sec=0),
        ]
        alerts = detect(packets)
        assert len(alerts) == 1
        assert alerts[0]["category"] == "XSS"

    def test_javascript_literal_detected(self):
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "GET /redirect?url=javascript:alert(1) HTTP/1.1",
                 timestamp_sec=0),
        ]
        alerts = detect(packets)
        assert len(alerts) >= 1
        # javascript: 匹配 SIG-007（low severity）
        js_alerts = [a for a in alerts if a["severity"] == "low"]
        assert len(js_alerts) >= 1


# ---------------------------------------------------------------------------
#  木马通信 + 恶意命令检测
# ---------------------------------------------------------------------------

class TestTrojanAndMaliciousCommand:
    """木马通信与恶意命令特征检测。"""

    def test_faxsurvey_trojan_detected(self):
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "GET /faxsurvey?/bin/cat%20/etc/passwd HTTP/1.1",
                 timestamp_sec=0),
        ]
        alerts = detect(packets)
        assert len(alerts) >= 1
        categories = {a["category"] for a in alerts}
        assert "木马通信" in categories

    def test_bin_cat_passwd_detected(self):
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "GET /cgi-bin/test?cmd=/bin/cat%20/etc/passwd HTTP/1.1",
                 timestamp_sec=0),
        ]
        alerts = detect(packets)
        assert len(alerts) >= 1
        categories = {a["category"] for a in alerts}
        assert "恶意命令" in categories

    def test_etc_shadow_detected(self):
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "GET /admin/exec?cmd=/bin/cat%20/etc/shadow HTTP/1.1",
                 timestamp_sec=0),
        ]
        alerts = detect(packets)
        assert len(alerts) >= 1
        assert any("恶意命令" == a["category"] for a in alerts)


# ---------------------------------------------------------------------------
#  协议过滤
# ---------------------------------------------------------------------------

class TestProtocolFiltering:
    """规则中的 protocol 字段过滤。"""

    def test_icmp_not_matched_by_tcp_rules(self):
        """ICMP 报文即使 payload 含 SQL 注入特征，TCP 规则也不应匹配。"""
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", None,
                 "UNION SELECT password FROM users",
                 timestamp_sec=0, protocol="ICMP", flags=""),
        ]
        alerts = detect(packets)
        assert alerts == []

    def test_udp_not_matched_by_tcp_rules(self):
        """UDP 报文不应触发仅限 TCP 的规则。"""
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 53,
                 "UNION SELECT password FROM users",
                 timestamp_sec=0, protocol="UDP", flags=""),
        ]
        alerts = detect(packets)
        assert alerts == []


# ---------------------------------------------------------------------------
#  60 秒窗口聚合
# ---------------------------------------------------------------------------

class TestWindowAggregation:
    """同一 (src_ip, dst_ip, category) 在 60 秒内的多次命中应合并为一条告警。"""

    def test_multiple_hits_in_window_merged(self):
        """同源同目标同类攻击，60 秒内 5 次命中 → 1 条告警。"""
        packets = []
        for i in range(5):
            packets.append(
                _pkt("10.0.0.1", "10.0.0.2", 80,
                     f"GET /?id={i} UNION SELECT col{i} FROM users-- HTTP/1.1",
                     timestamp_sec=i * 5, sport=50000 + i),
            )
        alerts = detect(packets)
        sql_alerts = [a for a in alerts if a["category"] == "SQL注入"]
        assert len(sql_alerts) == 1
        assert "hit_count=5" in sql_alerts[0]["evidence"]

    def test_hits_beyond_window_split(self):
        """同源同目标同类攻击，间隔超过 60 秒 → 分为多条告警。"""
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "GET /?q=UNION SELECT a FROM b-- HTTP/1.1",
                 timestamp_sec=0, sport=50001),
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "GET /?q=UNION SELECT c FROM d-- HTTP/1.1",
                 timestamp_sec=65, sport=50002),  # > 60s
        ]
        alerts = detect(packets)
        sql_alerts = [a for a in alerts if a["category"] == "SQL注入"]
        assert len(sql_alerts) == 2
        assert sql_alerts[0]["behavior_id"] != sql_alerts[1]["behavior_id"]

    def test_different_categories_not_merged(self):
        """不同攻击类型的命中不应合并。"""
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "GET /?q=UNION SELECT a FROM b-- HTTP/1.1",
                 timestamp_sec=0, sport=50001),
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "GET /comment?text=<script>alert(1)</script> HTTP/1.1",
                 timestamp_sec=1, sport=50002),
        ]
        alerts = detect(packets)
        categories = {a["category"] for a in alerts}
        assert categories == {"SQL注入", "XSS"}

    def test_different_dst_not_merged(self):
        """同一源对不同目标的攻击不应合并。"""
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "UNION SELECT a FROM b--",
                 timestamp_sec=0, sport=50001),
            _pkt("10.0.0.1", "10.0.0.3", 80,
                 "UNION SELECT c FROM d--",
                 timestamp_sec=1, sport=50002),
        ]
        alerts = detect(packets)
        sql_alerts = [a for a in alerts if a["category"] == "SQL注入"]
        assert len(sql_alerts) == 2


# ---------------------------------------------------------------------------
#  告警格式合规性
# ---------------------------------------------------------------------------

class TestAlertSchema:
    """告警格式合规性（docs/interface_spec.md §3.1）。"""

    def test_sql_injection_alert_schema(self):
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "UNION SELECT password FROM users--",
                 timestamp_sec=0),
        ]
        alerts = detect(packets)
        a = alerts[0]
        assert set(a.keys()) == REQUIRED_ALERT_FIELDS
        assert a["detector"] == "signature"
        assert a["severity"] in {"low", "medium", "high"}
        assert a["category"] == "SQL注入"
        assert len(a["alert_id"]) == 36  # UUID4
        assert len(a["behavior_id"]) == 36
        assert a["dst_network"] is None  # 单 IP 告警

    def test_xss_alert_schema(self):
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "<script>alert(1)</script>",
                 timestamp_sec=0),
        ]
        a = detect(packets)[0]
        assert set(a.keys()) == REQUIRED_ALERT_FIELDS
        assert a["category"] == "XSS"

    def test_description_is_behavior_oriented(self):
        """告警描述应为行为导向语态。"""
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "UNION SELECT password FROM users--",
                 timestamp_sec=0),
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "UNION SELECT email FROM users--",
                 timestamp_sec=10),
        ]
        alerts = detect(packets)
        desc = alerts[0]["description"]
        assert "60秒" in desc
        assert "10.0.0.1" in desc
        assert "10.0.0.2" in desc
        assert "命中" in desc

    def test_alerts_sorted_by_timestamp(self):
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "UNION SELECT a FROM b--",
                 timestamp_sec=70, sport=50001),
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "UNION SELECT c FROM d--",
                 timestamp_sec=10, sport=50002),
        ]
        alerts = detect(packets)
        assert alerts == sorted(alerts, key=lambda a: a["timestamp"])

    def test_evidence_contains_hit_count_and_pattern(self):
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "UNION SELECT password FROM users--",
                 timestamp_sec=0),
        ]
        a = detect(packets)[0]
        assert "hit_count=" in a["evidence"]
        assert "time_window_sec=" in a["evidence"]
        assert "UNION SELECT" in a["evidence"]


# ---------------------------------------------------------------------------
#  异常与边界情况
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """异常与边界输入（不应抛出未捕获异常）。"""

    def test_empty_input(self):
        assert detect([]) == []

    def test_no_payload_skipped(self):
        """无 payload 的报文应被跳过，不产生告警。"""
        packets = [{
            "timestamp": "2026-07-08T10:00:00.000",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "dst_port": 80,
            "protocol": "TCP",
            "payload": "",
            "payload_len": 0,
        }]
        assert detect(packets) == []

    def test_none_payload_skipped(self):
        packets = [{
            "timestamp": "2026-07-08T10:00:00.000",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "payload_len": 0,
        }]
        assert detect(packets) == []

    def test_normal_http_not_flagged(self):
        """正常 HTTP 流量不应产生告警。"""
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
                 timestamp_sec=0),
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "POST /login HTTP/1.1\r\n\r\nusername=admin&password=secret123",
                 timestamp_sec=1),
        ]
        assert detect(packets) == []

    def test_missing_fields_do_not_crash(self):
        packets = [
            {"timestamp": "2026-07-08T10:00:00.000"},
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
            {},
        ]
        alerts = detect(packets)
        assert alerts == []

    def test_malformed_records_skipped(self):
        packets = ["not a dict", 123, None, 3.14]
        packets.append(
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "UNION SELECT password FROM users--",
                 timestamp_sec=0),
        )
        alerts = detect(packets)
        assert len(alerts) == 1

    def test_unparseable_timestamp_does_not_crash(self):
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "UNION SELECT a FROM b--",
                 timestamp_sec=0, sport=50001),
        ]
        packets.append({
            "timestamp": "not-a-timestamp",
            "src_ip": "10.0.0.1", "src_port": 60000,
            "dst_ip": "10.0.0.2", "dst_port": 80,
            "protocol": "TCP", "payload": "UNION SELECT c FROM d--",
            "payload_len": 30,
        })
        alerts = detect(packets)
        assert len(alerts) >= 1

    def test_null_signatures_uses_default(self):
        """signatures=None 时自动加载默认规则库。"""
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", 80,
                 "UNION SELECT password FROM users--",
                 timestamp_sec=0),
        ]
        alerts = detect(packets, signatures=None)
        assert len(alerts) == 1

    def test_arp_not_matched(self):
        """ARP 协议不触发 TCP 限定规则。"""
        packets = [
            _pkt("10.0.0.1", "10.0.0.2", None,
                 "UNION SELECT a FROM b--",
                 timestamp_sec=0, protocol="ARP", flags=""),
        ]
        alerts = detect(packets)
        assert alerts == []


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

    def test_detects_sql_injection(self, mock_packets):
        """mock 数据中 192.168.1.10 的 6 条 SQL 注入应被检出并聚合为 1 条告警。"""
        alerts = detect(mock_packets)
        sql = [a for a in alerts if a["category"] == "SQL注入"]
        assert len(sql) == 1
        a = sql[0]
        assert a["src_ip"] == "192.168.1.10"
        assert a["dst_ip"] == "192.168.1.20"
        assert a["detector"] == "signature"
        assert "hit_count=6" in a["evidence"]

    def test_detects_xss(self, mock_packets):
        """mock 数据中 192.168.1.11 的 XSS 攻击应被检出并聚合为 1 条告警。"""
        alerts = detect(mock_packets)
        xss = [a for a in alerts if a["category"] == "XSS"]
        assert len(xss) == 1
        a = xss[0]
        assert a["src_ip"] == "192.168.1.11"
        assert a["dst_ip"] == "192.168.1.20"

    def test_detects_trojan_and_malicious_command(self, mock_packets):
        """mock 数据中 192.168.1.12 的木马+恶意命令应被检出。"""
        alerts = detect(mock_packets)
        trojan = [a for a in alerts if a["category"] == "木马通信"]
        malicious = [a for a in alerts if a["category"] == "恶意命令"]
        assert len(trojan) >= 1
        assert len(malicious) >= 1
        for a in trojan + malicious:
            assert a["src_ip"] == "192.168.1.12"
            assert a["dst_ip"] == "192.168.1.20"

    def test_normal_traffic_not_flagged(self, mock_packets):
        """正常 HTTP/SSH/FTP 流量不应产生 signature 告警。"""
        alerts = detect(mock_packets)
        attack_src_ips = {"192.168.1.10", "192.168.1.11", "192.168.1.12"}
        other_alerts = [a for a in alerts if a["src_ip"] not in attack_src_ips]
        assert other_alerts == []

    def test_all_alerts_conform_to_schema(self, mock_packets):
        for a in detect(mock_packets):
            assert set(a.keys()) == REQUIRED_ALERT_FIELDS
            assert a["detector"] == "signature"
            assert a["severity"] in {"low", "medium", "high"}
            assert len(a["alert_id"]) == 36
            assert a["behavior_id"] is not None

    def test_no_false_positive_on_bruteforce_packets(self, mock_packets):
        """暴力破解报文（大量 SSH SYN）不应触发 signature 告警。"""
        alerts = detect(mock_packets)
        bf_alerts = [a for a in alerts if a["src_ip"] == "192.168.1.99"]
        assert bf_alerts == []

    def test_alert_count_in_expected_range(self, mock_packets):
        """聚合后告警数量应在合理范围（3-5 条行为告警）。"""
        alerts = detect(mock_packets)
        assert 3 <= len(alerts) <= 5
