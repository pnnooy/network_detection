"""告警汇总与行为关联模块单元测试 —— 韩宇飞"""

import json
import tempfile
from pathlib import Path

import pytest

from src.gui_alert.aggregator import aggregate, correlate_behaviors, save_merged


class TestAggregator:
    """aggregator.py 测试"""

    def test_aggregate_empty_input(self):
        """空输入返回空列表"""
        result = aggregate([])
        assert result == []

    def test_aggregate_nonexistent_file(self):
        """不存在的文件被跳过，不崩溃"""
        result = aggregate(["nonexistent_file.json"])
        assert result == []

    def test_aggregate_multiple_files(self):
        """多个告警文件正确合并排序，并填充 behavior_id"""
        with tempfile.TemporaryDirectory() as tmpdir:
            alerts_a = [
                {
                    "alert_id": "a-1",
                    "detector": "signature",
                    "category": "SQL注入",
                    "src_ip": "10.0.0.1",
                    "src_port": 12345,
                    "dst_ip": "10.0.0.2",
                    "dst_port": 80,
                    "severity": "high",
                    "description": "test A",
                    "evidence": "test",
                    "timestamp": "2026-07-08T10:00:02",
                }
            ]
            alerts_b = [
                {
                    "alert_id": "b-1",
                    "detector": "bruteforce",
                    "category": "暴力破解",
                    "src_ip": "10.0.0.3",
                    "src_port": None,
                    "dst_ip": "10.0.0.4",
                    "dst_port": 22,
                    "severity": "medium",
                    "description": "test B",
                    "evidence": "test",
                    "timestamp": "2026-07-08T10:00:01",
                }
            ]

            fa = Path(tmpdir) / "a.json"
            fb = Path(tmpdir) / "b.json"
            fa.write_text(json.dumps(alerts_a), encoding="utf-8")
            fb.write_text(json.dumps(alerts_b), encoding="utf-8")

            result = aggregate([str(fa), str(fb)])
            assert len(result) == 2
            assert result[0]["alert_id"] == "b-1"
            assert result[1]["alert_id"] == "a-1"
            # 每条告警都有 behavior_id
            for alert in result:
                assert "behavior_id" in alert
                assert alert["behavior_id"] is not None

    def test_aggregate_deduplication(self):
        """相同 alert_id 去重"""
        with tempfile.TemporaryDirectory() as tmpdir:
            alert = {
                "alert_id": "dup-1",
                "detector": "signature",
                "category": "XSS",
                "src_ip": "10.0.0.1",
                "src_port": None,
                "dst_ip": "10.0.0.2",
                "dst_port": 80,
                "severity": "low",
                "description": "dup test",
                "evidence": "",
                "timestamp": "2026-07-08T10:00:00",
            }
            fa = Path(tmpdir) / "a.json"
            fb = Path(tmpdir) / "b.json"
            fa.write_text(json.dumps([alert]), encoding="utf-8")
            fb.write_text(json.dumps([alert]), encoding="utf-8")

            result = aggregate([str(fa), str(fb)])
            assert len(result) == 1


class TestBehaviorCorrelation:
    """correlate_behaviors() 测试"""

    def test_same_source_same_category_merged(self):
        """同源同类时间相近 → 同一 behavior_id"""
        alerts = [
            {
                "alert_id": "1",
                "detector": "signature",
                "category": "SQL注入",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "dst_port": 80,
                "severity": "high",
                "description": "SQL注入行为1",
                "evidence": "",
                "timestamp": "2026-07-08T10:00:00",
            },
            {
                "alert_id": "2",
                "detector": "signature",
                "category": "SQL注入",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "dst_port": 80,
                "severity": "high",
                "description": "SQL注入行为2",
                "evidence": "",
                "timestamp": "2026-07-08T10:00:30",
            },
        ]
        result = correlate_behaviors(alerts)
        assert result[0]["behavior_id"] == result[1]["behavior_id"]

    def test_different_source_separated(self):
        """不同源 → 不同 behavior_id"""
        alerts = [
            {
                "alert_id": "1",
                "detector": "signature",
                "category": "SQL注入",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "dst_port": 80,
                "severity": "high",
                "description": "SQL注入",
                "evidence": "",
                "timestamp": "2026-07-08T10:00:00",
            },
            {
                "alert_id": "2",
                "detector": "signature",
                "category": "SQL注入",
                "src_ip": "10.0.0.99",
                "dst_ip": "10.0.0.3",
                "dst_port": 80,
                "severity": "high",
                "description": "SQL注入",
                "evidence": "",
                "timestamp": "2026-07-08T10:00:15",
            },
        ]
        result = correlate_behaviors(alerts)
        assert result[0]["behavior_id"] != result[1]["behavior_id"]

    def test_time_gap_exceeds_window_separated(self):
        """时间间隔超出窗口 → 不同 behavior_id"""
        alerts = [
            {
                "alert_id": "1",
                "detector": "anomaly",
                "category": "端口扫描",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "dst_port": None,
                "severity": "high",
                "description": "扫描1",
                "evidence": "",
                "timestamp": "2026-07-08T10:00:00",
            },
            {
                "alert_id": "2",
                "detector": "anomaly",
                "category": "端口扫描",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "dst_port": None,
                "severity": "high",
                "description": "扫描2",
                "evidence": "",
                "timestamp": "2026-07-08T10:05:00",  # 5分钟间隔
            },
        ]
        result = correlate_behaviors(alerts, time_window_sec=60)
        assert result[0]["behavior_id"] != result[1]["behavior_id"]

    def test_preserve_existing_behavior_id(self):
        """已有 behavior_id 的告警保持原值不覆盖"""
        alerts = [
            {
                "alert_id": "1",
                "behavior_id": "preset-1",
                "detector": "bruteforce",
                "category": "暴力破解",
                "src_ip": "10.0.0.5",
                "dst_ip": "10.0.0.10",
                "dst_port": 22,
                "severity": "medium",
                "description": "暴力破解",
                "evidence": "",
                "timestamp": "2026-07-08T10:00:00",
            },
            {
                "alert_id": "2",
                "detector": "bruteforce",
                "category": "暴力破解",
                "src_ip": "10.0.0.5",
                "dst_ip": "10.0.0.10",
                "dst_port": 22,
                "severity": "medium",
                "description": "暴力破解-续",
                "evidence": "",
                "timestamp": "2026-07-08T10:00:30",
            },
        ]
        result = correlate_behaviors(alerts, time_window_sec=60)
        # 已预设的保持不变
        assert result[0]["behavior_id"] == "preset-1"
        # 后续同组告警继承预设的 behavior_id
        assert result[1]["behavior_id"] == "preset-1"


class TestCrossDetectorCorrelation:
    """协同联动测试（v2）"""

    @staticmethod
    def _alert(aid, detector, category, src_ip, severity="medium", ts="2026-07-08T10:00:00"):
        return {
            "alert_id": aid, "behavior_id": aid,
            "detector": detector, "category": category,
            "src_ip": src_ip, "dst_ip": "192.168.1.20", "dst_port": 80,
            "severity": severity, "description": "", "evidence": "",
            "timestamp": ts,
        }

    def test_cross_detector_correlation(self):
        """同一IP被多个检测器检出时，相互关联。"""
        from src.gui_alert.correlator import correlate_cross_detector

        alerts = [
            self._alert("a1", "signature", "SQL注入", "10.0.0.1"),
            self._alert("a2", "anomaly", "异常外联", "10.0.0.1"),
            self._alert("a3", "signature", "XSS", "10.0.0.2"),
        ]
        result = correlate_cross_detector(alerts)
        # 10.0.0.1 有 signature+anomaly → 应关联
        assert len(result[0]["correlated_alerts"]) == 1  # a1 refers to a2
        assert result[0]["cross_detector_count"] == 2
        # 10.0.0.2 仅有 signature → 不应有关联
        assert result[2]["correlated_alerts"] == []
        assert result[2]["cross_detector_count"] == 1

    def test_attack_stage_assignment(self):
        """告警应正确标注攻击阶段。"""
        from src.gui_alert.correlator import detect_attack_chain

        alerts = [
            self._alert("a1", "anomaly", "端口扫描", "10.0.0.1"),
            self._alert("a2", "signature", "SQL注入", "10.0.0.1"),
            self._alert("a3", "anomaly", "异常外联", "10.0.0.1"),
        ]
        result = detect_attack_chain(alerts)
        assert result[0]["attack_stage"] == "reconnaissance"
        assert result[1]["attack_stage"] == "exploitation"
        assert result[2]["attack_stage"] == "c2"
        # 同 IP 形成攻击链
        assert result[0]["attack_chain_id"] == result[1]["attack_chain_id"]

    def test_severity_escalation(self):
        """多检测器交叉验证时，低严重度升级。"""
        from src.gui_alert.correlator import escalate_severity

        alerts = [
            self._alert("a1", "signature", "SQL注入", "10.0.0.1", severity="low"),
            self._alert("a2", "anomaly", "异常外联", "10.0.0.1", severity="medium"),
            self._alert("a3", "signature", "XSS", "10.0.0.2", severity="low"),
        ]
        result = escalate_severity(alerts)
        # 10.0.0.1 有 2 个检测器 → a1 low→medium, a2 medium→high
        assert result[0]["severity"] == "medium"
        assert result[1]["severity"] == "high"
        # 10.0.0.2 仅 1 个检测器 → 不变
        assert result[2]["severity"] == "low"
        assert result[2]["escalated"] is False

    def test_correlator_no_false_cross_detector(self):
        """不同IP的告警不应被误关联。"""
        from src.gui_alert.correlator import correlate_cross_detector

        alerts = [
            self._alert("a1", "signature", "SQL注入", "10.0.0.1"),
            self._alert("a2", "anomaly", "端口扫描", "10.0.0.2"),
        ]
        result = correlate_cross_detector(alerts)
        assert result[0]["correlated_alerts"] == []
        assert result[1]["correlated_alerts"] == []

    def test_aggregator_includes_new_fields(self):
        """汇总后的告警应包含协同关联字段。"""
        from src.gui_alert.aggregator import aggregate as _agg
        import json, tempfile, os

        alerts = [
            self._alert("a1", "signature", "SQL注入", "10.0.0.1"),
            self._alert("a2", "anomaly", "异常外联", "10.0.0.1"),
        ]
        with tempfile.TemporaryDirectory() as td:
            f1 = os.path.join(td, "test1.json")
            f2 = os.path.join(td, "test2.json")
            json.dump([alerts[0]], open(f1, "w"))
            json.dump([alerts[1]], open(f2, "w"))
            merged = _agg([f1, f2])
            for a in merged:
                assert "correlated_alerts" in a
                assert "attack_stage" in a
                assert "cross_detector_count" in a
                assert "original_severity" in a
