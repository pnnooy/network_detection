"""告警汇总模块单元测试 —— 韩宇飞"""

import json
import tempfile
from pathlib import Path

import pytest

from src.gui_alert.aggregator import aggregate, save_merged


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
        """多个告警文件正确合并排序"""
        # 创建临时告警文件
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
            # 按 timestamp 排序，b 的时间更早应排前面
            assert result[0]["alert_id"] == "b-1"
            assert result[1]["alert_id"] == "a-1"

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
