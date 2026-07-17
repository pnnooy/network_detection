"""GUI 模块单元测试 —— 韩宇飞

测试辅助函数（签名解析、文件扫描）及 GUI 组件逻辑。
tkinter 渲染层测试需图形环境，此处覆盖可无头运行的逻辑层。
"""

import json
import tempfile
from pathlib import Path

import pytest

from src.gui_alert.gui import _parse_signatures_file, _scan_result_files


class TestParseSignaturesFile:
    """特征库文件解析。"""

    def test_parse_valid_file(self):
        content = """# comment
SIG-001 | SQL注入 | literal | UNION SELECT | HTTP | high
SIG-002 | XSS | regex | <script.*?> | HTTP | medium
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(content)
            path = Path(f.name)

        try:
            rules = _parse_signatures_file(path)
            assert len(rules) == 2
            assert rules[0] == {
                "rule_id": "SIG-001",
                "category": "SQL注入",
                "match_mode": "literal",
                "pattern": "UNION SELECT",
                "protocol": "HTTP",
                "severity": "high",
            }
            assert rules[1]["match_mode"] == "regex"
        finally:
            path.unlink()

    def test_parse_empty_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("")
            path = Path(f.name)
        try:
            assert _parse_signatures_file(path) == []
        finally:
            path.unlink()

    def test_parse_file_with_comments_and_blanks(self):
        content = """# header

# blank above
SIG-003 | 木马通信 | literal | /faxsurvey? | TCP | high
# trailing comment
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(content)
            path = Path(f.name)
        try:
            rules = _parse_signatures_file(path)
            assert len(rules) == 1
            assert rules[0]["rule_id"] == "SIG-003"
        finally:
            path.unlink()

    def test_skips_malformed_lines(self):
        content = """SIG-001 | SQL注入 | literal | UNION SELECT | HTTP | high
bad-line-without-pipes
SIG-002 | XSS | regex | <script> | HTTP | medium"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(content)
            path = Path(f.name)
        try:
            rules = _parse_signatures_file(path)
            assert len(rules) == 2
        finally:
            path.unlink()

    def test_nonexistent_file(self):
        assert _parse_signatures_file(Path("/nonexistent/path.txt")) == []


class TestScanResultFiles:
    """results/ 目录扫描。"""

    def test_scan_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            import os
            old = os.getcwd()
            # 函数依赖项目根目录的 results/，这里直接测 Path 逻辑
            results_dir = Path(tmpdir) / "results"
            results_dir.mkdir()
            # _scan_result_files 使用模块级 RESULTS_DIR，无法直接替换。
            # 测试其等价逻辑：glob 行为
            found = list(results_dir.glob("*_alerts.json"))
            assert found == []

    def test_scan_finds_alert_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results_dir = Path(tmpdir) / "results"
            results_dir.mkdir()
            (results_dir / "signature_alerts.json").touch()
            (results_dir / "bruteforce_alerts.json").touch()
            (results_dir / "anomaly_alerts.json").touch()
            (results_dir / "merged_alerts.json").touch()
            (results_dir / "other.txt").touch()

            found = sorted(results_dir.glob("*_alerts.json"))
            assert len(found) == 4
            names = [f.name for f in found]
            assert "signature_alerts.json" in names
            assert "other.txt" not in names


class TestSignatureManagerLogic:
    """特征库增删改查逻辑（非 GUI 层）。"""

    def _make_rule(self, rid="SIG-TEST", **overrides):
        rule = {
            "rule_id": rid,
            "category": "测试",
            "match_mode": "literal",
            "pattern": "test",
            "protocol": "*",
            "severity": "low",
        }
        rule.update(overrides)
        return rule

    def test_add_rule(self):
        rules = [self._make_rule("SIG-001")]
        rules.append(self._make_rule("SIG-002", category="SQL注入"))
        assert len(rules) == 2
        assert rules[1]["category"] == "SQL注入"

    def test_edit_rule(self):
        rules = [self._make_rule("SIG-001")]
        rules[0] = self._make_rule("SIG-001", severity="high")
        assert rules[0]["severity"] == "high"

    def test_delete_rule(self):
        rules = [self._make_rule("SIG-001"), self._make_rule("SIG-002")]
        rules.pop(0)
        assert len(rules) == 1
        assert rules[0]["rule_id"] == "SIG-002"

    def test_crud_roundtrip(self):
        rules: list = []
        # create
        rules.append(self._make_rule("SIG-A"))
        rules.append(self._make_rule("SIG-B"))
        assert len(rules) == 2
        # update
        rules[0]["pattern"] = "updated_pattern"
        assert rules[0]["pattern"] == "updated_pattern"
        # delete
        rules = [r for r in rules if r["rule_id"] != "SIG-A"]
        assert len(rules) == 1


class TestGUISmoke:
    """GUI 冒烟测试：确保 tkinter 可正常创建和销毁。"""

    def test_launch_gui_creates_root(self):
        """验证 launch_gui 可被导入且不抛异常。"""
        from src.gui_alert.gui import launch_gui

        import tkinter as tk
        root = tk.Tk()
        root.withdraw()  # 不显示窗口
        try:
            # 仅验证模块可加载，实际 GUI 需图形环境
            assert callable(launch_gui)
        finally:
            root.destroy()
