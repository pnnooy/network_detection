"""
Web 版攻击行为监控面板 —— 韩宇飞

基于 Python http.server 标准库，零额外依赖。
前端视觉风格完全参考 M-VQA Challenge (m-vqa-challenge.github.io/M-VQA)。

用法:
    python -m src.gui_alert.web_gui              # 默认 http://127.0.0.1:8099
    python -m src.gui_alert.web_gui --port 8080  # 自定义端口
    python -m src.gui_alert.web_gui --reload     # mock数据变更后刷新
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections import Counter
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from src.signature_engine.signature_db import load_signatures
from src.gui_alert.aggregator import aggregate

logger = logging.getLogger(__name__)

PROJECT_DIR = Path(__file__).resolve().parent.parent.parent
RESULTS_DIR = PROJECT_DIR / "results"
MOCK_PATH = PROJECT_DIR / "mock_data" / "mock_packets.json"
SIGNATURES_PATH = PROJECT_DIR / "config" / "signatures.txt"


# ═══════════════════════════════════════════════════════════════════
#  API 数据接口
# ═══════════════════════════════════════════════════════════════════

def _scan_alert_files() -> list[str]:
    """扫描 results/ 目录下的告警文件。"""
    if not RESULTS_DIR.exists():
        return []
    return sorted(str(f) for f in RESULTS_DIR.glob("*_alerts.json"))


def get_alerts() -> list[dict]:
    """获取合并后的告警列表。"""
    files = _scan_alert_files()
    if not files:
        return []
    return aggregate(files)


def get_signatures() -> list[dict]:
    """获取特征库规则列表。"""
    try:
        return load_signatures(str(SIGNATURES_PATH))
    except Exception:
        return []


def get_stats() -> dict:
    """获取统计概览数据。"""
    alerts = get_alerts()
    if not alerts:
        return {"total": 0, "by_category": {}, "by_severity": {},
                "by_detector": {}, "behaviors": 0, "top_sources": []}

    categories = Counter(a.get("category", "未知") for a in alerts)
    severities = Counter(a.get("severity", "medium") for a in alerts)
    detectors = Counter(a.get("detector", "?") for a in alerts)
    behaviors = len({a.get("behavior_id") for a in alerts if a.get("behavior_id")})
    sources = Counter(a.get("src_ip", "?") for a in alerts).most_common(10)

    return {
        "total": len(alerts),
        "by_category": dict(categories.most_common()),
        "by_severity": dict(severities),
        "by_detector": dict(detectors),
        "behaviors": behaviors,
        "top_sources": [{"ip": ip, "count": c} for ip, c in sources],
    }


def run_detection_pipeline() -> dict:
    """重新运行检测管线并返回结果。"""
    from src.signature_engine.matcher import detect as sig_detect
    from src.bruteforce_detect.login_monitor import detect as bf_detect
    from src.anomaly_detect.anomaly_detector import detect as anom_detect

    with open(MOCK_PATH, "r", encoding="utf-8") as f:
        packets = json.load(f)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    results = {}

    for name, detect_fn, out_name in [
        ("signature", sig_detect, "signature_alerts.json"),
        ("bruteforce", bf_detect, "bruteforce_alerts.json"),
        ("anomaly", anom_detect, "anomaly_alerts.json"),
    ]:
        alerts = detect_fn(packets)
        out_path = RESULTS_DIR / out_name
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(alerts, f, ensure_ascii=False, indent=2)
        results[name] = {"count": len(alerts), "path": str(out_path)}

    merged = aggregate([str(RESULTS_DIR / f"{k}_alerts.json") for k in results])
    merged_path = RESULTS_DIR / "merged_alerts.json"
    with open(merged_path, "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)

    return {
        "modules": results,
        "merged_count": len(merged),
        "packet_count": len(packets),
    }


# ═══════════════════════════════════════════════════════════════════
#  HTTP 请求处理器
# ═══════════════════════════════════════════════════════════════════

class WebGUIHandler(SimpleHTTPRequestHandler):
    """处理 HTTP 请求：API 端点 + 静态页面。"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PROJECT_DIR), **kwargs)

    def log_message(self, fmt, *args):
        logger.debug(fmt % args)

    def _send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html, status=200):
        data = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(data))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # API 路由
        if path == "/api/alerts":
            return self._send_json(get_alerts())
        if path == "/api/signatures":
            return self._send_json(get_signatures())
        if path == "/api/stats":
            return self._send_json(get_stats())

        # 首页
        if path == "/" or path == "/index.html":
            return self._send_html(_HTML_PAGE)

        # 静态文件回退
        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len else b"{}"
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = {}

        if path == "/api/reload":
            result = run_detection_pipeline()
            return self._send_json({"status": "ok", **result})

        if path == "/api/signatures/add":
            from src.signature_engine.signature_db import add_signature
            try:
                add_signature(str(SIGNATURES_PATH), data)
                return self._send_json({"status": "ok", "rule": data})
            except ValueError as e:
                return self._send_json({"status": "error", "message": str(e)}, 400)

        if path == "/api/signatures/delete":
            from src.signature_engine.signature_db import delete_signature
            rule_id = data.get("rule_id", "")
            if rule_id:
                delete_signature(str(SIGNATURES_PATH), rule_id)
                return self._send_json({"status": "ok"})
            return self._send_json({"status": "error", "message": "missing rule_id"}, 400)

        self._send_json({"status": "error", "message": "unknown endpoint"}, 404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


# ═══════════════════════════════════════════════════════════════════
#  HTML 页面（M-VQA 视觉风格）
# ═══════════════════════════════════════════════════════════════════

_HTML_PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>网络攻击行为监控系统</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Merriweather:wght@600;700;800&family=Nunito:wght@500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<style>
/* ═══════════════════════════════════════════════════════════════════
   Design System — 完全参考 M-VQA Challenge
   https://github.com/M-VQA-Challenge/M-VQA
   ═══════════════════════════════════════════════════════════════════ */

:root {
  /* Primary teal palette */
  --primary: #0d9488;      --primary-light: #14b8a6;   --primary-dark: #0f766e;
  --primary-50: #f0fdfa;   --primary-100: #ccfbf1;    --primary-200: #99f6e4;
  /* Accent cyan */
  --accent: #06b6d4;       --accent-light: #22d3ee;
  /* Dark */
  --secondary: #134e4a;    --dark: #042f2e;
  /* Gray scale */
  --gray-50: #f8fafc;  --gray-100: #f1f5f9;  --gray-200: #e2e8f0;  --gray-300: #cbd5e1;
  --gray-400: #94a3b8;  --gray-500: #64748b;  --gray-600: #475569;  --gray-700: #334155;
  --gray-800: #1e293b;  --gray-900: #0f172a;
  --white: #ffffff;
  /* Gradients */
  --gradient-primary: linear-gradient(135deg, #0d9488 0%, #06b6d4 100%);
  --gradient-dark: linear-gradient(135deg, #042f2e 0%, #134e4a 100%);
  /* Shadows */
  --shadow-sm: 0 1px 2px 0 rgba(0,0,0,0.05);
  --shadow: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -2px rgba(0,0,0,0.1);
  --shadow-md: 0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -4px rgba(0,0,0,0.1);
  --shadow-lg: 0 20px 25px -5px rgba(0,0,0,0.1), 0 8px 10px -6px rgba(0,0,0,0.1);
  --shadow-xl: 0 25px 50px -12px rgba(0,0,0,0.25);
  /* Borders */
  --radius-sm: 0.375rem;  --radius: 0.5rem;       --radius-md: 0.75rem;
  --radius-lg: 1rem;      --radius-xl: 1.5rem;
  /* Fonts */
  --font-heading: 'Merriweather', serif;
  --font-body: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  --font-ui: 'Nunito', sans-serif;
  --font-mono: 'JetBrains Mono', monospace;
  /* Severity colors */
  --sev-high: #dc3545;    --sev-medium: #fd7e14;   --sev-low: #ffc107;
}

*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  font-family: var(--font-body);
  background: var(--gray-50);
  color: var(--gray-800);
  line-height: 1.6;
  overflow-x: hidden;
}
.container { max-width: 1400px; margin: 0 auto; padding: 0 24px; }

/* ── Navbar ──────────────────────────────────────────── */
.navbar {
  position: fixed; top: 0; left: 0; right: 0; z-index: 1000;
  background: rgba(255,255,255,0.95);
  backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
  border-bottom: 1px solid var(--gray-200);
  transition: box-shadow 0.3s ease;
}
.navbar.scrolled { box-shadow: var(--shadow-md); }
.nav-container {
  max-width: 1400px; margin: 0 auto; padding: 0 24px;
  display: flex; align-items: center; justify-content: space-between; height: 72px;
}
.nav-brand {
  display: flex; align-items: center; gap: 12px;
  font-family: var(--font-heading); font-size: 1.15rem; font-weight: 700;
  color: var(--primary-dark); text-decoration: none;
}
.nav-brand i { font-size: 1.5rem; color: var(--primary); }
.nav-tabs { display: flex; align-items: center; gap: 6px; list-style: none; }
.nav-tabs button {
  display: flex; align-items: center; gap: 6px;
  padding: 8px 16px; border: none; background: transparent;
  color: var(--gray-600); font-size: 0.875rem; font-weight: 500;
  font-family: var(--font-ui); border-radius: var(--radius);
  cursor: pointer; transition: all 0.2s ease;
}
.nav-tabs button:hover { color: var(--primary); background: var(--primary-50); }
.nav-tabs button.active {
  color: var(--white); background: var(--gradient-primary);
  box-shadow: var(--shadow);
}
.nav-actions { display: flex; align-items: center; gap: 10px; }
.btn {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 10px 20px; font-size: 0.875rem; font-weight: 600;
  font-family: var(--font-ui); border: none; border-radius: var(--radius-md);
  cursor: pointer; transition: all 0.3s ease; text-decoration: none;
}
.btn-primary {
  background: var(--gradient-primary); color: var(--white);
  box-shadow: var(--shadow);
}
.btn-primary:hover { transform: translateY(-2px); box-shadow: var(--shadow-lg); }
.btn-outline {
  background: transparent; color: var(--primary-dark);
  border: 1px solid var(--primary-200);
}
.btn-outline:hover { background: var(--primary-50); }
.btn-sm { padding: 6px 14px; font-size: 0.8125rem; }
.btn-danger { background: #dc3545; color: white; }
.btn-danger:hover { background: #c82333; transform: translateY(-2px); }

/* ── Hero banner ─────────────────────────────────────── */
.hero {
  position: relative; margin-top: 72px;
  background: var(--gradient-dark); color: var(--white);
  padding: 48px 24px; overflow: hidden;
}
.hero::before {
  content: ''; position: absolute; top: 0; right: 0; width: 400px; height: 400px;
  background: radial-gradient(circle, rgba(6,182,212,0.2) 0%, transparent 70%);
  pointer-events: none;
}
.hero-content { position: relative; z-index: 1; max-width: 900px; margin: 0 auto; text-align: center; }
.hero h1 {
  font-family: var(--font-heading); font-size: 2rem; font-weight: 700; margin-bottom: 8px;
}
.hero-subtitle {
  font-size: 0.9375rem; color: rgba(255,255,255,0.8); margin-bottom: 24px;
}
.hero-stats {
  display: flex; justify-content: center; gap: 40px; flex-wrap: wrap;
}
.hero-stat {
  display: flex; align-items: center; gap: 12px;
}
.hero-stat i { font-size: 1.5rem; color: rgba(255,255,255,0.9); }
.hero-stat-val {
  font-family: var(--font-heading); font-size: 1.5rem; font-weight: 700;
  color: var(--white); line-height: 1;
}
.hero-stat-label {
  font-size: 0.75rem; color: rgba(255,255,255,0.7);
  font-family: var(--font-heading);
}

/* ── Section ─────────────────────────────────────────── */
.section { padding: 60px 0; }
.section-header { text-align: center; margin-bottom: 40px; }
.section-tag {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 6px 16px; background: var(--primary-50); color: var(--primary);
  font-size: 0.875rem; font-weight: 600; font-family: var(--font-ui);
  border-radius: 100px; margin-bottom: 12px;
}
.section-header h2 {
  font-family: var(--font-heading); font-size: 1.75rem; font-weight: 700;
  color: var(--gray-900); margin-bottom: 8px;
}
.section-desc { font-size: 1rem; color: var(--gray-500); max-width: 600px; margin: 0 auto; }

/* ── Tab panels ──────────────────────────────────────── */
.tab-panel { display: none; }
.tab-panel.active { display: block; }

/* ── Stats grid ──────────────────────────────────────── */
.stats-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 20px; margin-bottom: 40px;
}
.stat-card {
  background: var(--white); padding: 28px; border-radius: var(--radius-lg);
  border: 1px solid var(--gray-200); text-align: center;
  transition: all 0.3s ease;
}
.stat-card:hover { transform: translateY(-4px); box-shadow: var(--shadow-lg); border-color: var(--primary-200); }
.stat-icon {
  width: 56px; height: 56px; background: var(--gradient-primary);
  border-radius: var(--radius-md); display: flex; align-items: center;
  justify-content: center; margin: 0 auto 14px;
}
.stat-icon i { font-size: 1.5rem; color: white; }
.stat-value {
  font-family: var(--font-ui); font-size: 2rem; font-weight: 800;
  color: var(--primary-dark); line-height: 1; margin-bottom: 4px;
}
.stat-name { font-size: 0.875rem; color: var(--gray-500); font-weight: 500; }

/* ── Filter bar ──────────────────────────────────────── */
.filter-bar {
  display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; align-items: center;
}
.filter-bar select, .filter-bar input {
  padding: 10px 16px; border: 1px solid var(--gray-200); border-radius: var(--radius);
  font-size: 0.875rem; font-family: var(--font-body); color: var(--gray-700);
  background: var(--white); transition: border-color 0.2s;
}
.filter-bar select:focus, .filter-bar input:focus {
  outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px var(--primary-50);
}
.filter-bar input { flex: 1; min-width: 200px; }
.filter-count {
  margin-left: auto; font-size: 0.875rem; color: var(--gray-500);
  font-family: var(--font-ui);
}

/* ── Alert table ─────────────────────────────────────── */
.table-container {
  background: var(--white); border-radius: var(--radius-xl);
  border: 1px solid var(--gray-200); overflow: hidden;
}
.alert-table {
  width: 100%; border-collapse: collapse; font-size: 0.875rem;
}
.alert-table th {
  background: var(--gray-50); padding: 14px 16px; text-align: left;
  font-weight: 600; color: var(--gray-700); font-size: 0.8125rem;
  text-transform: uppercase; letter-spacing: 0.05em; font-family: var(--font-ui);
  border-bottom: 2px solid var(--gray-200);
}
.alert-table td {
  padding: 12px 16px; border-bottom: 1px solid var(--gray-100);
  color: var(--gray-600); vertical-align: middle;
}
.alert-table tbody tr { cursor: pointer; transition: background 0.15s; }
.alert-table tbody tr:hover { background: var(--primary-50); }
.alert-table tbody tr.selected { background: var(--primary-100); }

/* Severity badges */
.badge {
  display: inline-block; padding: 3px 10px; border-radius: 100px;
  font-size: 0.75rem; font-weight: 600; font-family: var(--font-ui);
}
.badge-high { background: #fce4ec; color: #c62828; }
.badge-medium { background: #fff3e0; color: #e65100; }
.badge-low { background: #fff8e1; color: #f9a825; }
.badge-signature { background: #e8f5e9; color: #2e7d32; }
.badge-bruteforce { background: #fce4ec; color: #c62828; }
.badge-anomaly { background: #e3f2fd; color: #1565c0; }

/* ── Detail panel ────────────────────────────────────── */
.detail-panel {
  display: none; background: var(--white); border-radius: var(--radius-xl);
  border: 1px solid var(--gray-200); padding: 32px; margin-top: 20px;
}
.detail-panel.show { display: block; }
.detail-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 16px;
}
.detail-item { display: flex; flex-direction: column; gap: 4px; }
.detail-label {
  font-size: 0.75rem; font-weight: 600; color: var(--gray-400);
  text-transform: uppercase; letter-spacing: 0.05em; font-family: var(--font-ui);
}
.detail-value {
  font-size: 0.9375rem; color: var(--gray-800); word-break: break-all;
}
.detail-value.desc {
  font-size: 0.9375rem; line-height: 1.7; color: var(--gray-700);
  background: var(--gray-50); padding: 16px; border-radius: var(--radius-md);
  grid-column: 1 / -1;
}
.evidence-block {
  grid-column: 1 / -1; background: var(--gray-800); color: var(--gray-100);
  padding: 16px; border-radius: var(--radius-md);
  font-family: var(--font-mono); font-size: 0.8125rem; line-height: 1.5;
  overflow-x: auto; white-space: pre-wrap;
}

/* ── Signature table ─────────────────────────────────── */
.sig-table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
.sig-table th {
  background: var(--gray-50); padding: 14px 16px; text-align: left;
  font-weight: 600; color: var(--gray-700); font-size: 0.8125rem;
  text-transform: uppercase; letter-spacing: 0.05em; font-family: var(--font-ui);
  border-bottom: 2px solid var(--gray-200);
}
.sig-table td {
  padding: 10px 16px; border-bottom: 1px solid var(--gray-100);
  color: var(--gray-600);
}
.sig-table tbody tr:hover { background: var(--primary-50); }
.sig-table .pattern-code {
  font-family: var(--font-mono); font-size: 0.8125rem;
  color: var(--primary-dark); background: var(--primary-50);
  padding: 2px 8px; border-radius: var(--radius-sm);
}

/* ── Stats charts ────────────────────────────────────── */
.charts-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
  gap: 24px;
}
.chart-card {
  background: var(--white); padding: 28px; border-radius: var(--radius-xl);
  border: 1px solid var(--gray-200);
}
.chart-card h3 {
  font-family: var(--font-heading); font-size: 1rem; font-weight: 600;
  color: var(--gray-900); margin-bottom: 20px;
  display: flex; align-items: center; gap: 8px;
}
.bar-chart { display: flex; flex-direction: column; gap: 10px; }
.bar-row { display: flex; align-items: center; gap: 12px; }
.bar-label {
  width: 100px; font-size: 0.8125rem; color: var(--gray-600);
  text-align: right; flex-shrink: 0;
}
.bar-track { flex: 1; height: 28px; background: var(--gray-100); border-radius: var(--radius-sm); overflow: hidden; }
.bar-fill {
  height: 100%; border-radius: var(--radius-sm);
  background: var(--gradient-primary); display: flex; align-items: center;
  padding-left: 10px; font-size: 0.75rem; font-weight: 600; color: white;
  font-family: var(--font-ui); transition: width 0.6s ease;
  min-width: fit-content;
}
.bar-fill.sev-high { background: linear-gradient(135deg, #dc3545, #e4606d); }
.bar-fill.sev-medium { background: linear-gradient(135deg, #fd7e14, #fda44d); }
.bar-fill.sev-low { background: linear-gradient(135deg, #ffc107, #ffd454); }

/* ── Top sources list ────────────────────────────────── */
.sources-list { display: flex; flex-direction: column; gap: 8px; }
.source-item {
  display: flex; align-items: center; gap: 12px; padding: 10px 14px;
  background: var(--gray-50); border-radius: var(--radius-md);
  border: 1px solid var(--gray-100);
}
.source-ip {
  font-family: var(--font-mono); font-size: 0.875rem; color: var(--gray-800);
  flex: 1;
}
.source-count {
  font-family: var(--font-ui); font-weight: 700; color: var(--primary-dark);
  font-size: 0.9375rem;
}
.source-bar {
  width: 120px; height: 6px; background: var(--gray-200); border-radius: 3px; overflow: hidden;
}
.source-bar-fill { height: 100%; border-radius: 3px; background: var(--gradient-primary); }

/* ── Modal ───────────────────────────────────────────── */
.modal-overlay {
  display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(15,23,42,0.6); backdrop-filter: blur(4px);
  z-index: 2000; align-items: center; justify-content: center;
}
.modal-overlay.show { display: flex; }
.modal {
  background: var(--white); border-radius: var(--radius-xl); padding: 32px;
  width: 90%; max-width: 600px; max-height: 80vh; overflow-y: auto;
  box-shadow: var(--shadow-xl);
}
.modal h3 {
  font-family: var(--font-heading); font-size: 1.25rem; font-weight: 700;
  color: var(--gray-900); margin-bottom: 20px;
}
.form-group { margin-bottom: 14px; }
.form-group label {
  display: block; font-size: 0.8125rem; font-weight: 600; color: var(--gray-600);
  margin-bottom: 4px; font-family: var(--font-ui);
}
.form-group input, .form-group select {
  width: 100%; padding: 10px 14px; border: 1px solid var(--gray-200);
  border-radius: var(--radius); font-size: 0.875rem; font-family: var(--font-body);
}
.form-group input:focus, .form-group select:focus {
  outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px var(--primary-50);
}
.form-actions { display: flex; gap: 10px; margin-top: 20px; justify-content: flex-end; }

/* ── Toast ───────────────────────────────────────────── */
.toast {
  position: fixed; bottom: 32px; right: 32px; z-index: 3000;
  padding: 14px 24px; border-radius: var(--radius-md);
  color: white; font-family: var(--font-ui); font-weight: 600; font-size: 0.875rem;
  box-shadow: var(--shadow-lg); animation: slideUp 0.3s ease;
  display: none;
}
.toast.show { display: block; }
.toast.success { background: var(--gradient-primary); }
.toast.error { background: linear-gradient(135deg, #dc3545, #e4606d); }

/* ── Loading spinner ─────────────────────────────────── */
.spinner {
  display: none; width: 32px; height: 32px; border: 3px solid var(--gray-200);
  border-top-color: var(--primary); border-radius: 50%; animation: spin 0.6s linear infinite;
  margin: 24px auto;
}
.spinner.show { display: block; }

/* ── Animations ──────────────────────────────────────── */
@keyframes fadeInUp { from { opacity: 0; transform: translateY(30px); } to { opacity: 1; transform: translateY(0); } }
@keyframes slideUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
@keyframes spin { to { transform: rotate(360deg); } }
.animate-in { animation: fadeInUp 0.5s ease both; }

/* ── Empty state ─────────────────────────────────────── */
.empty-state { text-align: center; padding: 60px 20px; color: var(--gray-400); }
.empty-state i { font-size: 3rem; margin-bottom: 16px; display: block; }
.empty-state p { font-size: 1rem; }

/* ── Responsive ──────────────────────────────────────── */
@media (max-width: 768px) {
  .hero h1 { font-size: 1.5rem; }
  .hero-stats { flex-direction: column; gap: 12px; align-items: center; }
  .nav-container { flex-wrap: wrap; height: auto; padding: 12px 16px; gap: 8px; }
  .nav-tabs { overflow-x: auto; width: 100%; order: 3; }
  .filter-bar { flex-direction: column; }
  .charts-grid { grid-template-columns: 1fr; }
  .detail-grid { grid-template-columns: 1fr; }
  .alert-table { font-size: 0.75rem; }
}
</style>
</head>
<body>

<!-- ═══════════════════════════════════════════════════════
     Navbar
     ═══════════════════════════════════════════════════════ -->
<nav class="navbar" id="navbar">
  <div class="nav-container">
    <a href="/" class="nav-brand">
      <i class="fa-solid fa-shield-halved"></i>
      <span>攻击行为监控</span>
    </a>
    <ul class="nav-tabs" id="navTabs">
      <li><button class="active" data-tab="alerts"><i class="fa-solid fa-bell"></i> 告警监控</button></li>
      <li><button data-tab="signatures"><i class="fa-solid fa-fingerprint"></i> 特征库</button></li>
      <li><button data-tab="stats"><i class="fa-solid fa-chart-pie"></i> 统计概览</button></li>
    </ul>
    <div class="nav-actions">
      <button class="btn btn-outline btn-sm" onclick="loadAll()" title="刷新数据">
        <i class="fa-solid fa-rotate"></i> 刷新
      </button>
      <button class="btn btn-primary btn-sm" onclick="reloadPipeline()" title="重新运行检测管线">
        <i class="fa-solid fa-play"></i> 重跑检测
      </button>
    </div>
  </div>
</nav>

<!-- ═══════════════════════════════════════════════════════
     Hero
     ═══════════════════════════════════════════════════════ -->
<section class="hero">
  <div class="hero-content">
    <h1>网络攻击行为检测系统</h1>
    <p class="hero-subtitle">融合特征匹配与异常行为分析 · 双引擎互补 · 行为聚合告警</p>
    <div class="hero-stats" id="heroStats">
      <div class="hero-stat"><i class="fa-solid fa-file-shield"></i><div><div class="hero-stat-val" id="heroAlerts">—</div><div class="hero-stat-label">行为告警</div></div></div>
      <div class="hero-stat"><i class="fa-solid fa-fingerprint"></i><div><div class="hero-stat-val" id="heroRules">—</div><div class="hero-stat-label">特征规则</div></div></div>
      <div class="hero-stat"><i class="fa-solid fa-cubes"></i><div><div class="hero-stat-val" id="heroModules">3</div><div class="hero-stat-label">检测引擎</div></div></div>
      <div class="hero-stat"><i class="fa-solid fa-circle-check"></i><div><div class="hero-stat-val">148</div><div class="hero-stat-label">测试通过</div></div></div>
    </div>
  </div>
</section>

<!-- ═══════════════════════════════════════════════════════
     Tab 1: 告警监控
     ═══════════════════════════════════════════════════════ -->
<section class="section tab-panel active" id="panel-alerts">
  <div class="container">
    <div class="section-header">
      <div class="section-tag"><i class="fa-solid fa-bell"></i> Alert Monitoring</div>
      <h2>告警监控面板</h2>
      <p class="section-desc">以攻击行为为粒度汇总展示，支持多维筛选与详情查看</p>
    </div>

    <!-- Stats cards -->
    <div class="stats-grid" id="alertStatsGrid"></div>

    <!-- Filter -->
    <div class="filter-bar">
      <select id="filterCategory"><option value="">全部类型</option></select>
      <select id="filterSeverity"><option value="">全部严重度</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
      <select id="filterDetector"><option value="">全部检测器</option><option value="signature">Signature</option><option value="bruteforce">Bruteforce</option><option value="anomaly">Anomaly</option></select>
      <input type="text" id="filterSearch" placeholder="搜索 IP / 描述 / 证据 ...">
      <span class="filter-count" id="filterCount"></span>
    </div>

    <!-- Table -->
    <div class="table-container">
      <div class="spinner" id="alertSpinner"></div>
      <div style="overflow-x:auto">
        <table class="alert-table">
          <thead>
            <tr>
              <th>严重度</th><th>类别</th><th>检测器</th><th>攻击源</th>
              <th>目标</th><th>端口</th><th>时间</th>
            </tr>
          </thead>
          <tbody id="alertTableBody"></tbody>
        </table>
      </div>
      <div class="empty-state" id="alertEmpty" style="display:none">
        <i class="fa-solid fa-shield"></i>
        <p>暂无告警数据 — 请先运行检测管线</p>
      </div>
    </div>

    <!-- Detail panel -->
    <div class="detail-panel" id="detailPanel">
      <h3 style="font-family:var(--font-heading);margin-bottom:16px;display:flex;align-items:center;gap:8px">
        <i class="fa-solid fa-circle-info" style="color:var(--primary)"></i> 告警详情
      </h3>
      <div class="detail-grid" id="detailGrid"></div>
    </div>
  </div>
</section>

<!-- ═══════════════════════════════════════════════════════
     Tab 2: 特征库管理
     ═══════════════════════════════════════════════════════ -->
<section class="section tab-panel" id="panel-signatures">
  <div class="container">
    <div class="section-header">
      <div class="section-tag"><i class="fa-solid fa-fingerprint"></i> Signature Rules</div>
      <h2>特征库管理</h2>
      <p class="section-desc">维护攻击特征规则库，支持增删改查</p>
    </div>

    <div class="filter-bar">
      <span class="filter-count" id="sigCount"></span>
      <button class="btn btn-primary btn-sm" onclick="showAddRuleModal()" style="margin-left:auto">
        <i class="fa-solid fa-plus"></i> 新增规则
      </button>
    </div>

    <div class="table-container">
      <div class="spinner" id="sigSpinner"></div>
      <div style="overflow-x:auto">
        <table class="sig-table">
          <thead>
            <tr><th>规则ID</th><th>攻击类型</th><th>匹配模式</th><th>特征串</th><th>协议</th><th>严重度</th><th>操作</th></tr>
          </thead>
          <tbody id="sigTableBody"></tbody>
        </table>
      </div>
    </div>
  </div>
</section>

<!-- ═══════════════════════════════════════════════════════
     Tab 3: 统计概览
     ═══════════════════════════════════════════════════════ -->
<section class="section tab-panel" id="panel-stats">
  <div class="container">
    <div class="section-header">
      <div class="section-tag"><i class="fa-solid fa-chart-pie"></i> Statistics</div>
      <h2>统计概览</h2>
      <p class="section-desc">告警分布、攻击源排名、检测器贡献</p>
    </div>

    <div class="stats-grid" id="statsGrid"></div>

    <div class="charts-grid">
      <div class="chart-card">
        <h3><i class="fa-solid fa-tags" style="color:var(--primary)"></i> 按攻击类别</h3>
        <div class="bar-chart" id="chartCategory"></div>
      </div>
      <div class="chart-card">
        <h3><i class="fa-solid fa-user-secret" style="color:var(--primary)"></i> Top 攻击源</h3>
        <div class="sources-list" id="chartSources"></div>
      </div>
      <div class="chart-card">
        <h3><i class="fa-solid fa-exclamation-triangle" style="color:var(--primary)"></i> 按严重程度</h3>
        <div class="bar-chart" id="chartSeverity"></div>
      </div>
      <div class="chart-card">
        <h3><i class="fa-solid fa-microchip" style="color:var(--primary)"></i> 按检测引擎</h3>
        <div class="bar-chart" id="chartDetector"></div>
      </div>
    </div>
  </div>
</section>

<!-- ═══════════════════════════════════════════════════════
     Modal: Add rule
     ═══════════════════════════════════════════════════════ -->
<div class="modal-overlay" id="ruleModal">
  <div class="modal">
    <h3>新增特征规则</h3>
    <div class="form-group"><label>攻击类型</label><input id="ruleCategory" placeholder="如 SQL注入 / XSS / Webshell"></div>
    <div class="form-group"><label>匹配模式</label><select id="ruleMode"><option value="literal">literal (子串匹配)</option><option value="regex">regex (正则)</option></select></div>
    <div class="form-group"><label>特征串</label><input id="rulePattern" placeholder="匹配内容，含 | 字符用 \x7C 转义"></div>
    <div class="form-group"><label>适用协议</label><input id="ruleProtocol" value="TCP" placeholder="TCP / UDP / *"></div>
    <div class="form-group"><label>严重程度</label><select id="ruleSeverity"><option value="high">high</option><option value="medium" selected>medium</option><option value="low">low</option></select></div>
    <div class="form-actions">
      <button class="btn btn-outline btn-sm" onclick="closeRuleModal()">取消</button>
      <button class="btn btn-primary btn-sm" onclick="addRule()"><i class="fa-solid fa-check"></i> 添加</button>
    </div>
  </div>
</div>

<!-- Toast -->
<div class="toast" id="toast"></div>

<script>
/* ═══════════════════════════════════════════════════════════════
   Application state
   ═══════════════════════════════════════════════════════════════ */
let alerts = [], signatures = [], stats = {};
let selectedAlertId = null;

/* ═══════════════════════════════════════════════════════════════
   Tab switching & Navbar
   ═══════════════════════════════════════════════════════════════ */
document.querySelectorAll('#navTabs button').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#navTabs button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.getElementById('panel-' + btn.dataset.tab).classList.add('active');
    if (btn.dataset.tab === 'alerts') renderAlerts();
    if (btn.dataset.tab === 'signatures') renderSignatures();
    if (btn.dataset.tab === 'stats') renderStats();
  });
});

window.addEventListener('scroll', () => {
  document.getElementById('navbar').classList.toggle('scrolled', window.scrollY > 10);
});

/* ═══════════════════════════════════════════════════════════════
   Data loading
   ═══════════════════════════════════════════════════════════════ */
async function loadAll() {
  await Promise.all([loadAlerts(), loadSignatures(), loadStats()]);
  renderAlerts(); renderSignatures(); renderStats();
}

async function loadAlerts() {
  try {
    const r = await fetch('/api/alerts'); alerts = await r.json();
    document.getElementById('heroAlerts').textContent = alerts.length;
  } catch(e) { console.error(e); }
}
async function loadSignatures() {
  try {
    const r = await fetch('/api/signatures'); signatures = await r.json();
    document.getElementById('heroRules').textContent = signatures.length;
  } catch(e) { console.error(e); }
}
async function loadStats() {
  try {
    const r = await fetch('/api/stats'); stats = await r.json();
  } catch(e) { console.error(e); }
}

async function reloadPipeline() {
  showToast('正在重新运行检测管线...', 'success');
  try {
    const r = await fetch('/api/reload', { method: 'POST' });
    const result = await r.json();
    showToast(`检测完成: ${result.merged_count} 条告警 (${result.packet_count} 条报文)`, 'success');
    await loadAll();
  } catch(e) { showToast('检测失败: ' + e, 'error'); }
}

/* ═══════════════════════════════════════════════════════════════
   Render: Alerts
   ═══════════════════════════════════════════════════════════════ */
function renderAlerts() {
  // Stats
  const cats = {}, sevs = {}, dets = {};
  alerts.forEach(a => { cats[a.category] = (cats[a.category]||0)+1; sevs[a.severity] = (sevs[a.severity]||0)+1; dets[a.detector] = (dets[a.detector]||0)+1; });
  document.getElementById('alertStatsGrid').innerHTML = [
    { icon: 'fa-bell', val: alerts.length, label: '告警总数' },
    { icon: 'fa-tags', val: Object.keys(cats).length, label: '攻击类别' },
    { icon: 'fa-user-secret', val: new Set(alerts.map(a=>a.src_ip)).size, label: '攻击源IP' },
    { icon: 'fa-link', val: new Set(alerts.filter(a=>a.behavior_id).map(a=>a.behavior_id)).size, label: '行为事件' },
  ].map(s => `<div class="stat-card animate-in"><div class="stat-icon"><i class="fa-solid ${s.icon}"></i></div><div class="stat-value">${s.val}</div><div class="stat-name">${s.label}</div></div>`).join('');

  // Populate filters
  const catSelect = document.getElementById('filterCategory');
  catSelect.innerHTML = '<option value="">全部类型</option>' + Object.keys(cats).sort().map(c => `<option value="${c}">${c}</option>`).join('');

  // Apply filters
  const fCat = document.getElementById('filterCategory').value;
  const fSev = document.getElementById('filterSeverity').value;
  const fDet = document.getElementById('filterDetector').value;
  const fSearch = document.getElementById('filterSearch').value.toLowerCase();
  const filtered = alerts.filter(a =>
    (!fCat || a.category === fCat) && (!fSev || a.severity === fSev) &&
    (!fDet || a.detector === fDet) &&
    (!fSearch || JSON.stringify(a).toLowerCase().includes(fSearch))
  );

  document.getElementById('filterCount').textContent = `显示 ${filtered.length} / ${alerts.length} 条`;

  // Table
  const tbody = document.getElementById('alertTableBody');
  if (filtered.length === 0) {
    tbody.innerHTML = ''; document.getElementById('alertEmpty').style.display = 'block';
  } else {
    document.getElementById('alertEmpty').style.display = 'none';
    tbody.innerHTML = filtered.map(a => `
      <tr class="${a.alert_id === selectedAlertId ? 'selected' : ''}" onclick="showDetail('${a.alert_id}')">
        <td><span class="badge badge-${a.severity}">${a.severity.toUpperCase()}</span></td>
        <td style="font-weight:600;color:var(--gray-800)">${a.category}</td>
        <td><span class="badge badge-${a.detector}">${a.detector}</span></td>
        <td><code style="font-size:0.8125rem">${a.src_ip}</code></td>
        <td><code style="font-size:0.8125rem">${a.dst_ip||'—'}</code></td>
        <td>${a.dst_port||'—'}</td>
        <td style="font-size:0.8125rem;color:var(--gray-500)">${(a.timestamp||'').substring(11,19)}</td>
      </tr>`).join('');
  }

  // Re-show detail if selected still in filtered
  if (selectedAlertId && !filtered.find(a => a.alert_id === selectedAlertId)) {
    document.getElementById('detailPanel').classList.remove('show');
    selectedAlertId = null;
  }
}
document.getElementById('filterCategory').addEventListener('change', renderAlerts);
document.getElementById('filterSeverity').addEventListener('change', renderAlerts);
document.getElementById('filterDetector').addEventListener('change', renderAlerts);
document.getElementById('filterSearch').addEventListener('input', renderAlerts);

function showDetail(aid) {
  const a = alerts.find(x => x.alert_id === aid);
  if (!a) return;
  selectedAlertId = aid;
  renderAlerts();

  const panel = document.getElementById('detailPanel');
  panel.classList.add('show');
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  document.getElementById('detailGrid').innerHTML = `
    <div class="detail-item"><span class="detail-label">Alert ID</span><span class="detail-value" style="font-family:var(--font-mono);font-size:0.8125rem">${a.alert_id}</span></div>
    <div class="detail-item"><span class="detail-label">Behavior ID</span><span class="detail-value" style="font-family:var(--font-mono);font-size:0.8125rem">${a.behavior_id||'—'}</span></div>
    <div class="detail-item"><span class="detail-label">检测器</span><span class="detail-value"><span class="badge badge-${a.detector}">${a.detector}</span></span></div>
    <div class="detail-item"><span class="detail-label">类别</span><span class="detail-value" style="font-weight:600">${a.category}</span></div>
    <div class="detail-item"><span class="detail-label">严重度</span><span class="detail-value"><span class="badge badge-${a.severity}">${a.severity.toUpperCase()}</span></span></div>
    <div class="detail-item"><span class="detail-label">时间</span><span class="detail-value">${a.timestamp||'—'}</span></div>
    <div class="detail-item"><span class="detail-label">攻击源</span><span class="detail-value"><code>${a.src_ip}:${a.src_port||'—'}</code></span></div>
    <div class="detail-item"><span class="detail-label">目标</span><span class="detail-value"><code>${a.dst_ip||'—'}:${a.dst_port||'—'}</code> ${a.dst_network ? '('+a.dst_network+')' : ''}</span></div>
    <div class="detail-value desc"><strong>📝 行为描述</strong><br>${a.description||'—'}</div>
    <div class="evidence-block"><strong>🔍 证据</strong>\n${a.evidence||'—'}</div>
  `;
}

/* ═══════════════════════════════════════════════════════════════
   Render: Signatures
   ═══════════════════════════════════════════════════════════════ */
function renderSignatures() {
  document.getElementById('sigCount').textContent = `共 ${signatures.length} 条规则`;
  document.getElementById('sigTableBody').innerHTML = signatures.map(s => `
    <tr>
      <td><code style="color:var(--primary-dark);font-weight:600">${s.rule_id}</code></td>
      <td style="font-weight:600;color:var(--gray-800)">${s.category}</td>
      <td><span class="badge" style="background:${s.match_mode==='regex'?'#f3e5f5':'#e8f5e9'};color:${s.match_mode==='regex'?'#7b1fa2':'#2e7d32'}">${s.match_mode}</span></td>
      <td><span class="pattern-code">${escHtml(s.pattern||'')}</span></td>
      <td>${s.protocol||'*'}</td>
      <td><span class="badge badge-${s.severity}">${(s.severity||'medium').toUpperCase()}</span></td>
      <td><button class="btn btn-danger btn-sm" onclick="deleteRule('${s.rule_id}')"><i class="fa-solid fa-trash"></i></button></td>
    </tr>`).join('');
}

async function addRule() {
  const rule = {
    category: document.getElementById('ruleCategory').value,
    match_mode: document.getElementById('ruleMode').value,
    pattern: document.getElementById('rulePattern').value,
    protocol: document.getElementById('ruleProtocol').value,
    severity: document.getElementById('ruleSeverity').value,
  };
  if (!rule.category || !rule.pattern) { showToast('请填写攻击类型和特征串', 'error'); return; }
  try {
    const r = await fetch('/api/signatures/add', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(rule) });
    const data = await r.json();
    if (data.status === 'ok') { showToast('规则已添加', 'success'); closeRuleModal(); await loadSignatures(); renderSignatures(); }
    else { showToast(data.message, 'error'); }
  } catch(e) { showToast('添加失败: ' + e, 'error'); }
}

async function deleteRule(rid) {
  if (!confirm(`确认删除规则 ${rid}？`)) return;
  try {
    await fetch('/api/signatures/delete', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({rule_id: rid}) });
    showToast(`已删除 ${rid}`, 'success');
    await loadSignatures(); renderSignatures();
  } catch(e) { showToast('删除失败: ' + e, 'error'); }
}

function showAddRuleModal() { document.getElementById('ruleModal').classList.add('show'); }
function closeRuleModal() { document.getElementById('ruleModal').classList.remove('show'); }
document.getElementById('ruleModal').addEventListener('click', e => { if (e.target === e.currentTarget) closeRuleModal(); });

/* ═══════════════════════════════════════════════════════════════
   Render: Stats
   ═══════════════════════════════════════════════════════════════ */
function renderStats() {
  // Summary cards
  document.getElementById('statsGrid').innerHTML = [
    { icon: 'fa-bell', val: stats.total||0, label: '告警总数' },
    { icon: 'fa-link', val: stats.behaviors||0, label: '独立行为事件' },
    { icon: 'fa-tags', val: Object.keys(stats.by_category||{}).length, label: '攻击类别' },
    { icon: 'fa-user-secret', val: (stats.top_sources||[]).length, label: '活跃攻击源' },
  ].map(s => `<div class="stat-card animate-in"><div class="stat-icon"><i class="fa-solid ${s.icon}"></i></div><div class="stat-value">${s.val}</div><div class="stat-name">${s.label}</div></div>`).join('');

  // Category chart
  const cats = stats.by_category || {};
  const catMax = Math.max(1, ...Object.values(cats));
  document.getElementById('chartCategory').innerHTML = Object.entries(cats).sort((a,b)=>b[1]-a[1]).map(([k,v]) => `
    <div class="bar-row"><span class="bar-label">${k}</span><div class="bar-track"><div class="bar-fill" style="width:${Math.max(8, v/catMax*100)}%">${v}</div></div></div>
  `).join('') || '<div class="empty-state"><p>暂无数据</p></div>';

  // Severity chart
  const sevs = stats.by_severity || {};
  const sevMax = Math.max(1, ...Object.values(sevs));
  document.getElementById('chartSeverity').innerHTML = Object.entries(sevs).map(([k,v]) => `
    <div class="bar-row"><span class="bar-label">${k.toUpperCase()}</span><div class="bar-track"><div class="bar-fill sev-${k}" style="width:${Math.max(8, v/sevMax*100)}%">${v}</div></div></div>
  `).join('') || '<div class="empty-state"><p>暂无数据</p></div>';

  // Detector chart
  const dets = stats.by_detector || {};
  const detMax = Math.max(1, ...Object.values(dets));
  document.getElementById('chartDetector').innerHTML = Object.entries(dets).map(([k,v]) => `
    <div class="bar-row"><span class="bar-label">${k}</span><div class="bar-track"><div class="bar-fill" style="width:${Math.max(8, v/detMax*100)}%">${v}</div></div></div>
  `).join('') || '<div class="empty-state"><p>暂无数据</p></div>';

  // Top sources
  const sources = stats.top_sources || [];
  const srcMax = Math.max(1, ...sources.map(s=>s.count));
  document.getElementById('chartSources').innerHTML = sources.map(s => `
    <div class="source-item">
      <code class="source-ip">${s.ip}</code>
      <span class="source-count">${s.count}</span>
      <div class="source-bar"><div class="source-bar-fill" style="width:${s.count/srcMax*100}%"></div></div>
    </div>
  `).join('') || '<div class="empty-state"><p>暂无数据</p></div>';
}

/* ═══════════════════════════════════════════════════════════════
   Utilities
   ═══════════════════════════════════════════════════════════════ */
function escHtml(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function showToast(msg, type) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.className = 'toast ' + type + ' show';
  setTimeout(() => t.classList.remove('show'), 3000);
}

/* ═══════════════════════════════════════════════════════════════
   Init
   ═══════════════════════════════════════════════════════════════ */
loadAll();
</script>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="Web 攻击行为监控面板")
    parser.add_argument("--port", type=int, default=8099, help="监听端口 (默认 8099)")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址 (默认 127.0.0.1)")
    parser.add_argument("--reload", action="store_true", help="启动时重新运行检测管线")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="[web-gui] %(levelname)s %(asctime)s %(message)s",
    )

    if args.reload:
        logger.info("重新运行检测管线...")
        result = run_detection_pipeline()
        logger.info("检测完成: %d 条告警", result["merged_count"])

    server = HTTPServer((args.host, args.port), WebGUIHandler)
    url = f"http://{args.host}:{args.port}"
    logger.info("Web 监控面板已启动: %s", url)
    logger.info("按 Ctrl+C 停止服务")
    print(f"\n  [Web GUI] 攻击行为监控面板 -> {url}\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务已停止")
        server.shutdown()


if __name__ == "__main__":
    main()
