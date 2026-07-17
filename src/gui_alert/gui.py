"""
图形界面模块 —— 韩宇飞

攻击行为监控面板 + 特征库管理 + 统计概览。
使用 tkinter + ttk（Python 标准库）实现，零额外依赖。
"""

from __future__ import annotations

import json
import logging
import tkinter as tk
from collections import Counter
from pathlib import Path
from tkinter import messagebox, ttk

from .aggregator import aggregate

logger = logging.getLogger(__name__)

# ── 路径常量 ──────────────────────────────────────────────────
RESULTS_DIR = Path(__file__).resolve().parent.parent.parent / "results"
SIGNATURES_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "signatures.txt"
MERGED_ALERTS = RESULTS_DIR / "merged_alerts.json"


# ── 主题配色 ──────────────────────────────────────────────────
COLORS = {
    "high": "#dc3545",     # 红色
    "medium": "#fd7e14",   # 橙色
    "low": "#ffc107",      # 黄色
    "bg": "#f8f9fa",
    "header_bg": "#343a40",
    "header_fg": "#ffffff",
}


# ═══════════════════════════════════════════════════════════════
# 告警监控页签
# ═══════════════════════════════════════════════════════════════

class AlertMonitorFrame(ttk.Frame):
    """告警监控面板：按行为聚合展示，支持筛选与详情。"""

    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)
        self._alerts: list[dict] = []
        self._filtered: list[dict] = []
        self._build_ui()

    # ── UI 构建 ─────────────────────────────────────────────

    def _build_ui(self) -> None:
        # 顶部筛选栏
        filter_bar = ttk.Frame(self)
        filter_bar.pack(fill=tk.X, padx=8, pady=(8, 4))

        ttk.Label(filter_bar, text="检测器:").pack(side=tk.LEFT, padx=(0, 4))
        self._detector_var = tk.StringVar(value="全部")
        detector_cb = ttk.Combobox(
            filter_bar, textvariable=self._detector_var,
            values=["全部", "signature", "bruteforce", "anomaly"],
            state="readonly", width=12,
        )
        detector_cb.pack(side=tk.LEFT, padx=(0, 12))
        detector_cb.bind("<<ComboboxSelected>>", lambda e: self._apply_filter())

        ttk.Label(filter_bar, text="严重度:").pack(side=tk.LEFT, padx=(0, 4))
        self._sev_vars: dict[str, tk.BooleanVar] = {}
        for sev in ("high", "medium", "low"):
            var = tk.BooleanVar(value=True)
            self._sev_vars[sev] = var
            cb = ttk.Checkbutton(
                filter_bar, text=sev, variable=var,
                command=self._apply_filter,
            )
            cb.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(filter_bar, text="搜索:").pack(side=tk.LEFT, padx=(8, 4))
        self._search_var = tk.StringVar()
        search_entry = ttk.Entry(filter_bar, textvariable=self._search_var, width=24)
        search_entry.pack(side=tk.LEFT, padx=(0, 12))
        search_entry.bind("<Return>", lambda e: self._apply_filter())
        search_entry.bind("<KeyRelease>", lambda e: self._apply_filter())

        ttk.Button(filter_bar, text="🔄 刷新", command=self.refresh).pack(side=tk.RIGHT)

        # 主内容区：左侧表格 + 右侧详情
        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        # 左侧表格
        tree_frame = ttk.Frame(paned)
        paned.add(tree_frame, weight=3)

        columns = ("behavior_id", "detector", "category", "src_ip", "dst_ip", "severity", "timestamp")
        self._tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings",
            selectmode="browse",
        )
        self._tree.heading("behavior_id", text="行为ID")
        self._tree.heading("detector", text="检测器")
        self._tree.heading("category", text="攻击类型")
        self._tree.heading("src_ip", text="攻击源IP")
        self._tree.heading("dst_ip", text="目标IP")
        self._tree.heading("severity", text="严重度")
        self._tree.heading("timestamp", text="时间")

        self._tree.column("behavior_id", width=100, minwidth=80)
        self._tree.column("detector", width=70, minwidth=60)
        self._tree.column("category", width=120, minwidth=80)
        self._tree.column("src_ip", width=110, minwidth=80)
        self._tree.column("dst_ip", width=110, minwidth=80)
        self._tree.column("severity", width=60, minwidth=50)
        self._tree.column("timestamp", width=140, minwidth=100)

        scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=scroll_y.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        self._tree.bind("<<TreeviewSelect>>", self._on_select)
        # 行为分组标签色
        self._tree.tag_configure("high", foreground=COLORS["high"])
        self._tree.tag_configure("medium", foreground=COLORS["medium"])
        self._tree.tag_configure("low", foreground=COLORS["low"])
        self._tree.tag_configure("behavior_header", background="#e9ecef", font=("", 9, "bold"))

        # 右侧详情面板
        detail_frame = ttk.LabelFrame(paned, text="告警详情")
        paned.add(detail_frame, weight=2)

        self._detail_text = tk.Text(
            detail_frame, wrap=tk.WORD, font=("Consolas", 9),
            state=tk.DISABLED, borderwidth=0,
        )
        detail_scroll = ttk.Scrollbar(detail_frame, orient=tk.VERTICAL, command=self._detail_text.yview)
        self._detail_text.configure(yscrollcommand=detail_scroll.set)
        self._detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        detail_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # 底部状态栏
        self._status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(self, textvariable=self._status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    # ── 数据加载 ─────────────────────────────────────────────

    def load_alerts(self, alert_files: list[str] | None = None) -> None:
        """加载告警数据并刷新显示。"""
        if alert_files is None:
            alert_files = _scan_result_files()

        if not alert_files:
            self._alerts = []
            self._status_var.set("未找到告警文件，请先运行检测模块")
        else:
            self._alerts = aggregate(alert_files)
            behaviors = len({a.get("behavior_id") for a in self._alerts})
            self._status_var.set(
                f"已加载 {len(self._alerts)} 条告警, "
                f"{behaviors} 个攻击行为事件"
                f"  ← {', '.join(Path(f).name for f in alert_files)}"
            )
        self._apply_filter()

    def refresh(self) -> None:
        """重新从文件加载（刷新按钮回调）。"""
        self.load_alerts()

    # ── 筛选与展示 ─────────────────────────────────────────────

    def _apply_filter(self) -> None:
        detector = self._detector_var.get()
        active_sev = {s for s, v in self._sev_vars.items() if v.get()}
        search = self._search_var.get().strip().lower()

        self._filtered = []
        for a in self._alerts:
            if detector != "全部" and a.get("detector") != detector:
                continue
            if a.get("severity") not in active_sev:
                continue
            if search:
                searchable = " ".join(str(v) for v in a.values() if isinstance(v, str))
                if search not in searchable.lower():
                    continue
            self._filtered.append(a)

        self._render_tree()

    def _render_tree(self) -> None:
        for item in self._tree.get_children():
            self._tree.delete(item)

        # 按 behavior_id 分组
        groups: dict[str, list[dict]] = {}
        for a in self._filtered:
            bid = a.get("behavior_id") or a.get("alert_id", "?")
            groups.setdefault(bid, []).append(a)

        # 按每组最早时间排序
        sorted_groups = sorted(
            groups.items(),
            key=lambda kv: min(a.get("timestamp", "") for a in kv[1]),
        )

        for bid, alerts in sorted_groups:
            # 行为分组头行
            count = len(alerts)
            first = alerts[0]
            header_text = (
                f"行为 {bid[:8]}… | {first.get('category','')} | "
                f"{first.get('src_ip','')} → {first.get('dst_ip','')} | "
                f"共 {count} 条告警"
            )
            header_iid = self._tree.insert(
                "", tk.END, values=(header_text, "", "", "", "", "", ""),
                tags=("behavior_header",),
            )
            # 组内逐条
            for a in alerts:
                sev = a.get("severity", "low")
                ts = a.get("timestamp", "")[:19]
                self._tree.insert(
                    header_iid, tk.END,
                    values=(
                        a.get("behavior_id", "")[:8] + "…",
                        a.get("detector", ""),
                        a.get("category", ""),
                        a.get("src_ip", ""),
                        a.get("dst_ip", ""),
                        sev,
                        ts,
                    ),
                    tags=(sev,),
                )

    def _on_select(self, event: object) -> None:
        selection = self._tree.selection()
        if not selection:
            return
        item = selection[0]
        values = self._tree.item(item, "values")
        if not values or not values[0]:
            return

        # 查找完整告警记录
        bid_prefix = values[0].replace("…", "")
        detail = None
        for a in self._filtered:
            if (a.get("behavior_id") or "").startswith(bid_prefix):
                detail = a
                break

        if detail is None and values[1]:
            for a in self._filtered:
                if a.get("detector") == values[1] and a.get("src_ip") == values[3]:
                    detail = a
                    break

        self._show_detail(detail)

    def _show_detail(self, alert: dict | None) -> None:
        self._detail_text.configure(state=tk.NORMAL)
        self._detail_text.delete("1.0", tk.END)

        if alert is None:
            self._detail_text.insert(tk.END, "（请选择一条告警）")
            self._detail_text.configure(state=tk.DISABLED)
            return

        formatted = json.dumps(alert, ensure_ascii=False, indent=2)
        self._detail_text.insert(tk.END, formatted)
        self._detail_text.configure(state=tk.DISABLED)


# ═══════════════════════════════════════════════════════════════
# 特征库管理页签
# ═══════════════════════════════════════════════════════════════

class SignatureManagerFrame(ttk.Frame):
    """攻击特征库管理：增删改查 + 导入导出。"""

    COLUMNS = ("rule_id", "category", "match_mode", "pattern", "protocol", "severity")
    FIELD_LABELS = {
        "rule_id": "规则ID",
        "category": "攻击类型",
        "match_mode": "匹配模式",
        "pattern": "特征串",
        "protocol": "适用协议",
        "severity": "严重程度",
    }

    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)
        self._rules: list[dict] = []
        self._build_ui()
        self.load_signatures()

    # ── UI 构建 ─────────────────────────────────────────────

    def _build_ui(self) -> None:
        # 工具栏
        toolbar = ttk.Frame(self)
        toolbar.pack(fill=tk.X, padx=8, pady=(8, 4))

        ttk.Button(toolbar, text="➕ 新增", command=self._add_rule).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(toolbar, text="✏️ 编辑", command=self._edit_rule).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(toolbar, text="🗑 删除", command=self._delete_rule).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Button(toolbar, text="📥 导入", command=self._import_file).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(toolbar, text="📤 导出", command=self._export_file).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(toolbar, text="💾 保存到文件", command=self.save_signatures).pack(side=tk.RIGHT)

        self._status_var = tk.StringVar(value="")
        ttk.Label(toolbar, textvariable=self._status_var).pack(side=tk.RIGHT, padx=(0, 12))

        # 表格
        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        self._tree = ttk.Treeview(
            tree_frame, columns=self.COLUMNS, show="headings", selectmode="browse",
        )
        for col in self.COLUMNS:
            self._tree.heading(col, text=self.FIELD_LABELS.get(col, col))
        self._tree.column("rule_id", width=70, minwidth=60)
        self._tree.column("category", width=100, minwidth=70)
        self._tree.column("match_mode", width=60, minwidth=50)
        self._tree.column("pattern", width=240, minwidth=100)
        self._tree.column("protocol", width=60, minwidth=50)
        self._tree.column("severity", width=60, minwidth=50)

        scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=scroll_y.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        self._tree.tag_configure("high", foreground=COLORS["high"])
        self._tree.tag_configure("medium", foreground=COLORS["medium"])
        self._tree.tag_configure("low", foreground=COLORS["low"])

    # ── 数据加载 ─────────────────────────────────────────────

    def load_signatures(self, filepath: str | None = None) -> None:
        """从文件加载特征库。"""
        path = Path(filepath) if filepath else SIGNATURES_PATH
        if not path.exists():
            self._rules = []
            self._status_var.set(f"特征库文件不存在: {path}")
            self._render_tree()
            return
        self._rules = _parse_signatures_file(path)
        self._render_tree()
        self._status_var.set(f"已加载 {len(self._rules)} 条规则 ← {path.name}")

    def save_signatures(self, filepath: str | None = None) -> None:
        """将当前规则保存到特征库文件。"""
        path = Path(filepath) if filepath else SIGNATURES_PATH
        lines = [
            "# 攻击特征库配置文件",
            "# 格式: 规则ID | 攻击类型 | 匹配模式 | 特征串 | 适用协议 | 严重程度",
            "#",
        ]
        for r in self._rules:
            lines.append(
                f"{r['rule_id']} | {r['category']} | {r['match_mode']} | "
                f"{r['pattern']} | {r['protocol']} | {r['severity']}"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self._status_var.set(f"已保存 {len(self._rules)} 条规则 → {path.name}")
        logger.info("特征库已保存: %s (%d 条)", path, len(self._rules))

    # ── 表格渲染 ─────────────────────────────────────────────

    def _render_tree(self) -> None:
        for item in self._tree.get_children():
            self._tree.delete(item)
        for r in self._rules:
            self._tree.insert(
                "", tk.END,
                values=tuple(r.get(c, "") for c in self.COLUMNS),
                tags=(r.get("severity", "low"),),
            )

    # ── CRUD 操作 ─────────────────────────────────────────────

    def _add_rule(self) -> None:
        dialog = _RuleDialog(self, title="新增规则")
        self.wait_window(dialog)
        if dialog.result:
            self._rules.append(dialog.result)
            self._render_tree()
            self._status_var.set(f"已新增规则 {dialog.result['rule_id']}（尚未保存到文件）")

    def _edit_rule(self) -> None:
        selection = self._tree.selection()
        if not selection:
            messagebox.showwarning("提示", "请先选择一条规则")
            return
        idx = self._tree.index(selection[0])
        dialog = _RuleDialog(self, title="编辑规则", rule=self._rules[idx])
        self.wait_window(dialog)
        if dialog.result:
            self._rules[idx] = dialog.result
            self._render_tree()
            self._status_var.set(f"已修改规则 {dialog.result['rule_id']}（尚未保存到文件）")

    def _delete_rule(self) -> None:
        selection = self._tree.selection()
        if not selection:
            messagebox.showwarning("提示", "请先选择一条规则")
            return
        idx = self._tree.index(selection[0])
        rule = self._rules[idx]
        if messagebox.askyesno("确认删除", f"确定删除规则 {rule['rule_id']}？"):
            self._rules.pop(idx)
            self._render_tree()
            self._status_var.set(f"已删除规则 {rule['rule_id']}（尚未保存到文件）")

    def _import_file(self) -> None:
        from tkinter import filedialog
        filepath = filedialog.askopenfilename(
            title="导入特征库",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
        )
        if filepath:
            imported = _parse_signatures_file(Path(filepath))
            self._rules = imported
            self._render_tree()
            self._status_var.set(f"已导入 {len(imported)} 条规则 ← {Path(filepath).name}")

    def _export_file(self) -> None:
        from tkinter import filedialog
        filepath = filedialog.asksaveasfilename(
            title="导出特征库",
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt")],
        )
        if filepath:
            self.save_signatures(filepath)


# ── 规则编辑弹窗 ─────────────────────────────────────────────

class _RuleDialog(tk.Toplevel):
    """新增/编辑规则的弹窗。"""

    def __init__(self, parent: tk.Widget, title: str = "规则", rule: dict | None = None) -> None:
        super().__init__(parent)
        self.title(title)
        self.result: dict | None = None
        self._entries: dict[str, ttk.Entry | ttk.Combobox] = {}

        fields = [
            ("rule_id", "规则ID", None),
            ("category", "攻击类型", None),
            ("match_mode", "匹配模式", ["literal", "regex"]),
            ("pattern", "特征串", None),
            ("protocol", "适用协议", ["*", "HTTP", "TCP", "TCP/HTTP"]),
            ("severity", "严重程度", ["low", "medium", "high"]),
        ]

        for i, (key, label, choices) in enumerate(fields):
            ttk.Label(self, text=label + ":").grid(row=i, column=0, sticky=tk.W, padx=8, pady=4)
            if choices:
                var = tk.StringVar(value=(rule or {}).get(key, choices[0]))
                widget = ttk.Combobox(self, textvariable=var, values=choices, state="readonly", width=28)
            else:
                var = tk.StringVar(value=(rule or {}).get(key, ""))
                widget = ttk.Entry(self, textvariable=var, width=30)
            widget.grid(row=i, column=1, padx=8, pady=4)
            self._entries[key] = widget

        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=len(fields), column=0, columnspan=2, pady=12)
        ttk.Button(btn_frame, text="确认", command=self._on_confirm).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="取消", command=self.destroy).pack(side=tk.LEFT, padx=4)

        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)

    def _on_confirm(self) -> None:
        rule = {}
        for key, widget in self._entries.items():
            val = widget.get().strip()
            if not val and key != "protocol":
                messagebox.showwarning("提示", f"字段 '{key}' 不能为空")
                return
            rule[key] = val
        self.result = rule
        self.destroy()


# ═══════════════════════════════════════════════════════════════
# 统计概览页签
# ═══════════════════════════════════════════════════════════════

class StatisticsFrame(ttk.Frame):
    """告警统计概览：类型分布 + 严重度分布 + 简单柱状图。"""

    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)
        self._canvas: tk.Canvas | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        self._summary_var = tk.StringVar(value="尚未加载数据")
        ttk.Label(self, textvariable=self._summary_var, font=("", 11)).pack(pady=(12, 4))

        self._canvas = tk.Canvas(self, bg="white", height=260)
        self._canvas.pack(fill=tk.BOTH, expand=True, padx=12, pady=(4, 12))

    def load_stats(self, alerts: list[dict]) -> None:
        """根据告警列表渲染统计图表。"""
        if not alerts:
            self._summary_var.set("暂无告警数据")
            self._canvas.delete("all")
            return

        behaviors = len({a.get("behavior_id") for a in alerts})
        self._summary_var.set(
            f"告警总数: {len(alerts)} | 攻击行为事件: {behaviors} | "
            f"涉及攻击源IP: {len({a.get('src_ip') for a in alerts})}"
        )
        self._draw_chart(alerts)

    def _draw_chart(self, alerts: list[dict]) -> None:
        c = self._canvas
        c.delete("all")
        w = c.winfo_width() or 600
        h = c.winfo_height() or 260

        # 告警类型分布 — 水平柱状图
        cats = Counter(a.get("category", "未知") for a in alerts)
        sevs = Counter(a.get("severity", "low") for a in alerts)

        # 左侧：类型分布柱状图
        left_margin = 120
        bar_area_w = (w - left_margin - 60) // 2
        chart_h = h - 60

        if cats:
            max_count = max(cats.values())
            bar_h = min(24, chart_h // max(len(cats), 1))
            y = 30
            c.create_text(left_margin // 2, 16, text="攻击类型分布", font=("", 9, "bold"))
            for i, (cat, count) in enumerate(cats.most_common(10)):
                bar_y = y + i * (bar_h + 4)
                bar_w = (count / max_count) * bar_area_w if max_count > 0 else 0
                x1 = left_margin
                x2 = left_margin + bar_w
                c.create_rectangle(x1, bar_y, x2, bar_y + bar_h, fill="#4e73df", outline="")
                c.create_text(x2 + 4, bar_y + bar_h // 2, text=str(count), anchor=tk.W, font=("", 8))
                c.create_text(left_margin - 6, bar_y + bar_h // 2, text=cat[:12], anchor=tk.E, font=("", 8))

        # 右侧：严重度分布柱状图
        right_start = left_margin + bar_area_w + 40
        if sevs:
            sev_order = ["high", "medium", "low"]
            sev_colors = {"high": COLORS["high"], "medium": COLORS["medium"], "low": COLORS["low"]}
            bar_w = 36
            gap = 20
            max_sev = max(sevs.values()) if sevs else 1
            c.create_text(right_start + 80, 16, text="严重度分布", font=("", 9, "bold"))
            for i, sev in enumerate(sev_order):
                count = sevs.get(sev, 0)
                bar_h_sev = (count / max_sev) * (chart_h - 40) if max_sev > 0 else 0
                x = right_start + i * (bar_w + gap)
                y_bottom = chart_h
                y_top = y_bottom - bar_h_sev
                c.create_rectangle(x, y_top, x + bar_w, y_bottom, fill=sev_colors.get(sev, "#888"), outline="")
                c.create_text(x + bar_w // 2, y_bottom + 14, text=sev, font=("", 8))
                c.create_text(x + bar_w // 2, y_top - 10, text=str(count), font=("", 9, "bold"))


# ═══════════════════════════════════════════════════════════════
# 主窗口
# ═══════════════════════════════════════════════════════════════

class AttackMonitorApp:
    """攻击行为监控系统主窗口。"""

    def __init__(self, root: tk.Tk, alert_files: list[str] | None = None) -> None:
        self.root = root
        root.title("网络攻击行为监控系统")
        root.geometry("1100x680")
        root.minsize(900, 500)

        # 页签容器
        notebook = ttk.Notebook(root)
        notebook.pack(fill=tk.BOTH, expand=True)

        # 页签 1: 告警监控
        self._alert_frame = AlertMonitorFrame(notebook)
        notebook.add(self._alert_frame, text=" 告警监控 ")

        # 页签 2: 特征库管理
        self._sig_frame = SignatureManagerFrame(notebook)
        notebook.add(self._sig_frame, text=" 特征库管理 ")

        # 页签 3: 统计概览
        self._stats_frame = StatisticsFrame(notebook)
        notebook.add(self._stats_frame, text=" 统计概览 ")

        # 切换页签到统计时自动刷新
        notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        # 加载数据
        self._alert_frame.load_alerts(alert_files)
        self._refresh_stats()

        # 定时自动刷新 (每 30 秒)
        self._auto_refresh()

    def _on_tab_changed(self, event: object) -> None:
        self._refresh_stats()

    def _refresh_stats(self) -> None:
        self._stats_frame.load_stats(self._alert_frame._alerts)

    def _auto_refresh(self) -> None:
        self._root = self.root
        self._root.after(30_000, self._auto_refresh)
        self._alert_frame.refresh()
        self._refresh_stats()


# ═══════════════════════════════════════════════════════════════
# 辅助函数
# ═══════════════════════════════════════════════════════════════

def _scan_result_files() -> list[str]:
    """扫描 results/ 目录下的告警 JSON 文件。"""
    if not RESULTS_DIR.exists():
        return []
    json_files = sorted(RESULTS_DIR.glob("*_alerts.json"))
    return [str(f) for f in json_files]


def _parse_signatures_file(path: Path) -> list[dict]:
    """解析特征库配置文件为规则列表。"""
    rules: list[dict] = []
    if not path.exists():
        return rules
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 6:
            continue
        rules.append({
            "rule_id": parts[0],
            "category": parts[1],
            "match_mode": parts[2],
            "pattern": parts[3],
            "protocol": parts[4],
            "severity": parts[5],
        })
    return rules


# ═══════════════════════════════════════════════════════════════
# 入口
# ═══════════════════════════════════════════════════════════════

def launch_gui(alert_files: list[str] | None = None) -> None:
    """
    启动图形界面。

    Args:
        alert_files: 告警文件路径列表，为 None 时自动扫描 results/ 目录
    """
    root = tk.Tk()
    _app = AttackMonitorApp(root, alert_files)
    root.mainloop()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="[%(name)s] %(levelname)s %(asctime)s %(message)s",
    )
    launch_gui()
