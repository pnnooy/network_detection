"""
特征匹配算法模块 —— 曾子恒

对报文 payload 执行攻击特征匹配。当前为 baseline 实现（逐条规则
子串/正则匹配）；AC 自动机 / KMP 等高效多模式匹配是待办加分项，尚未实现。
"""

import argparse
import json
import logging
import re
import uuid
from datetime import datetime
from pathlib import Path

from .signature_db import load_signatures

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
_AGGREGATION_WINDOW_SEC = 60


def detect(packets: list[dict], signatures: list[dict] | None = None) -> list[dict]:
    """
    对报文列表执行特征匹配检测。

    先逐包匹配特征规则（一个包最多命中一条规则），再将同一
    (src_ip, dst_ip, category) 在 60 秒窗口内的命中合并为一条行为告警。

    Args:
        packets:    符合"报文记录格式"的列表
        signatures: 特征规则列表，为 None 时自动从配置文件加载

    Returns:
        符合"统一告警格式"的列表（无告警时返回空列表）
    """
    if signatures is None:
        signatures = load_signatures()

    hits = _collect_hits(packets, signatures)
    alerts = _aggregate_hits(hits)

    logger.info("特征匹配完成: 扫描 %d 条报文, 命中 %d 次, 聚合为 %d 条行为告警",
                len(packets), len(hits), len(alerts))
    return alerts


def _match_signature(payload: str, protocol: str, signatures: list[dict]):
    """对单个报文的 payload 找第一条命中的规则（一个包最多命中一条）。"""
    for sig in signatures:
        sig_proto = sig.get("protocol", "*")
        if sig_proto != "*" and protocol.upper() not in sig_proto.upper().split("/"):
            continue

        pattern = sig.get("pattern", "")
        match_mode = sig.get("match_mode", "literal")

        if match_mode == "literal":
            # 子串匹配，大小写不敏感
            if pattern.lower() in payload.lower():
                return sig
        elif match_mode == "regex":
            try:
                if re.search(pattern, payload, re.IGNORECASE):
                    return sig
            except re.error as e:
                logger.warning("规则 %s 的正则匹配失败，跳过该规则: %s", sig.get("rule_id", "?"), e)
                continue
    return None


def _parse_timestamp(ts: str):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _collect_hits(packets: list[dict], signatures: list[dict]) -> list[dict]:
    """逐包匹配，收集命中事件（尚未聚合为告警）。"""
    hits = []
    for pkt in packets:
        if not isinstance(pkt, dict):
            continue
        payload = pkt.get("payload") or ""
        if not payload:
            continue

        protocol = pkt.get("protocol", "")
        sig = _match_signature(payload, protocol, signatures)
        if sig is None:
            continue

        ts = pkt.get("timestamp", "")
        hits.append({
            "src_ip": pkt.get("src_ip", ""),
            "src_port": pkt.get("src_port"),
            "dst_ip": pkt.get("dst_ip", ""),
            "dst_port": pkt.get("dst_port"),
            "category": sig.get("category", "未知攻击"),
            "severity": sig.get("severity", "medium"),
            "pattern": sig.get("pattern", ""),
            "timestamp": ts,
            "timestamp_dt": _parse_timestamp(ts),
            "evidence_sample": payload[:200],
        })
    return hits


def _within_window(window_start: dict, hit: dict) -> bool:
    """判断 hit 是否与窗口内第一条命中相隔不超过 60 秒（真正滑动窗口）。"""
    start_dt, dt = window_start["timestamp_dt"], hit["timestamp_dt"]
    if start_dt is None or dt is None:
        # 时间戳无法解析时不做跨包聚合，各自单独成组，避免误合并
        return False
    return (dt - start_dt).total_seconds() <= _AGGREGATION_WINDOW_SEC


def _build_alert(window: list[dict]) -> dict:
    """把同一 (src_ip, dst_ip, category) 窗口内的命中事件合并成一条行为告警。"""
    first, last = window[0], window[-1]
    count = len(window)
    behavior_id = str(uuid.uuid4())

    src_ports = {h["src_port"] for h in window}
    dst_ports = {h["dst_port"] for h in window}
    src_port = next(iter(src_ports)) if len(src_ports) == 1 else None
    dst_port = next(iter(dst_ports)) if len(dst_ports) == 1 else None

    severity = max((h["severity"] for h in window), key=lambda s: _SEVERITY_RANK.get(s, 1))
    patterns = list(dict.fromkeys(h["pattern"] for h in window))  # 去重且保留顺序

    return {
        "alert_id": str(uuid.uuid4()),
        "behavior_id": behavior_id,
        "detector": "signature",
        "category": first["category"],
        "src_ip": first["src_ip"],
        "src_port": src_port,
        "dst_ip": first["dst_ip"],
        "dst_network": None,
        "dst_port": dst_port,
        "severity": severity,
        "description": f"{_AGGREGATION_WINDOW_SEC}秒内 {first['src_ip']} 对 {first['dst_ip']} "
                        f"命中 {count} 次{first['category']}特征",
        "evidence": f"hit_count={count}, time_window_sec={_AGGREGATION_WINDOW_SEC}, "
                    f"patterns=[{', '.join(patterns[:5])}], sample={first['evidence_sample']}",
        "timestamp": last["timestamp"],
    }


def _aggregate_hits(hits: list[dict]) -> list[dict]:
    """按 (src_ip, dst_ip, category) 分组，组内按时间排序后按 60 秒窗口切分为多条告警。"""
    groups: dict[tuple, list[dict]] = {}
    for hit in hits:
        key = (hit["src_ip"], hit["dst_ip"], hit["category"])
        groups.setdefault(key, []).append(hit)

    alerts = []
    for group_hits in groups.values():
        group_hits.sort(key=lambda h: (h["timestamp_dt"] is None, h["timestamp_dt"] or h["timestamp"]))

        window: list[dict] = []
        for hit in group_hits:
            if window and not _within_window(window[0], hit):
                alerts.append(_build_alert(window))
                window = []
            window.append(hit)
        if window:
            alerts.append(_build_alert(window))

    return alerts


def main():
    """CLI 入口。"""
    parser = argparse.ArgumentParser(description="特征匹配检测引擎")
    parser.add_argument("--input", required=True, help="输入报文 JSON 文件路径")
    parser.add_argument("--output", required=True, help="输出告警 JSON 文件路径")
    parser.add_argument("--signatures", default=None, help="特征库文件路径（可选）")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[signature] %(levelname)s %(asctime)s %(message)s")

    packets = []
    input_path = Path(args.input)
    if not input_path.exists():
        logger.warning("输入文件不存在: %s，按空报文列表处理", input_path)
    else:
        with open(input_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
        if not content:
            logger.warning("输入文件为空: %s，按空报文列表处理", input_path)
        else:
            try:
                packets = json.loads(content)
            except json.JSONDecodeError as e:
                logger.warning("输入文件不是合法 JSON: %s，按空报文列表处理 (%s)", input_path, e)

    sigs = load_signatures(args.signatures) if args.signatures else None
    alerts = detect(packets, sigs)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, ensure_ascii=False, indent=2)

    print(f"特征匹配完成，聚合产生 {len(alerts)} 条行为告警 → {out_path}")


if __name__ == "__main__":
    main()
