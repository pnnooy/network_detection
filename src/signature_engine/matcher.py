"""
特征匹配算法模块 —— 曾子恒

对报文 payload 执行攻击特征匹配，支持字面子串匹配（baseline）
和 AC 自动机 / KMP 等高效多模式匹配（加分项）。
"""

import argparse
import json
import logging
import uuid
from pathlib import Path

from .signature_db import load_signatures

logger = logging.getLogger(__name__)


def detect(packets: list[dict], signatures: list[dict] | None = None) -> list[dict]:
    """
    对报文列表执行特征匹配检测。

    Args:
        packets:    符合"报文记录格式"的列表
        signatures: 特征规则列表，为 None 时自动从配置文件加载

    Returns:
        符合"统一告警格式"的列表（无告警时返回空列表）
    """
    if signatures is None:
        signatures = load_signatures()

    alerts: list[dict] = []

    for pkt in packets:
        payload = pkt.get("payload") or ""
        if not payload:
            continue

        protocol = pkt.get("protocol", "")

        for sig in signatures:
            # 检查协议是否匹配
            sig_proto = sig.get("protocol", "*")
            if sig_proto != "*" and protocol.upper() not in sig_proto.upper().split("/"):
                continue

            # 匹配
            pattern = sig.get("pattern", "")
            match_mode = sig.get("match_mode", "literal")

            matched = False
            if match_mode == "literal":
                # 子串匹配，大小写不敏感
                if pattern.lower() in payload.lower():
                    matched = True
            elif match_mode == "regex":
                import re
                if re.search(pattern, payload, re.IGNORECASE):
                    matched = True

            if matched:
                alerts.append({
                    "alert_id": str(uuid.uuid4()),
                    "detector": "signature",
                    "category": f"{sig.get('category', '未知攻击')}",
                    "src_ip": pkt.get("src_ip", ""),
                    "src_port": pkt.get("src_port"),
                    "dst_ip": pkt.get("dst_ip", ""),
                    "dst_port": pkt.get("dst_port"),
                    "severity": sig.get("severity", "medium"),
                    "description": f"检测到{sig.get('category', '未知攻击')}特征: {pattern[:60]}",
                    "evidence": payload[:500],
                    "timestamp": pkt.get("timestamp", ""),
                })
                break  # 一条报文最多产生一条告警

    logger.info("特征匹配完成: 扫描 %d 条报文, 产生 %d 条告警", len(packets), len(alerts))
    return alerts


def main():
    """CLI 入口。"""
    parser = argparse.ArgumentParser(description="特征匹配检测引擎")
    parser.add_argument("--input", required=True, help="输入报文 JSON 文件路径")
    parser.add_argument("--output", required=True, help="输出告警 JSON 文件路径")
    parser.add_argument("--signatures", default=None, help="特征库文件路径（可选）")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[signature] %(levelname)s %(asctime)s %(message)s")

    with open(args.input, "r", encoding="utf-8") as f:
        packets = json.load(f)

    sigs = load_signatures(args.signatures) if args.signatures else None
    alerts = detect(packets, sigs)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, ensure_ascii=False, indent=2)

    print(f"特征匹配完成，产生 {len(alerts)} 条告警 → {out_path}")


if __name__ == "__main__":
    main()
