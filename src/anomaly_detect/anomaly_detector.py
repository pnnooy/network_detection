"""
异常行为检测模块 —— 姜新晨

基于已建立的基线，识别偏离行为：
- 端口扫描（单IP短时间访问大量不同端口）
- 异常外联陌生公网IP
- 内网横向扩散
"""

import argparse
import json
import logging
import uuid
from pathlib import Path

from .baseline import load_config

logger = logging.getLogger(__name__)


def detect(packets: list[dict], config: dict | None = None) -> list[dict]:
    """
    检测异常行为。

    Args:
        packets: 符合"报文记录格式"的列表
        config:  基线阈值配置，为 None 时自动加载

    Returns:
        符合"统一告警格式"的列表（无告警时返回空列表）
    """
    if config is None:
        config = load_config()

    alerts: list[dict] = []

    # TODO: Phase2 实现以下检测逻辑
    # 1. 端口扫描检测
    # 2. 异常外联检测
    # 3. 内网横向扩散检测

    logger.info("异常检测完成: 扫描 %d 条报文, 产生 %d 条告警", len(packets), len(alerts))
    return alerts


def main():
    """CLI 入口。"""
    parser = argparse.ArgumentParser(description="异常行为检测引擎")
    parser.add_argument("--input", required=True, help="输入报文 JSON 文件路径")
    parser.add_argument("--output", required=True, help="输出告警 JSON 文件路径")
    parser.add_argument("--config", default=None, help="基线配置文件路径（可选）")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[anomaly] %(levelname)s %(asctime)s %(message)s")

    with open(args.input, "r", encoding="utf-8") as f:
        packets = json.load(f)

    cfg = load_config(args.config) if args.config else None
    alerts = detect(packets, cfg)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, ensure_ascii=False, indent=2)

    print(f"异常检测完成，产生 {len(alerts)} 条告警 → {out_path}")


if __name__ == "__main__":
    main()
