"""
告警汇总模块 —— 韩宇飞

汇总 B/C/D 三个检测模块产出的告警 JSON 文件，
去重、排序后统一输出 merged_alerts.json。
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def aggregate(alert_files: list[str]) -> list[dict]:
    """
    汇总多个告警文件。

    Args:
        alert_files: 告警 JSON 文件路径列表

    Returns:
        合并、按 timestamp 排序后的统一告警列表
    """
    all_alerts: list[dict] = []

    for filepath in alert_files:
        path = Path(filepath)
        if not path.exists():
            logger.warning("告警文件不存在，跳过: %s", filepath)
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                alerts = json.load(f)
            if not isinstance(alerts, list):
                logger.warning("告警文件格式异常（非列表），跳过: %s", filepath)
                continue
            all_alerts.extend(alerts)
            logger.info("已加载 %d 条告警 ← %s", len(alerts), filepath)
        except (json.JSONDecodeError, OSError) as e:
            logger.error("读取告警文件失败: %s, 错误: %s", filepath, e)
            continue

    # 按 timestamp 排序
    all_alerts.sort(key=lambda a: a.get("timestamp", ""))

    # 按 alert_id 去重
    seen: set[str] = set()
    deduped: list[dict] = []
    for alert in all_alerts:
        aid = alert.get("alert_id", "")
        if aid and aid not in seen:
            seen.add(aid)
            deduped.append(alert)

    logger.info("告警汇总完成: 共 %d 条 (去重前 %d 条)", len(deduped), len(all_alerts))
    return deduped


def save_merged(alerts: list[dict], output_path: str = "results/merged_alerts.json") -> None:
    """将汇总告警写入文件。"""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, ensure_ascii=False, indent=2)
    logger.info("汇总告警已写入: %s (%d 条)", path, len(alerts))
