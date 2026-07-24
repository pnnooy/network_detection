"""
告警汇总与行为关联模块 —— 韩宇飞

1. 汇总 B/C/D 三个检测模块产出的告警 JSON，去重、排序
2. 行为关联：将同源同类时间相近的告警归入同一攻击行为事件
3. 统一输出 merged_alerts.json（含 behavior_id）
"""

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# 行为关联默认时间窗口（秒）
DEFAULT_BEHAVIOR_WINDOW_SEC = 60


def _parse_ts(timestamp: str) -> datetime:
    """解析 ISO8601 时间戳，解析失败返回 epoch"""
    try:
        # 处理 Python < 3.11 无 fromisoformat Z 后缀兼容
        ts = timestamp.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except (ValueError, AttributeError):
        return datetime(1970, 1, 1, tzinfo=timezone.utc)


def correlate_behaviors(
    alerts: list[dict],
    time_window_sec: int = DEFAULT_BEHAVIOR_WINDOW_SEC,
) -> list[dict]:
    """
    行为关联：将同源同类时间相近的告警归入同一攻击行为。

    规则：
    - 同一 src_ip + 同一 category + 时间间隔 ≤ time_window_sec → 同一 behavior_id
    - 已有 behavior_id 的告警保持原值不覆盖（检测模块已标注的优先）
    - 跨 detector 的同源同类告警也会被关联（如 signature 和 anomaly 都检测到同一来源的攻击）

    Args:
        alerts:           已排序的告警列表
        time_window_sec:  关联时间窗口（秒）

    Returns:
        带 behavior_id 的告警列表（原地修改并返回）
    """
    # 按 (src_ip, category) 分组
    groups: dict[tuple[str, str], list[dict]] = {}
    for alert in alerts:
        key = (alert.get("src_ip", ""), alert.get("category", ""))
        groups.setdefault(key, []).append(alert)

    behavior_count = 0

    for alerts_in_group in groups.values():
        # 按时间排序
        alerts_in_group.sort(key=lambda a: a.get("timestamp", ""))

        current_behavior_id: str | None = None
        last_ts: datetime | None = None

        for alert in alerts_in_group:
            # 已有 behavior_id 的不覆盖（检测模块已标注的优先）
            if alert.get("behavior_id"):
                current_behavior_id = alert["behavior_id"]
                last_ts = _parse_ts(alert.get("timestamp", ""))
                continue

            this_ts = _parse_ts(alert.get("timestamp", ""))

            if current_behavior_id is not None and last_ts is not None:
                gap = (this_ts - last_ts).total_seconds()
                if gap <= time_window_sec:
                    # 时间窗口内 → 同一行为
                    alert["behavior_id"] = current_behavior_id
                    last_ts = max(last_ts, this_ts)
                    continue

            # 新行为开始
            current_behavior_id = str(uuid.uuid4())
            alert["behavior_id"] = current_behavior_id
            last_ts = this_ts
            behavior_count += 1

    logger.info(
        "行为关联完成: %d 条告警 → %d 个攻击行为事件 (窗口=%ds)",
        len(alerts),
        behavior_count,
        time_window_sec,
    )
    return alerts


def aggregate(alert_files: list[str]) -> list[dict]:
    """
    汇总多个告警文件，含去重、排序、行为关联。

    Args:
        alert_files: 告警 JSON 文件路径列表

    Returns:
        合并、排序、去重、关联 behavior_id 后的统一告警列表
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

    # 行为关联
    deduped = correlate_behaviors(deduped)

    # 跨检测器协同联动
    from .correlator import (
        correlate_cross_detector,
        detect_attack_chain,
        escalate_severity,
    )

    deduped = correlate_cross_detector(deduped)
    deduped = detect_attack_chain(deduped)
    deduped = escalate_severity(deduped)

    logger.info("告警汇总完成: 共 %d 条 (去重前 %d 条)", len(deduped), len(all_alerts))
    return deduped


def save_merged(alerts: list[dict], output_path: str = "results/merged_alerts.json") -> None:
    """将汇总告警写入文件。"""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, ensure_ascii=False, indent=2)
    logger.info("汇总告警已写入: %s (%d 条)", path, len(alerts))
