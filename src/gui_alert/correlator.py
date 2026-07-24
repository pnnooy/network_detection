"""
跨检测器协同关联模块 —— 韩宇飞

实现特征检测(signature)与异常检测(anomaly/bruteforce)之间的协同联动：

分工边界:
  - signature:  内容检测 — "是什么攻击"（SQL注入/XSS/Webshell/命令注入等）
  - bruteforce: 统计检测 — 暴力破解/非法登录尝试
  - anomaly:    行为检测 — "怎么攻击的"（扫描/横向扩散/异常外联/高频连接）

协同机制:
  1. 跨检测器关联: 同一 src_ip 被多个检测器检出 → 相互引用
  2. 攻击链识别:   按时间序列识别 侦察→利用→植入→控制→横向移动 的阶段演进
  3. 严重度提升:   多检测器交叉验证时提升告警置信度

用法:
    from src.gui_alert.correlator import (
        correlate_cross_detector,
        detect_attack_chain,
        escalate_severity,
    )
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════
#  攻击阶段映射表
# ═══════════════════════════════════════════════════════════════════

# (detector, category) → attack_stage
STAGE_MAP: dict[tuple[str, str], str] = {
    # Reconnaissance 侦察阶段
    ("anomaly", "端口扫描"): "reconnaissance",
    ("anomaly", "异常高频连接"): "reconnaissance",
    # Exploitation 利用阶段
    ("signature", "SQL注入"): "exploitation",
    ("signature", "XSS"): "exploitation",
    ("signature", "木马通信"): "exploitation",
    ("signature", "恶意命令"): "exploitation",
    ("signature", "Webshell"): "exploitation",
    ("signature", "路径遍历"): "exploitation",
    ("signature", "命令注入"): "exploitation",
    ("signature", "XXE注入"): "exploitation",
    ("signature", "DNS隧道"): "exploitation",
    ("signature", "SMB漏洞利用"): "exploitation",
    ("bruteforce", "暴力破解/非法登录"): "credential_access",
    # Installation 植入阶段
    ("signature", "Webshell"): "installation",
    ("signature", "木马通信"): "installation",
    # Command & Control 控制阶段
    ("anomaly", "异常外联"): "c2",
    # Lateral Movement 横向移动
    ("anomaly", "内网横向扩散"): "lateral_movement",
    # Credential Access 凭证访问
    ("bruteforce", "暴力破解/非法登录"): "credential_access",
}

# 阶段顺序（用于攻击链排序）
STAGE_ORDER = ["reconnaissance", "exploitation", "installation", "c2", "lateral_movement", "credential_access"]


def _get_stage(alert: dict) -> str | None:
    """查询告警对应的攻击阶段。"""
    key = (alert.get("detector", ""), alert.get("category", ""))
    return STAGE_MAP.get(key)


# ═══════════════════════════════════════════════════════════════════
#  跨检测器关联
# ═══════════════════════════════════════════════════════════════════

def correlate_cross_detector(alerts: list[dict]) -> list[dict]:
    """
    跨检测器关联：同一 src_ip 被多个 detector 检出时，相互引用。

    为每条告警新增:
      correlated_alerts: [aid1, aid2, ...]  — 不同检测器的关联告警ID列表
      cross_detector_count: int             — 涉及的检测器数量（1=仅自身）

    Args:
        alerts: 告警列表（会被原地修改）

    Returns:
        修改后的告警列表
    """
    if not alerts:
        return alerts

    # 按 src_ip 分组
    ip_groups: dict[str, list[dict]] = defaultdict(list)
    for a in alerts:
        ip_groups[a.get("src_ip", "") or ""].append(a)

    correlated_count = 0

    for ip_addr, group in ip_groups.items():
        if not ip_addr:
            continue

        detectors = {a.get("detector") for a in group if a.get("detector")}
        all_ids = [a.get("alert_id", "") for a in group if a.get("alert_id")]

        if len(detectors) >= 2:
            correlated_count += len(group)
            for a in group:
                a["correlated_alerts"] = [aid for aid in all_ids if aid != a.get("alert_id", "")]
                a["cross_detector_count"] = len(detectors)
                logger.debug(
                    "跨检测器关联: IP=%s 涉及 %d 个检测器 (%s)", ip_addr, len(detectors), ", ".join(sorted(detectors)),
                )
        else:
            for a in group:
                a["correlated_alerts"] = []
                a["cross_detector_count"] = 1

    logger.info("跨检测器关联完成: %d 条告警涉及多检测器交叉验证", correlated_count)
    return alerts


# ═══════════════════════════════════════════════════════════════════
#  攻击链识别
# ═══════════════════════════════════════════════════════════════════

def detect_attack_chain(alerts: list[dict]) -> list[dict]:
    """
    攻击链识别：按 src_ip 分组 + 时间排序，为每条告警标注攻击阶段。

    阶段判定:
      reconnaissance   — 端口扫描、高频连接
      exploitation     — SQL注入、XSS、命令注入、路径遍历、XXE、SMB利用
      installation     — Webshell、木马通信（payload 植入）
      c2               — 异常外联（C2 回连）
      lateral_movement — 内网横向扩散
      credential_access — 暴力破解

    每条告警新增:
      attack_stage: str | None    — 攻击阶段
      attack_chain_id: str | None — 同一攻击链共享此ID

    同一 src_ip 上时间连续的告警组成一条攻击链，共享 attack_chain_id。

    Args:
        alerts: 告警列表（会被原地修改）

    Returns:
        修改后的告警列表
    """
    if not alerts:
        return alerts

    # 按 src_ip 分组
    ip_groups: dict[str, list[dict]] = defaultdict(list)
    for a in alerts:
        ip_groups[a.get("src_ip", "") or ""].append(a)

    chain_count = 0
    staged_count = 0

    for ip_addr, group in ip_groups.items():
        if not ip_addr:
            continue

        # 按时间排序
        group.sort(key=lambda a: a.get("timestamp", ""))

        current_chain_id: str | None = None
        stages_seen: list[str] = []

        for a in group:
            stage = _get_stage(a)
            a["attack_stage"] = stage
            if stage:
                staged_count += 1

            # 攻击链判定：同 IP 上有 ≥2 个不同阶段 → 形成攻击链
            if stage and stage not in stages_seen:
                stages_seen.append(stage)

            if current_chain_id is None and stage and len(stages_seen) >= 1:
                current_chain_id = str(uuid.uuid4())
                chain_count += 1

            a["attack_chain_id"] = current_chain_id

        # 如果有多阶段，标注证据
        if len(stages_seen) >= 2:
            chain_desc = " → ".join(stages_seen)
            for a in group:
                if a.get("attack_stage"):
                    existing = a.get("evidence", "") or ""
                    if "attack_chain" not in existing:
                        a["evidence"] = f"{existing}; attack_chain: {chain_desc}"

    logger.info(
        "攻击链识别完成: %d 条攻击链, %d 条告警完成阶段标注",
        chain_count, staged_count,
    )
    return alerts


# ═══════════════════════════════════════════════════════════════════
#  严重度联动提升
# ═══════════════════════════════════════════════════════════════════

SEVERITY_LEVEL = {"low": 0, "medium": 1, "high": 2}
SEVERITY_LABELS = {0: "low", 1: "medium", 2: "high"}


def escalate_severity(alerts: list[dict]) -> list[dict]:
    """
    严重度提升：同一 src_ip 被多个检测器检出时，提升告警置信度。

    规则:
      - ≥2 个不同 detector 检出同一 IP → 所有告警升一级（low→medium, medium→high）
      - high 不再提升（已最高）
      - 单检测器检出 → 不变
      - 不降低任何告警的严重度

    原始严重度记录在 original_severity 字段中。

    Args:
        alerts: 告警列表（会被原地修改）

    Returns:
        修改后的告警列表
    """
    if not alerts:
        return alerts

    # 统计每个 IP 涉及的检测器数量
    ip_detectors: dict[str, set[str]] = defaultdict(set)
    for a in alerts:
        ip_detectors[a.get("src_ip", "") or ""].add(a.get("detector", ""))

    escalated_count = 0

    for a in alerts:
        ip = a.get("src_ip", "") or ""
        detectors = ip_detectors.get(ip, set())

        a["original_severity"] = a.get("severity", "medium")

        if len(detectors) >= 2:
            current_level = SEVERITY_LEVEL.get(a.get("severity", "medium"), 1)
            if current_level < 2:  # high 不再提升
                new_level = current_level + 1
                new_severity = SEVERITY_LABELS[new_level]
                a["severity"] = new_severity
                a["escalated"] = True
                escalated_count += 1
                logger.debug(
                    "严重度提升: IP=%s %s→%s (涉及检测器: %s)",
                    ip, SEVERITY_LABELS[current_level], new_severity, ", ".join(sorted(detectors)),
                )
            else:
                a["escalated"] = False
        else:
            a["escalated"] = False

    logger.info("严重度联动完成: %d 条告警升级", escalated_count)
    return alerts
