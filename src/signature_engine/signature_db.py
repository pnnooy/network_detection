"""
攻击特征库管理模块 —— 曾子恒

负责加载、解析 config/signatures.txt 中的规则，
提供增删改查接口供 GUI 调用。
"""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_VALID_MATCH_MODES = ("literal", "regex")
_VALID_SEVERITIES = ("low", "medium", "high")
_RULE_ID_PATTERN = re.compile(r"^SIG-(\d+)$")

# 默认特征库路径
DEFAULT_SIGNATURE_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "signatures.txt"


def load_signatures(filepath: str | None = None) -> list[dict]:
    """
    从配置文件加载攻击特征库。

    Args:
        filepath: 特征库文件路径，默认使用 config/signatures.txt

    Returns:
        规则列表，每条规则为 dict，字段:
        - rule_id, category, match_mode, pattern, protocol, severity
    """
    path = Path(filepath) if filepath else DEFAULT_SIGNATURE_PATH
    signatures = []

    if not path.exists():
        logger.warning("特征库文件不存在: %s", path)
        return signatures

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # 跳过空行和注释
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) != 6:
                logger.warning("跳过格式不正确的规则行: %s", line)
                continue

            rule_id, category, match_mode, pattern, protocol, severity = parts
            pattern = pattern.replace("\\x7C", "|")

            if match_mode == "regex":
                try:
                    re.compile(pattern)
                except re.error as e:
                    logger.warning("跳过规则 %s：regex 编译失败: %s", rule_id, e)
                    continue

            signatures.append({
                "rule_id": rule_id,
                "category": category,
                "match_mode": match_mode,
                "pattern": pattern,
                "protocol": protocol,
                "severity": severity,
            })

    logger.info("已加载 %d 条攻击特征规则", len(signatures))
    return signatures


def _next_rule_id(existing_ids: set) -> str:
    """在已有规则ID中找最大编号，生成下一个 SIG-NNN。"""
    max_n = 0
    for rid in existing_ids:
        m = _RULE_ID_PATTERN.match(rid)
        if m:
            max_n = max(max_n, int(m.group(1)))
    return f"SIG-{max_n + 1:03d}"


def add_signature(filepath: str, rule: dict) -> None:
    """
    向特征库追加一条规则。

    Args:
        filepath: 特征库文件路径
        rule: 规则字典，需包含 category/match_mode/pattern/protocol/severity；
              rule_id 可选，不提供时自动生成下一个 SIG-NNN

    Raises:
        ValueError: 字段缺失、取值非法、regex 无法编译，或 rule_id 已存在
    """
    required = ("category", "match_mode", "pattern", "protocol", "severity")
    missing = [f for f in required if not rule.get(f)]
    if missing:
        raise ValueError(f"规则缺少必填字段: {missing}")

    if rule["match_mode"] not in _VALID_MATCH_MODES:
        raise ValueError(f"match_mode 必须是 {_VALID_MATCH_MODES} 之一，收到: {rule['match_mode']}")
    if rule["severity"] not in _VALID_SEVERITIES:
        raise ValueError(f"severity 必须是 {_VALID_SEVERITIES} 之一，收到: {rule['severity']}")
    if rule["match_mode"] == "regex":
        try:
            re.compile(rule["pattern"])
        except re.error as e:
            raise ValueError(f"regex 特征串编译失败: {e}") from e

    path = Path(filepath)
    existing_ids = {sig["rule_id"] for sig in load_signatures(str(path))}

    rule_id = rule.get("rule_id")
    if rule_id:
        if rule_id in existing_ids:
            raise ValueError(f"规则ID已存在: {rule_id}")
    else:
        rule_id = _next_rule_id(existing_ids)

    # 文件用 | 分隔字段，特征串本身如果含 | 需要转义，避免破坏行格式
    escaped_pattern = rule["pattern"].replace("|", "\\x7C")
    line = f"{rule_id} | {rule['category']} | {rule['match_mode']} | {escaped_pattern} | {rule['protocol']} | {rule['severity']}\n"

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)

    logger.info("已新增规则 %s: %s", rule_id, rule["category"])


def delete_signature(filepath: str, rule_id: str) -> None:
    """
    从特征库删除指定规则（按 rule_id 精确匹配），保留其余行（含注释/空行）不变。

    Args:
        filepath: 特征库文件路径
        rule_id: 待删除的规则ID
    """
    path = Path(filepath)
    if not path.exists():
        logger.warning("特征库文件不存在: %s", path)
        return

    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    kept = []
    removed = False
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            parts = [p.strip() for p in stripped.split("|")]
            if parts and parts[0] == rule_id:
                removed = True
                continue
        kept.append(line)

    if not removed:
        logger.warning("未找到规则ID，未做任何修改: %s", rule_id)
        return

    with open(path, "w", encoding="utf-8") as f:
        f.writelines(kept)

    logger.info("已删除规则: %s", rule_id)
