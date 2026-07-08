"""
攻击特征库管理模块 —— 曾子恒

负责加载、解析 config/signatures.txt 中的规则，
提供增删改查接口供 GUI 调用。
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

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
            signatures.append({
                "rule_id": parts[0],
                "category": parts[1],
                "match_mode": parts[2],
                "pattern": parts[3],
                "protocol": parts[4],
                "severity": parts[5],
            })

    logger.info("已加载 %d 条攻击特征规则", len(signatures))
    return signatures


def add_signature(filepath: str, rule: dict) -> None:
    """向特征库追加一条规则。"""
    # TODO: Phase2 实现
    raise NotImplementedError


def delete_signature(filepath: str, rule_id: str) -> None:
    """从特征库删除指定规则。"""
    # TODO: Phase2 实现
    raise NotImplementedError
