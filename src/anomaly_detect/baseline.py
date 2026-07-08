"""
基线建立模块 —— 姜新晨

基于正常流量数据建立主机行为基线：
- 并发连接数分布
- 访问频次分布
- 端口访问分布
- 会话时长分布
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "baseline_config.json"


def load_config(config_path: str | None = None) -> dict:
    """加载基线阈值配置。"""
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    if not path.exists():
        logger.warning("基线配置文件不存在: %s，使用默认值", path)
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_baseline(packets: list[dict]) -> dict:
    """
    根据正常流量数据建立行为基线。

    Args:
        packets: 正常流量报文列表（不含攻击流量）

    Returns:
        基线统计值字典
    """
    # TODO: Phase2 实现
    raise NotImplementedError("基线建立将在 Phase2 实现")
