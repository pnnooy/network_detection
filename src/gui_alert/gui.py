"""
图形界面模块 —— 韩宇飞

提供规则库管理界面 + 实时告警展示。
使用 tkinter（Python 标准库）实现。
"""

import logging

logger = logging.getLogger(__name__)


def launch_gui(alert_files: list[str] | None = None) -> None:
    """
    启动图形界面。

    Args:
        alert_files: 告警文件路径列表，为 None 时自动扫描 results/ 目录
    """
    # TODO: Phase3-4 实现
    raise NotImplementedError("GUI 将在 Phase3 实现")


if __name__ == "__main__":
    launch_gui()
