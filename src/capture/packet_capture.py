"""
数据包捕获模块 —— 李哲

基于 scapy/libpcap 实现网络报文的实时捕获或离线读取。
"""

import logging

logger = logging.getLogger(__name__)


def capture_live(interface: str, count: int = 0, timeout: int = 60) -> list[dict]:
    """
    实时抓包。

    Args:
        interface: 网卡名称（如 eth0 / 以太网），需要管理员/root 权限
        count:    抓包数量，0 表示不限
        timeout:  超时秒数

    Returns:
        符合"报文记录格式"的列表
    """
    # TODO: Phase2 实现
    raise NotImplementedError("实时抓包功能将在 Phase2 实现")


def read_pcap(filepath: str) -> list[dict]:
    """
    从 pcap/pcapng 文件读取报文。

    Args:
        filepath: pcap 文件路径

    Returns:
        符合"报文记录格式"的列表
    """
    # TODO: Phase2 实现
    raise NotImplementedError("pcap 文件读取将在 Phase2 实现")
