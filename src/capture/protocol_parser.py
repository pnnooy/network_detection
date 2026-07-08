"""
协议识别与字段解析模块 —— 李哲

从原始报文中识别 IP / TCP / UDP / ICMP / ARP 协议层，
解析各层字段，提取应用层 payload。
"""

import logging

logger = logging.getLogger(__name__)


def parse_packet(raw_packet) -> dict:
    """
    解析单个原始报文为标准化记录。

    Args:
        raw_packet: scapy 或其他抓包库返回的原始报文对象

    Returns:
        符合"报文记录格式"的字典；解析失败返回 None
    """
    # TODO: Phase2 实现
    raise NotImplementedError("协议解析将在 Phase2 实现")


def build_flow_id(packet: dict) -> str:
    """
    根据五元组生成流标识。

    Args:
        packet: 单条报文记录

    Returns:
        流标识字符串，格式: "src_ip:src_port->dst_ip:dst_port/protocol"
    """
    src = f"{packet.get('src_ip', '?')}:{packet.get('src_port', '?')}"
    dst = f"{packet.get('dst_ip', '?')}:{packet.get('dst_port', '?')}"
    proto = packet.get('protocol', '?')
    return f"{src}->{dst}/{proto}"
