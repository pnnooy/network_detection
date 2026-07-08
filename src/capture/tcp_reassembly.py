"""
TCP 流重组模块 —— 李哲

将捕获的 TCP 报文按五元组（src_ip, src_port, dst_ip, dst_port, protocol）
重组为完整的 TCP 流，合并分片和乱序报文。
"""

import logging

logger = logging.getLogger(__name__)


def reassemble(packets: list[dict]) -> list[dict]:
    """
    对 TCP 报文列表进行流重组。

    Args:
        packets: 符合"报文记录格式"的报文列表

    Returns:
        重组后的报文列表（payload 可能被合并，payload_len 相应更新）。
        非 TCP 报文原样保留。
    """
    # TODO: Phase2 实现
    raise NotImplementedError("TCP 流重组将在 Phase2 实现")
