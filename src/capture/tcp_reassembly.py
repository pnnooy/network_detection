"""
TCP 流重组模块 —— 李哲

将捕获的 TCP 报文按五元组（src_ip, src_port, dst_ip, dst_port, protocol）
重组为完整的 TCP 流，合并分片和乱序报文（简化实现）。
"""

from __future__ import annotations

import logging
from collections import defaultdict

from .protocol_parser import build_flow_id

logger = logging.getLogger(__name__)


def _flow_key(packet: dict) -> str:
    """获取用于分组的流标识。"""
    return packet.get("flow_id") or build_flow_id(packet)


def _merge_flow_packets(flow_packets: list[dict]) -> list[dict]:
    """
    合并单条流内的 TCP 数据段。

    简化策略：按时间排序后拼接所有带 payload 的报文；
    控制报文（仅 SYN/FIN/RST 无数据）原样保留。
    """
    if not flow_packets:
        return []

    flow_packets.sort(key=lambda p: p.get("timestamp", ""))

    data_packets = [p for p in flow_packets if p.get("payload_len", 0) > 0]
    control_packets = [p for p in flow_packets if p.get("payload_len", 0) == 0]

    result: list[dict] = list(control_packets)

    if data_packets:
        merged = dict(data_packets[0])
        merged_payload = "".join(p.get("payload", "") or "" for p in data_packets)
        merged_len = sum(p.get("payload_len", 0) for p in data_packets)
        merged["payload"] = merged_payload
        merged["payload_len"] = merged_len
        result.append(merged)

    return result


def reassemble(packets: list[dict]) -> list[dict]:
    """
    对 TCP 报文列表进行流重组。

    Args:
        packets: 符合"报文记录格式"的报文列表

    Returns:
        重组后的报文列表（同流 payload 可能被合并，payload_len 相应更新）。
        非 TCP 报文原样保留。
    """
    if not packets:
        return []

    tcp_flows: dict[str, list[dict]] = defaultdict(list)
    non_tcp: list[dict] = []

    for packet in packets:
        if packet.get("protocol") == "TCP":
            tcp_flows[_flow_key(packet)].append(packet)
        else:
            non_tcp.append(packet)

    reassembled: list[dict] = list(non_tcp)
    for flow_id, flow_packets in tcp_flows.items():
        merged = _merge_flow_packets(flow_packets)
        reassembled.extend(merged)
        logger.debug("流 %s: %d 条报文重组为 %d 条", flow_id, len(flow_packets), len(merged))

    reassembled.sort(key=lambda p: p.get("timestamp", ""))
    logger.info("TCP 流重组完成: %d 条输入 -> %d 条输出", len(packets), len(reassembled))
    return reassembled
