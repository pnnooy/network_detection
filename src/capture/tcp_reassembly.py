"""
TCP 流重组模块 —— 李哲 (v2 增强版，韩宇飞协同完善)

基于 TCP 序列号的完整流重组，支持：
- 双向数据分离追踪（client→server / server→client 各自维护 seq 状态）
- 乱序报文缓冲重排（按 seq 而非 timestamp 确定正确顺序）
- 重传检测与去重（seq 区间重叠 → 丢弃重复数据）
- 数据缺失检测（seq 间隙 → 插入 [MISSING N bytes] 标记）
- 降级兼容：无 tcp_seq 字段时回退到时间戳拼接模式
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field

from .protocol_parser import build_flow_id

logger = logging.getLogger(__name__)

# 流重组超时（秒），超过此时间未收到新数据则 flush buffer
FLOW_TIMEOUT_SEC = 300
# 乱序 buffer 最大容量（防止内存耗尽）
MAX_BUFFER_SIZE = 64


# ═══════════════════════════════════════════════════════════════════
#  数据结构
# ═══════════════════════════════════════════════════════════════════

@dataclass
class TCPSegment:
    """单条 TCP 数据段（归一化内部表示）。"""
    seq: int
    ack: int
    payload: str
    payload_len: int
    flags: str
    timestamp: str
    raw_packet: dict


@dataclass
class DirectionState:
    """单个方向（client→server 或 server→client）的序列号追踪。"""
    isn: int | None = None            # 初始序列号
    next_seq: int | None = None       # 期望的下一个 seq
    buffer: dict[int, TCPSegment] = field(default_factory=dict)
    total_bytes: int = 0
    gap_count: int = 0
    gap_bytes: int = 0
    retrans_count: int = 0


# ═══════════════════════════════════════════════════════════════════
#  辅助函数
# ═══════════════════════════════════════════════════════════════════

def _flow_key(packet: dict) -> str:
    """获取用于分组的流标识。"""
    return packet.get("flow_id") or build_flow_id(packet)


def _has_seq_fields(packet: dict) -> bool:
    """检查报文是否包含 tcp_seq 字段。"""
    return packet.get("tcp_seq") is not None


def _is_syn(packet: dict) -> bool:
    return "S" in (packet.get("flags") or "")


def _is_data(packet: dict) -> bool:
    return (packet.get("payload_len") or 0) > 0


def _tcp_seq(packet: dict) -> int:
    return int(packet.get("tcp_seq", 0))


def _tcp_ack(packet: dict) -> int:
    return int(packet.get("tcp_ack", 0))


# ═══════════════════════════════════════════════════════════════════
#  基于序列号的流重组（v2 核心）
# ═══════════════════════════════════════════════════════════════════

def _reassemble_flow_with_seq(flow_packets: list[dict]) -> list[dict]:
    """
    基于 TCP 序列号对单条流进行完整重组。

    处理流程:
    1. 连接建立: 从 SYN 包记录各方向 ISN
    2. 逐包处理: 按 timestamp 排序遍历，按 seq 判定顺序/乱序/重传
    3. 流结束: flush buffer，标记不可恢复的 gap

    Returns:
        重组后的报文列表
    """
    if not flow_packets:
        return []

    # 按时间排序输入（注：输出顺序由 seq 决定，非 timestamp）
    sorted_packets = sorted(flow_packets, key=lambda p: p.get("timestamp", ""))

    # 按方向分别追踪
    client_state = DirectionState()   # request (client→server)
    server_state = DirectionState()   # response (server→client)

    # SYN 初始化：从首包中提取 ISN
    for pkt in sorted_packets:
        if _is_syn(pkt) and _has_seq_fields(pkt):
            seq = _tcp_seq(pkt)
            direction = pkt.get("direction")
            if direction == "request" and client_state.isn is None:
                client_state.isn = seq
                client_state.next_seq = (seq + 1) & 0xFFFFFFFF
                logger.debug("流 %s client ISN=%d", _flow_key(pkt), seq)
            elif direction == "response" and server_state.isn is None:
                server_state.isn = seq
                server_state.next_seq = (seq + 1) & 0xFFFFFFFF
                logger.debug("流 %s server ISN=%d", _flow_key(pkt), seq)

    # 无 SYN 但有序号 → 从第一个有数据的包推断起始 seq
    if client_state.next_seq is None:
        for pkt in sorted_packets:
            if pkt.get("direction") == "request" and _is_data(pkt) and _has_seq_fields(pkt):
                client_state.next_seq = _tcp_seq(pkt)
                break
    if server_state.next_seq is None:
        for pkt in sorted_packets:
            if pkt.get("direction") == "response" and _is_data(pkt) and _has_seq_fields(pkt):
                server_state.next_seq = _tcp_seq(pkt)
                break

    # 逐包处理
    output_control: list[dict] = []
    output_data: list[dict] = []

    for pkt in sorted_packets:
        if pkt.get("protocol") != "TCP":
            output_control.append(pkt)
            continue

        direction = pkt.get("direction")
        state = client_state if direction == "request" else server_state
        if direction == "response":
            state = server_state
        elif direction == "request":
            state = client_state
        else:
            # 无法判定方向 → 控制包保留，数据包按原样保留
            if _is_data(pkt):
                output_data.append(pkt)
            else:
                output_control.append(pkt)
            continue

        # 无 seq 字段的包：直接保留（控制包）或追加（数据包）
        if not _has_seq_fields(pkt):
            if _is_data(pkt):
                output_data.append(pkt)
            else:
                output_control.append(pkt)
            continue

        # 控制包（SYN/FIN/RST）保留但不影响数据流
        if not _is_data(pkt):
            output_control.append(pkt)
            # FIN 消耗 1 个序列号
            if "F" in (pkt.get("flags") or "") and state.next_seq is not None:
                state.next_seq = (state.next_seq + 1) & 0xFFFFFFFF
            continue

        # 数据包处理
        seg = TCPSegment(
            seq=_tcp_seq(pkt),
            ack=_tcp_ack(pkt),
            payload=pkt.get("payload", ""),
            payload_len=pkt.get("payload_len", 0),
            flags=pkt.get("flags", ""),
            timestamp=pkt.get("timestamp", ""),
            raw_packet=pkt,
        )

        _process_data_segment(state, seg, output_data)

    # Flush 两个方向的 buffer
    _flush_buffer(client_state, output_data)
    _flush_buffer(server_state, output_data)

    # 组装结果：控制包 + 重组数据
    result = output_control + output_data
    result.sort(key=lambda p: p.get("timestamp", ""))

    # 附加重组元信息到第一个数据包
    if output_data:
        output_data[0]["_reassembly_gaps"] = client_state.gap_count + server_state.gap_count
        output_data[0]["_reassembly_retrans"] = client_state.retrans_count + server_state.retrans_count
        output_data[0]["_reassembly_gap_bytes"] = client_state.gap_bytes + server_state.gap_bytes

    logger.debug(
        "流 %s seq重组: client=%d bytes (gaps=%d retrans=%d), server=%d bytes (gaps=%d retrans=%d)",
        _flow_key(flow_packets[0]) if flow_packets else "?",
        client_state.total_bytes, client_state.gap_count, client_state.retrans_count,
        server_state.total_bytes, server_state.gap_count, server_state.retrans_count,
    )
    return result


def _process_data_segment(state: DirectionState, seg: TCPSegment, output: list[dict]):
    """
    处理单个数据段：判定顺序/乱序/重传，相应处理。

    Args:
        state:  该方向的序列号追踪状态
        seg:    当前数据段
        output: 重组后的输出列表（追加到末尾）
    """
    if state.next_seq is None:
        state.next_seq = seg.seq

    expected = state.next_seq
    seg_end = (seg.seq + seg.payload_len) & 0xFFFFFFFF

    if seg.seq == expected:
        # === 顺序到达 ===
        _emit_data(state, seg, output)
        # 尝试 flush buffer 中连续的后续段
        while state.next_seq in state.buffer:
            next_seg = state.buffer.pop(state.next_seq)
            _emit_data(state, next_seg, output)

    elif seg.seq < expected:
        # === 可能的重传 ===
        overlap = (expected - seg.seq) & 0xFFFFFFFF
        if overlap >= seg.payload_len:
            # 完全重叠 → 完整重传，丢弃
            state.retrans_count += 1
            logger.debug("重传检测: seq=%d, 完全重叠(%d bytes), 丢弃", seg.seq, seg.payload_len)
            return
        else:
            # 部分重叠 → 截取新数据
            new_len = seg.payload_len - overlap
            state.retrans_count += 1
            logger.debug("重传检测: seq=%d, 部分重叠(%d/%d bytes)", seg.seq, overlap, seg.payload_len)
            seg.payload = seg.payload[overlap:]
            seg.payload_len = new_len
            seg.seq = expected
            _emit_data(state, seg, output)
            while state.next_seq in state.buffer:
                next_seg = state.buffer.pop(state.next_seq)
                _emit_data(state, next_seg, output)

    else:  # seg.seq > expected
        # === 乱序或缺失 ===
        gap = (seg.seq - expected) & 0xFFFFFFFF
        if gap > 0 and gap < 1_000_000_000:  # 合理的 gap（排除 seq 回绕）
            state.gap_count += 1
            state.gap_bytes += gap
            logger.debug("seq 间隙检测: expected=%d, received=%d, gap=%d bytes", expected, seg.seq, gap)
            # 插入 gap 标记
            gap_pkt = {
                "flow_id": seg.raw_packet.get("flow_id", ""),
                "timestamp": seg.timestamp,
                "protocol": "TCP",
                "payload": f"[MISSING {gap} bytes]",
                "payload_len": gap,
                "src_ip": seg.raw_packet.get("src_ip", ""),
                "dst_ip": seg.raw_packet.get("dst_ip", ""),
                "flags": "__GAP__",
                "direction": seg.raw_packet.get("direction"),
                "_is_gap_marker": True,
            }
            output.append(gap_pkt)

        # buffer 暂存（防止内存耗尽）
        if len(state.buffer) < MAX_BUFFER_SIZE:
            state.buffer[seg.seq] = seg
        else:
            # buffer 满 → 强制写入（退化到无序输出）
            logger.warning("seq buffer 满(%d), 强制写入 seq=%d", MAX_BUFFER_SIZE, seg.seq)
            _emit_data(state, seg, output)


def _emit_data(state: DirectionState, seg: TCPSegment, output: list[dict]):
    """输出一个数据段并更新期望序列号。"""
    state.next_seq = (seg.seq + seg.payload_len) & 0xFFFFFFFF
    state.total_bytes += seg.payload_len

    pkt = dict(seg.raw_packet)
    pkt["payload"] = seg.payload
    pkt["payload_len"] = seg.payload_len
    output.append(pkt)


def _flush_buffer(state: DirectionState, output: list[dict]):
    """超时/流结束时，将 buffer 中所有数据段按 seq 排序输出。"""
    if not state.buffer:
        return

    sorted_segs = sorted(state.buffer.values(), key=lambda s: s.seq)
    for seg in sorted_segs:
        # 记录间隙
        if state.next_seq is not None and seg.seq > state.next_seq:
            gap = (seg.seq - state.next_seq) & 0xFFFFFFFF
            if gap < 1_000_000_000:
                state.gap_count += 1
                state.gap_bytes += gap
                gap_pkt = {
                    "flow_id": seg.raw_packet.get("flow_id", ""),
                    "timestamp": seg.timestamp,
                    "protocol": "TCP",
                    "payload": f"[MISSING {gap} bytes]",
                    "payload_len": gap,
                    "src_ip": seg.raw_packet.get("src_ip", ""),
                    "dst_ip": seg.raw_packet.get("dst_ip", ""),
                    "flags": "__GAP__",
                    "direction": seg.raw_packet.get("direction"),
                    "_is_gap_marker": True,
                }
                output.append(gap_pkt)
        _emit_data(state, seg, output)

    state.buffer.clear()


# ═══════════════════════════════════════════════════════════════════
#  降级模式（无序列号时的兼容逻辑）
# ═══════════════════════════════════════════════════════════════════

def _merge_flow_packets_fallback(flow_packets: list[dict]) -> list[dict]:
    """
    无序列号时的降级合并（与 v1 行为一致）。

    按时间排序后拼接所有带 payload 的报文；
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


# ═══════════════════════════════════════════════════════════════════
#  公开 API
# ═══════════════════════════════════════════════════════════════════

def reassemble(packets: list[dict]) -> list[dict]:
    """
    对 TCP 报文列表进行流重组。

    - 当报文包含 tcp_seq 字段时：使用基于序列号的完整重组
      （处理双向/乱序/重传/缺失）
    - 当报文不包含 tcp_seq 字段时：降级为 timestamp 拼接模式
      （与 v1 行为完全一致，保证向后兼容）

    Args:
        packets: 符合"报文记录格式"的报文列表

    Returns:
        重组后的报文列表。非 TCP 报文原样保留。
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

    # 判断是否启用序列号模式：至少有一个 TCP 包带 tcp_seq
    has_any_seq = any(_has_seq_fields(pkt) for flow in tcp_flows.values() for pkt in flow)
    mode = "seq-based" if has_any_seq else "timestamp-fallback"

    for flow_id, flow_packets in tcp_flows.items():
        if has_any_seq:
            merged = _reassemble_flow_with_seq(flow_packets)
        else:
            merged = _merge_flow_packets_fallback(flow_packets)
        reassembled.extend(merged)
        logger.debug("流 %s: %d 条→ %d 条 [%s]", flow_id, len(flow_packets), len(merged), mode)

    reassembled.sort(key=lambda p: p.get("timestamp", ""))
    logger.info(
        "TCP 流重组完成: %d 条输入→ %d 条输出 [%s]",
        len(packets), len(reassembled), mode,
    )
    return reassembled
