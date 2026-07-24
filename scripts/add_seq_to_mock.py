"""
为 mock_packets.json 补充 TCP 序列号（一次性脚本）

用法:
    python scripts/add_seq_to_mock.py

算法:
  1. 按 flow_id 分组 TCP 报文
  2. 每条流随机生成 client_isn 和 server_isn
  3. 按 direction 分别追踪 seq（request=client→server, response=server→client）
  4. SYN 包消耗 1 个序列号, 数据包消耗 payload_len 个序列号
  5. 注入可控异常: 乱序(seq偏移) + 重传(相同seq)

输出: mock_data/mock_packets.json（原地更新）
备份: mock_data/mock_packets_backup.json（自动创建）
"""

import json
import random
import shutil
from collections import defaultdict
from pathlib import Path


def inject_seq(packets: list[dict], anomaly_rate: float = 0.05) -> list[dict]:
    """
    为 TCP 报文注入 tcp_seq / tcp_ack 字段。

    Args:
        packets: 原始 mock 数据
        anomaly_rate: 注入乱序/重传的概率（0.0 ~ 1.0）

    Returns:
        注入 seq/ack 后的报文列表
    """
    # 按 flow_id 分组 TCP 报文
    flows: dict[str, list[tuple[int, dict]]] = defaultdict(list)
    for idx, pkt in enumerate(packets):
        if pkt.get("protocol") == "TCP":
            fid = pkt.get("flow_id", f"{pkt['src_ip']}:{pkt['src_port']}->{pkt['dst_ip']}:{pkt['dst_port']}/TCP")
            flows[fid].append((idx, pkt))

    anomaly_count = 0
    seq_stats = {"total_tcp": 0, "with_seq": 0, "anomalies": 0}

    for fid, indexed_pkts in flows.items():
        indexed_pkts.sort(key=lambda x: x[1].get("timestamp", ""))
        n = len(indexed_pkts)
        seq_stats["total_tcp"] += n

        # 随机生成 ISN
        client_isn = random.randint(10_000_000, 400_000_000)
        server_isn = random.randint(500_000_000, 900_000_000)

        # 方向状态: expected_seq 和 ack
        client_next = client_isn
        server_next = server_isn
        # 记录每个方向的最后发送的 seq（用于构建 ack）
        last_client_seq = None
        last_server_seq = None

        # 第一遍：分配 seq（按时间顺序）
        for i, (idx, pkt) in enumerate(indexed_pkts):
            direction = pkt.get("direction", "")
            flags = pkt.get("flags", "")
            plen = pkt.get("payload_len", 0) or 0

            if direction == "request":
                seq = client_next
                # 非 SYN 包通常 ack 确认对方发来的数据
                ack = server_next if last_server_seq is not None else 0
                is_syn = "S" in flags and "A" not in flags
                if is_syn:
                    client_next = (seq + 1) & 0xFFFFFFFF
                elif plen > 0:
                    client_next = (seq + plen) & 0xFFFFFFFF
                last_client_seq = seq
            elif direction == "response":
                seq = server_next
                ack = client_next if last_client_seq is not None else 0
                is_syn = "S" in flags and "A" not in flags
                # SYN-ACK handshake: server responds to client SYN
                if "S" in flags and "A" in flags:
                    ack = client_isn + 1 if client_isn else 0
                if is_syn:
                    server_next = (seq + 1) & 0xFFFFFFFF
                elif plen > 0:
                    server_next = (seq + plen) & 0xFFFFFFFF
                last_server_seq = seq
            else:
                seq = 0
                ack = 0

            # 注入异常: 乱序（seq偏移100-500字节）
            if anomaly_rate > 0 and random.random() < anomaly_rate and plen > 0:
                bias = random.randint(100, 500)
                seq = (seq + bias) & 0xFFFFFFFF
                anomaly_count += 1
                seq_stats["anomalies"] += 1

            # 注入异常: 重传（取上一包的seq，约3%概率）
            if anomaly_rate > 0 and random.random() < anomaly_rate * 0.6 and i > 0 and plen > 0:
                prev_idx = i - 1
                while prev_idx >= 0:
                    prev_pkt = indexed_pkts[prev_idx][1]
                    if prev_pkt.get("payload_len", 0) > 0 and prev_pkt.get("direction") == direction:
                        seq = prev_pkt.get("tcp_seq", seq)
                        anomaly_count += 1
                        seq_stats["anomalies"] += 1
                        break
                    prev_idx -= 1

            pkt["tcp_seq"] = seq
            pkt["tcp_ack"] = ack
            seq_stats["with_seq"] += 1

        # 第二遍：非TCP包设置 null
        # (already handled — only TCP packets modified)

    # 为非 TCP 包设置 null
    for pkt in packets:
        if pkt.get("protocol") != "TCP":
            pkt["tcp_seq"] = None
            pkt["tcp_ack"] = None
        # 确保 TCP 包有这两个字段（第二遍安全检查）
        elif "tcp_seq" not in pkt:
            pkt["tcp_seq"] = 0
            pkt["tcp_ack"] = 0

    return seq_stats


def main():
    project_root = Path(__file__).resolve().parent.parent
    mock_path = project_root / "mock_data" / "mock_packets.json"
    backup_path = project_root / "mock_data" / "mock_packets_backup.json"

    if not mock_path.exists():
        print(f"[ERROR] {mock_path} not found")
        return 1

    # 备份
    shutil.copy2(mock_path, backup_path)
    print(f"[备份] {backup_path}")

    # 加载
    with open(mock_path, "r", encoding="utf-8") as f:
        packets = json.load(f)
    print(f"[加载] {len(packets)} 条报文")

    # 注入 seq/ack
    stats = inject_seq(packets, anomaly_rate=0.05)
    print(f"[注入] TCP {stats['total_tcp']} 条, 异常注入 {stats['anomalies']} 处")

    # 写入
    with open(mock_path, "w", encoding="utf-8") as f:
        json.dump(packets, f, ensure_ascii=False, indent=2)
    print(f"[完成] {mock_path}")


if __name__ == "__main__":
    main()
