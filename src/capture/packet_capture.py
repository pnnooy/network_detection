"""
数据包捕获模块 —— 李哲

基于 scapy/libpcap 实现网络报文的实时捕获或离线读取。
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from .protocol_parser import parse_packet
from .tcp_reassembly import reassemble

logger = logging.getLogger(__name__)


def _packets_to_records(raw_packets, do_reassemble: bool = True) -> list[dict]:
    """将 scapy 原始报文列表转为标准化记录。"""
    records: list[dict] = []
    for raw in raw_packets:
        record = parse_packet(raw)
        if record is not None:
            records.append(record)

    if do_reassemble:
        return reassemble(records)
    return records


def capture_live(
    interface: str,
    count: int = 0,
    timeout: int = 60,
    do_reassemble: bool = True,
) -> list[dict]:
    """
    实时抓包。

    Args:
        interface: 网卡名称（如 eth0 / 以太网），需要管理员/root 权限
        count:    抓包数量，0 表示不限
        timeout:  超时秒数
        do_reassemble: 是否进行 TCP 流重组

    Returns:
        符合"报文记录格式"的列表
    """
    try:
        from scapy.all import sniff
    except ImportError as exc:
        logger.error("scapy 未安装: %s", exc)
        return []

    sniff_count = count if count > 0 else 0
    logger.info(
        "开始实时抓包: interface=%s count=%s timeout=%ds",
        interface,
        sniff_count or "unlimited",
        timeout,
    )

    try:
        raw_packets = sniff(iface=interface, count=sniff_count, timeout=timeout)
    except Exception as exc:
        logger.error("实时抓包失败: %s", exc)
        return []

    records = _packets_to_records(raw_packets, do_reassemble=do_reassemble)
    logger.info("实时抓包完成: 捕获 %d 条标准化记录", len(records))
    return records


def read_pcap(filepath: str, do_reassemble: bool = True) -> list[dict]:
    """
    从 pcap/pcapng 文件读取报文。

    Args:
        filepath: pcap 文件路径
        do_reassemble: 是否进行 TCP 流重组

    Returns:
        符合"报文记录格式"的列表
    """
    path = Path(filepath)
    if not path.exists():
        logger.warning("pcap 文件不存在: %s", path)
        return []

    try:
        from scapy.all import rdpcap
    except ImportError as exc:
        logger.error("scapy 未安装: %s", exc)
        return []

    try:
        raw_packets = rdpcap(str(path))
    except Exception as exc:
        logger.error("读取 pcap 失败: %s", exc)
        return []

    records = _packets_to_records(raw_packets, do_reassemble=do_reassemble)
    logger.info("pcap 读取完成: %s -> %d 条记录", path, len(records))
    return records


def save_packets(packets: list[dict], output_path: str) -> None:
    """将报文记录列表保存为 JSON 文件。"""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(packets, f, ensure_ascii=False, indent=2)
    logger.info("已保存 %d 条报文记录 -> %s", len(packets), out)


def main():
    """CLI 入口。"""
    parser = argparse.ArgumentParser(description="数据包捕获与协议解析")
    parser.add_argument("--pcap", help="离线 pcap 文件路径")
    parser.add_argument("--live", action="store_true", help="实时抓包模式")
    parser.add_argument("--interface", default="eth0", help="实时抓包网卡名称")
    parser.add_argument("--count", type=int, default=0, help="抓包数量，0 为不限")
    parser.add_argument("--timeout", type=int, default=60, help="抓包超时（秒）")
    parser.add_argument("--output", default="results/captured_packets.json", help="输出 JSON 路径")
    parser.add_argument("--no-reassemble", action="store_true", help="跳过 TCP 流重组")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="[%(name)s] %(levelname)s %(asctime)s %(message)s",
    )

    do_reassemble = not args.no_reassemble

    if args.live:
        packets = capture_live(args.interface, args.count, args.timeout, do_reassemble)
    elif args.pcap:
        packets = read_pcap(args.pcap, do_reassemble)
    else:
        logger.error("请指定 --pcap 或 --live")
        return

    save_packets(packets, args.output)
    print(f"捕获完成，共 {len(packets)} 条报文记录 → {args.output}")


if __name__ == "__main__":
    main()
