"""
基线建立模块 —— 姜新晨

基于正常流量数据建立主机行为基线：
- 并发连接数分布
- 访问频次分布
- 端口访问分布
- 会话时长分布
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "baseline_config.json"


def _parse_ts(timestamp: object) -> datetime | None:
    """解析 ISO8601 时间戳字符串为 datetime。"""
    if not isinstance(timestamp, str) or not timestamp:
        return None
    try:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        try:
            return datetime.strptime(timestamp[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None


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
    根据流量数据建立主机行为基线统计。

    对每台活跃主机统计以下维度的行为指标，用于与固定阈值互补的
    动态基线偏离判定（如均值 ± N 倍标准差）：

    - 并发连接数（同一秒内的活跃连接数）
    - 访问频次（单位时间内的报文数）
    - 端口访问分布（访问的不同目标端口数）
    - 会话时长分布（同一 flow_id 首尾包时间差）

    Args:
        packets: 报文列表（既可是纯正常流量，也可是混合流量）

    Returns:
        基线统计值字典，包含 per_ip 与 aggregate 两级统计
    """
    if not packets:
        logger.warning("输入报文为空，无法建立基线")
        return {"per_ip": {}, "aggregate": {}}

    # ---- 按源 IP 聚合 ----
    # 每 IP 记录:
    #   timestamps:     该 IP 发出的所有报文时间戳
    #   unique_dst_ips: 访问过哪些目标 IP
    #   unique_dst_ports: 访问过哪些目标端口
    #   flows:          {flow_id: [first_ts, last_ts]}  用于会话时长
    ip_raw: dict = defaultdict(lambda: {
        "timestamps": [],
        "unique_dst_ips": set(),
        "unique_dst_ports": set(),
        "flows": {},
    })

    for pkt in packets:
        if not isinstance(pkt, dict):
            continue
        src_ip = pkt.get("src_ip")
        if not src_ip:
            continue

        ts = _parse_ts(pkt.get("timestamp"))
        dst_ip = pkt.get("dst_ip")
        dst_port = pkt.get("dst_port")
        flow_id = pkt.get("flow_id")

        stats = ip_raw[src_ip]
        if ts is not None:
            stats["timestamps"].append(ts)
        if dst_ip:
            stats["unique_dst_ips"].add(dst_ip)
        if dst_port is not None:
            stats["unique_dst_ports"].add(dst_port)
        if flow_id and ts is not None:
            flow = stats["flows"].setdefault(flow_id, [ts, ts])
            if ts < flow[0]:
                flow[0] = ts
            if ts > flow[1]:
                flow[1] = ts

    # ---- 逐 IP 计算统计指标 ----
    per_ip: dict = {}
    all_conn_rates: list[float] = []
    all_port_counts: list[int] = []
    all_dst_counts: list[int] = []
    all_session_durations: list[float] = []

    for ip, raw in ip_raw.items():
        timestamps = sorted(raw["timestamps"])
        unique_dst_ip_count = len(raw["unique_dst_ips"])
        unique_dst_port_count = len(raw["unique_dst_ports"])

        # 并发连接数：按秒归并，取每秒最大报文数作为该秒并发近似值
        sec_buckets: dict[str, int] = defaultdict(int)
        for t in timestamps:
            sec_buckets[t.strftime("%Y-%m-%dT%H:%M:%S")] += 1
        max_concurrent = max(sec_buckets.values()) if sec_buckets else 0

        # 访问频次（报文/秒）：总报文数 / 时间跨度
        if len(timestamps) >= 2:
            total_span = (timestamps[-1] - timestamps[0]).total_seconds()
            conn_rate = len(timestamps) / total_span if total_span > 0 else 0
        else:
            conn_rate = 0

        # 会话时长统计
        session_durations: list[float] = []
        for first_ts, last_ts in raw["flows"].values():
            dur = (last_ts - first_ts).total_seconds()
            if dur >= 0:
                session_durations.append(dur)

        per_ip[ip] = {
            "packet_count": len(timestamps),
            "max_concurrent_per_sec": max_concurrent,
            "connection_rate_per_sec": round(conn_rate, 4),
            "unique_dst_ip_count": unique_dst_ip_count,
            "unique_dst_port_count": unique_dst_port_count,
            "avg_session_duration_sec": round(sum(session_durations) / len(session_durations), 2)
            if session_durations
            else 0,
            "max_session_duration_sec": round(max(session_durations), 2)
            if session_durations
            else 0,
        }

        all_conn_rates.append(conn_rate)
        all_port_counts.append(unique_dst_port_count)
        all_dst_counts.append(unique_dst_ip_count)
        all_session_durations.extend(session_durations)

    # ---- 全局聚合统计（用于动态阈值参考） ----
    def _mean_std(values: list[float]) -> dict:
        if not values:
            return {"mean": 0, "std": 0, "min": 0, "max": 0}
        n = len(values)
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        return {
            "mean": round(mean, 4),
            "std": round(variance ** 0.5, 4),
            "min": round(min(values), 4),
            "max": round(max(values), 4),
        }

    aggregate = {
        "active_ip_count": len(per_ip),
        "connection_rate_per_sec": _mean_std(all_conn_rates),
        "unique_dst_port_count": _mean_std([float(v) for v in all_port_counts]),
        "unique_dst_ip_count": _mean_std([float(v) for v in all_dst_counts]),
        "session_duration_sec": _mean_std(all_session_durations),
    }

    logger.info(
        "基线建立完成: %d 台活跃主机, 共 %d 条报文, %d 条会话",
        len(per_ip),
        len(packets),
        len(all_session_durations),
    )
    return {"per_ip": per_ip, "aggregate": aggregate}
