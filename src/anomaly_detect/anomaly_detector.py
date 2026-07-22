"""
异常行为检测模块 —— 姜新晨

基于统计基线与固定阈值，识别偏离正常行为模式的网络活动：
- 端口扫描（单IP短时间探测大量不同目标端口）
- 异常外联（内网主机主动连接陌生公网IP）
- 内网横向扩散（单IP短时间访问大量不同内网IP）
- 高频连接（单IP在短时间内发起大量连接，超过正常频次基线）

检测策略：
  - 以固定阈值为主要判定依据（阈值统一存放于 config/baseline_config.json）
  - 滑动时间窗口统计，确保不遗漏窗口边界附近的攻击行为
  - 同一攻击源在时间窗口内对同一目标发起的同类攻击，合并为单条行为告警

输出严格遵循 docs/interface_spec.md 第三节"统一告警格式"。
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .baseline import _parse_ts, load_config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
#  辅助工具
# ---------------------------------------------------------------------------

def _is_internal_ip(ip_str: str, internal_networks: list[str]) -> bool:
    """判断 IP 是否属于给定的内网 CIDR 列表。"""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        logger.debug("无效 IP 地址: %r", ip_str)
        return False
    for net_str in internal_networks:
        try:
            if addr in ipaddress.ip_network(net_str, strict=False):
                return True
        except ValueError:
            logger.debug("无效 CIDR 网段: %r", net_str)
    return False


def _infer_network(ip_str: str, prefix_len: int = 24) -> str | None:
    """从 IP 推断其所属 /24 CIDR 网段。"""
    try:
        addr = ipaddress.ip_address(ip_str)
        net = ipaddress.ip_network(f"{addr}/{prefix_len}", strict=False)
        return str(net)
    except ValueError:
        return None


def _sliding_window_unique_count(
    events: list[tuple[datetime, int]],
    window_sec: float,
) -> tuple[int, datetime | None]:
    """
    双指针滑动窗口，求任意 window_sec 秒内最大唯一值数量。

    Args:
        events:  已按时间升序排列的 (时间戳, 标签) 列表
        window_sec: 窗口长度（秒）

    Returns:
        (窗口内最大唯一标签数, 该窗口内最后一次事件的时间)
    """
    if not events:
        return 0, None

    left = 0
    best_count = 0
    best_ts = events[0][0]
    seen: dict[int, int] = defaultdict(int)  # label → 窗口内出现次数

    for right in range(len(events)):
        label = events[right][1]
        seen[label] += 1

        while (events[right][0] - events[left][0]).total_seconds() > window_sec:
            left_label = events[left][1]
            seen[left_label] -= 1
            if seen[left_label] == 0:
                del seen[left_label]
            left += 1

        if len(seen) > best_count:
            best_count = len(seen)
            best_ts = events[right][0]

    return best_count, best_ts


# ---------------------------------------------------------------------------
#  子检测逻辑
# ---------------------------------------------------------------------------

def _detect_port_scan(
    packets: list[dict],
    config: dict,
) -> list[dict]:
    """
    端口扫描检测。

    对同一 (src_ip, dst_ip) 分组，统计滑动时间窗口内访问的唯一目标端口数。
    超过阈值则判定为端口扫描行为。
    """
    time_window = config.get("time_window_sec", 60)
    threshold = config.get("unique_dst_port_threshold", 20)

    if not packets or threshold <= 0:
        return []

    # 按 (src_ip, dst_ip) 分组收集 (timestamp, dst_port)
    groups: dict[tuple[str, str], list[tuple[datetime, int]]] = defaultdict(list)
    for pkt in packets:
        if not isinstance(pkt, dict):
            continue
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        dst_port = pkt.get("dst_port")
        if not src_ip or not dst_ip or dst_port is None:
            continue
        ts = _parse_ts(pkt.get("timestamp"))
        if ts is None:
            continue
        groups[(src_ip, dst_ip)].append((ts, dst_port))

    alerts: list[dict] = []
    # 按 src_ip 归集，用于给同一源的扫描告警分配共享 behavior_id
    src_behavior: dict[str, str] = {}

    for (src_ip, dst_ip), events in groups.items():
        events.sort(key=lambda x: x[0])
        unique_count, best_ts = _sliding_window_unique_count(events, time_window)

        if unique_count < threshold:
            continue

        dst_network = _infer_network(dst_ip)
        severity = "high" if unique_count >= threshold * 2 else "medium"

        description = (
            f"检测到针对目标 {dst_network or dst_ip} 的端口扫描行为，"
            f"攻击源 {src_ip} 在 {time_window} 秒内向 {dst_ip} 探测了 "
            f"{unique_count} 个不同端口，超出基线阈值 {threshold} 个"
        )

        evidence = (
            f"unique_dst_port_count={unique_count}, "
            f"time_window_sec={time_window}, "
            f"threshold={threshold}"
        )

        # 同一 src_ip 的扫描告警共享 behavior_id
        if src_ip not in src_behavior:
            src_behavior[src_ip] = str(uuid.uuid4())
        behavior_id = src_behavior[src_ip]

        alert_id = str(uuid.uuid4())
        alerts.append({
            "alert_id": alert_id,
            "behavior_id": behavior_id,
            "detector": "anomaly",
            "category": "端口扫描",
            "src_ip": src_ip,
            "src_port": None,
            "dst_ip": dst_ip,
            "dst_network": dst_network,
            "dst_port": None,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "timestamp": best_ts.isoformat(timespec="milliseconds")
            if best_ts
            else datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds"),
        })
        logger.info(
            "端口扫描告警: %s → %s (%s), %d 个端口(窗口 %ds, 阈值 %d)",
            src_ip, dst_ip, dst_network, unique_count, time_window, threshold,
        )

    return alerts


def _detect_external_connection(
    packets: list[dict],
    config: dict,
) -> list[dict]:
    """
    异常外联检测。

    检查内网主机是否主动连接不在 internal_networks 范围内的公网 IP。
    对外联陌生 IP 的行为逐条产生告警，同一源 IP 的告警共享 behavior_id。
    """
    internal_networks: list[str] = config.get("internal_networks", [])
    if not internal_networks or not packets:
        return []

    # 按 src_ip 收集外联事件
    # 用 (src_ip, dst_ip, dst_port) 去重，避免同一连接的多个报文重复报警
    seen_pairs: set[tuple[str, str, int | None]] = set()
    external_events: dict[str, list[dict]] = defaultdict(list)

    for pkt in packets:
        if not isinstance(pkt, dict):
            continue
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        if not src_ip or not dst_ip:
            continue

        # 仅关注内网 → 外网的连接
        if not _is_internal_ip(src_ip, internal_networks):
            continue
        if _is_internal_ip(dst_ip, internal_networks):
            continue

        dst_port = pkt.get("dst_port")
        pair = (src_ip, dst_ip, dst_port)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)

        ts = _parse_ts(pkt.get("timestamp"))
        if ts is None:
            continue
        external_events[src_ip].append({
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "src_port": pkt.get("src_port"),
            "timestamp": ts.isoformat(timespec="milliseconds"),
            "ts_obj": ts,
        })

    alerts: list[dict] = []
    for src_ip, events in external_events.items():
        behavior_id = str(uuid.uuid4())
        for evt in events:
            alert_id = str(uuid.uuid4())
            dst_ip = evt["dst_ip"]
            dst_port = evt["dst_port"]
            port_info = f":{dst_port}" if dst_port is not None else ""

            description = (
                f"检测到内网主机 {src_ip} 异常外联陌生公网IP "
                f"{dst_ip}{port_info} 的行为，该IP不在已知外联白名单中，"
                f"疑似 C2 通信或数据外传"
            )

            evidence = (
                f"dst_ip={dst_ip}, "
                f"internal_networks={internal_networks}"
            )

            alerts.append({
                "alert_id": alert_id,
                "behavior_id": behavior_id,
                "detector": "anomaly",
                "category": "异常外联",
                "src_ip": src_ip,
                "src_port": evt["src_port"],
                "dst_ip": dst_ip,
                "dst_network": None,
                "dst_port": dst_port,
                "severity": "medium",
                "description": description,
                "evidence": evidence,
                "timestamp": evt["timestamp"],
            })
            logger.info(
                "异常外联告警: %s → %s%s",
                src_ip, dst_ip, port_info,
            )

    return alerts


def _detect_lateral_movement(
    packets: list[dict],
    lateral_config: dict,
    external_config: dict,
) -> list[dict]:
    """
    内网横向扩散检测。

    对同一源 IP，统计滑动时间窗口内访问的不同内网目标 IP 数量。
    超过阈值则判定为内网横向扩散行为。
    """
    time_window = lateral_config.get("time_window_sec", 300)
    threshold = lateral_config.get("internal_dst_count_threshold", 10)
    internal_networks: list[str] = external_config.get("internal_networks", [])

    if not packets or threshold <= 0 or not internal_networks:
        return []

    # 按 src_ip 分组收集 (timestamp, dst_ip)
    groups: dict[str, list[tuple[datetime, int]]] = defaultdict(list)
    # 用 hash(dst_ip) 作为标签，便于滑动窗口计数
    ip_to_label: dict[str, int] = {}
    _next_label = 0

    for pkt in packets:
        if not isinstance(pkt, dict):
            continue
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        if not src_ip or not dst_ip:
            continue

        # 仅关注内网 → 内网（同一源访问多个不同内网目标）
        if not _is_internal_ip(src_ip, internal_networks):
            continue
        if not _is_internal_ip(dst_ip, internal_networks):
            continue
        # 排除自身通信
        if src_ip == dst_ip:
            continue

        ts = _parse_ts(pkt.get("timestamp"))
        if ts is None:
            continue

        if dst_ip not in ip_to_label:
            ip_to_label[dst_ip] = _next_label
            _next_label += 1
        groups[src_ip].append((ts, ip_to_label[dst_ip]))

    alerts: list[dict] = []
    for src_ip, events in groups.items():
        events.sort(key=lambda x: x[0])
        unique_count, best_ts = _sliding_window_unique_count(events, time_window)

        if unique_count < threshold:
            continue

        severity = "high" if unique_count >= threshold * 2 else "medium"

        description = (
            f"检测到内网横向扩散行为，攻击源 {src_ip} 在 "
            f"{time_window} 秒（{time_window // 60} 分钟）内访问了 "
            f"{unique_count} 个不同内网IP，超出基线阈值 {threshold} 个，"
            f"疑似内网侦察或恶意软件横向传播"
        )

        evidence = (
            f"internal_dst_count={unique_count}, "
            f"time_window_sec={time_window}, "
            f"threshold={threshold}"
        )

        alert_id = str(uuid.uuid4())
        alerts.append({
            "alert_id": alert_id,
            "behavior_id": alert_id,
            "detector": "anomaly",
            "category": "内网横向扩散",
            "src_ip": src_ip,
            "src_port": None,
            "dst_ip": "multiple",
            "dst_network": internal_networks[0] if internal_networks else None,
            "dst_port": None,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "timestamp": best_ts.isoformat(timespec="milliseconds")
            if best_ts
            else datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds"),
        })
        logger.info(
            "横向扩散告警: %s, %d 个内网IP(窗口 %ds, 阈值 %d)",
            src_ip, unique_count, time_window, threshold,
        )

    return alerts


def _detect_high_frequency(
    packets: list[dict],
    config: dict,
) -> list[dict]:
    """
    高频连接检测（连接速率异常）。

    对同一源 IP，统计滑动时间窗口内的连接次数。
    超过阈值则判定为异常高频连接行为（可能为 DoS 或蠕虫传播）。
    """
    time_window = config.get("time_window_sec", 60)
    threshold = config.get("max_connections_per_ip", 100)

    if not packets or threshold <= 0:
        return []

    # 按 src_ip 收集时间戳
    groups: dict[str, list[datetime]] = defaultdict(list)
    for pkt in packets:
        if not isinstance(pkt, dict):
            continue
        src_ip = pkt.get("src_ip")
        if not src_ip:
            continue
        ts = _parse_ts(pkt.get("timestamp"))
        if ts is None:
            continue
        groups[src_ip].append(ts)

    alerts: list[dict] = []
    for src_ip, timestamps in groups.items():
        timestamps.sort()
        left = 0
        best_count = 0
        best_ts = timestamps[0] if timestamps else None

        for right in range(len(timestamps)):
            while (timestamps[right] - timestamps[left]).total_seconds() > time_window:
                left += 1
            count = right - left + 1
            if count > best_count:
                best_count = count
                best_ts = timestamps[right]

        if best_count < threshold:
            continue

        severity = "high" if best_count >= threshold * 2 else "medium"

        description = (
            f"检测到异常高频连接行为，主机 {src_ip} 在 "
            f"{time_window} 秒内发起 {best_count} 次连接，"
            f"超出基线阈值 {threshold} 次，疑似 DoS 攻击或蠕虫传播"
        )

        evidence = (
            f"connection_count={best_count}, "
            f"time_window_sec={time_window}, "
            f"threshold={threshold}"
        )

        alert_id = str(uuid.uuid4())
        alerts.append({
            "alert_id": alert_id,
            "behavior_id": alert_id,
            "detector": "anomaly",
            "category": "异常高频连接",
            "src_ip": src_ip,
            "src_port": None,
            "dst_ip": "multiple",
            "dst_network": None,
            "dst_port": None,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "timestamp": best_ts.isoformat(timespec="milliseconds")
            if best_ts
            else datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds"),
        })
        logger.info(
            "高频连接告警: %s, %d 次连接(窗口 %ds, 阈值 %d)",
            src_ip, best_count, time_window, threshold,
        )

    return alerts


# ---------------------------------------------------------------------------
#  主检测入口
# ---------------------------------------------------------------------------

def detect(packets: list[dict], config: dict | None = None) -> list[dict]:
    """
    异常行为检测主入口。

    依次执行端口扫描、异常外联、内网横向扩散、高频连接四项检测，
    汇总所有告警并按时间排序返回。

    Args:
        packets: 符合"报文记录格式"的列表
        config:  基线阈值配置字典，为 None 时自动从 config/baseline_config.json 加载

    Returns:
        符合"统一告警格式"的列表（无告警时返回空列表 []，不返回 None）
    """
    if not packets:
        logger.warning("输入报文为空，返回空告警列表")
        return []

    if config is None:
        config = load_config()

    all_alerts: list[dict] = []

    # 端口扫描检测
    port_scan_cfg = config.get("port_scan", {})
    all_alerts.extend(_detect_port_scan(packets, port_scan_cfg))

    # 异常外联检测
    external_cfg = config.get("external_connection", {})
    all_alerts.extend(_detect_external_connection(packets, external_cfg))

    # 内网横向扩散检测
    lateral_cfg = config.get("lateral_movement", {})
    all_alerts.extend(_detect_lateral_movement(packets, lateral_cfg, external_cfg))

    # 高频连接检测
    conn_rate_cfg = config.get("connection_rate", {})
    all_alerts.extend(_detect_high_frequency(packets, conn_rate_cfg))

    # 按时间戳排序
    all_alerts.sort(key=lambda a: a["timestamp"])

    logger.info(
        "异常检测完成: 扫描 %d 条报文, 产生 %d 条告警 "
        "(端口扫描=%d, 异常外联=%d, 横向扩散=%d, 高频连接=%d)",
        len(packets),
        len(all_alerts),
        sum(1 for a in all_alerts if a["category"] == "端口扫描"),
        sum(1 for a in all_alerts if a["category"] == "异常外联"),
        sum(1 for a in all_alerts if a["category"] == "内网横向扩散"),
        sum(1 for a in all_alerts if a["category"] == "异常高频连接"),
    )
    return all_alerts


# ---------------------------------------------------------------------------
#  CLI 入口
# ---------------------------------------------------------------------------

def main():
    """CLI 入口。"""
    parser = argparse.ArgumentParser(description="异常行为检测引擎")
    parser.add_argument("--input", required=True, help="输入报文 JSON 文件路径")
    parser.add_argument("--output", required=True, help="输出告警 JSON 文件路径")
    parser.add_argument("--config", default=None, help="基线配置文件路径（可选）")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="[%(name)s] %(levelname)s %(asctime)s %(message)s",
    )

    # 加载报文
    input_path = Path(args.input)
    if not input_path.exists():
        logger.warning("输入文件不存在: %s", args.input)
        packets = []
    else:
        try:
            with open(input_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            packets = data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError) as e:
            logger.error("读取输入文件失败: %s, 错误: %s", args.input, e)
            packets = []

    # 加载配置并检测
    cfg = load_config(args.config) if args.config else None
    alerts = detect(packets, cfg)

    # 写结果
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, ensure_ascii=False, indent=2)

    print(f"异常检测完成，产生 {len(alerts)} 条告警 → {out_path}")


if __name__ == "__main__":
    main()
