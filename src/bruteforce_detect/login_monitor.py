"""
登录行为监控与暴力破解判定模块 —— 陈志恒

监控 SSH(22)、FTP(21)、Telnet(23)、RDP(3389)、数据库、Web 登录等端口的
连接与认证尝试，基于时间窗口的滑动计数识别暴力破解 / 非法登录行为。

判定思路（对应 README 5.C）：
  - 以"新建连接尝试"为计数单位。TCP 中一次登录尝试通常对应一次新连接，
    表现为一个 SYN 报文（flags 含 S 且不含 A）。
  - 对同一 (源IP → 目标IP:登录端口) 分组，统计任意 ``time_window_sec`` 秒
    滑动窗口内的连接尝试次数，达到/超过 ``threshold`` 即判定为暴力破解行为，
    聚合为一条攻击行为告警（而非逐包报警）。
  - 结合 direction / flags 字段辅助判断连接是否被目标拒绝（RST），作为佐证。

输出严格遵循 docs/interface_spec.md 第三节"统一告警格式"。
"""

from __future__ import annotations

import argparse
import json
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# 默认监控的登录 / 认证类端口
LOGIN_PORTS = {21, 22, 23, 3389, 3306, 5432, 6379, 8080, 8443}
# 默认时间窗口（秒）
DEFAULT_TIME_WINDOW_SEC = 60
# 默认连接次数阈值（窗口内达到该值即告警）
DEFAULT_THRESHOLD = 10

# 端口 → 服务名，用于生成行为导向的告警描述
_SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "Web",
    8443: "Web(HTTPS)",
}


def _service_name(port: int | None) -> str:
    """将端口映射为可读服务名。"""
    if port in _SERVICE_NAMES:
        return _SERVICE_NAMES[port]
    return f"{port} 端口服务"


def _parse_ts(timestamp: object) -> datetime | None:
    """
    解析 ISO8601 时间戳字符串为 datetime。

    兼容 ``Z`` 后缀与毫秒精度；无法解析时返回 None（调用方跳过该报文的时间判断）。
    """
    if not isinstance(timestamp, str) or not timestamp:
        return None
    try:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        # 退化处理：仅取到秒
        try:
            return datetime.strptime(timestamp[:19], "%Y-%m-%dT%H:%M:%S")
        except (ValueError, TypeError):
            logger.debug("无法解析时间戳: %r", timestamp)
            return None


def _is_syn_attempt(packet: dict) -> bool:
    """判断报文是否为一次新建连接尝试（TCP SYN 且非 SYN+ACK）。"""
    flags = packet.get("flags") or ""
    return "S" in flags and "A" not in flags


def _max_count_in_window(
    events: list[datetime], window_sec: int
) -> tuple[int, datetime | None]:
    """
    双指针求任意 ``window_sec`` 秒滑动窗口内的最大事件数。

    Args:
        events:      已按时间升序排列的事件时间列表
        window_sec:  窗口长度（秒）

    Returns:
        (窗口内最大事件数, 该最大窗口内最后一次事件的时间)
    """
    if not events:
        return 0, None

    left = 0
    best_count = 0
    best_ts = events[0]
    for right in range(len(events)):
        while (events[right] - events[left]).total_seconds() > window_sec:
            left += 1
        count = right - left + 1
        if count > best_count:
            best_count = count
            best_ts = events[right]
    return best_count, best_ts


def _collect_attempts(
    packets: list[dict], login_ports: set[int]
) -> tuple[dict, dict]:
    """
    扫描报文，按 (src_ip, dst_ip, dst_port) 归集"连接尝试"事件，
    并统计目标对攻击源的拒绝(RST)响应次数。

    连接尝试的判定：
      - 优先使用 SYN 报文（一次 SYN = 一次新建连接尝试）；
      - 若某分组不含任何 SYN（真实抓包可能缺失 flags 字段），
        退化为按 request 方向报文的不同 flow_id（连接）计数，
        每条连接计一次尝试，避免把同一会话的多个数据包重复计数。

    Returns:
        (attempts, rejects)
        attempts: {(src_ip, dst_ip, dst_port): {"syn": [ts...],
                                                 "flows": {flow_id: ts}}}
        rejects:  {(attacker_ip, victim_ip, dst_port): rejected_count}
    """
    attempts: dict = defaultdict(lambda: {"syn": [], "flows": {}})
    rejects: dict = defaultdict(int)

    for pkt in packets:
        if not isinstance(pkt, dict):
            continue

        protocol = pkt.get("protocol")
        # 暴力破解基于面向连接的 TCP；协议缺失时也放行由后续 flags 判断
        if protocol not in (None, "TCP"):
            # 记录 RST 拒绝响应（可能出现在其它协议判断之外，但通常为 TCP）
            pass

        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        dst_port = pkt.get("dst_port")
        flags = pkt.get("flags") or ""
        direction = pkt.get("direction")

        # 1) 统计目标 → 源方向的 RST 拒绝响应（辅助佐证：连接被拒绝）
        #    此类报文的 src 为受害目标，源端口才是登录端口。
        if "R" in flags and pkt.get("src_port") in login_ports and src_ip and dst_ip:
            rejects[(dst_ip, src_ip, pkt.get("src_port"))] += 1
            continue

        # 2) 仅关注指向登录端口的报文
        if dst_port not in login_ports or not src_ip or not dst_ip:
            continue
        # 明确的响应报文（服务器回包）不计为攻击尝试
        if direction == "response":
            continue

        key = (src_ip, dst_ip, dst_port)
        ts = _parse_ts(pkt.get("timestamp"))

        if _is_syn_attempt(pkt):
            if ts is not None:
                attempts[key]["syn"].append(ts)
        elif direction == "request" or protocol in (None, "TCP"):
            # 退化统计：按连接(flow_id)去重，一条连接记一次尝试
            flow_id = pkt.get("flow_id") or f"{src_ip}:{pkt.get('src_port')}->{dst_ip}:{dst_port}"
            if flow_id not in attempts[key]["flows"] and ts is not None:
                attempts[key]["flows"][flow_id] = ts

    return attempts, rejects


def detect(
    packets: list[dict],
    time_window_sec: int = DEFAULT_TIME_WINDOW_SEC,
    threshold: int = DEFAULT_THRESHOLD,
    login_ports: set[int] | None = None,
) -> list[dict]:
    """
    检测暴力破解 / 非法登录行为。

    Args:
        packets:          符合"报文记录格式"的列表
        time_window_sec:  时间窗口（秒），默认 60
        threshold:        窗口内连接尝试次数阈值，默认 10
        login_ports:      需监控的登录端口集合，默认 :data:`LOGIN_PORTS`

    Returns:
        符合"统一告警格式"的列表（无告警时返回空列表 []，不返回 None）
    """
    if not packets:
        logger.warning("输入报文为空，返回空告警列表")
        return []
    if login_ports is None:
        login_ports = LOGIN_PORTS

    attempts, rejects = _collect_attempts(packets, login_ports)
    alerts: list[dict] = []

    for (src_ip, dst_ip, dst_port), data in attempts.items():
        # 优先采用 SYN 计数；无 SYN 时退化为按连接计数
        if data["syn"]:
            events = sorted(data["syn"])
        else:
            events = sorted(data["flows"].values())

        if len(events) < threshold:
            continue

        best_count, best_ts = _max_count_in_window(events, time_window_sec)
        if best_count < threshold:
            continue

        rejected = rejects.get((src_ip, dst_ip, dst_port), 0)
        service = _service_name(dst_port)
        # 严重程度：达到 2 倍阈值判定为 high，否则 medium
        severity = "high" if best_count >= threshold * 2 else "medium"

        description = (
            f"检测到针对 {service} 服务({dst_port}端口)的暴力破解行为，"
            f"攻击源 {src_ip} 在 {time_window_sec} 秒内向 {dst_ip} 发起 "
            f"{best_count} 次连接尝试，超出基线阈值 {threshold} 次"
        )
        if rejected > 0:
            description += f"，其中 {rejected} 次连接被目标拒绝(RST)，疑似认证失败"

        evidence = (
            f"attempt_count={best_count}, time_window_sec={time_window_sec}, "
            f"threshold={threshold}"
        )
        if rejected > 0:
            evidence += f", rejected_conn={rejected}"

        alert_id = str(uuid.uuid4())
        alert = {
            "alert_id": alert_id,
            # 每个分组即一个攻击行为事件，检测模块直接标注 behavior_id
            "behavior_id": alert_id,
            "detector": "bruteforce",
            "category": "暴力破解/非法登录",
            "src_ip": src_ip,
            "src_port": None,  # 暴力破解跨多个临时源端口，不指定单一端口
            "dst_ip": dst_ip,
            "dst_network": None,
            "dst_port": dst_port,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "timestamp": best_ts.isoformat(timespec="milliseconds")
            if best_ts is not None
            else datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds"),
        }
        alerts.append(alert)
        logger.info(
            "暴力破解告警: %s → %s:%s, %d 次尝试(窗口 %ds, 阈值 %d), 拒绝 %d 次",
            src_ip, dst_ip, dst_port, best_count, time_window_sec, threshold, rejected,
        )

    # 按时间排序，输出稳定
    alerts.sort(key=lambda a: a["timestamp"])
    logger.info("暴力破解检测完成: 扫描 %d 条报文, 产生 %d 条告警", len(packets), len(alerts))
    return alerts


def _load_packets(input_path: str) -> list[dict]:
    """从 JSON 文件加载报文列表，异常时记录日志并返回空列表。"""
    path = Path(input_path)
    if not path.exists():
        logger.warning("输入文件不存在: %s", input_path)
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("读取输入文件失败: %s, 错误: %s", input_path, e)
        return []
    if not isinstance(data, list):
        logger.warning("输入文件格式异常（非列表）: %s", input_path)
        return []
    return data


def main() -> None:
    """CLI 入口。"""
    parser = argparse.ArgumentParser(description="暴力破解 / 非法登录检测引擎")
    parser.add_argument("--input", required=True, help="输入报文 JSON 文件路径")
    parser.add_argument("--output", required=True, help="输出告警 JSON 文件路径")
    parser.add_argument("--window", type=int, default=DEFAULT_TIME_WINDOW_SEC, help="时间窗口（秒）")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD, help="连接次数阈值")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="[%(name)s] %(levelname)s %(asctime)s %(message)s",
    )

    packets = _load_packets(args.input)
    alerts = detect(packets, args.window, args.threshold)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, ensure_ascii=False, indent=2)

    print(f"暴力破解检测完成，产生 {len(alerts)} 条告警 → {out_path}")


if __name__ == "__main__":
    main()
