"""
登录行为监控与暴力破解判定模块 —— 陈志恒

监控 SSH(22)、FTP(21)、Web 登录等端口的连接与认证尝试，
基于时间窗口统计识别暴力破解行为。
"""

import argparse
import json
import logging
import uuid
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)

# 默认监控的登录端口
LOGIN_PORTS = {21, 22, 23, 3389, 3306, 5432, 6379, 8080, 8443}
# 默认时间窗口（秒）
DEFAULT_TIME_WINDOW_SEC = 60
# 默认连接次数阈值
DEFAULT_THRESHOLD = 10


def detect(
    packets: list[dict],
    time_window_sec: int = DEFAULT_TIME_WINDOW_SEC,
    threshold: int = DEFAULT_THRESHOLD,
    login_ports: set[int] | None = None,
) -> list[dict]:
    """
    检测暴力破解行为。

    Args:
        packets:          符合"报文记录格式"的列表
        time_window_sec:  时间窗口（秒）
        threshold:        窗口内连接次数阈值
        login_ports:      需监控的登录端口集合

    Returns:
        符合"统一告警格式"的列表（无告警时返回空列表）
    """
    if login_ports is None:
        login_ports = LOGIN_PORTS

    alerts: list[dict] = []
    # 按 (src_ip, dst_ip, dst_port) 分组统计连接次数
    # TODO: Phase2 实现基于时间窗口的滑动计数
    # 当前仅提供函数签名与接口骨架

    logger.info("暴力破解检测完成: 扫描 %d 条报文, 产生 %d 条告警", len(packets), len(alerts))
    return alerts


def main():
    """CLI 入口。"""
    parser = argparse.ArgumentParser(description="暴力破解检测引擎")
    parser.add_argument("--input", required=True, help="输入报文 JSON 文件路径")
    parser.add_argument("--output", required=True, help="输出告警 JSON 文件路径")
    parser.add_argument("--window", type=int, default=DEFAULT_TIME_WINDOW_SEC, help="时间窗口（秒）")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD, help="连接次数阈值")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[bruteforce] %(levelname)s %(asctime)s %(message)s")

    with open(args.input, "r", encoding="utf-8") as f:
        packets = json.load(f)

    alerts = detect(packets, args.window, args.threshold)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, ensure_ascii=False, indent=2)

    print(f"暴力破解检测完成，产生 {len(alerts)} 条告警 → {out_path}")


if __name__ == "__main__":
    main()
