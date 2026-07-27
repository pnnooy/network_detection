"""
网络攻击检测系统 —— 主入口（韩宇飞维护）

用法:
    # 运行全链路（mock 数据）
    python main.py --input mock_data/mock_packets.json

    # 实时抓包 + 检测（配合 live_capture.py）
    python main.py --watch 3 --input results/live_capture.json

    # 仅运行 GUI（读取已有告警）
    python main.py --gui-only
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path

# 将项目根目录加入 sys.path，确保模块可导入
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.gui_alert.aggregator import aggregate, save_merged

logger = logging.getLogger(__name__)


def run_detection_pipeline(input_file: str, output_dir: str = "results",
                          packets: list[dict] | None = None) -> dict[str, str]:
    """
    运行完整的检测管线：调用 B/C/D 三个模块。

    Args:
        input_file: 输入报文 JSON 文件路径
        output_dir: 输出目录
        packets: 预加载的报文列表，为 None 时从 input_file 读取

    Returns:
        {模块名: 输出文件路径} 的映射
    """
    from src.signature_engine.matcher import detect as sig_detect
    from src.bruteforce_detect.login_monitor import detect as bf_detect
    from src.anomaly_detect.anomaly_detector import detect as anom_detect

    if packets is None:
        with open(input_file, "r", encoding="utf-8") as f:
            packets = json.load(f)

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    outputs = {}

    # 特征匹配
    sig_alerts = sig_detect(packets)
    sig_path = out_dir / "signature_alerts.json"
    with open(sig_path, "w", encoding="utf-8") as f:
        json.dump(sig_alerts, f, ensure_ascii=False, indent=2)
    outputs["signature"] = str(sig_path)
    logger.info("特征匹配: %d 条告警 → %s", len(sig_alerts), sig_path)

    # 暴力破解
    bf_alerts = bf_detect(packets)
    bf_path = out_dir / "bruteforce_alerts.json"
    with open(bf_path, "w", encoding="utf-8") as f:
        json.dump(bf_alerts, f, ensure_ascii=False, indent=2)
    outputs["bruteforce"] = str(bf_path)
    logger.info("暴力破解: %d 条告警 → %s", len(bf_alerts), bf_path)

    # 异常检测
    anom_alerts = anom_detect(packets)
    anom_path = out_dir / "anomaly_alerts.json"
    with open(anom_path, "w", encoding="utf-8") as f:
        json.dump(anom_alerts, f, ensure_ascii=False, indent=2)
    outputs["anomaly"] = str(anom_path)
    logger.info("异常检测: %d 条告警 → %s", len(anom_alerts), anom_path)

    return outputs


def watch_loop(input_file: str, output_dir: str, interval: int) -> None:
    """
    持续监控模式：每 interval 秒重新读取 capture 文件并运行检测。

    仅当文件更新时（文件大小/内容变化）才触发检测，避免重复计算。

    Args:
        input_file: 监测的 capture JSON 文件路径
        output_dir: 输出目录
        interval: 轮询间隔（秒）
    """
    import os

    last_size = -1
    cycle = 0
    logger.info("Watch 模式启动: interval=%ds, monitoring=%s", interval, input_file)
    print(f"\n  [Watch] 监控中 {input_file} (每 {interval}s 检测一次)")

    while True:
        try:
            time.sleep(interval)
            cycle += 1

            if not os.path.exists(input_file):
                continue

            current_size = os.path.getsize(input_file)
            force = (cycle % 10 == 0)  # 每 10 轮强制重检
            if current_size == last_size and last_size >= 0 and not force:
                continue
            last_size = current_size

            with open(input_file, "r", encoding="utf-8") as f:
                packets = json.load(f)

            # 若有清空基线，只检测基线之后的新包
            baseline_file = Path(output_dir) / "baseline_count.txt"
            if baseline_file.exists():
                try:
                    baseline = int(baseline_file.read_text().strip())
                    if baseline > 0 and baseline < len(packets):
                        packets = packets[baseline:]
                    elif baseline >= len(packets):
                        packets = []
                except (ValueError, FileNotFoundError):
                    pass

            if not packets:
                continue

            outputs = run_detection_pipeline(input_file, output_dir, packets=packets)

            # 汇总
            merged = aggregate(list(outputs.values()))
            merged_path = Path(output_dir) / "merged_alerts.json"
            save_merged(merged, str(merged_path))

            total_alerts = len(merged)
            # 从 output dict 取 count（run_detection_pipeline 不直接返回 count，用 len 读文件）
            sig_cnt = len(json.load(open(outputs["signature"], encoding="utf-8")))
            bf_cnt = len(json.load(open(outputs["bruteforce"], encoding="utf-8")))
            anom_cnt = len(json.load(open(outputs["anomaly"], encoding="utf-8")))
            ts = time.strftime("%H:%M:%S")
            print(f"  [{ts}] {len(packets)} pkts -> {total_alerts} alerts (sig={sig_cnt} bf={bf_cnt} anom={anom_cnt})", flush=True)

        except json.JSONDecodeError:
            pass  # 文件正在写入中，等下一轮
        except KeyboardInterrupt:
            print("\n  [Watch] 已停止")
            break
        except Exception as e:
            logger.error("Watch 轮询异常: %s", e)


def main():
    parser = argparse.ArgumentParser(description="网络攻击检测系统")
    parser.add_argument("--input", default="mock_data/mock_packets.json", help="输入报文 JSON 文件路径")
    parser.add_argument("--output-dir", default="results", help="告警输出目录")
    parser.add_argument("--watch", type=int, default=0, metavar="SEC",
                        help="持续监控模式：每 SEC 秒检测一次（如 --watch 3）")
    parser.add_argument("--live", action="store_true", help="实时抓包模式（已废弃，请用 demo/live_capture.py）")
    parser.add_argument("--interface", default="eth0", help="实时抓包网卡名称")
    parser.add_argument("--gui-only", action="store_true", help="仅启动 GUI（tkinter 桌面版，不运行检测）")
    parser.add_argument("--web", action="store_true", help="启动 Web 监控面板（浏览器访问）")
    parser.add_argument("--web-port", type=int, default=8099, help="Web 面板端口（默认 8099）")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="[%(name)s] %(levelname)s %(asctime)s %(message)s",
    )

    if args.gui_only:
        from src.gui_alert.gui import launch_gui
        launch_gui()
        return

    if args.web:
        from src.gui_alert.web_gui import main as web_main
        sys.argv = ["web_gui", "--port", str(args.web_port)]
        web_main()
        return

    if args.live:
        logger.error("--live 已废弃，请用: python demo/live_capture.py")
        sys.exit(1)

    # 持续监控模式
    if args.watch > 0:
        watch_loop(args.input, args.output_dir, args.watch)
        return

    # 默认：单次检测管线 + 汇总
    logger.info("=== 网络攻击检测系统启动 ===")
    outputs = run_detection_pipeline(args.input, args.output_dir)

    merged = aggregate(list(outputs.values()))
    merged_path = Path(args.output_dir) / "merged_alerts.json"
    save_merged(merged, str(merged_path))

    print("\n" + "=" * 50)
    print("检测完成摘要")
    print("=" * 50)
    for module, path in outputs.items():
        print(f"  {module}: {path}")
    print(f"  汇总: {merged_path} ({len(merged)} 条告警)")
    print("=" * 50)


if __name__ == "__main__":
    main()
