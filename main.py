"""
网络攻击检测系统 —— 主入口（韩宇飞维护）

用法:
    # 运行全链路（mock 数据）
    python main.py --input mock_data/mock_packets.json

    # 实时抓包模式（Phase4+）
    python main.py --live --interface eth0

    # 仅运行 GUI（读取已有告警）
    python main.py --gui-only
"""

import argparse
import json
import logging
import sys
from pathlib import Path

# 将项目根目录加入 sys.path，确保模块可导入
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.gui_alert.aggregator import aggregate, save_merged

logger = logging.getLogger(__name__)


def run_detection_pipeline(input_file: str, output_dir: str = "results") -> dict[str, str]:
    """
    运行完整的检测管线：调用 B/C/D 三个模块。

    Args:
        input_file: 输入报文 JSON 文件路径
        output_dir: 输出目录

    Returns:
        {模块名: 输出文件路径} 的映射
    """
    from src.signature_engine.matcher import detect as sig_detect
    from src.bruteforce_detect.login_monitor import detect as bf_detect
    from src.anomaly_detect.anomaly_detector import detect as anom_detect

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


def main():
    parser = argparse.ArgumentParser(description="网络攻击检测系统")
    parser.add_argument("--input", default="mock_data/mock_packets.json", help="输入报文 JSON 文件路径")
    parser.add_argument("--output-dir", default="results", help="告警输出目录")
    parser.add_argument("--live", action="store_true", help="实时抓包模式（Phase4+）")
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
        logger.error("实时抓包模式尚未实现，请等待 Phase4")
        sys.exit(1)

    # 默认：运行检测管线 + 汇总
    logger.info("=== 网络攻击检测系统启动 ===")
    outputs = run_detection_pipeline(args.input, args.output_dir)

    # 汇总告警
    merged = aggregate(list(outputs.values()))
    merged_path = Path(args.output_dir) / "merged_alerts.json"
    save_merged(merged, str(merged_path))

    # 打印摘要
    print("\n" + "=" * 50)
    print("检测完成摘要")
    print("=" * 50)
    for module, path in outputs.items():
        print(f"  {module}: {path}")
    print(f"  汇总: {merged_path} ({len(merged)} 条告警)")
    print("=" * 50)


if __name__ == "__main__":
    main()
