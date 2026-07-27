"""Windows Npcap 实时抓包 —— 用于跨机器演示。

用法：python demo/live_capture.py <interface> <output.json> [timeout]
示例：python demo/live_capture.py "VMware Network Adapter VMnet8" results/live_capture.json

关键设计：边抓边存（每 10 包 flush 一次），进程被强行终止也不丢太多数据。
"""

import sys, json, os, time

# 接口名通过环境变量 CAPTURE_IFACE 传入（CMD 空格传参不可靠）
# 用法: set CAPTURE_IFACE=VMware Network Adapter VMnet8 && python demo/live_capture.py results/live_capture.json 300
iface = os.environ.get("CAPTURE_IFACE", sys.argv[1] if len(sys.argv) > 1 else "lo")
iface = iface.strip()  # 去掉 CMD set 命令可能带入的首尾空格
output = sys.argv[1] if len(sys.argv) > 1 else "results/live_capture.json"
timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 120

os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ".")

from scapy.all import sniff
from src.capture.protocol_parser import parse_packet

records = []
last_flush = time.time()

def save_one(pkt):
    global last_flush
    r = parse_packet(pkt)
    if r:
        records.append(r)
    # 每 10 包或每 2 秒 flush 一次到磁盘
    if len(records) > 0 and (len(records) % 10 == 0 or time.time() - last_flush > 2):
        _write()
        last_flush = time.time()

def _write():
    if records:
        tmp = output + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False, indent=2)
        os.replace(tmp, output)  # 原子替换，避免写到一半被读到
        print(f"[sniffer] {len(records)} records written", flush=True)

print(f"[sniffer] capturing on {iface}, timeout={timeout}s, output={output}", flush=True)
try:
    sniff(iface=iface, timeout=timeout, prn=save_one, store=0)
except KeyboardInterrupt:
    print("[sniffer] interrupted", flush=True)
except Exception as e:
    print(f"[sniffer] error: {e}", flush=True)

_write()
print(f"[sniffer] done: {len(records)} records saved to {output}", flush=True)
