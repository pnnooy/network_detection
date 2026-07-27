#!/bin/bash
# ============================================================================
# 一键启动：靶机服务 + 实时抓包 + 攻击执行 + 检测报告
#
# 用法:
#   sudo bash demo/run_live_demo.sh              # 完整演示（本机 lo 回环）
#   sudo bash demo/run_live_demo.sh --quick      # 快速演示（减少攻击次数）
#   sudo bash demo/run_live_demo.sh --attack-only # 仅攻击（不抓包，用于测试靶机）
#
# 跨机器演示（Kali 攻击 Windows）:
#   sudo TARGET_IP=192.168.xxx.1 CAPTURE_IFACE=eth0 bash demo/run_live_demo.sh
#
# 环境要求: Linux (Ubuntu 22.04+) / WSL2 + root 权限
# 前置安装: pip install scapy
# 跨机器时: 靶机端需开启 sshd + 防火墙放行端口 8080 和 22
# ============================================================================

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ATTACK_DIR="$SCRIPT_DIR/attack_scripts"
RESULTS_DIR="$PROJECT_DIR/results"

# ---- 可配置参数（支持环境变量覆盖） ----
TARGET_IP="${TARGET_IP:-127.0.0.1}"                # 靶机 IP（跨机器时改为 Windows IP）
TARGET_HTTP="${TARGET_HTTP:-127.0.0.1:8080}"        # HTTP 靶机地址（含端口）
CAPTURE_IFACE="${CAPTURE_IFACE:-lo}"                 # 抓包网卡（跨机器时改为 eth0/ens33）
SKIP_TARGET="${SKIP_TARGET:-0}"                      # 跨机器时设为 1，跳过本地靶机启动

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

MODE="${1:---full}"

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║    网络攻击检测系统 —— 真实攻击演示                    ║"
    echo "║    Network Attack Detection — Live Demo               ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[错误] 需要 root 权限运行（scapy 抓包必需）${NC}"
        echo "  请用: sudo bash demo/run_live_demo.sh"
        exit 1
    fi
}

check_deps() {
    echo -e "${YELLOW}[检查] 环境依赖...${NC}"

    if ! python3 -c "import scapy" 2>/dev/null; then
        echo -e "${RED}[错误] scapy 未安装${NC}"
        echo "  请运行: pip install scapy"
        exit 1
    fi
    echo "  scapy .............. OK"

    if ! python3 -c "import tkinter" 2>/dev/null; then
        echo -e "${YELLOW}  tkinter 未安装 (GUI 将不可用，检测仍正常)${NC}"
    else
        echo "  tkinter ............ OK"
    fi

    echo -e "${GREEN}[检查] 依赖就绪${NC}"
}

start_target() {
    echo -e "${YELLOW}[启动] 靶机 HTTP 服务 (0.0.0.0:8080)...${NC}"
    python3 "$PROJECT_DIR/demo/target_server.py" &
    TARGET_PID=$!
    sleep 1

    if ! kill -0 $TARGET_PID 2>/dev/null; then
        echo -e "${RED}[错误] 靶机服务启动失败${NC}"
        exit 1
    fi
    echo -e "${GREEN}  靶机 PID: $TARGET_PID${NC}"
}

start_capture() {
    echo -e "${YELLOW}[启动] scapy 实时抓包 (${CAPTURE_IFACE} 接口, 120s)...${NC}"

    # 后台启动抓包，输出到 results/live_capture.json
    # 用 prn 回调边抓边存——被 kill 时已捕获的报文不会丢失
    python3 -c "
import json, sys, signal, os, atexit
sys.path.insert(0, '$PROJECT_DIR')
from scapy.all import sniff
from src.capture.protocol_parser import parse_packet
from src.capture.packet_capture import save_packets

out_path = '$RESULTS_DIR/live_capture.json'
records = []
count = 0

def save_one(raw_pkt):
    global count
    rec = parse_packet(raw_pkt)
    if rec is not None:
        records.append(rec)
    count += 1

def flush():
    if records:
        save_packets(records, out_path)
        print(f'[抓包] 已保存 {len(records)} 条报文 (共捕获 {count} 包)', flush=True)

def on_signal(sig, frame):
    flush()
    os._exit(0)

atexit.register(flush)
for sig in (signal.SIGTERM, signal.SIGINT):
    try:
        signal.signal(sig, on_signal)
    except Exception:
        pass  # 非主线程可能抛异常

print(f'[抓包] 开始捕获 ${CAPTURE_IFACE} 接口流量...', flush=True)
try:
    sniff(iface='${CAPTURE_IFACE}', timeout=120, prn=save_one, store=0)
except Exception as e:
    print(f'[抓包] 异常: {e}', flush=True)
flush()
print(f'[抓包] 结束: {len(records)} 条报文', flush=True)
" &
    CAPTURE_PID=$!
    sleep 2
    echo -e "${GREEN}  抓包 PID: $CAPTURE_PID${NC}"
}

run_attacks() {
    local delay="${1:-1}"

    echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  开始执行攻击脚本${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"

    chmod +x "$ATTACK_DIR"/*.sh

    for script in \
        "$ATTACK_DIR/sql_injection.sh" \
        "$ATTACK_DIR/xss.sh" \
        "$ATTACK_DIR/path_traversal.sh" \
        "$ATTACK_DIR/cmd_injection.sh" \
        "$ATTACK_DIR/webshell.sh" \
        "$ATTACK_DIR/trojan.sh" \
        "$ATTACK_DIR/xxe.sh"; do

        if [ -f "$script" ]; then
            echo ""
            TARGET="$TARGET_HTTP" bash "$script"
            sleep "$delay"
        fi
    done

    # 端口扫描和 SSH 爆破只需要 IP（不含端口）
    for script in \
        "$ATTACK_DIR/port_scan.sh" \
        "$ATTACK_DIR/ssh_bruteforce.sh"; do

        if [ -f "$script" ]; then
            echo ""
            TARGET="$TARGET_IP" bash "$script"
            sleep "$delay"
        fi
    done

    # 批量 SYN 包模拟高频连接
    echo ""
    echo "[高频连接] 开始发送 90 个 SYN 包到 ${TARGET_HTTP}..."
    for i in $(seq 1 90); do
        timeout 0.1 bash -c "echo >/dev/tcp/${TARGET_HTTP%:*}/${TARGET_HTTP##*:}" 2>/dev/null
    done
    echo "[高频连接] 完成"

    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  攻击阶段完成${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
}

run_detection() {
    local input="${1:-$RESULTS_DIR/live_capture.json}"

    echo ""
    echo -e "${CYAN}[检测] 运行检测管线...${NC}"

    cd "$PROJECT_DIR"

    # 检查抓包文件
    if [ ! -f "$input" ]; then
        echo -e "${YELLOW}[警告] 抓包文件不存在: $input${NC}"
        echo "  将使用 mock 数据进行检测"
        input="mock_data/mock_packets.json"
    fi

    python3 main.py --input "$input" --output-dir "$RESULTS_DIR"

    echo ""
    echo -e "${GREEN}[检测] 完成！结果见: $RESULTS_DIR/merged_alerts.json${NC}"
}

print_summary() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  演示完成！${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  输出文件:"
    echo "    抓包数据:  $RESULTS_DIR/live_capture.json"
    echo "    signature: $RESULTS_DIR/signature_alerts.json"
    echo "    bruteforce:$RESULTS_DIR/bruteforce_alerts.json"
    echo "    anomaly:   $RESULTS_DIR/anomaly_alerts.json"
    echo "    汇总告警:  $RESULTS_DIR/merged_alerts.json"
    echo ""
    echo "  启动 GUI 查看: python3 main.py --gui-only"
    echo "  运行全量测试: python3 -m pytest tests/ -v"
}

cleanup() {
    echo ""
    echo -e "${YELLOW}[清理] 停止后台服务...${NC}"
    [ -n "$TARGET_PID" ] && kill $TARGET_PID 2>/dev/null && echo "  靶机已停止"
    [ -n "$CAPTURE_PID" ] && kill $CAPTURE_PID 2>/dev/null && echo "  抓包已停止"
}

# ====== 主流程 ======

banner

case "$MODE" in
    --quick)
        echo -e "${YELLOW}[模式] 快速演示${NC}"
        check_root
        check_deps
        trap cleanup EXIT
        mkdir -p "$RESULTS_DIR"
        if [ "$SKIP_TARGET" -ne 1 ]; then start_target; fi
        start_capture
        sleep 1
        run_attacks 0.5
        sleep 3
        cleanup
        trap - EXIT
        run_detection "$RESULTS_DIR/live_capture.json"
        print_summary
        ;;

    --attack-only)
        echo -e "${YELLOW}[模式] 仅攻击（测试靶机）${NC}"
        trap cleanup EXIT
        if [ "$SKIP_TARGET" -ne 1 ]; then start_target; fi
        run_attacks 1
        cleanup
        trap - EXIT
        ;;

    --full|*)
        echo -e "${YELLOW}[模式] 完整演示${NC}"
        echo "  靶机: ${TARGET_HTTP} | 抓包: ${CAPTURE_IFACE}"
        if [ "$SKIP_TARGET" -eq 1 ]; then
            echo -e "  ${CYAN}跨机器模式 —— 靶机由外部提供${NC}"
        fi
        check_root
        check_deps
        trap cleanup EXIT
        mkdir -p "$RESULTS_DIR"
        if [ "$SKIP_TARGET" -ne 1 ]; then start_target; fi
        start_capture
        sleep 2
        run_attacks 1
        sleep 5
        cleanup
        trap - EXIT
        run_detection "$RESULTS_DIR/live_capture.json"
        print_summary
        ;;
esac
