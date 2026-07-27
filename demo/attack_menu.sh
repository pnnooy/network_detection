#!/bin/bash
# ============================================================================
# 攻击菜单 — 输入数字执行单个攻击，完成后回到菜单
#
# 用法:
#   TARGET=192.168.235.1:8080 bash demo/attack_menu.sh           # 默认打 Windows
#   TARGET=192.168.235.1:8080 TARGET_IP=192.168.235.1 bash ...  # 完整配置
#
# 按键: 1-9 执行攻击 | 0 或 q 退出
# ============================================================================

TARGET="${TARGET:-127.0.0.1:8080}"
TARGET_IP="${TARGET_IP:-${TARGET%:*}}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ATTACK_DIR="$SCRIPT_DIR/attack_scripts"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

# 攻击列表（序号:名称:脚本:参数说明）
declare -A ATTACKS
ATTACKS=(
  [1]="SQL 注入|sql_injection|SQLi 探测绕过+DROP+UNION"
  [2]="XSS 跨站|xss|script/alert 注入"
  [3]="路径遍历|path_traversal|../../../etc/passwd"
  [4]="命令注入|cmd_injection|wget/nc/shell 注入"
  [5]="Webshell 上传|webshell|eval/system/assert"
  [6]="木马通信|trojan|C2 命令+信息收集"
  [7]="XXE 注入|xxe|外部实体+DTD 引用"
  [8]="端口扫描|port_scan|nmap 扫描前25端口"
  [9]="SSH 爆破|ssh_bruteforce|hydra 字典攻击"
)

cleanup() {
    echo -e "\n${GREEN}已退出攻击菜单${NC}"
    exit 0
}
trap cleanup SIGINT SIGTERM

show_menu() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}  网络攻击脚本菜单  ${NC}${CYAN}                              ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}目标: ${TARGET}${NC}"
    if [ "$TARGET_IP" != "${TARGET%:*}" ]; then
        echo -e "${CYAN}║${NC}  ${YELLOW}扫描目标: ${TARGET_IP}${NC}"
    fi
    echo -e "${CYAN}╠════════════════════════════════════════════════╣${NC}"

    for i in $(seq 1 9); do
        IFS='|' read -r name script desc <<< "${ATTACKS[$i]}"
        printf "${CYAN}║${NC}  ${BOLD}%s${NC}) %-20s ${CYAN}│${NC} %s\n" "$i" "$name" "$desc"
    done

    echo -e "${CYAN}╠════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}A${NC}) 一键执行全部攻击"
    echo -e "${CYAN}║${NC}  ${BOLD}0${NC} 或 ${BOLD}q${NC}) 退出"
    echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
}

run_attack() {
    local num=$1
    IFS='|' read -r name script desc <<< "${ATTACKS[$num]}"
    local script_path="$ATTACK_DIR/${script}.sh"

    echo ""
    echo -e "${RED}════════════════════════════════════════════════${NC}"
    echo -e "${RED}  ▸ 执行攻击 #${num}: ${name}${NC}"
    echo -e "${RED}════════════════════════════════════════════════${NC}"

    if [ ! -f "$script_path" ]; then
        echo -e "${RED}[错误] 脚本不存在: ${script_path}${NC}"
        echo -e "${YELLOW}可用脚本:$(ls $ATTACK_DIR/*.sh | xargs -I{} basename {})${NC}"
        return 1
    fi

    # 端口扫描和 SSH 爆破只需要 IP
    if [ "$script" = "port_scan" ] || [ "$script" = "ssh_bruteforce" ]; then
        export TARGET="$TARGET_IP"
    else
        export TARGET="$TARGET"
    fi

    bash "$script_path"
    local rc=$?

    echo ""
    if [ $rc -eq 0 ]; then
        echo -e "${GREEN}✓ #${num} ${name} 完成${NC}"
    else
        echo -e "${RED}✗ #${num} ${name} 失败 (exit=${rc})${NC}"
    fi
    echo -e "${YELLOW}按 Enter 返回菜单...${NC}"
    read -r
}

run_all() {
    echo -e "\n${RED}${BOLD}一键执行全部 9 类攻击...${NC}\n"
    for i in $(seq 1 9); do
        run_attack_silent $i
        sleep 0.5
    done
    echo -e "\n${GREEN}${BOLD}全部攻击执行完毕！${NC}"
    echo -e "${YELLOW}按 Enter 返回菜单...${NC}"
    read -r
}

run_attack_silent() {
    local num=$1
    IFS='|' read -r name script desc <<< "${ATTACKS[$num]}"
    local script_path="$ATTACK_DIR/${script}.sh"
    if [ ! -f "$script_path" ]; then return; fi

    if [ "$script" = "port_scan" ] || [ "$script" = "ssh_bruteforce" ]; then
        export TARGET="$TARGET_IP"
    else
        export TARGET="$TARGET"
    fi

    echo -e "  [${num}/9] ${name}..."
    bash "$script_path" 2>&1 | tail -1
}

# ---- main ----
chmod +x "$ATTACK_DIR"/*.sh 2>/dev/null

while true; do
    show_menu
    echo ""
    echo -n -e "${BOLD}选择攻击 [1-9/A/0/q]: ${NC}"
    read -r choice

    case "$choice" in
        1|2|3|4|5|6|7|8|9) run_attack "$choice" ;;
        [Aa])               run_all ;;
        0|[Qq])             cleanup ;;
        *)                  echo -e "${RED}无效选择，按 Enter 继续...${NC}"; read -r ;;
    esac
done
