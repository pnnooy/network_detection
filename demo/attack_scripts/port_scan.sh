#!/bin/bash
# 端口扫描攻击脚本
# 用法: TARGET=127.0.0.1 ./port_scan.sh
# 注意: 扫描本地回环地址不需要 root，扫描外网需要

TARGET="${TARGET:-127.0.0.1}"
PORTS="${PORTS:-25}"  # 扫描端口数

echo "[端口扫描] 开始扫描 $TARGET (${PORTS} 个端口) ..."
sleep 1

# 方案 A: 用 nmap (需要安装)
if command -v nmap &> /dev/null; then
    echo "  使用 nmap 进行端口扫描..."
    nmap -p 1-${PORTS} --max-retries 0 -T5 "$TARGET" 2>&1 | tail -5
else
    # 方案 B: 纯 shell 循环 nc 模拟扫描
    echo "  使用纯 shell nc 模拟端口扫描..."
    COMMON_PORTS=(21 22 23 25 53 80 110 135 139 143 443 445 993 995 1433 3306 3389 5432 5900 6379 8000 8080 8443 9200 27017)
    for port in "${COMMON_PORTS[@]:0:$PORTS}"; do
        timeout 0.3 bash -c "echo >/dev/tcp/$TARGET/$port" 2>/dev/null && echo "    $port: open" || echo "    $port: closed"
    done
fi

echo "[端口扫描] 完成"
