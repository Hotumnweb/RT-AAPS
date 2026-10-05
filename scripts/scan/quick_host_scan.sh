#!/bin/bash
# ============================================================
# 快速存活主机扫描脚本
# 用法: bash quick_host_scan.sh <网段>
# 示例: bash quick_host_scan.sh 192.168.10.0/24
# ============================================================
TARGET=$1

if [ -z "$TARGET" ]; then
    echo "用法: bash quick_host_scan.sh <网段>"
    echo "示例: bash quick_host_scan.sh 192.168.10.0/24"
    exit 1
fi

echo "[*] 快速存活主机扫描: $TARGET"

# ARP 探测优先（内网虚拟机禁 ping 也能扫到）
nmap -sn -PR -T4 -n "$TARGET" 2>/dev/null || nmap -sn -T4 -n "$TARGET"

echo "[*] 扫描完成"
