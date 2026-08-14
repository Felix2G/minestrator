#!/usr/bin/env python3
"""
Minecraft 假玩家协议挂机 Bot (Minecraft Protocol 1.21.x)
======================================================
通过原生的 TCP Minecraft Handshake & Login Start 握手发包，
让 MineStrator 控制面板将在线玩家显示为 👤 1 / 20，彻底骗过人头检测机制。
"""

import os
import socket
import struct
import sys
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

def write_varint(val: int) -> bytes:
    """编码 Minecraft 协议标准 VarInt。"""
    out = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val != 0:
            b |= 0x80
            out.append(b)
        else:
            out.append(b)
            break
    return bytes(out)

def write_string(s: str) -> bytes:
    """编码 Minecraft 协议 UTF-8 字符串。"""
    encoded = s.encode('utf-8')
    return write_varint(len(encoded)) + encoded

def make_packet(pkt_id: int, payload: bytes) -> bytes:
    """封装带 Length 前缀与 Packet ID 的标准包。"""
    data = write_varint(pkt_id) + payload
    return write_varint(len(data)) + data

def send_mc_bot_join(host: str = "127.0.0.1", port: int = 25565, username: str = "Bot_Keeper", hold_seconds: int = 5) -> bool:
    """建立 TCP 连接并发送 Minecraft Handshake & Login 包，使面板显示玩家在线。"""
    try:
        print(f"[*] 正在尝试以玩家 '{username}' 身份登入 Minecraft 服务器 ({host}:{port}) ...")
        s = socket.create_connection((host, int(port)), timeout=10)

        # 1. 构造 Handshake Packet (ID: 0x00, Protocol: 767 = 1.21, NextState: 2 = Login)
        handshake_payload = (
            write_varint(767) +                  # Protocol Version
            write_string(host) +                 # Hostname
            struct.pack(">H", int(port)) +      # Port
            write_varint(2)                      # Next State: Login
        )
        handshake_pkt = make_packet(0x00, handshake_payload)

        # 2. 构造 Login Start Packet (ID: 0x00, Username, Random UUID)
        login_payload = (
            write_string(username) +             # Player Name
            os.urandom(16)                        # Player UUID
        )
        login_pkt = make_packet(0x00, login_payload)

        # 发送 Handshake 与 Login 协议包
        s.sendall(handshake_pkt + login_pkt)
        time.sleep(1)

        # 保持连接数秒激活控制台玩家在线判定
        if hold_seconds > 0:
            print(f"[+] ✅ 假玩家 '{username}' 握手成功！保持连接 {hold_seconds} 秒以刷新面板 👤 1 / 20 ...")
            time.sleep(hold_seconds)

        s.close()
        print(f"[+] ✅ 假玩家 '{username}' 挂机动作完成！")
        return True

    except Exception as e:
        print(f"[!] 假玩家连入尝试跳过: {e}")
        return False

if __name__ == "__main__":
    send_mc_bot_join()
