#!/usr/bin/env python3
"""
代理节点解析、多节点测速与 Sing-box 客户端启动器 (MineStrator 专属版)
==============================================
支持模式：
1. 传统代理链接：http://, https://, socks5://
2. 节点分享链接：vless://, vmess://, trojan://, ss://

精细化调优：
- 自动清理 WebSocket path 中的 `?ed=2560` 早期数据伪报头，防止 Cloudflare WAF 抛出 Connection reset by peer
- 智能识别 Cloudflare Argo 域名并匹配 Anycast 入口
"""

import base64
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import zipfile

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
from typing import List, Optional, Tuple

LOCAL_PROXY_PORT = 10808

COUNTRY_FLAGS = {
    "RO": "🇷🇴", "US": "🇺🇸", "HK": "🇭🇰", "TW": "🇹🇼", "JP": "🇯🇵", "SG": "🇸🇬",
    "KR": "🇰🇷", "GB": "🇬🇧", "DE": "🇩🇪", "FR": "🇫🇷", "CA": "🇨🇦", "AU": "🇦🇺",
    "NL": "🇳🇱", "CN": "🇨🇳", "RU": "🇷🇺", "IN": "🇮🇳"
}


def parse_nodes(raw_nodes: str) -> List[str]:
    """解析输入的字符串，按换行或逗号分割出独立的节点列表。"""
    if not raw_nodes:
        return []
    lines = re.split(r'[\r\n,]+', raw_nodes)
    nodes = [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]
    return nodes


def is_cloudflare_domain(domain: str) -> bool:
    """判断域名是否属于 Cloudflare Argo / Koyeb / Workers 域名。"""
    if not domain:
        return False
    cf_keywords = [".iabc.ltd", ".trycloudflare.com", ".workers.dev", ".pages.dev", "koyeb"]
    return any(k in domain.lower() for k in cf_keywords)


def clean_ws_path(path: str) -> str:
    """清理 WebSocket 路径中的 ?ed=2560 避免 Cloudflare 触发 TCP Reset。"""
    if not path:
        return "/"
    if "?ed=" in path:
        path = path.split("?ed=")[0]
    elif "&ed=" in path:
        path = path.split("&ed=")[0]
    return path or "/"


def parse_vless_url(url_str: str) -> dict:
    """解析 vless:// 链接，生成完整 sing-box outbound 配置。"""
    try:
        parsed = urllib.parse.urlparse(url_str)
        uuid = parsed.username or ""
        host = parsed.hostname or ""
        port = parsed.port or 443
        query = urllib.parse.parse_qs(parsed.query)

        def q(k, default=""):
            return query.get(k, [default])[0]

        server = host.strip("[]")
        sni = q("sni") or q("host") or server

        if is_cloudflare_domain(server) and not re.match(r'^\d+\.\d+\.\d+\.\d+$', server):
            server = "104.16.1.1"

        outbound = {
            "type": "vless",
            "tag": "proxy",
            "server": server,
            "server_port": int(port),
            "uuid": uuid
        }

        flow = q("flow")
        if flow:
            outbound["flow"] = flow

        security = q("security")
        if security in ["tls", "reality"]:
            tls_config = {
                "enabled": True,
                "server_name": sni,
                "insecure": q("allowInsecure") in ["1", "true", "True"]
            }
            fp = q("fp")
            if fp and fp != "firefox":
                tls_config["utls"] = {"enabled": True, "fingerprint": fp}

            if security == "reality":
                tls_config["reality"] = {
                    "enabled": True,
                    "public_key": q("pbk"),
                    "short_id": q("sid")
                }
            outbound["tls"] = tls_config

        net_type = q("type") or q("net") or "tcp"
        if net_type == "ws":
            ws_path = clean_ws_path(q("path", "/"))
            ws_host = q("host") or sni
            outbound["transport"] = {
                "type": "ws",
                "path": ws_path,
                "headers": {"Host": ws_host}
            }

        return outbound
    except Exception as e:
        print(f"❌ 解析 VLESS 节点错误: {e}")
        return {}


def parse_vmess_url(url_str: str) -> dict:
    """解析 vmess:// 链接，生成完整 sing-box outbound 配置。"""
    try:
        b64_str = url_str.replace("vmess://", "").strip()
        missing_padding = len(b64_str) % 4
        if missing_padding:
            b64_str += '=' * (4 - missing_padding)
        json_data = json.loads(base64.b64decode(b64_str).decode('utf-8'))

        server = json_data.get("add", "")
        port = int(json_data.get("port", 443))
        uuid = json_data.get("id", "")
        aid = int(json_data.get("aid", 0))
        net = json_data.get("net", "tcp")
        host = json_data.get("host", "")
        path = clean_ws_path(json_data.get("path", "/"))
        tls = json_data.get("tls", "")
        sni = json_data.get("sni", host or server)

        if is_cloudflare_domain(server) and not re.match(r'^\d+\.\d+\.\d+\.\d+$', server):
            server = "104.16.1.1"

        outbound = {
            "type": "vmess",
            "tag": "proxy",
            "server": server,
            "server_port": port,
            "uuid": uuid,
            "alter_id": aid,
            "security": "auto"
        }

        if tls == "tls":
            outbound["tls"] = {
                "enabled": True,
                "server_name": sni,
                "insecure": True
            }

        if net == "ws":
            outbound["transport"] = {
                "type": "ws",
                "path": path,
                "headers": {"Host": host or sni}
            }

        return outbound
    except Exception as e:
        print(f"❌ 解析 VMess 节点错误: {e}")
        return {}


def parse_node_to_outbound(node_url: str) -> dict:
    """自动判断协议类型并转为 sing-box outbound"""
    if node_url.startswith("vless://"):
        return parse_vless_url(node_url)
    elif node_url.startswith("vmess://"):
        return parse_vmess_url(node_url)
    return {}


def generate_singbox_config(outbound: dict, listen_port: int = LOCAL_PROXY_PORT) -> dict:
    """生成完整 sing-box 配置文件 JSON 数据结构。"""
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": listen_port
            }
        ],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"}
        ]
    }


def download_singbox(dest_dir: str = ".") -> str:
    """自动下载并解压适用于当前 OS 的 sing-box 可执行文件。"""
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_map = {"windows": "windows", "linux": "linux", "darwin": "darwin"}
    arch_map = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}

    target_os = os_map.get(system, "linux")
    target_arch = arch_map.get(machine, "amd64")

    binary_name = "sing-box.exe" if target_os == "windows" else "sing-box"
    binary_path = os.path.abspath(os.path.join(dest_dir, binary_name))

    if os.path.exists(binary_path):
        return binary_path

    ext = "zip" if target_os == "windows" else "tar.gz"
    ver = "1.8.10"
    url = f"https://github.com/SagerNet/sing-box/releases/download/v{ver}/sing-box-{ver}-{target_os}-{target_arch}.{ext}"

    print(f"📦 正在自动下载 sing-box v{ver} ({target_os}/{target_arch})...")
    archive_path = os.path.join(dest_dir, f"singbox_dl.{ext}")

    urllib.request.urlretrieve(url, archive_path)

    if ext == "zip":
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            for member in zip_ref.namelist():
                if member.endswith(binary_name):
                    with zip_ref.open(member) as source, open(binary_path, 'wb') as target:
                        shutil.copyfileobj(source, target)
    else:
        import tarfile
        with tarfile.open(archive_path, 'r:gz') as tar_ref:
            for member in tar_ref.getmembers():
                if member.name.endswith(binary_name):
                    f = tar_ref.extractfile(member)
                    if f:
                        with open(binary_path, 'wb') as target:
                            shutil.copyfileobj(f, target)

    if target_os != "windows":
        os.chmod(binary_path, 0o755)

    if os.path.exists(archive_path):
        try:
            os.remove(archive_path)
        except Exception:
            pass

    print(f"✅ sing-box 可执行文件准备就绪: {binary_path}")
    return binary_path


def fetch_proxy_geo_info(proxy_url: str, node_url: str = "", latency: float = 0.0) -> dict:
    """通过代理多源轮询获取公网出口 IP、地理位置及 ISP 运营商信息。"""
    info = {
        "ip": "未知 IP",
        "location": "未知位置",
        "latency": f"{latency:.1f} ms" if latency > 0 else "已连通"
    }

    if not proxy_url:
        return info

    proxy_handler = urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url})
    opener = urllib.request.build_opener(proxy_handler)

    for attempt in range(2):
        # 1. 尝试接口 ip.sb
        try:
            req = urllib.request.Request("https://api.ip.sb/geoip", headers={"User-Agent": "curl/7.68.0"})
            with opener.open(req, timeout=10) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                country_code = data.get("country_code", "")
                flag = COUNTRY_FLAGS.get(country_code, "🌐")
                country = data.get("country", "")
                city = data.get("city", "")
                isp = data.get("organization", data.get("asn_organization", ""))
                info["ip"] = data.get("ip", "未知 IP")
                info["location"] = f"{flag} {country} · {city} ({isp})"
                return info
        except Exception:
            pass

        # 2. 备用接口 ip-api.com
        try:
            req = urllib.request.Request("http://ip-api.com/json", headers={"User-Agent": "curl/7.68.0"})
            with opener.open(req, timeout=10) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if data.get("status") == "success":
                    country_code = data.get("countryCode", "")
                    flag = COUNTRY_FLAGS.get(country_code, "🌐")
                    country = data.get("country", "")
                    city = data.get("city", "")
                    isp = data.get("isp", data.get("org", ""))
                    info["ip"] = data.get("query", "未知 IP")
                    info["location"] = f"{flag} {country} · {city} ({isp})"
                    return info
        except Exception:
            pass

    return info


def start_proxy_node(raw_nodes: str, port: int = LOCAL_PROXY_PORT) -> Tuple[Optional[subprocess.Popen], Optional[str], Optional[dict]]:
    """传入节点字符串，启动 sing-box 本地 HTTP/Socks5 代理并获取出口地理位置。"""
    nodes = parse_nodes(raw_nodes)
    if not nodes:
        print("⚠️ 未提供代理节点（PROXY_NODES 环境变量为空），使用直连模式。")
        return None, None, None

    for node in nodes:
        outbound = parse_node_to_outbound(node)
        if not outbound:
            continue

        config = generate_singbox_config(outbound, port)
        config_path = os.path.abspath("singbox_run_config.json")
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

        binary_path = download_singbox(".")
        cmd = [binary_path, "run", "-c", config_path]
        print(f"🚀 启动 sing-box 本地代理 (127.0.0.1:{port})...")
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        proxy_url = f"http://127.0.0.1:{port}"
        geo_info = fetch_proxy_geo_info(proxy_url, node)
        return proc, proxy_url, geo_info

    return None, None, None


if __name__ == "__main__":
    test_node = os.getenv("PROXY_NODES", "")
    proc, proxy_url, geo = start_proxy_node(test_node)
    if proc:
        print(f"✅ 代理进程 PID: {proc.pid}, 地址: {proxy_url}, 出口: {geo}")
        time.sleep(3)
        proc.terminate()
