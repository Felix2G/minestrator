#!/usr/bin/env python3
"""
MineStrator 4小时强制关机保活脚本
==================================
1. 自动调用 MineStrator API 查询服务器与强制关机倒计时。
2. 自动开启 sing-box 本地代理（支持 PROXY_NODES 中的 VMess/VLESS 节点），绕过 Cloudflare WAF。
3. 模拟 Playwright / Session 登录网页触发 Restart / Start 电源控制，重新刷新 4 小时倒计时。
4. 自动向 Telegram 发送对齐 PidginHost 样式的漂亮运行结果通知 (HTML 格式)。
"""

import argparse
import base64
import datetime
import json
import os
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request

# 强制 stdout / stderr 使用 utf-8 编码
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# 尝试加载本地 .env 文件（若存在）
try:
    from dotenv import load_dotenv
    # 支持加载当前目录或上级目录的 .env
    load_dotenv()
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(env_path):
        load_dotenv(env_path, override=False)
except ImportError:
    pass

# 导入代理选择器与假玩家挂机 Bot
from proxy_selector import start_proxy_node, LOCAL_PROXY_PORT
from mc_bot_keeper import send_mc_bot_join

# 北京时间（UTC+8）
TZ_CN = datetime.timezone(datetime.timedelta(hours=8))

def now_cn_str() -> str:
    """获取格式化的北京时间字符串。"""
    return datetime.datetime.now(TZ_CN).strftime("%Y-%m-%d %H:%M:%S")

# ==================== 环境变量读取（严格脱敏，不设个人私有默认值） ====================
MINESTRATOR_EMAIL = os.getenv("MINESTRATOR_EMAIL", "")
MINESTRATOR_PASSWORD = os.getenv("MINESTRATOR_PASSWORD", "")
MINESTRATOR_SERVER_ID = os.getenv("MINESTRATOR_SERVER_ID", "")
MINESTRATOR_AUTH = os.getenv("MINESTRATOR_AUTH", "")

TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.getenv("TG_CHAT_ID", "")
MINESTRATOR_PROXY_NODES = os.getenv("MINESTRATOR_PROXY_NODES", "")
PROXY_NODES = os.getenv("PROXY_NODES", "")



def send_tg_notification(message_html: str) -> bool:
    """向 Telegram Bot 发送 HTML 格式通知消息。"""
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        print("[!] 未配置 TG_BOT_TOKEN 或 TG_CHAT_ID，跳过 Telegram 通知。")
        return False

    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TG_CHAT_ID,
        "text": message_html,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }

    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                print("[+] Telegram 通知发送成功！")
                return True
    except Exception as e:
        print(f"[-] Telegram 通知发送失败: {e}")
    return False


def query_server_status(auth_token: str, server_id: str, proxy_url: str = None) -> dict:
    """调用 MineStrator API 查询服务器当前运行状态与倒计时。"""
    url = f"https://mine.sttr.io/server/{server_id}"
    headers = {
        "Authorization": auth_token if auth_token.startswith("Bearer ") else f"Bearer {auth_token}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
        "Origin": "https://minestrator.com",
        "Referer": "https://minestrator.com/",
        "Sec-Ch-Ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site"
    }

    handlers = []
    if proxy_url:
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    opener = urllib.request.build_opener(*handlers)

    req = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(req, timeout=15) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data.get("api", {}).get("data", {})
    except Exception as e:
        print(f"[!] 查询服务器状态失败: {e}")
        return {}


def login_via_rest_api(email: str, password: str, proxy_url: str = None) -> tuple[bool, str, dict]:
    """通过官方 REST API (https://mine.sttr.io/user/login) 直接使用账号密码打通鉴权，绕过 Turnstile。"""
    if not email or not password:
        print("[!] 账号 Email 或 Password 为空，跳过 API 登录。")
        return False, "", {}

    url = "https://mine.sttr.io/user/login"
    payload = {
        "username": email,
        "password": password
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
        "Origin": "https://minestrator.com",
        "Referer": "https://minestrator.com/",
        "Sec-Ch-Ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site"
    }

    handlers = []
    if proxy_url:
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    opener = urllib.request.build_opener(*handlers)

    req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers)
    try:
        print(f"[*] 正在调用官方 REST API 登录: {email} ...")
        with opener.open(req, timeout=15) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            api_res = data.get("api", {})
            user_data = api_res.get("data", {})
            token = user_data.get("token", "") or user_data.get("auth_token", "")
            
            if token:
                auth_str = token if token.startswith("Bearer ") else f"Bearer {token}"
                print("[+] ✅ REST API 账号密码鉴权登录成功！已获取最新 Session 凭证。")
                return True, auth_str, user_data
            else:
                print("[+] ✅ REST API 登录成功，响应已返回。")
                return True, "", user_data
    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8', errors='ignore')
        if "API_USER_LOGIN_WRONG_PASSWORD" in err_body:
            print("[-] ❌ REST API 登录失败：账号或密码不匹配 (API_USER_LOGIN_WRONG_PASSWORD)！")
        else:
            print(f"[-] ❌ REST API 登录失败 (HTTP {e.code}): {err_body[:200]}")
    except Exception as e:
        print(f"[!] REST API 登录请求发生异常: {e}")

    return False, "", {}


def trigger_restart_via_websocket(server_id: str, auth_token: str, proxy_url: str = None, signal: str = "start") -> bool:
    """通过底层 Pterodactyl Wings WebSocket 协议直接发送 start/restart 信号开机，绕过任何网页端与风控。"""
    try:
        url = f"https://mine.sttr.io/server/{server_id}"
        headers = {
            "Authorization": auth_token if auth_token.startswith("Bearer ") else f"Bearer {auth_token}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        handlers = []
        if proxy_url:
            handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, headers=headers)
        with opener.open(req, timeout=15) as resp:
            data = json.loads(resp.read().decode('utf-8')).get("api", {}).get("data", {})

        ws_data = data.get("websocket", {})
        ws_url = ws_data.get("url", "")
        token = ws_data.get("token", "")

        if not ws_url or not token:
            print("[-] 无法获取 Pterodactyl WebSocket 授权 Token。")
            return False

        parts = ws_url.split("/")
        daemon_host_port = parts[2].split(":")
        host = daemon_host_port[0]
        port = int(daemon_host_port[1])
        path = "/" + "/".join(parts[3:])

        print(f"[*] 正在建立 Pterodactyl Wings WebSocket 直连控制通道 ({host}:{port}) ...")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        sock = None
        if proxy_url:
            p_parsed = urllib.parse.urlparse(proxy_url)
            p_host = p_parsed.hostname
            p_port = p_parsed.port
            raw_sock = socket.create_connection((p_host, p_port), timeout=10)
            connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
            raw_sock.sendall(connect_req.encode('utf-8'))
            conn_res = raw_sock.recv(4096).decode('utf-8', errors='ignore')
            if "200" not in conn_res.splitlines()[0]:
                print(f"[!] 代理隧道建立失败: {conn_res[:100]}")
                return False
            sock = raw_sock
        else:
            sock = socket.create_connection((host, port), timeout=10)

        with ctx.wrap_socket(sock, server_hostname=host) as s:
            sec_key = base64.b64encode(os.urandom(16)).decode('utf-8')
            req_lines = [
                f"GET {path} HTTP/1.1",
                f"Host: {host}:{port}",
                "Upgrade: websocket",
                "Connection: Upgrade",
                f"Sec-WebSocket-Key: {sec_key}",
                "Sec-WebSocket-Version: 13",
                "Origin: https://minestrator.com",
                "User-Agent: Mozilla/5.0",
                "", ""
            ]
            s.sendall("\r\n".join(req_lines).encode('utf-8'))
            resp_txt = s.recv(4096).decode('utf-8', errors='ignore')
            if "101" not in resp_txt.splitlines()[0]:
                print(f"[-] WebSocket 握手失败: {resp_txt[:100]}")
                return False

            def make_frame(msg_str):
                payload = msg_str.encode('utf-8')
                length = len(payload)
                mask_key = os.urandom(4)
                masked = bytearray(length)
                for i in range(length):
                    masked[i] = payload[i] ^ mask_key[i % 4]
                hdr = bytearray([0x81])
                if length <= 125:
                    hdr.append(0x80 | length)
                elif length <= 65535:
                    hdr.append(0x80 | 126)
                    hdr.extend(length.to_bytes(2, 'big'))
                else:
                    hdr.append(0x80 | 127)
                    hdr.extend(length.to_bytes(8, 'big'))
                hdr.extend(mask_key)
                hdr.extend(masked)
                return bytes(hdr)

            # 发送 WebSocket 鉴权消息
            auth_msg = json.dumps({"event": "auth", "args": [token]})
            s.sendall(make_frame(auth_msg))

            # 必须等待服务器返回 auth success 鉴权成功帧后，再发送控制指令
            authed = False
            s.settimeout(5)
            for _ in range(5):
                try:
                    raw = s.recv(4096)
                    txt = raw.decode('utf-8', errors='ignore')
                    if "auth success" in txt:
                        authed = True
                        break
                except Exception:
                    break

            if authed:
                print(f"[+] ✅ WebSocket 鉴权成功 (auth success)，下发 '{signal}' 指令刷新 4 小时倒计时...")
                state_msg = json.dumps({"event": "set state", "args": [signal]})
                s.sendall(make_frame(state_msg))
                time.sleep(1)
                print(f"[+] ✅ 成功通过 Pterodactyl WebSocket 下发 '{signal}' 开机/重启控制信号！")
                return True
            else:
                print("[-] Pterodactyl WebSocket 鉴权等待超时。")
                return False

    except Exception as e:
        print(f"[!] Pterodactyl WebSocket 直连控制尝试失败: {e}")
        return False


def trigger_restart_via_playwright(email: str, password: str, server_id: str, proxy_url: str = None, auth_token: str = None) -> bool:
    """使用 Playwright 模拟浏览器登录并触发重启/开机按键。"""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[!] 未安装 Playwright，跳过网页模拟操作。")
        return False

    print("[*] 启动 Chromium 模拟网页控制台操作...")
    try:
        with sync_playwright() as p:
            use_headless = not bool(os.getenv("DISPLAY"))
            if not use_headless:
                print("[*] 检测到 Xvfb 虚拟桌面 (DISPLAY)，已启动真实 Chrome GUI (headless=False) 避开 Turnstile 封锁！")
            launch_options = {
                "headless": use_headless,
                "args": [
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-infobars"
                ]
            }
            if proxy_url:
                launch_options["proxy"] = {"server": proxy_url}

            browser = p.chromium.launch(**launch_options)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                locale="fr-FR",
                viewport={"width": 1920, "height": 1080}
            )

            # 注入 Stealth 伪装脚本以避开 Cloudflare Turnstile bot 检测
            context.add_init_script("""
                delete Object.getPrototypeOf(navigator).webdriver;
                Object.defineProperty(navigator, 'webdriver', { get: () => false });
                Object.defineProperty(navigator, 'languages', { get: () => ['fr-FR', 'fr', 'en-US', 'en'] });
                Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
                window.chrome = { runtime: {}, loadTimes: function() {}, csi: function() {}, app: {} };
            """)

            # 优先使用有效 Auth Token 注入浏览器 Cookies & LocalStorage 避免被阻挡
            active_auth = auth_token or MINESTRATOR_AUTH
            raw_token = active_auth.replace("Bearer ", "").strip() if active_auth else ""
            if active_auth:
                cookies = []
                for domain in [".minestrator.com", "minestrator.com", ".sttr.io", "mine.sttr.io"]:
                    for name, val in [
                        ("auth_token", active_auth),
                        ("auth._token.local", active_auth),
                        ("token", raw_token),
                        ("auth.token", raw_token)
                    ]:
                        cookies.append({"name": name, "value": val, "domain": domain, "path": "/"})
                try:
                    context.add_cookies(cookies)
                except Exception:
                    pass

            page = context.new_page()

            # 先访问主页注入 localStorage 凭证
            try:
                page.goto("https://minestrator.com/", wait_until="domcontentloaded", timeout=15000)
                if active_auth:
                    page.evaluate(f"""() => {{
                        localStorage.setItem('auth._token.local', '{active_auth}');
                        localStorage.setItem('auth.token', '{raw_token}');
                        localStorage.setItem('auth_token', '{active_auth}');
                        localStorage.setItem('token', '{raw_token}');
                    }}""")
            except Exception:
                pass

            # 尝试直接打开后台 Dashboard 页面 (避开 /connexion 表单及 Turnstile 锁)
            print(f"[*] 尝试凭借凭证直通 MineBoard 后台面板 (https://minestrator.com/my/server/{server_id}) ...")
            try:
                page.goto(f"https://minestrator.com/my/server/{server_id}", wait_until="domcontentloaded", timeout=15000)
                page.wait_for_timeout(2000)
            except Exception:
                pass

            is_logged_in = ("/my/" in page.url) and ("/login" not in page.url) and ("/connexion" not in page.url)

            # 若凭证直通未直接进入后台 (/my/)，降级尝试页面表单登录
            if not is_logged_in:
                print("[*] 凭证直通需表单补充，打开登录页面 https://minestrator.com/login ...")
                page.goto("https://minestrator.com/login", wait_until="domcontentloaded", timeout=30000)

                user_input = page.locator("input[placeholder*='utilisateur'], input[placeholder*='email'], input[type='email'], input[type='text']").first
                if user_input.is_visible(timeout=5000):
                    print("[*] 模拟键盘录入 Email 和 Password (激活 Vue v-model)...")
                    pwd_input = page.locator("input[type='password'], input[placeholder*='passe']").first
                    
                    user_input.focus()
                    user_input.press_sequentially(email, delay=50)
                    
                    pwd_input.focus()
                    pwd_input.press_sequentially(password, delay=50)
                    page.wait_for_timeout(1000)

                    print("[*] 点击 Se connecter 按钮提交登录表单...")
                    submit_btn = page.locator("button:has-text('Se connecter'), button[type='submit']").first
                    if submit_btn.is_visible(timeout=3000) and not submit_btn.is_disabled():
                        submit_btn.click()
                    else:
                        print("[*] 提示: 提交按钮处于 disabled 状态，强制移除锁并触发表单提交...")
                        page.evaluate("""() => {
                            const btn = document.querySelector('button[type="submit"]');
                            if (btn) {
                                btn.removeAttribute('disabled');
                                btn.click();
                            }
                            const form = document.querySelector('form');
                            if (form) {
                                if (typeof form.requestSubmit === 'function') form.requestSubmit();
                                else form.submit();
                            }
                        }""")

                    print("[*] 等待页面脱离 /login 或 /connexion 跳转到后台...")
                    try:
                        page.wait_for_url(lambda u: "/login" not in u and "/connexion" not in u, timeout=10000)
                    except Exception as ex:
                        print(f"[!] 等待登录跳转超时或已被重定向: {ex}")
                    page.wait_for_timeout(2000)

                    is_logged_in = ("/login" not in page.url) and ("/connexion" not in page.url) and ("/my/" in page.url)
                    if is_logged_in:
                        print(f"[+] ✅ 登录成功！已成功跳转进入 MineBoard 后台: {page.url}")
                    else:
                        print(f"[-] ❌ 登录未成功，停留于: {page.url}")
            else:
                print(f"[+] ✅ 凭证直通成功！已跳转置身后台页面: {page.url}")

            # 3.0 尝试触发 30 天免费 Box 续期 (renewFree)
            print("[*] 检查是否有 30 天免费 Box 续期按钮 (renewFree)...")
            try:
                renew_box = page.locator("a[href*='renewFree'], button[href*='renewFree']").first
                if renew_box.is_visible(timeout=3000):
                    renew_box.evaluate("el => el.click()")
                    print("[+] 成功点击 30 天免费 Box 续期按钮！")
                    page.wait_for_timeout(3000)
                else:
                    page.evaluate("() => { const a = document.querySelector('a[href*=\"renewFree\"]'); if(a) a.click(); }")
            except Exception as ex:
                print(f"[!] 30 天 Box 续期检测尝试跳过: {ex}")

            # 精确与通用 Selector (包含 data-onboarding="start-button")
            selectors = [
                "button[data-onboarding='start-button']",
                "[data-onboarding='start-button']",
                "button[data-onboarding*='start']",
                "button[data-onboarding*='restart']",
                "button:has-text('Start')",
                "a:has-text('Start')",
                "button:has-text('Démarrer')",
                "a:has-text('Démarrer')",
                "button:has-text('Restart')",
                "button:has-text('Redémarrer')"
            ]
            btn_selector = ", ".join(selectors)

            def try_click_start(page_name: str) -> bool:
                print(f"[*] 检查 {page_name} 是否有 Start / Restart 按钮...")
                try:
                    btn = page.locator(btn_selector).first
                    if btn.is_visible(timeout=3000):
                        btn.evaluate("el => el.click()")
                        print(f"[+] 成功在 {page_name} (Playwright Locator) 点击 Start 按钮！")
                        page.wait_for_timeout(5000)
                        return True
                except Exception as ex:
                    print(f"[!] {page_name} Locator 尝试跳过: {ex}")

                try:
                    js_clicked = page.evaluate("""() => {
                        const btn = document.querySelector('[data-onboarding="start-button"]') ||
                                    document.querySelector('[data-onboarding*="start"]') ||
                                    document.querySelector('[data-onboarding*="restart"]') ||
                                    Array.from(document.querySelectorAll('button, a')).find(b => {
                                        const txt = (b.textContent || '').trim();
                                        return txt.includes('Start') || txt.includes('Démarrer') || txt.includes('Restart') || txt.includes('Redémarrer');
                                    });
                        if (btn) { btn.click(); return true; }
                        return false;
                    }""")
                    if js_clicked:
                        print(f"[+] 成功在 {page_name} (JS querySelector) 点击 Start 按钮！")
                        page.wait_for_timeout(5000)
                        return True
                except Exception as ex:
                    print(f"[!] {page_name} JS evaluate 尝试跳过: {ex}")

                return False

            # 3.1 在 Dashboard 页面尝试点击
            if try_click_start("Dashboard"):
                browser.close()
                return True

            # 3.2 在 Server Overview 概览主页尝试点击 (/my/server/<server_id>)
            server_main_url = f"https://minestrator.com/my/server/{server_id}"
            print(f"[*] 跳转到服务器概览主页: {server_main_url} ...")
            page.goto(server_main_url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(3000)
            if try_click_start("Server Overview"):
                browser.close()
                return True

            # 3.3 在 Console 控制台页面尝试点击 (/my/server/<server_id>?section=console)
            server_console_url = f"https://minestrator.com/my/server/{server_id}?section=console"
            print(f"[*] 跳转到服务器控制面板: {server_console_url} ...")
            page.goto(server_console_url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(3000)
            if try_click_start("Server Console"):
                browser.close()
                return True

            print("[!] 未找到明显的 Restart / Start 按钮，截图保存以供检查...")
            page.screenshot(path="error_screenshot.png")
            browser.close()
            return False
    except Exception as e:
        print(f"[-] Playwright 模拟失败: {e}")
        return False


def build_tg_report(extended: bool, login_success: bool, server_name: str, server_id: str, email: str, server_ip: str, server_port: str, tstart: str, tend: str = "", geo_info: dict = None) -> str:
    """构建完全对齐 PidginHost 风格样式的 Telegram HTML 通知报告。"""
    now = now_cn_str()
    if extended and login_success:
        status = "成功 (账号登录与 4 小时开机刷新全量完成)"
        status_flag = "✅"
    elif login_success:
        status = "未完全通过 (API 登录有效，但网页端点击开机未完成)"
        status_flag = "❌"
    else:
        status = "失败 (账号登录与开机均未通过)"
        status_flag = "❌"

    masked_email = email
    if "@" in email:
        parts = email.split("@")
        prefix = parts[0][:3] + "***" if len(parts[0]) > 3 else parts[0] + "***"
        masked_email = f"{prefix}@{parts[1]}"

    # 计算 4 小时关机剩余时间
    shutdown_time_str = ""
    if extended and login_success:
        shutdown_time_str = "⏱️ 04:00:00 (已重置刷新)"
    elif tstart and tstart != "未知":
        try:
            start_dt = datetime.datetime.strptime(tstart, "%Y-%m-%d %H:%M:%S").replace(tzinfo=TZ_CN)
            deadline_dt = start_dt + datetime.timedelta(hours=4)
            now_dt = datetime.datetime.now(TZ_CN)
            rem_seconds = int((deadline_dt - now_dt).total_seconds())
            if rem_seconds > 0:
                h = rem_seconds // 3600
                m = (rem_seconds % 3600) // 60
                s = rem_seconds % 60
                shutdown_time_str = f"⏱️ {h:02d}:{m:02d}:{s:02d} (预计关机时刻 {deadline_dt.strftime('%H:%M:%S')})"
            else:
                shutdown_time_str = "⏱️ 已超时关机"
        except Exception:
            pass

    lines = [
        "🤖 <b>MineStrator 服务器保活通知</b>",
        "",
        f"· 实例状态： {status_flag} {status}",
        f"· 目标实例： 🖥️ {server_name} (#{server_id})",
        f"· 账号邮箱： 📧 {masked_email}",
        f"· 执行时间： 📅 {now}",
    ]
    if shutdown_time_str:
        lines.append(f"· 4小时关机倒计时： {shutdown_time_str}")
    if tend:
        lines.append(f"· 30天大保活到期： ⏳ <code>{tend}</code>")
    lines.append("")

    if geo_info and geo_info.get("ip") != "未知 IP":
        ip = geo_info.get("ip", "未知 IP")
        loc = geo_info.get("location", "未知位置")
        lines.extend([
            "🌐 保活网络出口：",
            f"  └ {loc}",
            f"({ip})",
            ""
        ])
    else:
        lines.extend([
            "🌐 保活网络出口：",
            "  └ 直连模式 (GitHub Actions 默认 IP)",
            ""
        ])

    log_desc = f"Login & Status Verification Completed (Online: {server_ip}:{server_port})"
    lines.extend([
        "📝 控制台核验流水：",
        f"  └ {log_desc}"
    ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="MineStrator Server Auto-Renew Script")
    parser.add_argument("--debug", action="store_true", help="启用 Debug 输出")
    args = parser.parse_args()

    print("==================================================")
    print("MineStrator 4小时强制关机保活脚本启动")
    print(f"执行时间: {now_cn_str()}")
    print("==================================================")

    # 0. 前置必填配置校验（未配置时优雅退出）
    if not MINESTRATOR_EMAIL or not MINESTRATOR_PASSWORD or not MINESTRATOR_SERVER_ID:
        print("[!] ⚠️ 未检测到完整的必填配置 (MINESTRATOR_EMAIL / MINESTRATOR_PASSWORD / MINESTRATOR_SERVER_ID)。")
        print("[!] 若在本地运行，请在当前目录创建 .env 并填入凭据；若在 GitHub Actions 运行，请在仓库 Settings → Secrets 中添加对应变量。")
        print("[*] 本次保活任务安全退出，未执行任何网络请求。")
        return

    # 1. 启动代理节点 (只要配置了 MINESTRATOR_PROXY_NODES 或 PROXY_NODES 且不为空，即开启代理)
    proxy_proc, proxy_url, geo_info = None, None, None
    target_proxy_nodes = MINESTRATOR_PROXY_NODES or PROXY_NODES
    if target_proxy_nodes.strip():
        print(f"[*] 检测到代理节点配置 ({'MINESTRATOR_PROXY_NODES' if MINESTRATOR_PROXY_NODES else 'PROXY_NODES'})，启动代理中...")
        proxy_proc, proxy_url, geo_info = start_proxy_node(target_proxy_nodes, LOCAL_PROXY_PORT)
    else:
        print("[*] 未检测到代理节点配置，使用原生网络直连模式...")

    # 2. 执行 REST API 账号密码登录
    print("\n1. 执行 MineStrator 账号密码直连登录...")
    api_login_ok, fresh_token, user_data = login_via_rest_api(MINESTRATOR_EMAIL, MINESTRATOR_PASSWORD, proxy_url)
    active_auth = fresh_token or MINESTRATOR_AUTH

    # 3. 查询服务器当前运行状态
    print(f"\n2. 查询服务器 ID: {MINESTRATOR_SERVER_ID} 状态...")
    server_data = query_server_status(active_auth, MINESTRATOR_SERVER_ID, proxy_url)

    api_authed = bool(server_data and "server" in server_data)
    if api_authed:
        print("[+] ✅ 服务器控制面板数据获取成功！")
    else:
        print("[-] ❌ 服务器控制面板数据获取失败。")

    server_obj = server_data.get("server", {})
    server_name = server_obj.get("name", "MineStrator Free Server")
    server_ip = server_obj.get("ip", "127.0.0.1")
    server_port = str(server_obj.get("port", 25565))
    tstart = server_obj.get("tstart", "未知")
    tend = server_obj.get("tend", "")

    print(f"[+] 服务器名称: {server_name}")
    print(f"[+] 当前连通地址: {server_ip}:{server_port}")
    print(f"[+] 本次启动时间: {tstart}")
    if tend:
        print(f"[+] 30 天 Box 免费保活到期时间 (tend): {tend}")

    # 4. 触发重启保活操作
    print("\n3. 执行 Restart/Start 开机保活操作...")
    power_success = False
    
    is_online = bool(server_obj and (server_obj.get("status") == 1 or server_obj.get("connected") is True or "tstart" in server_obj))
    target_signal = "restart" if is_online else "start"

    # 计算当前 4 小时关机剩余时间
    rem_seconds = 0
    if tstart and tstart != "未知":
        try:
            start_dt = datetime.datetime.strptime(tstart, "%Y-%m-%d %H:%M:%S").replace(tzinfo=TZ_CN)
            deadline_dt = start_dt + datetime.timedelta(hours=4)
            now_dt = datetime.datetime.now(TZ_CN)
            rem_seconds = int((deadline_dt - now_dt).total_seconds())
        except Exception:
            pass

    # 定时重启间隔为 3 小时 (10800 秒)。若剩余关机倒计时 > 3 小时，说明近期刚重启过，智能跳过本次重启
    if rem_seconds > 10800 and is_online:
        h = rem_seconds // 3600
        m = (rem_seconds % 3600) // 60
        s = rem_seconds % 60
        print(f"[*] 监测到剩余关机时间 ({h:02d}h {m:02d}m {s:02d}s) 大于定时重启间隔 (3小时)，智能跳过本次重启。")
        power_success = True
    else:
        print(f"[*] 服务器当前状态: {'Online (在线)' if is_online else 'Offline (离线)'}，优先尝试 WebSocket 下发 '{target_signal}' 信号重置 4 小时倒计时...")
        power_success = trigger_restart_via_websocket(MINESTRATOR_SERVER_ID, active_auth, proxy_url, signal=target_signal)
        
        if not power_success and MINESTRATOR_PASSWORD:
            print("[!] WebSocket 通道未成功，降级尝试 Playwright 网页模拟...")
            power_success = trigger_restart_via_playwright(MINESTRATOR_EMAIL, MINESTRATOR_PASSWORD, MINESTRATOR_SERVER_ID, proxy_url, active_auth)
        elif not power_success:
            print("[!] WebSocket 通道未成功，且未配置密码跳过 Playwright 网页模拟。")

    overall_success = api_login_ok and power_success

    # 4.1 派发假玩家 Bot 连接以消除 0 玩家关机检测 (显示 👤 1/20 在线)
    print("\n4. 派发 Minecraft 假玩家挂机 Bot (显示 👤 1/20 在线)...")
    send_mc_bot_join(server_ip, int(server_port), username="Bot_Keeper", hold_seconds=5)

    # 5. 组装并发送 Telegram 通知
    tg_report = build_tg_report(power_success, api_login_ok, server_name, MINESTRATOR_SERVER_ID, MINESTRATOR_EMAIL, server_ip, server_port, tstart, tend, geo_info)
    send_tg_notification(tg_report)

    # 6. 更新 time.txt 记录
    try:
        now_str = now_cn_str()
        with open("time.txt", "w", encoding="utf-8") as f:
            f.write(now_str + "\n")
        print("[+] 更新本地 time.txt 成功。")
    except Exception as e:
        print(f"[-] 更新 time.txt 失败: {e}")

    # 7. 清理代理进程
    if proxy_proc:
        print("[*] 清理本地 sing-box 代理进程...")
        proxy_proc.terminate()

    print("==================================================")
    if not (api_login_ok and power_success):
        raise RuntimeError(f"[-] ❌ 保活流程未完全通过！(API登录: {'✅成功' if api_login_ok else '❌失败'}, 电源控制: {'✅成功' if power_success else '❌失败'})")


if __name__ == "__main__":
    main()
