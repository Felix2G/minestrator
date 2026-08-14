# 🎮 MineStrator Server 自动保活与 4 小时关机重置工具

本项目专门用于解决 [MineStrator](https://minestrator.com) 免费版（MyBox Free）每 4 小时强制关机、以及人头检测判定掉线的限制。通过定时调度、Pterodactyl 协议直连与假玩家 TCP 挂机握手，实现全天候稳定运行。

---

## 🌟 功能特性

- ⏱️ **自动重置 4 小时关机**：每 3 小时自动触发服务器重启/唤醒，将关机倒计时重置回 `4h 00m 00s`。
- 👤 **假玩家 Minecraft 协议挂机**：通过轻量级 TCP 协议握手模拟玩家在线，规避空载人头关机检测。
- 🛡️ **绕过 Cloudflare 风控**：支持通过代理节点接入，彻底规避 GitHub Actions IP 被阻挡的问题。
- 📲 **Telegram 实时推送**：每次保活后自动上报服务器当前状态、4小时倒计时以及 30 天大保活有效期。

---

## 🔐 环境变量 & Secrets 参数配置说明

无论是在 **GitHub Actions**（推荐）还是在 **本地环境** 运行，均需配置以下环境变量：

### 1. 参数列表与必填项

| 参数名称 | 属性 | 示例值 | 说明 |
| :--- | :---: | :--- | :--- |
| `MINESTRATOR_EMAIL` | **必填** | `user@example.com` | MineStrator 账号的登录邮箱 |
| `MINESTRATOR_PASSWORD` | **必填** | `YourPassword123` | MineStrator 账号登录密码（用于模拟登录并获取面板控制权） |
| `MINESTRATOR_SERVER_ID` | **必填** | `123456` | 你的服务器数字 ID（见下文获取方式） |
| `MINESTRATOR_AUTH` | *可选* | `Bearer Z1p...` | MineStrator API Token（留空时脚本会自动登录网页获取） |
| `MINESTRATOR_PROXY_NODES` | *可选* | `vless://...` | **MineStrator 专用代理节点**（填入住宅/专线节点，不为空时自动启用本地代理） |
| `PROXY_NODES` | *可选* | `vmess://...` | 备用代理节点链接（支持 VMess / VLESS） |
| `TG_BOT_TOKEN` | *可选* | `123456789:ABCdef...` | Telegram Bot Token，用于接收运行状态推送 |
| `TG_CHAT_ID` | *可选* | `123456789` | 接收通知的 Telegram 个人或群组 Chat ID |

---

### 2. 核心参数获取方法

#### ① 获取 `MINESTRATOR_SERVER_ID`
1. 登录 [MineStrator 控制面板](https://minestrator.com/my)。
2. 点击进入你的免费服务器管理页面。
3. 查看浏览器地址栏中的 URL，例如：`https://minestrator.com/my/server/123456`，其中的 **`123456`** 即为你的 `MINESTRATOR_SERVER_ID`。

#### ② 获取 `MINESTRATOR_AUTH`（可选，推荐留空自动登录）
- 若留空，脚本会使用 `MINESTRATOR_EMAIL` 和 `MINESTRATOR_PASSWORD` 自动完成网页授权。
- 若需要手动抓取：打开浏览器 F12 开发者工具，切换到 **Network (网络)** 标签页，刷新控制台页面，在任意发往 `minestrator.com/api/...` 的请求头中找到 `Authorization` 字段（格式通常为 `Bearer xxx...`）。

#### ③ 获取 Telegram 通知参数（可选）
- **`TG_BOT_TOKEN`**：在 Telegram 中私聊 [@BotFather](https://t.me/BotFather) 发送 `/newbot` 创建机器人获取。
- **`TG_CHAT_ID`**：私聊 [@userinfobot](https://t.me/userinfobot) 获取你的个人数字 ID。

---

## 🚀 部署与使用方式

### 方式 A：GitHub Actions 自动托管运行（推荐）

1. **Fork 本仓库** 或克隆到你自己的 GitHub 账号下。
2. 进入仓库页面，点击 **Settings** → **Secrets and variables** → **Actions**。
3. 点击 **New repository secret**，依次添加上述参数（至少需要添加 `MINESTRATOR_EMAIL`、`MINESTRATOR_PASSWORD` 和 `MINESTRATOR_SERVER_ID`）。
4. 进入仓库的 **Actions** 标签页，启用工作流（Workflow），点击 **Auto Renew MineStrator Server** → **Run workflow** 进行首次测试。
5. 工作流已预设定时任务：**每 3 小时自动触发一次**，无需人工干预。

---

### 方式 B：本地 / VPS 运行

1. **克隆代码与安装依赖**：
   ```bash
   git clone https://github.com/Felix2G/minestrator.git
   cd minestrator
   pip install -r requirements.txt
   playwright install chromium
   ```

2. **配置环境变量**：
   复制配置文件模板并填入你的参数：
   ```bash
   cp .env.example .env
   # 使用文本编辑器修改 .env 填入你的账号信息
   ```

3. **执行保活脚本**：
   ```bash
   python renew_minestrator.py --debug
   ```

---

## 📋 常见问题排查 (FAQ)

- **Q: 遇到 Cloudflare 403 阻挡或验证码怎么办？**
  - 在 Secrets 中配置 `MINESTRATOR_PROXY_NODES` 或 `PROXY_NODES` 填入可用的代理节点，脚本会自动启动本地 `sing-box` 转发流量绕过风控。
- **Q: 是否支持多台服务器？**
  - 当前单实例对应单台服务器。如需保活多台，可在 GitHub 仓库创建多个分支或在同一工作流矩阵中配置不同 Server ID。

---

## ⚖️ 免责声明
本项目仅供个人学习、技术研究与自动化运维测试使用，请勿用于违反服务商条款或任何商业用途。
