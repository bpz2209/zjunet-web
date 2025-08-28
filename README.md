# zjunet-web（ZJU EE 实验室自用）

一个极简的 **zjunet VPN Web 管理面板**：让实验室同学无需登录宿主机 CLI，就能在浏览器里输入学号和密码发起连接。

> ⚠️ 仅供 ZJU EE 某实验室内部自用。与浙江大学及 zjunet 官方无关。请勿公开暴露在互联网。

---

## ✨ 功能特性

- **一键连接**：输入学号（纯数字）与密码，自动完成：
  1. 断开当前 PPP；
  2. **删除**所有现有 zju 账户配置；
  3. 以交互方式执行 `zjunet user add`（用户名↵、密码↵）；
  4. 执行 `zjunet vpn -c` 连接。
- **单用户模型**：始终只保留一个 zjunet 账户（当前登录人）。
- **当前用户名显示**：界面直接显示 `zjunet user list` 的结果（通常只有一个学号）。
- **状态与时长**：展示 PPP 状态、连接开始时间与 **在线时长秒表**。
- **失败诊断**：自动收集日志，能识别常见失败原因（如 **CHAP 认证失败/密码错误**、IPCP 超时等）。
- **轻量自动刷新**：页面每 **5s** 轮询 `/status`，无整页刷新。
- **并发保护**：文件锁 `state.lock`（含**陈旧锁自清理**，>5min 自动清）。

---

## 🧩 运行环境

- Ubuntu 20.04/22.04（其他现代发行版一般也可）
- 已安装并可用的：
  - `zjunet`（命令行）
  - `xl2tpd`, `pppd`
- Python 3.9+（建议）
- 能以 sudo 执行系统命令（细见下一节）

---

## 🔐 sudo 权限说明

- **启动时强制输入一次 sudo 密码**（非 root）：程序先 `sudo -K` 清缓存，再 `sudo -v` 验证并后台 **5 分钟保活**，之后所有调用都走 `sudo -n`，不会再二次询问。
- 若要 **无密码常驻**（例如 systemd 服务），建议为运行用户配置 **sudoers NOPASSWD** 白名单（见下文）。

---

## 🚀 快速开始

```bash
# 1) 获取代码与依赖
git clone <your-repo-or-folder> zjunet-web
cd zjunet-web
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

# 2) 可选：指定状态目录（避免权限问题）
export ZJUNET_WEB_STATE_DIR="$HOME/.local/state/zjunet-web"
mkdir -p "$ZJUNET_WEB_STATE_DIR"

# 3) 运行（终端会要求你输入一次 sudo 密码）
python app.py

# 4) 浏览器访问（同局域网即可）
# http://<宿主机IP>:5080/

