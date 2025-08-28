# zjunet-web

一个极简的 Web 面板，用于在服务器上以**有线网账号**发起 ZJU L2TP 拨号（`zjunet vpn -c`）。

- 仅允许一个活跃账号：连接前会清理历史 zju 账户配置（`chap-secrets` / `xl2tpd.conf` 中以 `zju-l2tp-` 开头的条目）。
- 只展示**结果级**信息：`已连接 / 密码错误 / 连接超时 / 连接失败 / 系统正忙`，不回显原始系统日志到页面。
- 前端每 **5 秒**自动刷新连接状态与在线时长。
- 首次启动**强制输入一次 sudo 密码**，随后自动保活（周期性 `sudo -n -v`）。
- 所有可能卡住的 root 命令均由 **`timeout`** 控时，避免 Python 在超时后 kill 不掉 root 进程导致 `PermissionError`。
- BasicAuth 账号/密码、服务端口、Flask secret 均从 **`config.json`** 读取；**不存在则自动生成**。
- 锁健壮性：自动检测并清理可能的“假死”锁（`state.lock`），避免并发时 500。

> 适用：多用户共用一台宿主机，允许用户在网页上用**自己的有线网账号**拨号联网，且不泄露系统细节。

---

## 目录结构

```
.
├─ app.py                 # Flask 后端（核心逻辑）
├─ requirements.txt       # Python 依赖
├─ templates/
│  └─ index.html          # 前端页面（含 5 秒轮询脚本）
└─ config.json            # 运行时自动生成/读取（BasicAuth / port / secret）
```

运行期状态目录（JSON/Lock，以下路径会按顺序尝试与回退）：

- `$HOME/.local/state/zjunet-web/`
- `/run/user/$UID/zjunet-web/`
- `/var/lib/zjunet-web/`
- `/tmp/zjunet-web/`

文件：`state.json`, `state.lock`。

---

## 前置条件

### 系统与工具
- Ubuntu 20.04+（Debian/其它发行版可参考调整）
- `python3 (>= 3.10)` 与 `venv`
- `zjunet`（命令行可用）
- `xl2tpd`、`ppp`、`poff`（例如：`sudo apt install xl2tpd ppp`）
- `iproute2`（包含 `ip` 命令）
- `coreutils`（自带 `timeout`）
- `lsof`（可选，用于检测锁持有者，建议安装：`sudo apt install lsof`）
- `systemd`（用于 `systemctl restart xl2tpd`）

### 网络与权限
- Web 端口默认 **5080**，需放行或通过反向代理暴露。
- 需要 **sudo** 执行若干命令；程序启动时会交互输入一次 sudo 密码。

---

## 快速开始（开发/本地运行）

```bash
git clone <your-repo-url> zjunet-web
cd zjunet-web

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
python app.py          # 首次会生成 config.json，并提示输入 sudo 密码
```

然后在浏览器访问：`http://<服务器IP或域名>:<端口>`（默认端口 5080）。

> 首次运行会在项目根目录生成 `config.json`，并随机写入 `secret`。


---

## 配置说明（config.json）

示例（首次启动自动生成）：
```json
{
  "basic_user": "plz change it",
  "basic_pass": "plz change it",
  "secret": "自动生成的随机hex",
  "port": 5080
}
```

字段含义：

- `basic_user` / `basic_pass`：Web 面板 BasicAuth 的用户名与密码。
- `secret`：Flask 的会话/CSRF 秘钥，**建议随机且足够长**（首次生成）。
- `port`：监听端口（默认 `5080`）。

> 修改 `config.json` 后，重启程序生效。


---

## 使用说明（用户视角）

1. 打开 `http://<服务器>:<port>`，输入 BasicAuth（在 `config.json` 中）。
2. 在页面右侧表单输入：
   - **有线网账号**（必须**纯数字**，例如学号）
   - **有线网密码**
3. 点击“连接”。
4. 页面**仅**显示结果级文本：
   - ✅ **已连接**
   - ❌ **密码错误**
   - ⏱️ **连接超时**
   - ⚠️ **连接失败**
   - ⛔ **系统正忙，请稍后再试**（通常是上一次连接流程未完全结束或锁占用）

左侧面板会显示：
- 当前用户名（从 `zjunet user list` 解析到的账号，通常只有一个）
- 连接开始时间与在线时长（前端每 5 秒自动刷新）
- “断开连接”按钮

> 页面不会显示任何系统日志或敏感信息。


---

## 运行机制（简述）

- 登录时序：
  1) **断开**已有连接：`zjunet vpn -d`、`xl2tpd-control disconnect zju-l2tp`、`poff -a`
  2) **清理账户配置**：从 `/etc/ppp/chap-secrets` 与 `/etc/xl2tpd/xl2tpd.conf` 中移除以 `zju-l2tp-` 开头的条目
  3) **重启** `xl2tpd`
  4) 交互式添加账户：`zjunet user add`（通过 `stdin` 依次写入“账号↵密码↵”）
  5) 拨号：`zjunet vpn -c`（用 `timeout` 控时；返回码 124 视为超时）
  6) 验证 `ppp0` 是否就绪；若失败，根据日志/输出归因到“密码错误/连接超时/连接失败”

- 并发与锁：所有连接流程包裹在 `state.lock` 内；如果锁长时间无持有者或 mtime 过旧会被自动清理。抢锁失败时返回“系统正忙”。

- 安全头：设置 CSP，允许 `style`/`script` 的 `unsafe-inline`，以便页面内联脚本实现 5 秒轮询与秒表显示。


---

## 生产部署建议

### 前台运行（简便）
```bash
cd /path/to/zjunet-web
source .venv/bin/activate
uv run app.py
```
- 首次以交互方式输入 sudo 密码。



## 接口（仅供自测/集成）

### `GET /`（需 BasicAuth）
- 渲染页面，显示当前状态与连接表单。

### `GET /status`（需 BasicAuth）
返回 JSON：
```json
{
  "current_users": ["22310046"],
  "since": "2025-08-28 11:20:33",
  "ppp_up": true,
  "duration_seconds": 1234,
  "last_status": "已连接"
}
```

### `POST /login`（需 BasicAuth + CSRF）
- 表单字段：`username`（纯数字）、`password`（有线网密码）。
- 只返回最小结果（页面闪烁提示）。

### `POST /logout`（需 BasicAuth + CSRF）
- 断开连接并清理状态。

---

## 常见问题（FAQ）

### 1) 页面不自动刷新
- 检查浏览器控制台是否有 CSP 报错；本项目已在响应头允许了 `script-src 'unsafe-inline'`。
- 确认 `/status` 请求为 **200**。若是 **401**，说明 BasicAuth 未携带（同域同端口一般会自动带上）。

### 2) 显示“系统正忙，请稍后再试”
- 通常为并发请求或上次连接尚未结束；等待数秒后重试。
- 如果频繁出现，可手动清理锁：
  ```bash
  sudo rm -f ~/.local/state/zjunet-web/state.lock
  ```
  或检查实际状态目录（见前文）。

### 3) 权限/超时相关报错
- 本项目通过 `timeout` 控时（退出码 `124` 视为“连接超时”），避免 Python 杀不掉 root 进程引发 `PermissionError`。
- 确认系统存在 `timeout`： `which timeout`。若不存在：`sudo apt install coreutils`。

### 4) `zjunet` / `xl2tpd` / `ppp` 未安装
```bash
sudo apt update
sudo apt install xl2tpd ppp
# zjunet 请按学校/团队文档安装
```

### 5) BasicAuth 或端口修改
- 编辑 `config.json` 的 `basic_user`、`basic_pass`、`port`，然后重启程序。

### 6) 仍无法联网
- 登录用户的“有线网账号/密码”是否正确（账号必须**纯数字**）。
- 服务器外层网络与 L2TP 是否被上游设备/ISP 限制（UDP 1701 / L2TP over IPsec 等）。
- `journalctl -u pppd` 或 `tail -n 200 /var/log/syslog` 查看详细日志（仅运维自查，不会回显到页面）。

---

## 卸载/清理

```bash
systemctl stop zjunet-web.service  # 若使用 systemd
systemctl disable zjunet-web.service
sudo rm -f /etc/systemd/system/zjunet-web.service
sudo systemctl daemon-reload

# 删除程序目录
rm -rf /opt/zjunet-web  # 或你的安装路径

# 清理状态目录（若需要）
rm -rf ~/.local/state/zjunet-web
rm -rf /run/user/$UID/zjunet-web
sudo rm -rf /var/lib/zjunet-web
rm -rf /tmp/zjunet-web
```

---

## 许可

按你的项目策略自行添加（MIT/Apache-2.0 等）。默认无许可证不建议对外分发。

---

## 变更点（实现要点回顾）

- BasicAuth / 端口 / secret → `config.json`（无则自动生成，`secret` 随机）。
- 首次 sudo，随后 `sudo -n -v` 保活。
- 连接流程统一使用 root 侧 `timeout` 控时。
- 仅回传“结果级”信息（成功/密码错误/超时/失败/正忙）。
- 锁文件假死自动检测与清理；抢锁失败时用户得到友好提示。
- 前端使用 5 秒轮询 `/status`，并有秒表显示在线时长。
