#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple, List
from threading import Thread, Event

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from filelock import FileLock, Timeout
import getpass
import sys

app = Flask(__name__)
app.secret_key = "change-me"  # 生产替换

# ---------------- 可调参数 ----------------
CONNECT_TIMEOUT  = 30    # zjunet 连接超时（秒）
LOCK_TIMEOUT     = 8     # 文件锁等待（秒）
LOCK_STALE_SECS  = 300   # 锁文件超过 5 分钟视为陈旧，自动清理一次
LOG_LINES        = 120   # 失败采集日志行数
SUDO_REFRESH     = 300   # sudo 凭据保活周期（秒，默认 5 分钟）

# ---------------- 状态目录选择（可写优先） ----------------
def _pick_state_dir() -> Path:
    cand = []
    if os.environ.get("ZJUNET_WEB_STATE_DIR"):
        cand.append(Path(os.environ["ZJUNET_WEB_STATE_DIR"]))
    if os.environ.get("XDG_STATE_HOME"):
        cand.append(Path(os.environ["XDG_STATE_HOME"]) / "zjunet-web")
    cand += [
        Path.home() / ".local/state/zjunet-web",
        Path(f"/run/user/{os.getuid()}/zjunet-web"),
        Path("/var/lib/zjunet-web"),
        Path(tempfile.gettempdir()) / "zjunet-web",
    ]
    for p in cand:
        try:
            p.mkdir(parents=True, exist_ok=True)
            t = p / ".writetest"
            t.write_text("ok")
            t.unlink(missing_ok=True)
            return p
        except Exception:
            continue
    return Path(tempfile.gettempdir()) / "zjunet-web"

STATE_DIR  = _pick_state_dir()
STATE_FILE = STATE_DIR / "state.json"
LOCK_FILE  = STATE_DIR / "state.lock"

# ---------------- 自动 sudo：启动时要求输入一次密码并保活 ----------------
SUDO: List[str] = ["sudo", "-n"]
SUDO_MODE = "sudo 缓存"
_sudo_keepalive_stop = Event()

def _sudo_keepalive_loop():
    while not _sudo_keepalive_stop.is_set():
        try:
            subprocess.run(["sudo", "-n", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        _sudo_keepalive_stop.wait(SUDO_REFRESH)

def require_sudo_once():
    """非 root 强制输入一次 sudo 密码，然后全程用 -n；后台保活。"""
    global SUDO, SUDO_MODE
    if os.geteuid() == 0:
        SUDO = []
        SUDO_MODE = "root(无需 sudo)"
        return

    print("需要 sudo 权限：将清除旧缓存并强制验证一次密码（之后自动保活）", file=sys.stderr)
    # 1) 清除任何已存在的 sudo 缓存，保证一定会提示密码
    subprocess.run(["sudo", "-K"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 2) 在当前 TTY 验证一次
    rc = subprocess.run(["sudo", "-v"]).returncode
    if rc != 0:
        # 兜底：以 -S 方式读取一次密码
        pw = getpass.getpass("sudo 密码: ")
        p = subprocess.run(["sudo", "-S", "-v"], input=pw + "\n", text=True)
        pw = None
        if p.returncode != 0:
            raise SystemExit("获得 sudo 失败：请在终端运行并确保密码正确，或改用 root 运行。")

    # 3) 后续全程 -n + 保活
    SUDO = ["sudo", "-n"]
    SUDO_MODE = "sudo -n(已缓存)"
    Thread(target=_sudo_keepalive_loop, daemon=True).start()
# ---------------- 系统路径 ----------------
CHAP_SECRETS = Path("/etc/ppp/chap-secrets")
XL2TPD_CONF  = Path("/etc/xl2tpd/xl2tpd.conf")
ZJU_PREFIX   = "zju-l2tp-"

# ---------------- 通用工具 ----------------
def run(cmd, *, input_text: Optional[str]=None, check=True, timeout=60) -> Tuple[int, str, str]:
    proc = subprocess.run(
        cmd, input=input_text if input_text is not None else None,
        text=True, capture_output=True, timeout=timeout
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"cmd failed: {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
    return proc.returncode, proc.stdout, proc.stderr

def is_numeric_user(u: str) -> bool:
    return bool(re.fullmatch(r"\d+", u))

def safe_read(path: Path) -> str:
    try:
        return path.read_text()
    except PermissionError:
        rc, out, err = run(SUDO + ["cat", str(path)], check=False)
        if rc != 0:
            raise RuntimeError(f"无法读取 {path}：{err or out}")
        return out

def safe_write(path: Path, content: str):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    except PermissionError:
        path.parent.mkdir(parents=True, exist_ok=True)
        _, out, err = run(SUDO + ["tee", str(path)], input_text=content, check=False)
        if "Permission denied" in err:
            raise RuntimeError(f"无法写入 {path}，请配置 sudoers 或使用 root。详情：{err or out}")

def _with_lock(fn):
    """获取文件锁；如锁陈旧（mtime>LOCK_STALE_SECS），清理后重试一次。"""
    try:
        with FileLock(str(LOCK_FILE), timeout=LOCK_TIMEOUT):
            return fn()
    except Timeout:
        try:
            if LOCK_FILE.exists() and (time.time() - LOCK_FILE.stat().st_mtime) > LOCK_STALE_SECS:
                try:
                    os.remove(LOCK_FILE)
                except PermissionError:
                    subprocess.run(SUDO + ["rm", "-f", str(LOCK_FILE)], check=False)
                with FileLock(str(LOCK_FILE), timeout=LOCK_TIMEOUT):
                    return fn()
        except FileNotFoundError:
            with FileLock(str(LOCK_FILE), timeout=LOCK_TIMEOUT):
                return fn()
        raise RuntimeError(f"状态锁被占用：{LOCK_FILE}。请稍后重试或手动删除该锁文件。")

def load_state() -> Dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"active_user": None, "since": None, "last_log": ""}

def save_state(d: Dict):
    _with_lock(lambda: STATE_FILE.write_text(json.dumps(d, ensure_ascii=False, indent=2)))

def current_ppp_up() -> bool:
    rc, out, _ = run(SUDO + ["ip", "-4", "addr", "show", "dev", "ppp0"], check=False)
    return rc == 0 and "ppp0" in out

def disconnect():
    run(SUDO + ["zjunet", "vpn", "-d"], check=False, timeout=20)
    run(SUDO + ["xl2tpd-control", "disconnect", "zju-l2tp"], check=False, timeout=10)
    run(SUDO + ["poff", "-a"], check=False, timeout=10)
    time.sleep(1)

def fmt_duration(seconds: int) -> str:
    if seconds < 0: seconds = 0
    h, r = divmod(seconds, 3600)
    m, s = divmod(r, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"

# ---------------- zjunet 用户列表（用于“当前用户名”展示） ----------------
def zjunet_user_list() -> Tuple[List[str], str]:
    rc, out, err = run(SUDO + ["zjunet", "user", "list"], check=False, timeout=10)
    text = (out or "") + ("\n" + err if err else "")
    users: List[str] = []
    for line in text.splitlines():
        m = re.search(r"zju-l2tp-(\d+)", line)
        if m:
            users.append(m.group(1)); continue
        m2 = re.findall(r"\b(\d{5,})\b", line)
        for u in m2:
            if u not in users:
                users.append(u)
    return users, text

# ---------------- 删除所有 zju 账户配置（不回滚） ----------------
def purge_chap_all_zju():
    txt = safe_read(CHAP_SECRETS) if CHAP_SECRETS.exists() else ""
    lines = txt.splitlines()
    out = []
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("#"):
            out.append(ln); continue
        parts = s.split()
        if parts and parts[0].startswith(ZJU_PREFIX):
            continue
        out.append(ln)
    safe_write(CHAP_SECRETS, ("\n".join(out).rstrip() + "\n") if out else "")

def purge_xl2tpd_all_zju():
    if not XL2TPD_CONF.exists():
        return
    txt = safe_read(XL2TPD_CONF)
    blocks = re.split(r"(?=\[lac\s+[^\]]+\])", txt, flags=re.IGNORECASE)
    out_blocks = []
    for b in blocks:
        if not b.strip():
            continue
        m = re.match(r"\[lac\s+([^\]]+)\]", b, flags=re.IGNORECASE)
        if not m:
            out_blocks.append(b); continue
        name = m.group(1).strip()
        if name.startswith(ZJU_PREFIX):
            continue
        out_blocks.append(b)
    safe_write(XL2TPD_CONF, "".join(out_blocks))

# ---------------- 日志 & 诊断 ----------------
def collect_ppp_logs(max_lines: int = LOG_LINES) -> str:
    rc, out, err = run(SUDO + ["journalctl", "-u", "pppd", "-n", str(max_lines), "--no-pager"], check=False)
    if rc == 0 and out.strip():
        return out
    for path in ("/var/log/syslog", "/var/log/messages", "/var/log/ppp/pppd.log", "/var/log/ppp.log"):
        rc, out, err = run(SUDO + ["sh", "-lc", f"tail -n {max_lines} {path} 2>/dev/null | grep -E 'pppd|xl2tp|l2tp|CHAP|IPCP' || true"], check=False)
        if out.strip():
            return out
    return "(未获取到 ppp 日志)"

def diagnose_failure(zjunet_out: str, zjunet_err: str, logs: str) -> str:
    text = "\n".join([zjunet_out or "", zjunet_err or "", logs or ""])
    if re.search(r"CHAP authentication failed|Login incorrect|authentication failed", text, re.I):
        return "账号或密码错误（CHAP 认证失败）"
    if re.search(r"LCP terminated by peer|no response to \d+ echo-requests", text, re.I):
        return "链路断开或对端无响应（LCP）"
    if re.search(r"IPCP: timeout|IPCP terminated", text, re.I):
        return "IP 配置阶段失败（IPCP 协商超时/失败）"
    if re.search(r"Fail to bring up ppp|timeout", text, re.I):
        return "建立 PPP 失败（超时/对端未响应）"
    if re.search(r"could not resolve|temporary failure resolving", text, re.I):
        return "DNS 解析失败"
    return "连接失败（具体见下方日志）"

# ---------------- 交互式新增账户 & 连接（不回滚） ----------------
def zjunet_user_add_interactive(username: str, password: str) -> Tuple[int, str, str]:
    payload = f"{username}\n{password}\n"
    return run(SUDO + ["zjunet", "user", "add"], input_text=payload, check=False, timeout=20)

def connect_with_account(username: str, password: str) -> str:
    if not is_numeric_user(username):
        raise ValueError("账号必须为纯数字")

    def _do_connect():
        # 1) 断开
        disconnect()
        # 2) 删除所有已有 zju 账户（chap & xl2tpd）
        purge_chap_all_zju()
        purge_xl2tpd_all_zju()
        run(SUDO + ["systemctl", "restart", "xl2tpd"], check=False, timeout=20)
        # 3) 交互式新增账户（用户名↵，密码↵）
        ac_rc, ac_out, ac_err = zjunet_user_add_interactive(username, password)
        if ac_rc != 0:
            users, raw = zjunet_user_list()
            raise RuntimeError(f"""新增账户失败：
--- zjunet user add 输出 ---
{ac_out}{('\n'+ac_err) if ac_err else ''}
--- 现有用户列表 ---
{', '.join(users) if users else '(无)'}
原始：
{raw}""")
        # 4) 发起连接（限时）
        try:
            rc, out, err = run(SUDO + ["zjunet", "vpn", "-c"], check=False, timeout=CONNECT_TIMEOUT)
        except subprocess.TimeoutExpired:
            rc, out, err = 124, "", "zjunet 连接命令超时"
        ok = current_ppp_up()
        users, raw_list = zjunet_user_list()
        log = []
        if ac_out: log.append(ac_out)
        if ac_err: log.append(ac_err)
        if out:    log.append(out)
        if err:    log.append(err)
        log.append("--- zjunet user list ---")
        log.append(raw_list)
        final_log = "\n".join([s for s in log if s and s.strip()])
        if not ok:
            ppp_logs = collect_ppp_logs()
            reason   = diagnose_failure(out, err, ppp_logs)
            raise RuntimeError(f"""{reason}
--- 汇总输出 ---
{final_log}
--- ppp 日志 ---
{ppp_logs}""")
        return final_log

    return _with_lock(_do_connect)

# ---------------- 路由 ----------------
@app.get("/")
def index():
    s = load_state()
    users, _ = zjunet_user_list()               # 用于“当前用户名”的展示
    display_users = "、".join(users) if users else "—"

    # 在线时长
    duration_hms = None
    duration_sec = 0
    ppp = current_ppp_up()
    since_js = None
    if s.get("since") and ppp:
        try:
            since_dt = datetime.strptime(s["since"], "%Y-%m-%d %H:%M:%S")
            duration_sec = int((datetime.now() - since_dt).total_seconds())
            duration_hms = fmt_duration(duration_sec)
            since_js = s["since"].replace(" ", "T")  # 供前端秒表使用
        except Exception:
            pass

    return render_template(
        "index.html",
        display_users=display_users,   # 当前用户名 = user list
        since=s.get("since"),
        since_js=since_js,
        duration_hms=duration_hms,
        last_log=s.get("last_log"),
        ppp_up=ppp,
        state_dir=str(STATE_DIR),
        sudo_mode=SUDO_MODE,
    )

@app.post("/login")
def login():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    if not is_numeric_user(username):
        flash("账号必须为纯数字", "error")
        return redirect(url_for("index"))

    try:
        log = connect_with_account(username, password)
        save_state({"active_user": username, "since": time.strftime("%F %T"), "last_log": log})
        flash(f"已连接为 {username}", "ok")
    except Exception as e:
        save_state({"active_user": None, "since": None, "last_log": str(e)})
        flash(str(e), "error")
    return redirect(url_for("index"))

@app.post("/logout")
def logout():
    try:
        disconnect()
        flash("已断开连接", "ok")
    finally:
        save_state({"active_user": None, "since": None, "last_log": "disconnected"})
    return redirect(url_for("index"))

@app.get("/status")
def status():
    s = load_state()
    ppp = current_ppp_up()
    duration_sec = 0
    if s.get("since") and ppp:
        try:
            since_dt = datetime.strptime(s["since"], "%Y-%m-%d %H:%M:%S")
            duration_sec = int((datetime.now() - since_dt).total_seconds())
        except Exception:
            pass
    return jsonify({
        "current_users": zjunet_user_list()[0],  # 直接暴露 user list
        "since": s.get("since"),
        "ppp_up": ppp,
        "duration_seconds": duration_sec,
        "state_dir": str(STATE_DIR),
        "sudo_mode": SUDO_MODE,
    })

def _shutdown():
    _sudo_keepalive_stop.set()

if __name__ == "__main__":
    require_sudo_once()
    try:
        app.run(host="0.0.0.0", port=5080, debug=True, use_reloader=False)
    finally:
        _shutdown()

