#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json, os, re, subprocess, tempfile, time, secrets, hmac, getpass, sys, shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple, List
from threading import Thread, Event
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, session, Response
from filelock import FileLock, Timeout

# ---------------- config.json 读取 / 自动生成 ----------------
BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"

DEFAULT_CONFIG = {
    "basic_user": "zjuee229",
    "basic_pass": "helloworld229",
    "secret": None,           # 首次运行会自动填充随机值
    "port": 5080
}

def _write_config(cfg: Dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if cfg.get("secret") is None:
        cfg["secret"] = secrets.token_hex(32)
    tmp = CONFIG_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2))
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    tmp.replace(CONFIG_PATH)

def load_or_init_config() -> Dict:
    if not CONFIG_PATH.exists():
        cfg = DEFAULT_CONFIG.copy()
        cfg["secret"] = secrets.token_hex(32)
        _write_config(cfg)
        return cfg
    try:
        cfg = json.loads(CONFIG_PATH.read_text())
    except Exception:
        cfg = {}
    changed = False
    for k, v in DEFAULT_CONFIG.items():
        if k not in cfg or (k == "secret" and not cfg.get("secret")):
            cfg[k] = secrets.token_hex(32) if k == "secret" else v
            changed = True
    if changed:
        _write_config(cfg)
    return cfg

CFG = load_or_init_config()

app = Flask(__name__)
app.secret_key = CFG["secret"]  # 用于 session/CSRF
PORT = int(CFG.get("port", 5080))

# ====== BasicAuth（从 config.json 读取）======
BASIC_USER = CFG["basic_user"]
BASIC_PASS = CFG["basic_pass"]

def _unauth():
    return Response("Auth required", 401, {"WWW-Authenticate": 'Basic realm="zjunet-web"'})

def require_basic_auth():
    def deco(fn):
        @wraps(fn)
        def wrap(*args, **kwargs):
            auth = request.authorization
            if not auth or auth.username != BASIC_USER or auth.password != BASIC_PASS:
                return _unauth()
            return fn(*args, **kwargs)
        return wrap
    return deco
# ===========================================

# —— 可调参数 ——
CONNECT_TIMEOUT  = 30
LOCK_TIMEOUT     = 8
LOCK_STALE_SECS  = 45   # 锁文件“看起来卡住”多少秒后可判为陈旧
LOG_LINES        = 120
SUDO_REFRESH     = 300

# —— 可写状态目录 ——
def _pick_state_dir() -> Path:
    cand = [
        Path.home() / ".local/state/zjunet-web",
        Path(f"/run/user/{os.getuid()}/zjunet-web"),
        Path("/var/lib/zjunet-web"),
        Path(tempfile.gettempdir()) / "zjunet-web",
    ]
    for p in cand:
        try:
            p.mkdir(parents=True, exist_ok=True)
            (p / ".writetest").write_text("ok")
            (p / ".writetest").unlink(missing_ok=True)
            return p
        except Exception:
            continue
    return Path(tempfile.gettempdir()) / "zjunet-web"

STATE_DIR  = _pick_state_dir()
STATE_FILE = STATE_DIR / "state.json"
LOCK_FILE  = STATE_DIR / "state.lock"

# —— 强制 sudo：启动时要一次密码并保活 ——
SUDO: List[str] = ["sudo", "-n"]
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
    global SUDO
    if os.geteuid() == 0:
        SUDO = []
        return
    print("需要 sudo 权限：将清除旧缓存并强制验证一次密码（之后自动保活）", file=sys.stderr)
    subprocess.run(["sudo", "-K"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rc = subprocess.run(["sudo", "-v"]).returncode
    if rc != 0:
        pw = getpass.getpass("sudo 密码: ")
        p = subprocess.run(["sudo", "-S", "-v"], input=pw + "\n", text=True)
        pw = None
        if p.returncode != 0:
            raise SystemExit("获得 sudo 失败：请在终端运行并确保密码正确，或改用 root 运行。")
    SUDO = ["sudo", "-n"]
    Thread(target=_sudo_keepalive_loop, daemon=True).start()

# —— CSRF 防护 ——
def _get_csrf_token() -> str:
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token

def _check_csrf():
    token = session.get("_csrf")
    form  = request.form.get("_csrf")
    if not token or not form or not hmac.compare_digest(token, form):
        abort(400, "CSRF token invalid")

# —— 系统路径 ——
CHAP_SECRETS = Path("/etc/ppp/chap-secrets")
XL2TPD_CONF  = Path("/etc/xl2tpd/xl2tpd.conf")
ZJU_PREFIX   = "zju-l2tp-"

# —— 基础执行工具 ——
def run(cmd, *, input_text: Optional[str]=None, check=True, timeout=60) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, input=input_text if input_text is not None else None,
                       text=True, capture_output=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"cmd failed: {' '.join(cmd)}\nstdout:\n{p.stdout}\nstderr:\n{p.stderr}")
    return p.returncode, p.stdout, p.stderr

def run_root_timeout(args: List[str], seconds: int, input_text: Optional[str] = None) -> Tuple[int, str, str]:
    """
    以 root 执行并用 coreutils 的 timeout 控时，避免 Python 在超时后 kill root 进程导致 PermissionError。
    返回码 124 表示超时。
    """
    return run(
        SUDO + ["timeout", "-k", f"{seconds+5}s", f"{seconds}s"] + args,
        input_text=input_text,
        check=False,
        timeout=seconds + 10,
    )

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

def _lsof_pids(path: Path) -> List[str]:
    exe = shutil.which("lsof")
    if not exe:
        return []
    rc, out, _ = run([exe, "-t", "--", str(path)], check=False, timeout=2)
    return [p for p in out.strip().splitlines() if p.strip()]

def _force_unlock_if_stale() -> bool:
    """若锁文件无持有者或 MTime 超过阈值，则强制删除；返回是否删除。"""
    try:
        if not LOCK_FILE.exists():
            return False
        age = time.time() - LOCK_FILE.stat().st_mtime
        pids = _lsof_pids(LOCK_FILE)
        if pids:
            # 有进程持有，认为不陈旧
            return False
        # 无持有者：如果年龄超过阈值，或者大小为0（常见软锁）直接删
        if age >= LOCK_STALE_SECS or LOCK_FILE.stat().st_size == 0:
            try:
                LOCK_FILE.unlink()
                return True
            except PermissionError:
                run(SUDO + ["rm", "-f", str(LOCK_FILE)], check=False, timeout=4)
                return not LOCK_FILE.exists()
    except Exception:
        pass
    return False

def _with_lock(fn):
    try:
        with FileLock(str(LOCK_FILE), timeout=LOCK_TIMEOUT):
            return fn()
    except Timeout:
        # 第一次拿锁失败，尝试识别并清理由于崩溃/异常留下的“假死”锁
        removed = _force_unlock_if_stale()
        if removed:
            with FileLock(str(LOCK_FILE), timeout=LOCK_TIMEOUT):
                return fn()
        # 仍抢不到 -> 抛出更友好的错误（由路由捕获并给用户提示“系统正忙”）
        raise RuntimeError(f"状态锁被占用：{LOCK_FILE}")

def load_state() -> Dict:
    if STATE_FILE.exists():
        try: return json.loads(STATE_FILE.read_text())
        except Exception: pass
    return {"active_user": None, "since": None, "last_status": ""}

def save_state(d: Dict):
    _with_lock(lambda: STATE_FILE.write_text(json.dumps(d, ensure_ascii=False, indent=2)))

def current_ppp_up() -> bool:
    rc, out, _ = run(SUDO + ["ip", "-4", "addr", "show", "dev", "ppp0"], check=False)
    return rc == 0 and "ppp0" in out

def disconnect():
    run_root_timeout(["zjunet", "vpn", "-d"], 10)
    run_root_timeout(["xl2tpd-control", "disconnect", "zju-l2tp"], 10)
    run_root_timeout(["poff", "-a"], 10)
    time.sleep(1)

def fmt_duration(seconds: int) -> str:
    if seconds < 0: seconds = 0
    h, r = divmod(seconds, 3600); m, s = divmod(r, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"

# —— 用户列表（页面显示当前用户名） ——
def zjunet_user_list() -> Tuple[List[str], str]:
    rc, out, err = run(SUDO + ["zjunet", "user", "list"], check=False, timeout=10)
    text = (out or "") + ("\n" + err if err else "")
    users: List[str] = []
    for line in text.splitlines():
        m = re.search(r"zju-l2tp-(\d+)", line)
        if m: users.append(m.group(1)); continue
        for u in re.findall(r"\b(\d{5,})\b", line):
            if u not in users: users.append(u)
    return users, text

# —— 清理 zju 账户 ——
def purge_chap_all_zju():
    txt = safe_read(CHAP_SECRETS) if CHAP_SECRETS.exists() else ""
    lines = txt.splitlines(); out = []
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("#"): out.append(ln); continue
        parts = s.split()
        if parts and parts[0].startswith(ZJU_PREFIX): continue
        out.append(ln)
    safe_write(CHAP_SECRETS, ("\n".join(out).rstrip() + "\n") if out else "")

def purge_xl2tpd_all_zju():
    if not XL2TPD_CONF.exists(): return
    txt = safe_read(XL2TPD_CONF)
    blocks = re.split(r"(?=\[lac\s+[^\]]+\])", txt, flags=re.IGNORECASE)
    out_blocks = []
    for b in blocks:
        if not b.strip(): continue
        m = re.match(r"\[lac\s+([^\]]+)\]", b, flags=re.IGNORECASE)
        if not m: out_blocks.append(b); continue
        name = m.group(1).strip()
        if name.startswith(ZJU_PREFIX): continue
        out_blocks.append(b)
    safe_write(XL2TPD_CONF, "".join(out_blocks))

# —— 日志采集 + 简要归因（仅内部判断，不对外暴露原始日志） ——
def collect_ppp_logs(max_lines: int = LOG_LINES) -> str:
    rc, out, err = run(SUDO + ["journalctl", "-u", "pppd", "-n", str(max_lines), "--no-pager"], check=False)
    if rc == 0 and out.strip(): return out
    patterns = re.compile(r"(pppd|xl2tp|l2tp|CHAP|IPCP)", re.I)
    for p in ("/var/log/syslog", "/var/log/messages", "/var/log/ppp/pppd.log", "/var/log/ppp.log"):
        rc, t, _ = run(SUDO + ["tail", "-n", str(max_lines), p], check=False)
        if t.strip():
            return "\n".join([ln for ln in t.splitlines() if patterns.search(ln)])
    return ""

def summarize_reason(z_out: str, z_err: str, logs: str, timed_out: bool) -> str:
    text = "\n".join([z_out or "", z_err or "", logs or ""])
    if timed_out or re.search(r"timeout|timed out", text, re.I):
        return "连接超时"
    if re.search(r"CHAP authentication failed|Login incorrect|authentication failed", text, re.I):
        return "密码错误"
    return "连接失败"

# —— 交互新增账户 & 连接：仅返回“已连接/密码错误/连接超时/连接失败” ——
def zjunet_user_add_interactive(username: str, password: str) -> Tuple[int, str, str]:
    payload = f"{username}\n{password}\n"
    return run_root_timeout(["zjunet", "user", "add"], 20, input_text=payload)

def connect_with_account(username: str, password: str) -> Dict[str, str]:
    if not is_numeric_user(username): raise ValueError("账号必须为纯数字")
    def _do_connect():
        disconnect()
        purge_chap_all_zju(); purge_xl2tpd_all_zju()
        run_root_timeout(["systemctl", "restart", "xl2tpd"], 20)

        ac_rc, _, _ = zjunet_user_add_interactive(username, password)
        if ac_rc != 0:
            return {"ok": False, "summary": "连接失败"}  # 最小披露

        rc, out, err = run_root_timeout(["zjunet", "vpn", "-c"], CONNECT_TIMEOUT)
        timed_out = (rc == 124)

        ok = current_ppp_up()
        if ok:
            return {"ok": True, "summary": "已连接"}
        reason = summarize_reason(out, err, collect_ppp_logs(), timed_out)
        return {"ok": False, "summary": reason}
    return _with_lock(_do_connect)

# —— 安全响应头（允许内联脚本用于自动刷新） ——
@app.after_request
def _security_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'"
    )
    return resp

# —— 路由（加 BasicAuth；POST 校验 CSRF；锁冲突友好提示） ——
@app.get("/")
@require_basic_auth()
def index():
    s = load_state()
    users, _ = zjunet_user_list()
    display_users = "、".join(users) if users else "—"

    duration_hms = None; since_js = None; ppp = current_ppp_up()
    if s.get("since") and ppp:
        try:
            since_dt = datetime.strptime(s["since"], "%Y-%m-%d %H:%M:%S")
            duration_hms = fmt_duration(int((datetime.now() - since_dt).total_seconds()))
            since_js = s["since"].replace(" ", "T")
        except Exception: pass

    return render_template("index.html",
        display_users=display_users, since=s.get("since"), since_js=since_js,
        duration_hms=duration_hms, last_status=s.get("last_status",""),
        ppp_up=ppp, csrf_token=_get_csrf_token()
    )

@app.post("/login")
@require_basic_auth()
def login():
    _check_csrf()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    if not is_numeric_user(username):
        flash("账号必须为纯数字", "error"); return redirect(url_for("index"))

    try:
        result = connect_with_account(username, password)
    except RuntimeError:
        flash("系统正忙，请稍后再试", "error")
        return redirect(url_for("index"))

    if result.get("ok"):
        save_state({"active_user": username, "since": time.strftime("%F %T"), "last_status": "已连接"})
        flash("已连接", "ok")
    else:
        save_state({"active_user": None, "since": None, "last_status": result.get("summary","连接失败")})
        flash(result.get("summary","连接失败"), "error")
    return redirect(url_for("index"))

@app.post("/logout")
@require_basic_auth()
def logout():
    _check_csrf()
    try:
        disconnect(); flash("已断开连接", "ok")
    finally:
        save_state({"active_user": None, "since": None, "last_status": "未连接"})
    return redirect(url_for("index"))

@app.get("/status")
@require_basic_auth()
def status():
    s = load_state(); ppp = current_ppp_up()
    duration_sec = 0
    if s.get("since") and ppp:
        try:
            since_dt = datetime.strptime(s["since"], "%Y-%m-%d %H:%M:%S")
            duration_sec = int((datetime.now() - since_dt).total_seconds())
        except Exception: pass
    return jsonify({
        "current_users": zjunet_user_list()[0],
        "since": s.get("since"),
        "ppp_up": ppp,
        "duration_seconds": duration_sec,
        "last_status": s.get("last_status",""),
    })

def _shutdown(): _sudo_keepalive_stop.set()

if __name__ == "__main__":
    require_sudo_once()
    try:
        app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
    finally:
        _shutdown()
