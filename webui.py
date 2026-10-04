#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Web 管理面板 —— 看扫描状态、优选结果、日志，并能手动触发一轮。

纯标准库（http.server），不需要 pip 装任何东西。

安全说明：
  默认只监听 127.0.0.1，只有本机能访问。
  要对外暴露必须显式 -host 0.0.0.0 并给一个 token；所有 API 都校验 token，
  否则任何人拿到地址就能触发扫描、看你的 IP 列表。

用法：
  python webui.py                          # 只监听本机 127.0.0.1:8080
  python webui.py -host 0.0.0.0 -port 8080 -token 你的口令
  # 然后浏览器打开 http://<VPS_IP>:8080/?token=你的口令
"""

import argparse
import json
import os
import shlex
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
STATUS_FILE = os.path.join(HERE, "output", "status.json")
LOG_DIR = os.path.join(HERE, "output")

if HERE not in sys.path:
    sys.path.insert(0, HERE)

TOKEN = ""
RUN_ARGS = ""
_run_lock = threading.Lock()
_last_run = {"started": 0.0, "rc": None, "pid": None}


# ==================== 数据读取 ====================
def load_status():
    st = {}
    if os.path.exists(STATUS_FILE):
        try:
            with open(STATUS_FILE, "r", encoding="utf-8") as f:
                st = json.load(f) or {}
        except (OSError, json.JSONDecodeError):
            st = {}
    # 判断扫描进程是否还活着
    pid = st.get("pid")
    alive = False
    if pid:
        try:
            if os.name == "nt":
                out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"],
                                     capture_output=True, text=True, timeout=5).stdout
                alive = str(pid) in out
            else:
                os.kill(int(pid), 0)
                alive = True
        except Exception:
            alive = False
    st["alive"] = alive
    age = time.time() - float(st.get("updated_ts") or 0)
    st["age_sec"] = round(age, 1) if st.get("updated_ts") else None
    return st


def load_results():
    try:
        import fetch_ips as ff
        return ff.read_final_summary(limit=300)
    except Exception as e:                       # noqa: BLE001
        return {"error": str(e), "ip_txt": [], "rows": []}


def tail_log(lines=200):
    if not os.path.isdir(LOG_DIR):
        return []
    best, best_mt = None, 0.0
    for dirpath, _d, files in os.walk(LOG_DIR):
        for fn in files:
            if fn.endswith(".log"):
                p = os.path.join(dirpath, fn)
                try:
                    mt = os.path.getmtime(p)
                except OSError:
                    continue
                if mt > best_mt:
                    best, best_mt = p, mt
    if not best:
        return []
    try:
        with open(best, "r", encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()[-lines:]
    except OSError:
        return []


def spawn_run():
    """手动触发一轮（不循环）。同一时间只允许一个。"""
    if not _run_lock.acquire(blocking=False):
        return {"ok": False, "msg": "已经有一轮在跑了"}
    try:
        cmd = [sys.executable, os.path.join(HERE, "fetch_ips.py")]
        cmd += shlex.split(RUN_ARGS, posix=(os.name != "nt"))
        # 让这一轮的结果也写日志，方便面板看
        os.makedirs(LOG_DIR, exist_ok=True)
        logf = os.path.join(LOG_DIR, f"webui-run-{time.strftime('%Y%m%d-%H%M%S')}.log")
        fh = open(logf, "w", encoding="utf-8")
        env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONUTF8="1")

        def _worker():
            try:
                p = subprocess.Popen(cmd, cwd=HERE, stdout=fh, stderr=subprocess.STDOUT, env=env)
                _last_run.update(started=time.time(), rc=None, pid=p.pid)
                rc = p.wait()
                _last_run.update(rc=rc)
            except Exception as e:               # noqa: BLE001
                _last_run.update(rc=-1)
                fh.write(f"\n[webui] 启动失败: {e}\n")
            finally:
                fh.close()
                _run_lock.release()

        threading.Thread(target=_worker, daemon=True).start()
        return {"ok": True, "cmd": " ".join(cmd), "log": logf}
    except Exception as e:                       # noqa: BLE001
        _run_lock.release()
        return {"ok": False, "msg": str(e)}


def _num(s, unit=""):
    """把 '62.0ms' / '3.7MB/s' / '0%' 这类字符串解析成数字。"""
    if s is None:
        return None
    t = str(s).strip().replace(unit, "").replace("%", "").replace("ms", "") \
          .replace("MB/s", "").strip()
    try:
        return float(t)
    except ValueError:
        return None


def serve_ips(qs):
    """给其他服务消费的 IP 列表接口。

    这是整个工具对外的「成品出口」——别的服务只需要拉这个接口，
    不用关心扫描是怎么跑的。

    格式（format=）：
      text   一行一个 IP（默认，最省事，直接喂给别的脚本）
      json   带完整字段的 JSON 数组
      csv    CSV
      hosts  /etc/hosts 风格（配合 dnsmasq / AdGuard 用）
    过滤（可选）：
      limit=200            最多返回多少个
      max_latency=100      延迟上限 ms
      max_loss=5           丢包率上限 %
      min_speed=1          速度下限 MB/s
      country=HK,JP        只要这些地区
    """
    fmt = (qs.get("format") or ["text"])[0].lower()
    limit = int((qs.get("limit") or ["200"])[0])
    max_lat = _num((qs.get("max_latency") or [""])[0])
    max_loss = _num((qs.get("max_loss") or [""])[0])
    min_speed = _num((qs.get("min_speed") or [""])[0])
    want_cc = {c.strip().upper() for c in (qs.get("country") or [""])[0].split(",") if c.strip()}

    res = load_results()
    rows = res.get("rows") or []

    # 没有 CSV（比如只跑了 -stage1）就退回 ip.txt，直接给纯 IP
    if not rows:
        ips = []
        for ln in res.get("ip_txt") or []:
            ip = ln.split("#")[0].split()[0].strip()
            if ip:
                ips.append(ip)
        ips = ips[:limit]
        if fmt == "json":
            return {"count": len(ips), "source": "ip.txt", "ips": ips}
        return "\n".join(ips) + ("\n" if ips else "")

    out = []
    for r in rows:
        lat, loss, spd = _num(r.get("latency")), _num(r.get("loss")), _num(r.get("speed"))
        cc = (r.get("country") or "").upper()
        if max_lat is not None and (lat is None or lat > max_lat):
            continue
        if max_loss is not None and (loss is None or loss > max_loss):
            continue
        if min_speed is not None and (spd is None or spd < min_speed):
            continue
        if want_cc and cc not in want_cc:
            continue
        out.append({"ip": r.get("ip", ""), "latency": lat, "loss": loss, "speed": spd,
                    "score": _num(r.get("score")), "country": cc,
                    "city": r.get("city", ""), "route": r.get("route", ""),
                    "cfcountry": r.get("cfcountry", "")})
        if len(out) >= limit:
            break

    if fmt == "json":
        return {"count": len(out), "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                "filters": {"max_latency": max_lat, "max_loss": max_loss,
                            "min_speed": min_speed, "country": sorted(want_cc)},
                "ips": out}
    if fmt == "csv":
        lines = ["ip,latency_ms,loss_pct,speed_mbps,score,country,city,route"]
        for r in out:
            lines.append(",".join(str(x if x is not None else "") for x in
                                  [r["ip"], r["latency"], r["loss"], r["speed"],
                                   r["score"], r["country"], r["city"], r["route"]]))
        return "\n".join(lines) + "\n"
    if fmt == "hosts":
        # /etc/hosts 风格；域名用 cf.example.com，按需替换
        dom = (qs.get("domain") or ["cf.example.com"])[0]
        return "\n".join(f"{r['ip']} {dom}" for r in out) + ("\n" if out else "")
    return "\n".join(r["ip"] for r in out) + ("\n" if out else "")


# ==================== 页面 ====================
PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CF 反代 IP 优选 · 控制台</title>
<style>
 :root{--bg:#0f1115;--card:#181b22;--fg:#e6e8ee;--dim:#8b93a7;--ok:#3ddc84;--warn:#ffb020;--bad:#ff5c5c;--acc:#4c8dff}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 -apple-system,"Segoe UI",Roboto,"Microsoft YaHei",sans-serif}
 .wrap{max-width:1180px;margin:0 auto;padding:20px}
 h1{font-size:19px;margin:0 0 4px}
 .sub{color:var(--dim);font-size:12px;margin-bottom:18px}
 .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:18px}
 .card{background:var(--card);border:1px solid #232733;border-radius:10px;padding:14px}
 .k{color:var(--dim);font-size:12px;margin-bottom:6px}
 .v{font-size:20px;font-weight:600;word-break:break-all}
 .v.sm{font-size:14px;font-weight:400}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th,td{padding:7px 9px;text-align:left;border-bottom:1px solid #232733;white-space:nowrap}
 th{color:var(--dim);font-weight:500;position:sticky;top:0;background:var(--card)}
 tr:hover td{background:#1e222b}
 .scroll{max-height:440px;overflow:auto;border-radius:8px}
 pre{background:#12141a;border:1px solid #232733;border-radius:8px;padding:12px;overflow:auto;max-height:320px;font-size:12px;color:#b9c1d4}
 button{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:9px 16px;font-size:14px;cursor:pointer}
 button:disabled{opacity:.5;cursor:default}
 button.gray{background:#2a2f3c}
 .pill{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px}
 .on{background:rgba(61,220,132,.15);color:var(--ok)}
 .off{background:rgba(255,92,92,.15);color:var(--bad)}
 .idle{background:rgba(255,176,32,.15);color:var(--warn)}
 .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
 .err{color:var(--bad)}
</style></head><body><div class="wrap">
<h1>Cloudflare 反代 IP 优选 · 控制台</h1>
<div class="sub" id="sub">加载中…</div>

<div class="row">
  <button id="run">立即跑一轮</button>
  <button class="gray" id="refresh">刷新</button>
  <span id="runmsg" class="sub" style="margin:0"></span>
</div>

<div class="grid" id="stats"></div>

<div class="card" style="margin-bottom:18px">
  <div class="k">优选结果（按 延迟+丢包 综合评分排序）</div>
  <div class="scroll"><table id="res"><thead><tr>
    <th>#</th><th>IP</th><th>评分</th><th>延迟</th><th>丢包</th><th>速度</th><th>线路</th><th>地区</th><th>城市</th>
  </tr></thead><tbody></tbody></table></div>
</div>

<div class="card" style="margin-bottom:18px">
  <div class="k">ip.txt</div>
  <pre id="iptxt">—</pre>
</div>

<div class="card">
  <div class="k">日志（尾部）</div>
  <pre id="log">—</pre>
</div>
</div>
<script>
const TOKEN = new URLSearchParams(location.search).get('token') || '';
const q = TOKEN ? ('?token=' + encodeURIComponent(TOKEN)) : '';
async function api(p, opt){ const r = await fetch(p + q, opt); return r.json(); }

function esc(s){ return String(s==null?'':s).replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

async function refresh(){
  try{
    const st = await api('/api/status');
    const alive = st.alive;
    const state = st.state || (alive ? 'running' : 'idle');
    const badge = alive
      ? `<span class="pill on">运行中</span>`
      : `<span class="pill idle">空闲</span>`;
    document.getElementById('sub').innerHTML =
      badge + ` 状态 <b>${esc(state)}</b> · 第 <b>${esc(st.round||0)}</b> 轮 · ` +
      `更新于 ${esc(st.updated||'—')}${st.age_sec!=null?`（${st.age_sec}s 前）`:''}`;
    const cards = [
      ['轮次', st.round||0],
      ['候选总数', (st.candidates||0).toLocaleString()],
      ['保留 IP', (st.kept||0).toLocaleString()],
      ['数据源', st.source||'—'],
      ['ASN 档位', st.asns||'—'],
      ['循环间隔', st.loop? st.loop+'s' : '单次'],
    ];
    document.getElementById('stats').innerHTML = cards.map(([k,v])=>
      `<div class="card"><div class="k">${k}</div><div class="v sm">${esc(v)}</div></div>`).join('');

    const rs = await api('/api/results');
    const tb = document.querySelector('#res tbody');
    const rows = rs.rows || [];
    tb.innerHTML = rows.length ? rows.map((r,i)=>`<tr>
      <td>${esc(r.rank||i+1)}</td><td>${esc(r.ip)}</td><td>${esc(r.score)}</td>
      <td>${esc(r.latency)}</td><td>${esc(r.loss)}</td><td>${esc(r.speed)}</td>
      <td>${esc(r.route)}</td><td>${esc(r.country)}</td><td>${esc(r.city)}</td></tr>`).join('')
      : '<tr><td colspan="9" style="color:#8b93a7">还没有结果</td></tr>';
    document.getElementById('iptxt').textContent = (rs.ip_txt&&rs.ip_txt.length) ? rs.ip_txt.join('\n') : '—';

    const lg = await api('/api/log?lines=200');
    const pre = document.getElementById('log');
    pre.textContent = (lg.lines&&lg.lines.length) ? lg.lines.join('\n') : '（还没有日志文件，加 -log 或跑一轮就会生成）';
    pre.scrollTop = pre.scrollHeight;
  }catch(e){
    document.getElementById('sub').innerHTML = '<span class="err">连接失败：'+esc(e.message)+'</span>';
  }
}

document.getElementById('refresh').onclick = refresh;
document.getElementById('run').onclick = async () => {
  const b = document.getElementById('run'); b.disabled = true;
  const m = document.getElementById('runmsg'); m.textContent = '正在启动…';
  try{
    const r = await api('/api/run', {method:'POST'});
    m.textContent = r.ok ? ('已启动：' + (r.cmd||'')) : ('失败：' + (r.msg||''));
  }catch(e){ m.textContent = '失败：' + e.message; }
  setTimeout(()=>{ b.disabled = false; refresh(); }, 1500);
};
refresh(); setInterval(refresh, 5000);
</script></body></html>
"""


# ==================== HTTP ====================
class Handler(BaseHTTPRequestHandler):
    server_version = "cfip-webui/1.0"

    def log_message(self, fmt, *args):          # 静音默认访问日志
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else str(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def _authed(self, qs):
        if not TOKEN:
            return True
        got = (qs.get("token") or [""])[0]
        return got == TOKEN

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if u.path == "/healthz":
            return self._json({"ok": True})
        if not self._authed(qs):
            return self._json({"error": "token 不正确"}, 401)
        if u.path == "/api/status":
            return self._json(load_status())
        if u.path == "/api/results":
            return self._json(load_results())
        if u.path == "/api/ips":
            fmt = (qs.get("format") or ["text"])[0].lower()
            ctype = {"json": "application/json; charset=utf-8",
                     "csv": "text/csv; charset=utf-8"}.get(fmt, "text/plain; charset=utf-8")
            body = serve_ips(qs)
            if isinstance(body, dict):
                return self._json(body)
            return self._send(200, body, ctype)
        if u.path == "/api/log":
            n = int((qs.get("lines") or ["200"])[0])
            return self._json({"lines": tail_log(min(max(n, 10), 2000))})
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if not self._authed(qs):
            return self._json({"error": "token 不正确"}, 401)
        if u.path == "/api/run":
            return self._json(spawn_run())
        return self._json({"error": "not found"}, 404)


def main():
    global TOKEN, RUN_ARGS
    p = argparse.ArgumentParser(description="CF 反代 IP 优选 · Web 控制台")
    p.add_argument("-host", default="127.0.0.1",
                   help="监听地址，默认 127.0.0.1（只本机）。对外暴露填 0.0.0.0，"
                        "此时必须同时给 -token")
    p.add_argument("-port", type=int, default=8080, help="监听端口，默认 8080")
    p.add_argument("-token", default=os.environ.get("WEBUI_TOKEN", ""),
                   help="访问口令；监听 0.0.0.0 时必填")
    p.add_argument("-run-args", default=os.environ.get("WEBUI_RUN_ARGS", ""),
                   help='点「立即跑一轮」时执行的参数，例："-source asn -max 200 -run -- -threads 20 -d 5 -log"')
    a = p.parse_args()

    TOKEN = (a.token or "").strip()
    RUN_ARGS = a.run_args.strip() or "-source asn -max 200 -run -- -threads 20 -d 5 -log"

    if a.host not in ("127.0.0.1", "localhost", "::1") and not TOKEN:
        print("[X] 监听 0.0.0.0 必须设置 -token，否则任何人拿到地址就能控制你的扫描。")
        print("    例：python webui.py -host 0.0.0.0 -port 8080 -token 你的口令")
        return 2

    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    shown = a.host if a.host != "0.0.0.0" else "<本机IP>"
    print("=" * 60)
    print(f"  Web 控制台已启动： http://{shown}:{a.port}/"
          + (f"?token={TOKEN}" if TOKEN else ""))
    print(f"  监听 {a.host}:{a.port}   手动跑一轮的参数：{RUN_ARGS}")
    print("  Ctrl+C 停止")
    print("=" * 60)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 已停止")
    return 0


if __name__ == "__main__":
    sys.exit(main())
