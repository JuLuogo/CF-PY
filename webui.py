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
import re
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

# 强制 stdout/stderr 用 UTF-8。
# 很多 VPS 没配 locale（LANG 为空），Python 会退回 C locale，stdout 变成
# latin-1，一 print 中文就 UnicodeEncodeError 直接崩。
# 实测 cfip-web 就是这么挂的（systemd 里无限重启，status=1/FAILURE）。
# 在代码里兜住比依赖 unit 文件里的环境变量可靠得多。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

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
            # 用 utf-8-sig：带不带 BOM 都能读。
            # 用纯 utf-8 的话，一旦文件带 BOM 就会抛 JSONDecodeError，
            # 被下面的 except 吞掉，面板静默显示空白 —— 这个坑踩过。
            with open(STATUS_FILE, "r", encoding="utf-8-sig") as f:
                st = json.load(f) or {}
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
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


def _region_tag():
    """第二套列表的地区后缀（和 ip.py 里生成的保持一致）。"""
    try:
        import ip as _ip
        cfg = _ip.load_config(CONFIG_PATH)
        raw = str(cfg.get("OUTPUT_REGIONS") or "").strip().strip('"')
        want = sorted({x.strip().upper() for x in re.split(r"[,;\s]+", raw) if x.strip()})
        return "".join(want).lower(), want
    except Exception:                            # noqa: BLE001
        return "", []


def load_results():
    try:
        import fetch_ips as ff
        return ff.read_final_summary(limit=300)
    except Exception as e:                       # noqa: BLE001
        return {"error": str(e), "ip_txt": [], "rows": []}


def load_pool(limit=500, region=None):
    """从累积池里读结果。这是给下游用的【主数据源】。

    为什么主数据源是池子而不是「最近一轮」：
      上游 5~7 天才跑一轮，单轮结果会波动。池子是累积的，
      只增不减（除非条目 30 天没再出现），下游拿到的才是稳定的。
    """
    try:
        import fetch_ips as ff
        return ff.read_pool_rows(limit=limit, region=region)
    except Exception as e:                       # noqa: BLE001
        return []


def load_pool_summary():
    try:
        import fetch_ips as ff
        return ff.pool_summary()
    except Exception:                            # noqa: BLE001
        return {"total": 0}


def load_results_region():
    """读第二套（只含白名单地区）的结果文件。"""
    tag, want = _region_tag()
    out = {"tag": tag, "regions": want, "ip_txt": [], "rows": [], "exists": False}
    if not tag:
        return out
    # ip.txt -> ip-<tag>.txt；bestips-*.csv -> bestips-*-<tag>.csv
    for cand in (os.path.join(HERE, f"ip-{tag}.txt"),):
        if os.path.exists(cand):
            try:
                with open(cand, "r", encoding="utf-8-sig", errors="replace") as f:
                    out["ip_txt"] = [ln for ln in f.read().splitlines() if ln.strip()]
                out["exists"] = True
            except OSError:
                pass
    # 找最新的地区 CSV
    best, best_mt = None, 0.0
    if os.path.isdir(LOG_DIR):
        for dirpath, _d, files in os.walk(LOG_DIR):
            for fn in files:
                if fn.startswith("bestips") and fn.endswith(f"-{tag}.csv"):
                    p = os.path.join(dirpath, fn)
                    try:
                        mt = os.path.getmtime(p)
                    except OSError:
                        continue
                    if mt > best_mt:
                        best, best_mt = p, mt
    if best:
        try:
            import csv as _csv
            with open(best, "r", encoding="utf-8-sig", errors="replace") as f:
                out["rows"] = list(_csv.DictReader(f))
            out["exists"] = True
        except OSError:
            pass
    return out


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
        with open(best, "r", encoding="utf-8-sig", errors="replace") as f:
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
        # 面板的「立即跑一轮」必须是一次性的，不能受配置里 LOOP 影响
        if "-once" not in cmd and "-loop" not in cmd:
            cmd.append("-once")
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
    两套数据（set=）：
      all     所有可用 IP，不限制地区（默认）—— /api/ips
      region  只含 OUTPUT_REGIONS 白名单里的地区 —— /api/ips?set=region
    """
    fmt = (qs.get("format") or ["text"])[0].lower()
    limit = int((qs.get("limit") or ["200"])[0])
    max_lat = _num((qs.get("max_latency") or [""])[0])
    max_loss = _num((qs.get("max_loss") or [""])[0])
    min_speed = _num((qs.get("min_speed") or [""])[0])
    want_cc = {c.strip().upper() for c in (qs.get("country") or [""])[0].split(",") if c.strip()}

    which = (qs.get("set") or ["pool"])[0].lower()
    # 数据源：
    #   pool（默认）累积池，只增不减 —— 下游应该用这个
    #   region      池子里只要白名单地区的
    #   last        只看最近一轮的结果（调试用）
    #   all         同 pool，兼容旧写法
    if which in ("last", "round", "latest"):
        res = load_results()
        rows = res.get("rows") or []
    else:
        region = None
        if which in ("region", "regions", "area", "filtered"):
            _tag, region = _region_tag()
            if not region:
                return {"error": "OUTPUT_REGIONS 没配置，无法筛选地区",
                        "set": "region"}
        pool_rows = load_pool(limit=100000, region=set(region) if region else None)
        if not pool_rows:
            # 池子还空着（第一次跑之前），退回最近一轮
            res = load_results()
            rows = res.get("rows") or []
        else:
            rows = pool_rows

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
        out.append({"ip": r.get("ip", ""), "port": r.get("port", "443"),
                    "last_seen": r.get("last_seen", ""),
                    "seen_count": r.get("seen_count", ""),
                    "latency": lat, "loss": loss, "speed": spd,
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


CHANNELS = [
    ("pushplus", "推送加 PushPlus（微信）", "你的 token（pushplus.plus 获取）"),
    ("bark", "Bark（iOS）", "https://api.day.app/你的key"),
    ("ntfy", "ntfy（全平台/可自建）", "https://ntfy.sh/你的topic"),
    ("pushdeer", "PushDeer（开源 iOS/Android）", "https://api2.pushdeer.com"),
    ("serverchan", "Server酱³（微信）", "https://sctapi.ftqq.com/你的key.send"),
    ("telegram", "Telegram Bot", "<bot_token>|<chat_id>"),
    ("wecom", "企业微信群机器人", "webhook 完整地址"),
    ("dingtalk", "钉钉群机器人", "webhook 完整地址"),
    ("feishu", "飞书群机器人", "webhook 完整地址"),
    ("webhook", "通用 POST JSON", "你的地址"),
]

CONFIG_PATH = os.path.join(HERE, "config.ini")


def _mask(s, keep=26):
    s = str(s or "")
    return s if len(s) <= keep else s[:keep] + "…"


def load_notify_settings():
    """从 config.ini 读推送配置。"""
    out = {"channel": "", "target": "", "target_masked": "",
           "only_with_result": True, "configured": False, "channels": CHANNELS}
    try:
        import ip as _ip
        cfg = _ip.load_config(CONFIG_PATH)
        out["channel"] = str(cfg.get("NOTIFY_CHANNEL") or "").strip()
        out["target"] = str(cfg.get("NOTIFY_TARGET") or "").strip()
        out["only_with_result"] = bool(cfg.get("NOTIFY_ONLY_WITH_RESULT", True))
    except Exception as e:                       # noqa: BLE001
        out["error"] = str(e)
    out["target_masked"] = _mask(out["target"])
    out["configured"] = bool(out["channel"] and out["target"])
    return out


def save_notify_settings(channel, target, only_with_result=True):
    """把推送配置写回 config.ini（只动 NOTIFY_* 三个键）。"""
    import re as _re
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            txt = f.read()
    except OSError as e:
        return False, f"读不到 config.ini: {e}"

    def setkey(t, k, v):
        pat = _re.compile(rf"^{_re.escape(k)}\s*=.*$", _re.M)
        line = f"{k} = {v}"
        return pat.sub(lambda _m: line, t, count=1) if pat.search(t) else t + f"\n{line}\n"

    txt = setkey(txt, "NOTIFY_CHANNEL", f'"{channel}"')
    txt = setkey(txt, "NOTIFY_TARGET", f'"{target}"')
    txt = setkey(txt, "NOTIFY_ONLY_WITH_RESULT", "true" if only_with_result else "false")
    try:
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(txt)
        os.replace(tmp, CONFIG_PATH)
    except OSError as e:
        return False, f"写 config.ini 失败: {e}"
    return True, "已保存（下一轮生效）"


def notify_preview():
    """渲染推送正文预览（用当前最新结果）。"""
    try:
        import notify as _n
        res = load_results()
        rows = res.get("rows") or []
        st = load_status()
        avail = st.get("available") or st.get("kept")
        body = _n.build_summary(st.get("round") or 1, avail, len(rows), rows)
        head = f"第 {st.get('round') or 1} 轮完成"
        return {"ok": True, "title": f"CF 反代 IP · {head}",
                "body": body, "rows": len(rows)}
    except Exception as e:                       # noqa: BLE001
        return {"ok": False, "error": str(e)}


def notify_test(channel=None, target=None):
    """发一条测试推送。不传就用 config.ini 里的。"""
    try:
        import notify as _n
        st = load_notify_settings()
        _n.NOTIFY_CHANNEL = (channel or st["channel"]).strip()
        _n.NOTIFY_TARGET = (target or st["target"]).strip()
        if not _n.NOTIFY_CHANNEL or not _n.NOTIFY_TARGET:
            return {"ok": False, "msg": "渠道或目标为空，先在下面填好再测"}
        ok, msg = _n.self_test()
        return {"ok": ok, "msg": msg, "channel": _n.NOTIFY_CHANNEL}
    except Exception as e:                       # noqa: BLE001
        return {"ok": False, "msg": str(e)}


# 可在 Web 面板里改的设置。加新配置项只要往这里加一行，前端会自动渲染。
# type: text / number / select / bool / password
SETTING_SCHEMA = [
    {"group": "扫描范围", "key": "ASNS", "label": "ASN 档位 / 厂商", "type": "select",
     "options": [["niche", "niche · 小众优质线路（约 4000 网段，几十秒一轮）"],
                 ["vps", "vps · 主流便宜 VPS（约 22 万网段）"],
                 ["all", "all · 除大陆外全部（约 204 万网段，一轮约 4 小时）"]],
     "hint": "也可以直接写厂商名，逗号分隔：alibaba,tencent,dmit,akile,cloudie…"},
    {"group": "扫描范围", "key": "ASN_SAMPLE", "label": "每轮采样多少个 /24", "type": "number",
     "hint": "0 = 全量不采样（vps 档位约 18 万个网段，一轮 1~2 小时）"},
    {"group": "扫描范围", "key": "ASN_EXCLUDE_REGIONS", "label": "排除地区（黑名单）", "type": "text",
     "hint": "默认 CN，留空 = 不排除"},
    {"group": "扫描范围", "key": "ASN_REGIONS", "label": "只要地区（白名单）", "type": "text",
     "hint": "留空 = 不启用；填 HK,JP,SG 就只要这些"},
    {"group": "扫描范围", "key": "PORTS", "label": "测试端口", "type": "text",
     "hint": "CF 的 HTTPS 端口：443,2053,2083,2087,2096,8443。注意是乘法，6 个端口 = 探测点数 ×6"},
    {"group": "扫描范围", "key": "LIST_URLS", "label": "第三方列表源", "type": "text",
     "hint": "zip / wwuyi / luuaiyan / xgonce / muhaip，或完整 URL"},

    {"group": "运行参数", "key": "THREADS", "label": "并发线程数", "type": "number",
     "hint": "VPS 建议 50~200"},
    {"group": "运行参数", "key": "LOOP", "label": "每轮间隔（秒）", "type": "number",
     "hint": "1800 = 半小时一轮"},

    {"group": "筛选与排序", "key": "MAX_LATENCY_MS", "label": "延迟上限（ms）", "type": "number",
     "hint": "超过就淘汰"},
    {"group": "筛选与排序", "key": "MAX_LOSS_PCT", "label": "丢包上限（%）", "type": "number",
     "hint": "超过就淘汰。丢包比延迟更致命"},
    {"group": "筛选与排序", "key": "MIN_SPEED_MBPS", "label": "速度下限（MB/s）", "type": "number",
     "hint": ""},
    {"group": "筛选与排序", "key": "TOP_N", "label": "最终保留前 N 个", "type": "number",
     "hint": "0 = 不限制。推 DNS 用 150~200 够"},

    {"group": "推送", "key": "NOTIFY_CHANNEL", "label": "渠道", "type": "select",
     "options": [["", "（不推送）"], ["pushplus", "推送加 PushPlus（微信）"],
                 ["bark", "Bark（iOS）"], ["ntfy", "ntfy（全平台/可自建）"],
                 ["pushdeer", "PushDeer（开源）"], ["serverchan", "Server酱³（微信）"],
                 ["telegram", "Telegram Bot"], ["wecom", "企业微信机器人"],
                 ["dingtalk", "钉钉机器人"], ["feishu", "飞书机器人"],
                 ["webhook", "通用 Webhook"]],
     "hint": "选 PushPlus 就在下面填 token（pushplus.plus 个人中心获取）"},
    {"group": "推送", "key": "NOTIFY_TARGET", "label": "目标 / token", "type": "password",
     "hint": "PushPlus 填 token；webhook 类填完整地址；telegram 填 <bot_token>|<chat_id>"},
    {"group": "推送", "key": "NOTIFY_ONLY_WITH_RESULT", "label": "没有可用 IP 时不推送",
     "type": "bool", "hint": ""},

    {"group": "数据源", "key": "LIST_REGIONS", "label": "列表源地区过滤", "type": "text",
     "hint": "如 HK,JP,SG,KR,TW"},
    {"group": "数据源", "key": "IPDB_TYPES", "label": "IPDB 列表类型", "type": "text",
     "hint": "bestproxy;cfv4;proxy"},
]

SECRET_KEYS = {"NOTIFY_TARGET", "FOFA_KEY", "token"}


def _read_cfg_text():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def load_settings():
    """读所有可编辑设置，返回 {值, schema}。密钥类做掩码。"""
    vals = {}
    try:
        import ip as _ip
        cfg = _ip.load_config(CONFIG_PATH)
        for item in SETTING_SCHEMA:
            k = item["key"]
            v = cfg.get(k, "")
            if v is None:
                v = ""
            vals[k] = "" if isinstance(v, bool) and not v else (
                v if not isinstance(v, bool) else "true")
            if isinstance(v, bool):
                vals[k] = "true" if v else "false"
            else:
                vals[k] = str(v)
    except Exception as e:                       # noqa: BLE001
        return {"ok": False, "error": str(e)}
    masked = {}
    for k, v in vals.items():
        masked[k] = (_mask(v, 8) if (k in SECRET_KEYS and v) else v)
    return {"ok": True, "values": masked, "schema": SETTING_SCHEMA,
            "secret_keys": sorted(SECRET_KEYS)}


def save_settings(payload):
    """把设置写回 config.ini。只动 schema 里列出的键。"""
    import re as _re
    txt = _read_cfg_text()
    if not txt:
        return False, "读不到 config.ini"

    changed = []
    for item in SETTING_SCHEMA:
        k = item["key"]
        if k not in payload:
            continue
        v = payload[k]
        if isinstance(v, bool):
            v = "true" if v else "false"
        v = str(v).strip()
        # 掩码值原样提交时不要覆盖真实密钥
        if k in SECRET_KEYS and ("…" in v or v == ""):
            if "…" in v:
                continue
        if item["type"] in ("number",):
            if v != "" and not _re.fullmatch(r"-?\d+(\.\d+)?", v):
                return False, f"{item['label']} 必须是数字，收到「{v}」"
        if item["type"] == "bool":
            v = "true" if v.lower() in ("true", "1", "yes", "on") else "false"
        if item["type"] in ("text", "password", "select") and v != "" and \
                not _re.fullmatch(r"-?\d+(\.\d+)?", v):
            v = f'"{v}"'
        pat = _re.compile(rf"^{_re.escape(k)}\s*=.*$", _re.M)
        if pat.search(txt):
            txt = pat.sub(lambda _m, _l=f"{k} = {v}": _l, txt, count=1)
        else:
            txt += f"\n{k} = {v}\n"
        changed.append(k)

    try:
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(txt)
        os.replace(tmp, CONFIG_PATH)
    except OSError as e:
        return False, f"写 config.ini 失败: {e}"
    return True, f"已保存 {len(changed)} 项（下一轮生效，无需重启）"


def restart_service(name="cfip"):
    """重启扫描服务。只允许重启 cfip / cfip-web，避免被当成通用命令执行器。"""
    if name not in ("cfip", "cfip-web"):
        return {"ok": False, "msg": "只允许重启 cfip / cfip-web"}
    try:
        r = subprocess.run(["systemctl", "restart", name],
                           capture_output=True, timeout=30)
        if r.returncode != 0:
            err = (r.stderr or b"").decode("utf-8", "replace")[:200]
            return {"ok": False, "msg": f"重启失败：{err or r.returncode}"}
        return {"ok": True, "msg": f"{name} 已重启"}
    except FileNotFoundError:
        return {"ok": False, "msg": "这台机器没有 systemctl（不是 systemd 环境）"}
    except Exception as e:                       # noqa: BLE001
        return {"ok": False, "msg": str(e)}


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
 h2{font-size:15px;margin:0 0 12px;color:var(--fg)}
 .sub{color:var(--dim);font-size:12px;margin-bottom:16px}
 .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
 .card{background:var(--card);border:1px solid #232733;border-radius:10px;padding:14px;margin-bottom:16px}
 .k{color:var(--dim);font-size:12px;margin-bottom:6px}
 .v{font-size:20px;font-weight:600;word-break:break-all}
 .v.sm{font-size:14px;font-weight:400}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th,td{padding:7px 9px;text-align:left;border-bottom:1px solid #232733;white-space:nowrap}
 th{color:var(--dim);font-weight:500;position:sticky;top:0;background:var(--card)}
 tr:hover td{background:#1e222b}
 .scroll{max-height:420px;overflow:auto;border-radius:8px}
 pre{background:#12141a;border:1px solid #232733;border-radius:8px;padding:12px;overflow:auto;max-height:300px;font-size:12px;color:#b9c1d4;white-space:pre-wrap;word-break:break-all}
 button{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:8px 14px;font-size:13px;cursor:pointer}
 button:disabled{opacity:.5;cursor:default}
 button.gray{background:#2a2f3c}
 button.sm{padding:5px 11px;font-size:12px}
 input,select{background:#12141a;border:1px solid #2b3040;color:var(--fg);border-radius:7px;padding:7px 10px;font-size:13px;font-family:inherit}
 input{flex:1;min-width:200px}
 .pill{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px}
 .on{background:rgba(61,220,132,.15);color:var(--ok)}
 .off{background:rgba(255,92,92,.15);color:var(--bad)}
 .idle{background:rgba(255,176,32,.15);color:var(--warn)}
 .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
 .bar{height:9px;background:#12141a;border-radius:99px;overflow:hidden;margin-top:8px;border:1px solid #232733}
 .bar>i{display:block;height:100%;background:linear-gradient(90deg,#4c8dff,#3ddc84);width:0;transition:width .4s}
 .err{color:var(--bad)}
 .ok{color:var(--ok)}
 .hint{color:var(--dim);font-size:12px;margin-top:6px}
 .two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
 @media(max-width:760px){.two{grid-template-columns:1fr}}
</style></head><body><div class="wrap">
<h1>Cloudflare 反代 IP 优选 · 控制台</h1>
<div class="sub" id="sub">加载中…</div>

<div class="card">
  <div class="row" style="margin:0 0 10px">
    <button id="run">立即跑一轮</button>
    <button class="gray" id="refresh">刷新</button>
    <span id="runmsg" class="sub" style="margin:0"></span>
  </div>
  <div id="progwrap"><div class="hint">还没有进度信息（等扫描跑起来）</div></div>
</div>

<div class="grid" id="stats"></div>

<div class="card">
  <h2>优选结果 · 全量 <span class="k" id="resCountAll"></span></h2>
  <div class="hint" style="margin-bottom:8px">所有可用 IP，<b>不限制地区</b>。下游服务用 <code>/api/ips</code> 取这一套。</div>
  <div class="scroll"><table id="resAll"><thead><tr>
    <th>#</th><th>IP</th><th>端口</th><th>评分</th><th>延迟</th><th>丢包</th><th>速度</th><th>线路</th><th>地区</th><th>城市</th>
  </tr></thead><tbody></tbody></table></div>
</div>

<div class="card">
  <h2>优选结果 · 地区版 <span class="k" id="resCountRegion"></span></h2>
  <div class="hint" style="margin-bottom:8px">
    只含白名单地区的 IP（在下面「筛选与排序」里配 <code>OUTPUT_REGIONS</code>）。
    下游服务用 <code>/api/ips?set=region</code> 取这一套。
  </div>
  <div class="scroll"><table id="resRegion"><thead><tr>
    <th>#</th><th>IP</th><th>端口</th><th>评分</th><th>延迟</th><th>丢包</th><th>速度</th><th>线路</th><th>地区</th><th>城市</th>
  </tr></thead><tbody></tbody></table></div>
</div>

<div class="two">
  <div class="card">
    <h2>设置 <span class="k" id="cfgmsg" style="margin:0"></span></h2>
    <div id="cfgform">加载中…</div>
    <div class="row" style="margin:14px 0 0">
      <button id="cfgsave">保存设置</button>
      <button class="gray sm" id="cfgreload">重新读取</button>
      <button class="gray sm" id="svcrestart">重启扫描服务</button>
    </div>
    <div class="hint">
      保存后写入 config.ini，<b>下一轮自动生效，不用重启</b>（脚本每轮会重读配置）。<br>
      只有改了 systemd unit 里的东西才需要「重启扫描服务」。
    </div>
  </div>

  <div class="card">
    <h2>推送</h2>
    <div class="row" style="margin-bottom:8px">
      <button class="gray sm" id="ntest">发测试推送</button>
      <button class="gray sm" id="nprev">刷新预览</button>
      <span id="nmsg" class="sub" style="margin:0"></span>
    </div>
    <div class="k" id="prevTitle" style="margin-bottom:6px"></div>
    <pre id="prev">点「刷新预览」看下一轮会推什么</pre>
    <div class="hint">
      渠道和目标在左边的「推送」分组里选。PushPlus 直接填 token 就行。
    </div>
  </div>
</div>

<div class="card">
  <h2>ip.txt</h2>
  <pre id="iptxt">—</pre>
</div>

<div class="card">
  <h2>日志（尾部 200 行）</h2>
  <pre id="log">—</pre>
</div>
</div>
<script>
const TOKEN = new URLSearchParams(location.search).get('token') || '';
const q = TOKEN ? ('?token=' + encodeURIComponent(TOKEN)) : '';
async function api(p, opt){ const r = await fetch(p + q, opt); return r.json(); }
function esc(s){ return String(s==null?'':s).replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

// 整条流水线的顺序。全部都会渲染出来（没开始的显示 0%），
// 这样一眼能看到「现在在哪一步、后面还有几步」。
const STAGE_ORDER = ['asn', 'geo', 's0', 's1', 's2', 's3'];
const STAGE_SHORT = {
  asn: '抓取 · 查询 ASN 宣告网段', geo: '抓取 · 地区标注',
  s0: 'stage0 · TCP 预筛',
  s1: 'stage1 · 可用性检查（确认是不是真反代）',
  s2: 'stage2 · 延迟与测速', s3: 'stage3 · 线路分析'
};

function progBarHtml(k, p){
  const pct = (p.pct != null) ? p.pct : 0;
  const done = (p.done != null) ? p.done : 0;
  const total = p.total || 0;
  // 「当前任务」要一眼能看到：正在处理什么
  let cur = '';
  if (p.ip) {
    cur = '正在测 <b>' + esc(p.ip) + '</b>';
    if (p.cidr) cur += '　网段 <b>' + esc(p.cidr) + '</b>';
    if (p.port && p.port !== '443') cur += '　端口 <b>' + esc(p.port) + '</b>';
  } else if (p.current) {
    cur = '正在处理 <b>' + esc(p.current) + '</b>';
  }
  return '<div style="margin-bottom:14px">'
    + '<div class="row" style="margin:0 0 4px;justify-content:space-between">'
    +   '<span><b>' + esc(p.name || STAGE_SHORT[k] || k) + '</b>'
    +     (pct >= 100 ? ' <span class="pill on">已完成</span>' : '') + '</span>'
    +   '<span class="k" style="margin:0">' + done.toLocaleString()
    +     ' / ' + total.toLocaleString() + '　' + pct.toFixed(1) + '%</span>'
    + '</div>'
    + '<div class="bar"><i style="width:' + pct + '%"></i></div>'
    + (cur ? '<div class="hint" style="margin-top:5px">' + cur + '</div>' : '')
    + '</div>';
}

function renderProgress(st){
  const prog = st.progress || {};
  const wrap = document.getElementById('progwrap');
  // 当前任务 = 第一个还没跑完的阶段
  let curTask = null;
  for (const k of STAGE_ORDER) {
    if (prog[k] && (prog[k].pct == null || prog[k].pct < 100)) { curTask = k; break; }
  }
  if (!curTask) {
    // 都跑完了，或者都还没开始 -> 取最后一个有数据的
    for (let i = STAGE_ORDER.length - 1; i >= 0; i--) {
      if (prog[STAGE_ORDER[i]]) { curTask = STAGE_ORDER[i]; break; }
    }
  }
  if (!curTask) curTask = 'asn';

  // 顶部：当前任务
  const cp = prog[curTask] || {};
  let head = '<div class="row" style="margin:0 0 14px">'
    + '<span class="pill on">当前任务</span>'
    + '<b style="font-size:15px">' + esc(cp.name || STAGE_SHORT[curTask] || curTask) + '</b>'
    + '<span class="k" style="margin:0">第 ' + (st.round || 0) + ' 轮</span>';
  if (cp.ip) head += '<span class="k" style="margin:0">' + esc(cp.ip)
    + (cp.cidr ? '（' + esc(cp.cidr) + '）' : '') + '</span>';
  else if (cp.current) head += '<span class="k" style="margin:0">' + esc(cp.current) + '</span>';
  head += '</div>';

  // 下面：整条流水线，每步一条。没开始的显示 0%（灰）。
  const bars = STAGE_ORDER.map(function(k){
    const p = prog[k];
    const isCur = (k === curTask);
    if (!p) {
      return '<div style="margin-bottom:12px;opacity:.45">'
        + '<div class="row" style="margin:0 0 4px;justify-content:space-between">'
        +   '<span>' + esc(STAGE_SHORT[k] || k) + ' <span class="k">未开始</span></span>'
        +   '<span class="k" style="margin:0">—</span>'
        + '</div>'
        + '<div class="bar"><i style="width:0"></i></div>'
        + '</div>';
    }
    const pct = (p.pct != null) ? p.pct : 0;
    const done = (p.done != null) ? p.done : 0;
    const total = p.total || 0;
    let cur = '';
    if (p.ip) {
      cur = '正在测 <b>' + esc(p.ip) + '</b>';
      if (p.cidr) cur += '　网段 <b>' + esc(p.cidr) + '</b>';
      if (p.port && p.port !== '443') cur += '　端口 <b>' + esc(p.port) + '</b>';
    } else if (p.current) {
      cur = '正在处理 <b>' + esc(p.current) + '</b>';
    }
    return '<div style="margin-bottom:12px' + (isCur ? '' : ';opacity:.75') + '">'
      + '<div class="row" style="margin:0 0 4px;justify-content:space-between">'
      +   '<span>' + (isCur ? '<b>' : '') + esc(p.name || STAGE_SHORT[k] || k)
      +     (isCur ? '</b>' : '')
      +     (pct >= 100 ? ' <span class="pill on">完成</span>' : '') + '</span>'
      +   '<span class="k" style="margin:0">' + done.toLocaleString()
      +     ' / ' + total.toLocaleString() + '　' + pct.toFixed(1) + '%</span>'
      + '</div>'
      + '<div class="bar"><i style="width:' + pct + '%"></i></div>'
      + (cur ? '<div class="hint" style="margin-top:5px">' + cur + '</div>' : '')
      + '</div>';
  }).join('');

  wrap.innerHTML = head + bars;
}

function renderTable(tbodyId, countId, rows, emptyMsg){
  const tb = document.querySelector('#' + tbodyId + ' tbody');
  document.getElementById(countId).textContent = '共 ' + rows.length + ' 个';
  tb.innerHTML = rows.length ? rows.map((r, i) => '<tr>'
    + '<td>' + esc(r.rank || i + 1) + '</td>'
    + '<td>' + esc(r.ip) + '</td>'
    + '<td>' + esc(r.port || '443') + '</td>'
    + '<td>' + esc(r.score) + '</td>'
    + '<td>' + esc(r.latency) + '</td>'
    + '<td>' + esc(r.loss) + '</td>'
    + '<td>' + esc(r.speed) + '</td>'
    + '<td>' + esc(r.route) + '</td>'
    + '<td>' + esc(r.country) + '</td>'
    + '<td>' + esc(r.city) + '</td></tr>').join('')
    : '<tr><td colspan="10" style="color:#8b93a7">' + emptyMsg + '</td></tr>';
}

async function refresh(){
  try{
    const st = await api('/api/status');
    const badge = st.alive ? '<span class="pill on">运行中</span>'
                           : '<span class="pill idle">空闲</span>';
    document.getElementById('sub').innerHTML =
      badge + ' 状态 <b>' + esc(st.state || '—') + '</b> · 第 <b>' + esc(st.round || 0)
      + '</b> 轮 · 更新于 ' + esc(st.updated || '—')
      + (st.age_sec != null ? '（' + st.age_sec + 's 前）' : '');

    renderProgress(st);

    const cards = [
      ['轮次', st.round || 0],
      ['候选总数', (st.candidates || 0).toLocaleString()],
      ['保留 IP', (st.kept || 0).toLocaleString()],
      ['数据源', st.source || '—'],
      ['ASN 档位', st.asns || '—'],
      ['循环间隔', st.loop ? st.loop + 's' : '单次'],
      ['可用磁盘', (st.free_mb != null ? Math.round(st.free_mb) + ' MB' : '—')],
    ];
    document.getElementById('stats').innerHTML = cards.map(([k, v]) =>
      '<div class="card" style="margin:0"><div class="k">' + k + '</div>'
      + '<div class="v sm">' + esc(v) + '</div></div>').join('');

    // 两套结果都从【池子】读 ——
    // 上游模式只做 stage1，不产出 ip.py 的 CSV，所以不能读 /api/results。
    try{
      const all = await api('/api/pool');
      const rows = all.rows || [];
      renderTable('resAll', 'resCountAll', rows, '池子还是空的（等一轮扫完）');
      const regRows = rows.filter(r => REGIONS.includes(String(r.country || '').toUpperCase()));
      renderTable('resRegion', 'resCountRegion', regRows,
        '池子里暂时没有 ' + REGIONS.join('/') + ' 的 IP');
      document.getElementById('iptxt').textContent = rows.length
        ? rows.map(r => r.ip + (r.port && r.port !== '443' ? ':' + r.port : '')).join('\n')
        : '—';
    }catch(e){
      renderTable('resAll', 'resCountAll', [], '读取池子失败：' + esc(e.message));
      renderTable('resRegion', 'resCountRegion', [], '读取池子失败');
    }

    const lg = await api('/api/log?lines=200');
    const pre = document.getElementById('log');
    pre.textContent = (lg.lines && lg.lines.length) ? lg.lines.join('\n')
      : '（还没有日志文件，加 -log 就会生成）';
    pre.scrollTop = pre.scrollHeight;
  }catch(e){
    document.getElementById('sub').innerHTML =
      '<span class="err">连接失败：' + esc(e.message) + '</span>';
  }
}

let CFG = {values:{}, schema:[], secret_keys:[]};
// 地区白名单，用来在「地区版」表里做前端过滤（从 /api/config 里取）
let REGIONS = ['HK','JP','SG','KR','TW'];

function fieldHtml(it, v){
  const id = 'cfg_' + it.key;
  let input;
  if (it.type === 'select') {
    input = '<select id="'+id+'">' + (it.options||[]).map(([val,label])=>
      '<option value="'+esc(val)+'"'+(String(v)===String(val)?' selected':'')+'>'+esc(label)+'</option>').join('') + '</select>';
  } else if (it.type === 'bool') {
    input = '<label class="sub" style="margin:0"><input type="checkbox" id="'+id+'" style="width:auto;min-width:0"'
          + (String(v)==='true'?' checked':'') + '> 开启</label>';
  } else {
    const ph = it.type === 'password' ? '（已设置，留空则不修改）' : '';
    input = '<input id="'+id+'" type="'+(it.type==='password'?'text':'text')+'" value="'+esc(v)+'" placeholder="'+ph+'">';
  }
  return '<div style="margin-bottom:11px">'
       + '<div class="k" style="margin-bottom:4px">'+esc(it.label)+'</div>'
       + '<div class="row" style="margin:0">'+input+'</div>'
       + (it.hint ? '<div class="hint">'+esc(it.hint)+'</div>' : '')
       + '</div>';
}

function renderSettings(){
  const groups = {};
  (CFG.schema||[]).forEach(it => { (groups[it.group] = groups[it.group]||[]).push(it); });
  document.getElementById('cfgform').innerHTML = Object.keys(groups).map(g =>
    '<div style="margin-bottom:16px"><div style="font-weight:600;margin-bottom:9px;color:#cfd6e6">'
    + esc(g) + '</div>'
    + groups[g].map(it => fieldHtml(it, CFG.values[it.key]||'')).join('')
    + '</div>').join('');
}

async function loadSettings(){
  try{
    const r = await api('/api/config');
    if (!r.ok) { document.getElementById('cfgform').innerHTML = '<span class="err">'+esc(r.error)+'</span>'; return; }
    CFG = r; renderSettings();
    const raw = (r.values && r.values.OUTPUT_REGIONS) || '';
    const parsed = String(raw).split(/[,;\s]+/).map(x => x.trim().toUpperCase()).filter(Boolean);
    if (parsed.length) REGIONS = parsed;
  }catch(e){ document.getElementById('cfgform').innerHTML = '<span class="err">读取失败：'+esc(e.message)+'</span>'; }
}

document.getElementById('cfgsave').onclick = async () => {
  const m = document.getElementById('cfgmsg'); m.textContent = '保存中…';
  const payload = {};
  (CFG.schema||[]).forEach(it => {
    const el = document.getElementById('cfg_'+it.key);
    if (!el) return;
    payload[it.key] = (it.type === 'bool') ? el.checked : el.value;
  });
  const r = await api('/api/config', {method:'POST', headers:{'Content-Type':'application/json'},
                                      body: JSON.stringify(payload)});
  m.innerHTML = r.ok ? '<span class="ok">'+esc(r.msg)+'</span>' : '<span class="err">'+esc(r.msg)+'</span>';
  if (r.ok) { setTimeout(loadSettings, 600); }
};
document.getElementById('cfgreload').onclick = loadSettings;
document.getElementById('svcrestart').onclick = async () => {
  const m = document.getElementById('cfgmsg'); m.textContent = '重启中…';
  const r = await api('/api/service', {method:'POST', headers:{'Content-Type':'application/json'},
                                       body: JSON.stringify({name:'cfip'})});
  m.innerHTML = r.ok ? '<span class="ok">'+esc(r.msg)+'</span>' : '<span class="err">'+esc(r.msg)+'</span>';
};

document.getElementById('refresh').onclick = refresh;
document.getElementById('nprev').onclick = async () => {
  const p = await api('/api/notify/preview');
  document.getElementById('prevTitle').textContent = p.ok ? (p.title + '  ·  ' + p.rows + ' 个 IP') : '';
  document.getElementById('prev').textContent = p.ok ? p.body : ('生成失败：' + p.error);
};
document.getElementById('ntest').onclick = async () => {
  const m = document.getElementById('nmsg'); m.textContent = '发送中…';
  const r = await api('/api/notify/test', {method:'POST'});
  m.innerHTML = r.ok ? '<span class="ok">推送成功（'+esc(r.channel||'')+'）</span>'
                     : '<span class="err">失败：'+esc(r.msg)+'</span>';
};
document.getElementById('run').onclick = async () => {
  const b = document.getElementById('run'); b.disabled = true;
  const m = document.getElementById('runmsg'); m.textContent = '正在启动…';
  try{
    const r = await api('/api/run', {method:'POST'});
    m.textContent = r.ok ? '已启动' : ('失败：' + (r.msg||''));
  }catch(e){ m.textContent = '失败：' + e.message; }
  setTimeout(()=>{ b.disabled = false; refresh(); }, 1500);
};
refresh(); loadSettings(); setInterval(refresh, 3000);
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
        if u.path == "/api/results/region":
            return self._json(load_results_region())
        if u.path == "/api/pool":
            return self._json({"summary": load_pool_summary(),
                               "rows": load_pool(limit=500)})
        if u.path == "/api/ips":
            fmt = (qs.get("format") or ["text"])[0].lower()
            ctype = {"json": "application/json; charset=utf-8",
                     "csv": "text/csv; charset=utf-8"}.get(fmt, "text/plain; charset=utf-8")
            body = serve_ips(qs)
            if isinstance(body, dict):
                return self._json(body)
            return self._send(200, body, ctype)
        if u.path == "/api/ips/region":
            # 等价的便捷写法：/api/ips/region == /api/ips?set=region
            qs = dict(qs)
            qs["set"] = ["region"]
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
        if u.path == "/api/notify":
            return self._json(load_notify_settings())
        if u.path == "/api/notify/preview":
            return self._json(notify_preview())
        if u.path == "/api/config":
            return self._json(load_settings())
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if not self._authed(qs):
            return self._json({"error": "token 不正确"}, 401)
        if u.path == "/api/run":
            return self._json(spawn_run())
        if u.path == "/api/notify/test":
            return self._json(notify_test())
        if u.path == "/api/notify":
            n = int(self.headers.get("Content-Length") or 0)
            try:
                payload = json.loads(self.rfile.read(n).decode("utf-8")) if n else {}
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                return self._json({"ok": False, "msg": f"请求体不是 JSON: {e}"}, 400)
            ok, msg = save_notify_settings(
                str(payload.get("channel") or "").strip(),
                str(payload.get("target") or "").strip(),
                bool(payload.get("only_with_result", True)))
            return self._json({"ok": ok, "msg": msg})
        if u.path == "/api/config":
            n = int(self.headers.get("Content-Length") or 0)
            try:
                payload = json.loads(self.rfile.read(n).decode("utf-8")) if n else {}
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                return self._json({"ok": False, "msg": f"请求体不是 JSON: {e}"}, 400)
            ok, msg = save_settings(payload)
            return self._json({"ok": ok, "msg": msg})
        if u.path == "/api/service":
            n = int(self.headers.get("Content-Length") or 0)
            try:
                payload = json.loads(self.rfile.read(n).decode("utf-8")) if n else {}
            except (json.JSONDecodeError, UnicodeDecodeError):
                payload = {}
            return self._json(restart_service(str(payload.get("name") or "cfip")))
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
