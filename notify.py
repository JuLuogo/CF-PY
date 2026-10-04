#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""推送通知 —— 每轮扫描完成后把结果推到手机。

纯标准库实现。支持常见的推送渠道，填哪个用哪个：

  bark        iOS，Bark App           target = https://api.day.app/你的key
  pushplus    推送加 PushPlus（微信）   target = 你的 token
  pushdeer    开源，iOS/Android       target = https://api2.pushdeer.com   key = pushkey
  ntfy        开源，全平台/可自建      target = https://ntfy.sh/你的topic
  serverchan  Server酱³（微信）        target = https://sctapi.ftqq.com/你的key.send
  telegram    Telegram Bot            target = <bot_token>|<chat_id>
  wecom       企业微信群机器人         target = webhook 完整地址
  dingtalk    钉钉群机器人             target = webhook 完整地址
  feishu      飞书群机器人             target = webhook 完整地址
  webhook     通用：POST 一段 JSON     target = 你的地址

配置（config.ini 或环境变量）：
  NOTIFY_CHANNEL = "bark"
  NOTIFY_TARGET  = "https://api.day.app/xxxxx"
  NOTIFY_ONLY_WITH_RESULT = true   # 没有可用 IP 时不打扰
"""

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# 强制 stdout/stderr 用 UTF-8（VPS 常没配 locale，Python 会退回 latin-1，
# 一 print 中文就 UnicodeEncodeError 崩掉）
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

NOTIFY_CHANNEL = ""
NOTIFY_TARGET = ""
NOTIFY_ONLY_WITH_RESULT = True
NOTIFY_TIMEOUT = 15

# 国家代码 -> 中文名（推送里比两字母码好读）
CC_NAME = {
    "HK": "香港", "JP": "日本", "SG": "新加坡", "KR": "韩国", "TW": "台湾",
    "US": "美国", "CA": "加拿大", "GB": "英国", "DE": "德国", "FR": "法国",
    "NL": "荷兰", "RU": "俄罗斯", "AU": "澳大利亚", "IN": "印度", "ID": "印尼",
    "TH": "泰国", "VN": "越南", "MY": "马来西亚", "PH": "菲律宾", "TR": "土耳其",
    "BR": "巴西", "IT": "意大利", "ES": "西班牙", "SE": "瑞典", "CH": "瑞士",
    "PL": "波兰", "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰",
    "AT": "奥地利", "BE": "比利时", "CZ": "捷克", "UA": "乌克兰", "AE": "阿联酋",
    "IL": "以色列", "ZA": "南非", "MX": "墨西哥", "AR": "阿根廷", "CL": "智利",
    "NZ": "新西兰", "PT": "葡萄牙", "RO": "罗马尼亚", "BG": "保加利亚",
    "LT": "立陶宛", "LV": "拉脱维亚", "EE": "爱沙尼亚", "MD": "摩尔多瓦",
    "KZ": "哈萨克斯坦", "CN": "中国大陆",
}


def cc_label(cc):
    cc = (cc or "").upper()
    if not cc:
        return "未知"
    return f"{cc} {CC_NAME[cc]}" if cc in CC_NAME else cc


def _post(url, data=None, headers=None, timeout=NOTIFY_TIMEOUT, raw_body=None):
    """发一个请求。data=dict 时发 JSON，raw_body=bytes 时原样发。"""
    body = raw_body
    hdrs = {"User-Agent": "cfip-notify/1.0"}
    if data is not None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        hdrs["Content-Type"] = "application/json; charset=utf-8"
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=body, headers=hdrs,
                                 method="POST" if body else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", errors="replace")[:300]


def build_summary(round_no, available, quality, rows, started=None, finished=None,
                  duration=None, sample_note=""):
    """生成推送正文。

    available : 通过可用性检查的数量（真的反代了 CF）
    quality   : 通过延迟/丢包/速度筛选的数量
    rows      : 最终结果行（含 ip/latency/loss/speed/country/city/port）
    """
    rows = rows or []
    lines = []

    # ---- 概览 ----
    if round_no:
        lines.append(f"第 {round_no} 轮扫描完成")
    if duration:
        lines.append(f"耗时 {duration}")
    if sample_note:
        lines.append(sample_note)
    lines.append("")

    # ---- 按地区统计（用最终结果，因为只有它带国家信息）----
    dist = {}
    for r in rows:
        cc = (r.get("country") or r.get("cfcountry") or "??").upper()
        dist[cc] = dist.get(cc, 0) + 1

    if dist:
        lines.append(f"可用地区（共 {len(rows)} 个）：")
        for cc, n in sorted(dist.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {cc_label(cc)}  {n} 个")
    else:
        lines.append("本轮没有通过筛选的 IP")

    # ---- 端口统计 ----
    ports = {}
    for r in rows:
        p = str(r.get("port") or "443").strip() or "443"
        ports[p] = ports.get(p, 0) + 1
    if ports:
        lines.append("")
        lines.append("端口：" + "、".join(f"{p} × {n}" for p, n in
                                        sorted(ports.items(), key=lambda kv: -kv[1])))

    # ---- 最好的几个 ----
    best = rows[:5]
    if best:
        lines.append("")
        lines.append("最佳：")
        for r in best:
            lat = r.get("latency") or "?"
            loss = r.get("loss") or "?"
            spd = r.get("speed") or "?"
            city = r.get("city") or ""
            cc = cc_label(r.get("country") or r.get("cfcountry"))
            lines.append(f"  {r.get('ip','')}  {cc} {city}  {lat} {loss} {spd}")

    return "\n".join(lines)


def send(title, body):
    """按配置的渠道发一条推送。返回 (ok, 说明)。"""
    ch = (NOTIFY_CHANNEL or "").strip().lower()
    tgt = (NOTIFY_TARGET or "").strip()
    if not ch or not tgt:
        return False, "未配置 NOTIFY_CHANNEL / NOTIFY_TARGET"

    try:
        if ch == "bark":
            # https://api.day.app/<key>/<标题>/<正文>
            base = tgt.rstrip("/")
            url = f"{base}/{urllib.parse.quote(title)}/{urllib.parse.quote(body)}"
            st, _ = _post(url + "?group=CF-IP&isArchive=1")
            return st == 200, f"HTTP {st}"

        if ch == "pushplus":
            # 推送加 PushPlus：target 直接填 token（pushplus.plus 个人中心获取）
            # 也允许填完整地址，那就从 URL 里把 token 抠出来
            token = tgt
            if "/" in tgt:
                m = re.search(r"[?&]token=([^&\s]+)", tgt) or re.search(r"/([0-9a-zA-Z]{16,})", tgt)
                token = m.group(1) if m else tgt
            st, txt = _post("https://www.pushplus.plus/send",
                            data={"token": token, "title": title,
                                  "content": body, "template": "txt"})
            ok = False
            try:
                j = json.loads(txt)
                ok = str(j.get("code")) == "200"
                return ok, f"HTTP {st} {j.get('msg', txt[:80])}"
            except json.JSONDecodeError:
                return st == 200, f"HTTP {st} {txt[:80]}"

        if ch == "pushdeer":
            url = tgt.rstrip("/") + "/message/push"
            st, _ = _post(url, data={"text": title, "desp": body, "type": "markdown"})
            return st == 200, f"HTTP {st}"

        if ch == "ntfy":
            # topic 就是完整地址，正文直接放 body，标题放 Title 头
            st, _ = _post(tgt, raw_body=body.encode("utf-8"),
                          headers={"Title": title.encode("utf-8").decode("latin-1", "ignore"),
                                   "Tags": "white_check_mark"})
            return st == 200, f"HTTP {st}"

        if ch == "serverchan":
            url = tgt if tgt.endswith(".send") else tgt.rstrip("/") + ".send"
            st, _ = _post(url, data={"title": title, "desp": body})
            return st == 200, f"HTTP {st}"

        if ch == "telegram":
            # target = "<bot_token>|<chat_id>"
            if "|" not in tgt:
                return False, "telegram 的 target 要写成 <bot_token>|<chat_id>"
            token, chat = tgt.split("|", 1)
            url = f"https://api.telegram.org/bot{token.strip()}/sendMessage"
            st, _ = _post(url, data={"chat_id": chat.strip(),
                                     "text": f"{title}\n\n{body}",
                                     "disable_web_page_preview": True})
            return st == 200, f"HTTP {st}"

        if ch == "wecom":
            st, txt = _post(tgt, data={"msgtype": "text",
                                       "text": {"content": f"{title}\n{body}"}})
            return st == 200, f"HTTP {st} {txt[:80]}"

        if ch == "dingtalk":
            st, txt = _post(tgt, data={"msgtype": "text",
                                       "text": {"content": f"{title}\n{body}"}})
            return st == 200, f"HTTP {st} {txt[:80]}"

        if ch == "feishu":
            st, txt = _post(tgt, data={"msg_type": "text",
                                       "content": {"text": f"{title}\n{body}"}})
            return st == 200, f"HTTP {st} {txt[:80]}"

        if ch == "webhook":
            st, _ = _post(tgt, data={"title": title, "body": body})
            return st == 200, f"HTTP {st}"

        return False, f"不认识的渠道：{ch}"
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", errors="replace")[:200]
        except Exception:                        # noqa: BLE001
            pass
        return False, f"HTTP {e.code} {detail}"
    except Exception as e:                       # noqa: BLE001
        return False, str(e)


def self_test():
    """发一条测试推送，验证配置对不对。"""
    return send("CF 反代 IP 优选 · 测试推送",
                "如果你看到这条消息，说明推送配置正确。\n\n"
                "之后每轮扫描完成会推送：完成情况、各地区可用数量、端口分布、最佳几个 IP。")


if __name__ == "__main__":
    import argparse
    import sys
    HERE = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, HERE)
    ap = argparse.ArgumentParser(description="推送测试")
    ap.add_argument("-channel", default=None, help="渠道，如 bark / ntfy / telegram ...")
    ap.add_argument("-target", default=None, help="渠道的 key 或 webhook 地址")
    ap.add_argument("-list", action="store_true", help="列出支持的渠道")
    a = ap.parse_args()

    if a.list:
        print("支持的渠道：")
        for c, d in [("bark", "iOS，target=https://api.day.app/你的key"),
                     ("pushplus", "推送加 PushPlus（微信），target=你的 token"),
                     ("pushdeer", "开源，target=https://api2.pushdeer.com"),
                     ("ntfy", "开源全平台，target=https://ntfy.sh/你的topic"),
                     ("serverchan", "Server酱³，target=https://sctapi.ftqq.com/你的key.send"),
                     ("telegram", "target=<bot_token>|<chat_id>"),
                     ("wecom", "企业微信机器人 webhook"),
                     ("dingtalk", "钉钉机器人 webhook"),
                     ("feishu", "飞书机器人 webhook"),
                     ("webhook", "通用 POST JSON")]:
            print(f"  {c:<12} {d}")
        sys.exit(0)

    # 没给参数就从 config.ini 读
    if not a.channel:
        try:
            import ip as _ip
            cfg = _ip.load_config(os.path.join(HERE, "config.ini"))
            NOTIFY_CHANNEL = str(cfg.get("NOTIFY_CHANNEL") or "").strip().strip('"')
            NOTIFY_TARGET = str(cfg.get("NOTIFY_TARGET") or "").strip().strip('"')
        except Exception as e:                   # noqa: BLE001
            print(f"[!] 读配置失败：{e}")
    else:
        NOTIFY_CHANNEL = a.channel
        NOTIFY_TARGET = a.target or ""

    NOTIFY_CHANNEL = NOTIFY_CHANNEL or os.environ.get("NOTIFY_CHANNEL", "")
    NOTIFY_TARGET = NOTIFY_TARGET or os.environ.get("NOTIFY_TARGET", "")

    if not NOTIFY_CHANNEL or not NOTIFY_TARGET:
        print("[!] 没配置渠道。用法：")
        print("    python notify.py -channel bark -target https://api.day.app/你的key")
        print("    或写进 config.ini 的 NOTIFY_CHANNEL / NOTIFY_TARGET")
        print("    python notify.py -list   # 看支持哪些渠道")
        sys.exit(2)

    print(f"渠道 {NOTIFY_CHANNEL}  目标 {NOTIFY_TARGET[:50]}...")
    ok, msg = self_test()
    print(("✓ 推送成功  " if ok else "✗ 推送失败  ") + msg)
    sys.exit(0 if ok else 1)
