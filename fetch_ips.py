#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""多源候选 IP 抓取器 —— 自动搜集 Cloudflare 反代 IP，产出 ip.py 可直接消费的 ip.csv。

它补上了 cloudflare-sni-proxy-tester 缺失的“数据来源”那一环：

    数据源（IPDB / FOFA / 本地CSV）
        -> 合并去重 -> 本地过滤（只留 443、剔私网、排除 Cloudflare 自家 ASN）
        -> 写出 ip.csv（列名与 README 的“csv输入示例”完全一致）
        -> （-run）自动调用 ip.py 做 可用性 / 延迟 / 速度 / 线路 测试

两个数据源的取舍：

  IPDB  https://ipdb.api.030101.xyz/   反代池每 10 分钟刷新，不需要任何 key。
        反代池有 700+ 条，是“当下还活着”的名单，适合做全自动定时任务。
  FOFA  https://fofa.info              网络空间测绘索引，按指纹反查，覆盖面更广，
        但索引是快照（可能是几个月前扫到的），且 API 需要账号权限。

用法示例：
    python fetch_ips.py                            # 默认走 IPDB，抓完写 ip.csv
    python fetch_ips.py -run                       # 抓完立刻跑 ip.py
    python fetch_ips.py -run -- -skipt -d 5        # -- 之后的参数原样透传给 ip.py
    python fetch_ips.py -source fofa -regions HK,JP
    python fetch_ips.py -source fofa --dry-run     # 只打印 FOFA 语法，不消耗额度
    python fetch_ips.py -source csv -import-csv fofa_export.csv
    python fetch_ips.py -max 200                   # 只取前 200 个候选，避免过量测速
    python fetch_ips.py -loop 3600                 # 每 3600 秒自动跑一轮（全自动/容器用）
    python fetch_ips.py --self-test                # 不联网抓取，用内置样例自检整条链路

本项目为纯标准库实现，不需要 pip install 任何东西。
"""

import argparse
import base64
import csv
import ipaddress
import itertools
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_FILE = os.path.join(HERE, "config.ini")

# 强制 stdout/stderr 用 UTF-8。
# 很多 VPS 没配 locale（LANG 为空），Python 会退回 C locale，stdout 变成
# latin-1，一 print 中文就 UnicodeEncodeError 直接崩。
# 在代码里兜住比依赖 systemd unit 里的环境变量可靠得多。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

# ==================== 默认配置（可被 config.ini / 环境变量 / 命令行覆盖） ====================
FOFA_API_BASE = "https://fofa.info"
FOFA_EMAIL = ""
FOFA_KEY = ""
FOFA_FIELDS = "ip,port,protocol,title,domain,country,city,link,org"
FOFA_PAGE_SIZE = 100          # 单次请求条数（FOFA 上限 10000，取小一点更稳）
FOFA_MAX_PER_REGION = 500     # 每个地区最多抓多少条（page*size 不得超过 10000）
FOFA_REGIONS = "HK,JP,KR,SG,TW,US"
FOFA_PRESET = "proxy"
FOFA_QUERY_TEMPLATE = ""      # 非空时覆盖 preset
FOFA_EXTRA_QUERY = ""         # 追加自定义过滤，例：asn=="45102"
FOFA_EXCLUDE_ASNS = "13335,209242"   # Cloudflare 自家 ASN，必须排除
FOFA_EXCLUDE_CIDRS = ""       # 追加排除的网段，逗号分隔
FOFA_REQUIRE_PORT = "443"     # ip.py 只测 443，所以默认只收 443 的结果；留空表示不过滤
FOFA_CSV_OUTPUT = "./ip.csv"
FOFA_FULL = False             # false=只搜一年内数据，true=搜全部
FOFA_DELAY = 1.0              # 翻页间隔秒数，避免触发 FOFA 频率限制
FOFA_TIMEOUT = 20
FOFA_RETRIES = 3
FOFA_SKIP_FILE = ""           # 例：./ip.txt，跳过已收录的 IP，避免重复测速
FOFA_RUN = False
FOFA_RUN_ARGS = ""            # -run 时追加给 ip.py 的参数（字符串形式）

# ==================== IPDB（https://ipdb.api.030101.xyz/）默认配置 ====================
# 免费公开接口，不需要 key。反代池 type=proxy 每 10 分钟刷新一次。
IPDB_API_BASE = "https://ipdb.api.030101.xyz/"
# 取哪些列表，用 ; 分隔（和接口本身的写法一致）：
#   bestproxy  已优选的反代 IP（每 30 分钟刷新，带地区，数量少但质量高）
#   proxy      全量反代 IP 池（每 10 分钟刷新，700+ 条，不带地区）
#   cfv4       Cloudflare 官方网段 —— 会按不同 /24 采样 IPDB_CF_SAMPLE 个地址
#   bestcf     已优选的 Cloudflare 官方 IP（不是反代，一般不需要）
#   cfv6       Cloudflare 官方 IPv6 网段，ip.py 不支持 IPv6，会被跳过
# 顺序有讲究：小列表在前。IPDB 的 proxy 大列表在国内直连经常读不完（实测 90s
# 只收到 428/723 行），放最后即使超时也不影响前面已经拿到的好数据。
IPDB_TYPES = "bestproxy;cfv4;proxy"
IPDB_COUNTRY = True           # 对支持地区标注的列表追加 country=true
IPDB_TIMEOUT = 120            # 国内直连 IPDB 偏慢，给足时间
IPDB_RETRIES = 3
IPDB_MAX = 0                  # 只取前 N 个候选，0 = 不限制
# 从 Cloudflare 官方网段（cfv4）采样多少个 IP 一起测。0 = 不采样官方 IP。
# 只测第三方反代往往不够用（反代池会失效/被限速），配上官方 IP 才有兜底。
# 建议 10~50：采样按「不同 /24」进行，30 个已经能覆盖绝大多数路由差异。
IPDB_CF_SAMPLE = 30
# 第三方列表源（-source list）。填 LIST_SOURCES 里的名字或完整 URL，逗号分隔可组合。
# 可选名字：zip / luuaiyan / xgonce / wwuyi / wwuyi_c / muhaip
LIST_URLS = "zip"
LIST_TIMEOUT = 60
# 只保留这些地区的条目（空字符串 = 不筛选）。
# 列表里有 74 个国家，不筛的话 -max 会随机取到一堆欧洲 IP（实测 150~290ms），
# 而 HK/JP/SG 这类近端才可能跑到 30~80ms。没有地区标注的条目会被保留。
LIST_REGIONS = "HK,JP,SG,KR,TW"

# ==================== FOFA 查询预设 ====================
# 反代的特征：请求它，它把请求转发给 Cloudflare，于是 HTTP 响应头里带着 CF 的
# Server: cloudflare，页面内容是 CF 的 403 Forbidden。这是社区里最常用的筛选语法。
QUERY_PRESETS = {
    # 默认：命中率最高，抓到的基本就是 CF 反代
    "proxy": 'server=="cloudflare" && port=="443" && header="Forbidden"',
    # 放宽：只要 Server: cloudflare，多抓一些交给 ip.py 的真实性校验去淘汰
    "relaxed": 'server=="cloudflare" && port=="443"',
    # 证书指纹：证书签发者是 Cloudflare，多为套了 CF 证书的中转/反代
    "cert": 'cert.issuer="Cloudflare, Inc." && port=="443"',
    # 直接搜 trace 页特征（取决于 FOFA 是否收录了该路径，命中率不稳定）
    "trace": 'body="h=www.cloudflare.com" && port=="443"',
}

# fields 兜底链：不同 FOFA 账号/套餐可返回的字段不完全一致，逐个降级直到成功
FIELD_CANDIDATES = [
    "ip,port,protocol,title,domain,country,city,link,org",
    "ip,port,protocol,title,domain,country,city",
    "ip,port,host",
]

# 自检样例：Cloudflare 官方任播 IP，仅用于在不消耗 FOFA 额度的前提下验证链路
SELF_TEST_ROWS = [
    {"ip": "104.16.132.229", "port": "443", "protocol": "https", "title": "Cloudflare",
     "domain": "cloudflare.com", "country": "US", "city": "San Francisco",
     "link": "https://104.16.132.229", "org": "Cloudflare, Inc."},
    {"ip": "172.66.0.227", "port": "443", "protocol": "https", "title": "Cloudflare",
     "domain": "cloudflare.com", "country": "US", "city": "San Francisco",
     "link": "https://172.66.0.227", "org": "Cloudflare, Inc."},
]

DEBUG = False


def log(msg):
    print(msg, flush=True)


# ==================== 配置读取 ====================
def _fallback_load_config(path):
    """ip.py 的极简替身解析器，只在无法 import ip.py 时兜底。"""
    cfg = {}
    if not os.path.exists(path):
        return cfg
    for enc in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            with open(path, "r", encoding=enc) as f:
                lines = f.readlines()
            break
        except (UnicodeDecodeError, OSError):
            continue
    else:
        return cfg
    for line in lines:
        out, quote, esc = [], None, False
        for ch in line:
            if esc:
                out.append(ch); esc = False; continue
            if ch == "\\":
                out.append(ch); esc = True; continue
            if quote:
                out.append(ch)
                if ch == quote:
                    quote = None
            elif ch in ("'", '"'):
                quote = ch; out.append(ch)
            elif ch == "#":
                break
            else:
                out.append(ch)
        line = "".join(out).strip()
        if not line or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if v.endswith(";"):
            v = v[:-1].strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
            v = v[1:-1]
        elif v.lower() in ("true", "yes", "on"):
            v = True
        elif v.lower() in ("false", "no", "off"):
            v = False
        elif re.fullmatch(r"\d+", v):
            v = int(v)
        cfg[k] = v
    return cfg


def load_config(path):
    """复用 ip.py 的解析器，保证两个脚本对同一个 config.ini 的理解完全一致。"""
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    try:
        import ip as tester          # ip.py 模块级只有定义，import 不会执行 main()
        return tester.load_config(path)
    except Exception as e:            # pragma: no cover - 仅在 ip.py 缺失/损坏时触发
        log(f"[!] 无法复用 ip.py 的配置解析器（{e}），改用内置解析器")
        return _fallback_load_config(path)


def as_bool(v, default=False):
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off", ""):
        return False
    return default


def as_int(v, default):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def as_float(v, default):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def as_list(v):
    """按 , ; ，； 切分成列表。IPDB 的类型分隔符是 ;，地区是 ,。"""
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x.strip() for x in re.split(r"[,;，；]", str(v)) if x.strip()]


def apply_config(cfg):
    global FOFA_API_BASE, FOFA_EMAIL, FOFA_KEY, FOFA_FIELDS, FOFA_PAGE_SIZE
    global FOFA_MAX_PER_REGION, FOFA_REGIONS, FOFA_PRESET, FOFA_QUERY_TEMPLATE
    global FOFA_EXTRA_QUERY, FOFA_EXCLUDE_ASNS, FOFA_EXCLUDE_CIDRS, FOFA_REQUIRE_PORT
    global FOFA_CSV_OUTPUT, FOFA_FULL, FOFA_DELAY, FOFA_TIMEOUT, FOFA_RETRIES
    global FOFA_SKIP_FILE, FOFA_RUN, FOFA_RUN_ARGS
    global IPDB_API_BASE, IPDB_TYPES, IPDB_COUNTRY, IPDB_TIMEOUT, IPDB_RETRIES, IPDB_MAX
    global IPDB_CF_SAMPLE, LIST_URLS, LIST_TIMEOUT, LIST_REGIONS
    global ASNS, ASN_SAMPLE, ASN_REGIONS, ASN_EXCLUDE_REGIONS
    global NOTIFY_CHANNEL, NOTIFY_TARGET, NOTIFY_TIMEOUT, NOTIFY_ONLY_WITH_RESULT, PORTS
    global THREADS, LOOP
    global OUTPUT_REGIONS, OUTPUT_SPLIT, CHUNK_SIZE, FULL_SCAN, SUB_BATCH
    global PREFIX_MIN_BATCH
    global SYS_GUARD_ENABLED, SYS_MIN_FREE_MB, PER_CONN_KB
    global POOL_ENABLED, POOL_FILE, POOL_MAX_AGE_DAYS, POOL_MIN_KEEP_RATIO
    global UPSTREAM_STAGE1_ONLY, POOL_MODE

    get = cfg.get
    if "FOFA_API_BASE" in cfg:        FOFA_API_BASE = str(get("FOFA_API_BASE")).strip() or FOFA_API_BASE
    if "FOFA_EMAIL" in cfg:           FOFA_EMAIL = str(get("FOFA_EMAIL") or "").strip()
    if "FOFA_KEY" in cfg:             FOFA_KEY = str(get("FOFA_KEY") or "").strip()
    if "FOFA_FIELDS" in cfg:          FOFA_FIELDS = str(get("FOFA_FIELDS")).strip()
    if "FOFA_PAGE_SIZE" in cfg:       FOFA_PAGE_SIZE = as_int(get("FOFA_PAGE_SIZE"), FOFA_PAGE_SIZE)
    if "FOFA_MAX_PER_REGION" in cfg:  FOFA_MAX_PER_REGION = as_int(get("FOFA_MAX_PER_REGION"), FOFA_MAX_PER_REGION)
    if "FOFA_REGIONS" in cfg:         FOFA_REGIONS = str(get("FOFA_REGIONS")).strip()
    if "FOFA_PRESET" in cfg:          FOFA_PRESET = str(get("FOFA_PRESET")).strip()
    if "FOFA_QUERY_TEMPLATE" in cfg:  FOFA_QUERY_TEMPLATE = str(get("FOFA_QUERY_TEMPLATE") or "").strip()
    if "FOFA_EXTRA_QUERY" in cfg:     FOFA_EXTRA_QUERY = str(get("FOFA_EXTRA_QUERY") or "").strip()
    if "FOFA_EXCLUDE_ASNS" in cfg:    FOFA_EXCLUDE_ASNS = str(get("FOFA_EXCLUDE_ASNS") or "").strip()
    if "FOFA_EXCLUDE_CIDRS" in cfg:   FOFA_EXCLUDE_CIDRS = str(get("FOFA_EXCLUDE_CIDRS") or "").strip()
    if "FOFA_REQUIRE_PORT" in cfg:    FOFA_REQUIRE_PORT = str(get("FOFA_REQUIRE_PORT") or "").strip()
    if "FOFA_CSV_OUTPUT" in cfg:      FOFA_CSV_OUTPUT = str(get("FOFA_CSV_OUTPUT")).strip()
    if "FOFA_FULL" in cfg:            FOFA_FULL = as_bool(get("FOFA_FULL"), FOFA_FULL)
    if "FOFA_DELAY" in cfg:           FOFA_DELAY = as_float(get("FOFA_DELAY"), FOFA_DELAY)
    if "FOFA_TIMEOUT" in cfg:         FOFA_TIMEOUT = as_int(get("FOFA_TIMEOUT"), FOFA_TIMEOUT)
    if "FOFA_RETRIES" in cfg:         FOFA_RETRIES = as_int(get("FOFA_RETRIES"), FOFA_RETRIES)
    if "FOFA_SKIP_FILE" in cfg:       FOFA_SKIP_FILE = str(get("FOFA_SKIP_FILE") or "").strip()
    if "FOFA_RUN" in cfg:             FOFA_RUN = as_bool(get("FOFA_RUN"), FOFA_RUN)
    if "FOFA_RUN_ARGS" in cfg:        FOFA_RUN_ARGS = str(get("FOFA_RUN_ARGS") or "").strip()

    if "IPDB_API_BASE" in cfg:        IPDB_API_BASE = str(get("IPDB_API_BASE")).strip() or IPDB_API_BASE
    if "IPDB_TYPES" in cfg:           IPDB_TYPES = str(get("IPDB_TYPES") or "").strip()
    if "IPDB_COUNTRY" in cfg:         IPDB_COUNTRY = as_bool(get("IPDB_COUNTRY"), IPDB_COUNTRY)
    if "IPDB_TIMEOUT" in cfg:         IPDB_TIMEOUT = as_int(get("IPDB_TIMEOUT"), IPDB_TIMEOUT)
    if "IPDB_RETRIES" in cfg:         IPDB_RETRIES = as_int(get("IPDB_RETRIES"), IPDB_RETRIES)
    if "IPDB_MAX" in cfg:             IPDB_MAX = as_int(get("IPDB_MAX"), IPDB_MAX)
    if "IPDB_CF_SAMPLE" in cfg:       IPDB_CF_SAMPLE = as_int(get("IPDB_CF_SAMPLE"), IPDB_CF_SAMPLE)
    if "LIST_URLS" in cfg:            LIST_URLS = str(get("LIST_URLS") or "").strip()
    if "LIST_TIMEOUT" in cfg:         LIST_TIMEOUT = as_int(get("LIST_TIMEOUT"), LIST_TIMEOUT)
    if "LIST_REGIONS" in cfg:         LIST_REGIONS = str(get("LIST_REGIONS") or "").strip()
    if "ASNS" in cfg:                 ASNS = str(get("ASNS") or "").strip()
    if "ASN_SAMPLE" in cfg:           ASN_SAMPLE = as_int(get("ASN_SAMPLE"), ASN_SAMPLE)
    if "ASN_REGIONS" in cfg:          ASN_REGIONS = str(get("ASN_REGIONS") or "").strip()
    if "ASN_EXCLUDE_REGIONS" in cfg:  ASN_EXCLUDE_REGIONS = str(get("ASN_EXCLUDE_REGIONS") or "").strip()
    if "NOTIFY_CHANNEL" in cfg:       NOTIFY_CHANNEL = str(get("NOTIFY_CHANNEL") or "").strip()
    if "NOTIFY_TARGET" in cfg:        NOTIFY_TARGET = str(get("NOTIFY_TARGET") or "").strip()
    if "NOTIFY_TIMEOUT" in cfg:       NOTIFY_TIMEOUT = as_int(get("NOTIFY_TIMEOUT"), NOTIFY_TIMEOUT)
    if "NOTIFY_ONLY_WITH_RESULT" in cfg:
        NOTIFY_ONLY_WITH_RESULT = as_bool(get("NOTIFY_ONLY_WITH_RESULT"), NOTIFY_ONLY_WITH_RESULT)
    if "PORTS" in cfg:                PORTS = str(get("PORTS") or "").strip()
    if "CHUNK_SIZE" in cfg:          CHUNK_SIZE = as_int(get("CHUNK_SIZE"), CHUNK_SIZE)
    if "SUB_BATCH" in cfg:            SUB_BATCH = max(1000, as_int(get("SUB_BATCH"), SUB_BATCH))
    if "PREFIX_MIN_BATCH" in cfg:
        PREFIX_MIN_BATCH = max(254, as_int(get("PREFIX_MIN_BATCH"), PREFIX_MIN_BATCH))
    if "SYS_GUARD_ENABLED" in cfg:
        SYS_GUARD_ENABLED = as_bool(get("SYS_GUARD_ENABLED"), SYS_GUARD_ENABLED)
    if "SYS_MIN_FREE_MB" in cfg:
        SYS_MIN_FREE_MB = max(50, as_int(get("SYS_MIN_FREE_MB"), SYS_MIN_FREE_MB))
    if "PER_CONN_KB" in cfg:
        PER_CONN_KB = max(16, as_int(get("PER_CONN_KB"), PER_CONN_KB))
    if "FULL_SCAN" in cfg:            FULL_SCAN = as_bool(get("FULL_SCAN"), FULL_SCAN)
    if "POOL_ENABLED" in cfg:         POOL_ENABLED = as_bool(get("POOL_ENABLED"), POOL_ENABLED)
    if "POOL_FILE" in cfg:            POOL_FILE = str(get("POOL_FILE") or POOL_FILE).strip().strip('"')
    if "POOL_MAX_AGE_DAYS" in cfg:    POOL_MAX_AGE_DAYS = as_int(get("POOL_MAX_AGE_DAYS"), POOL_MAX_AGE_DAYS)
    if "POOL_MIN_KEEP_RATIO" in cfg:
        POOL_MIN_KEEP_RATIO = float(get("POOL_MIN_KEEP_RATIO"))
    if "UPSTREAM_STAGE1_ONLY" in cfg:
        UPSTREAM_STAGE1_ONLY = as_bool(get("UPSTREAM_STAGE1_ONLY"), UPSTREAM_STAGE1_ONLY)
    if "POOL_MODE" in cfg:
        POOL_MODE = str(get("POOL_MODE") or "auto").strip().strip('"').lower()
    if "OUTPUT_REGIONS" in cfg:
        OUTPUT_REGIONS = str(get("OUTPUT_REGIONS") or "").strip().strip('"')
    if "OUTPUT_SPLIT" in cfg:         OUTPUT_SPLIT = as_bool(get("OUTPUT_SPLIT"), OUTPUT_SPLIT)
    if "THREADS" in cfg:              THREADS = as_int(get("THREADS"), THREADS)
    if "LOOP" in cfg:                 LOOP = as_int(get("LOOP"), LOOP)


def apply_env():
    """环境变量覆盖 config.ini —— 便于容器部署时不改配置文件。

    优先级：命令行 > 环境变量 > config.ini > 内置默认。
    """
    global FOFA_EMAIL, FOFA_KEY, FOFA_REGIONS
    global ASNS, ASN_SAMPLE, ASN_REGIONS, ASN_EXCLUDE_REGIONS
    global NOTIFY_CHANNEL, NOTIFY_TARGET, NOTIFY_TIMEOUT, NOTIFY_ONLY_WITH_RESULT, PORTS
    global THREADS, LOOP
    global LIST_URLS, LIST_REGIONS, IPDB_TYPES, IPDB_CF_SAMPLE

    env = os.environ.get
    if env("FOFA_EMAIL"):
        FOFA_EMAIL = env("FOFA_EMAIL").strip()
    if env("FOFA_KEY"):
        FOFA_KEY = env("FOFA_KEY").strip()
    if env("FOFA_REGIONS"):
        FOFA_REGIONS = env("FOFA_REGIONS").strip()
    if env("ASNS"):
        ASNS = env("ASNS").strip()
    if env("ASN_REGIONS") is not None:
        ASN_REGIONS = env("ASN_REGIONS").strip()
    if env("ASN_EXCLUDE_REGIONS") is not None:
        ASN_EXCLUDE_REGIONS = env("ASN_EXCLUDE_REGIONS").strip()
    if env("ASN_SAMPLE", "").strip().isdigit():
        ASN_SAMPLE = int(env("ASN_SAMPLE").strip())
    if env("LIST_URLS"):
        LIST_URLS = env("LIST_URLS").strip()
    if env("LIST_REGIONS") is not None:
        LIST_REGIONS = env("LIST_REGIONS").strip()
    if env("IPDB_TYPES"):
        IPDB_TYPES = env("IPDB_TYPES").strip()
    if env("IPDB_CF_SAMPLE", "").strip().isdigit():
        IPDB_CF_SAMPLE = int(env("IPDB_CF_SAMPLE").strip())


# ==================== 查询构造 ====================
def build_query(template, region, extra, exclude_asns):
    """把模板 + 地区 + 追加条件 + 排除 ASN 拼成一条完整 FOFA 语法。"""
    parts = [f"({template})"]
    if region:
        parts.append(f'country=="{region.upper()}"')
    for asn in exclude_asns:
        a = str(asn).replace("AS", "").replace("as", "").strip()
        if a:
            parts.append(f'asn!="{a}"')
    if extra:
        parts.append(f"({extra})")
    return " && ".join(parts)


def human_query(regions, template, extra, exclude_asns):
    """生成人类可读的查询清单，方便直接粘贴到 fofa.info 搜索框。"""
    out = []
    for r in regions:
        out.append((r, build_query(template, r, extra, exclude_asns)))
    return out


# ==================== FOFA API ====================
class FetchError(Exception):
    pass


def fofa_search(query, fields, page, size, full, timeout, retries, debug=False):
    """调用 /api/v1/search/all，返回 (rows:list[dict], raw_count:int)。"""
    qb64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
    params = {
        "key": FOFA_KEY,
        "qbase64": qb64,
        "fields": fields,
        "page": str(page),
        "size": str(size),
        "full": "true" if full else "false",
    }
    if FOFA_EMAIL:
        params["email"] = FOFA_EMAIL
    url = f"{FOFA_API_BASE.rstrip('/')}/api/v1/search/all?" + urllib.parse.urlencode(params)

    last_err = None
    for attempt in range(1, max(1, retries) + 1):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "cloudflare-sni-proxy-tester/fetch_ips",
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read().decode("utf-8", errors="replace")
            data = json.loads(body)
        except urllib.error.HTTPError as e:
            raw = ""
            try:
                raw = e.read().decode("utf-8", errors="replace")
                data = json.loads(raw)
            except Exception:
                data = None
            if data is None:
                last_err = FetchError(f"HTTP {e.code}: {raw[:200] or e.reason}")
                if e.code in (429, 500, 502, 503, 504) and attempt < retries:
                    time.sleep(2 * attempt)
                    continue
                raise last_err
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            last_err = FetchError(f"请求失败: {e}")
            if attempt < retries:
                time.sleep(2 * attempt)
                continue
            raise last_err

        if data.get("error"):
            errmsg = str(data.get("errmsg", "")).strip()
            code = ""
            m = re.match(r"\[(-\d+)\]", errmsg)
            if m:
                code = m.group(1)
            raise FetchError(f"FOFA 返回错误 {code} {errmsg}")

        names = [f.strip() for f in fields.split(",")]
        rows = []
        for item in data.get("results") or []:
            if not isinstance(item, (list, tuple)):
                continue
            rows.append({names[i]: ("" if i >= len(item) or item[i] is None else str(item[i]))
                         for i in range(len(names))})
        if debug:
            log(f"[DEBUG] page={page} size={size} 返回 {len(rows)} 条 | query={query}")
        return rows, as_int(data.get("size"), len(rows))

    raise last_err or FetchError("未知错误")


def resolve_fields(preferred, timeout, retries, debug=False):
    """探测当前账号可用的 fields，失败则逐级降级。"""
    tried = []
    for cand in [preferred] + [c for c in FIELD_CANDIDATES if c != preferred]:
        try:
            fofa_search('ip="1.1.1.1"', cand, 1, 1, False, timeout, retries, debug)
            if tried:
                log(f"[!] fields 降级为：{cand}（以下字段不可用：{', '.join(tried)}）")
            return cand
        except FetchError as e:
            msg = str(e)
            if re.search(r"field|字段|参数|\[\-40[246]\]|\[\-41\d\]", msg, re.I):
                tried.append(cand)
                continue
            raise
    raise FetchError("所有候选 fields 均被拒绝，请检查账号 API 权限或修改 FOFA_FIELDS")


def fetch_region(region, template, extra, exclude_asns, fields, max_rows, page_size,
                 full, delay, timeout, retries, debug=False):
    """按地区翻页抓取，返回归一化前的原始行。"""
    query = build_query(template, region, extra, exclude_asns)
    collected, page = [], 1
    while len(collected) < max_rows:
        want = min(page_size, max_rows - len(collected))
        rows, _ = fofa_search(query, fields, page, want, full, timeout, retries, debug)
        if not rows:
            break
        collected.extend(rows)
        log(f"    [{region or 'ALL'}] 第 {page} 页 +{len(rows)} 条（累计 {len(collected)}）")
        if len(rows) < want:
            break
        page += 1
        if page * page_size > 10000:
            log(f"    [{region or 'ALL'}] 已达 FOFA 单查询 10000 条上限，停止翻页")
            break
        if delay:
            time.sleep(delay)
    return collected


# ==================== IPDB ====================
# 免费公开接口，不需要 key：https://ipdb.api.030101.xyz/
#   bestproxy  已优选的反代 IP（30 分钟刷新，带地区）
#   proxy      全量反代池（10 分钟刷新，700+ 条独立 IP）
#   bestcf     已优选的 Cloudflare 官方 IP
#   cfv4/cfv6  Cloudflare 官方 anycast 网段，返回的是 CIDR 而不是单个 IP
#
# 为什么绝不展开 cfv4/cfv6：
#   实测 cfv4 是 15 个网段、展开后有 1,524,736 个 IPv4；cfv6 有 1.11e30 个地址。
#   而且这些是 Cloudflare 自家 anycast 网段——同一网段在全球几百个机房同时宣告，
#   你连哪个地址、实际落到哪个机房由运营商路由决定，跟 IP 本身几乎无关。
#   同一 /24 内所有地址行为一致，展开扫 152 万个不如每个 /24 取一个代表。
#   本工具找的是「第三方反代服务器」（proxy/bestproxy），不是 CF 官方边缘节点。
IPDB_CIDR_TYPES = {"cfv4", "cfv6"}


def cf_sample_addresses(cidr_text, count, debug=False):
    """从 Cloudflare 官方网段文本里采样 count 个 IPv4 地址。

    先把所有网段拆成 /24，随机挑 count 个**互不相同的 /24**，每个 /24 里随机取一个地址。
    这样 N 个样本就对应 N 条不同的路由路径——比在整个大网段里均匀随机更能覆盖路由差异。
    同一 /24 内的地址对 anycast 来说行为一致，多取纯属浪费。

    这就是「不展开」和「要测官方 IP」之间的折中：cfv4 全展开是 152 万个地址，
    但采样 30 个不同 /24 已经能覆盖绝大多数路由差异。
    """
    nets24 = []
    for line in (cidr_text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if net.version != 4:
            continue
        if net.prefixlen >= 24:
            nets24.append(net)
        else:
            try:
                nets24.extend(net.subnets(new_prefix=24))
            except ValueError:
                continue
    if not nets24:
        return []
    picks = random.sample(nets24, min(count, len(nets24)))
    out = []
    for n in picks:
        if n.num_addresses >= 2:
            out.append(str(n.network_address + random.randint(1, n.num_addresses - 1)))
        else:
            out.append(str(n.network_address))
    if debug:
        log(f"[DEBUG] cf 采样：候选 /24 共 {len(nets24)} 个，取 {len(picks)} 个")
    return out


def http_get_text(url, timeout=30, retries=3, debug=False):
    """极简 GET，返回解码后的文本。

    按块流式读取，中途超时/断流时**保留已经读到的部分**：
    IPDB 的 proxy 大列表在国内直连经常慢到读不完（实测 90s 只收到 428/723 行），
    拿到多少算多少，比整条丢弃有用得多。
    """
    last = None
    for attempt in range(1, max(1, retries) + 1):
        buf = bytearray()
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "cloudflare-sni-proxy-tester/fetch_ips",
                "Accept": "text/plain,*/*",
            })
            with urllib.request.urlopen(req, timeout=timeout) as r:
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    buf.extend(chunk)
        except Exception as e:                       # noqa: BLE001 - 统一重试
            last = e
            if not buf:                              # 一个字都没读到 → 重试/报错
                if attempt < retries:
                    time.sleep(1.5 * attempt)
                    continue
                raise FetchError(f"请求失败 {url}：{e}")
            if debug:                                # 读到一半断了 → 保留部分
                log(f"[DEBUG] {url} 中途中断（{e}），保留已读 {len(buf)} 字节")
        raw = bytes(buf)
        for enc in ("utf-8-sig", "utf-8", "gb18030"):
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                continue
        return raw.decode("utf-8", errors="replace")
    raise FetchError(f"请求失败 {url}：{last}")


def ipdb_fetch(types, use_country, timeout, retries, cf_sample=0, debug=False):
    """从 IPDB 拉取候选 IP，返回 (rows, stats)。

    接口行为：返回纯文本，每行一个条目。
    country=true 只对 bestproxy / bestcf 这类「优选」列表生效，
    对全量 proxy 池无效（实测传了也不带 #CC 后缀）。

    cf_sample > 0 时，对 cfv4 做有界采样（见 cf_sample_addresses），
    而不是傻乎乎地展开上百万个地址。
    """
    stats = {"cidr_skipped": 0, "lines": 0, "cf_sampled": 0}
    rows = []
    for t in types:
        t = str(t).strip()
        if not t:
            continue
        if t in IPDB_CIDR_TYPES:
            if cf_sample <= 0:
                log(f"[!] 跳过 {t}：这是 Cloudflare 官方 anycast 网段（CIDR 列表）。")
                log("    想测官方 IP 就加 -cf-sample 30（建议 10~50），脚本会按不同 /24")
                log("    采样，而不是把上百万个地址全展开。")
                stats["cidr_skipped"] += 1
                continue
            if t == "cfv6":
                log("[!] 跳过 cfv6：ip.py 只支持 IPv4（load_ips 用 IPv4Address 校验），")
                log("    IPv6 候选会被直接丢掉。要测 v6 得先改 ip.py。")
                stats["cidr_skipped"] += 1
                continue
            url = f"{IPDB_API_BASE.rstrip('/')}/?" + urllib.parse.urlencode({"type": t})
            try:
                text = http_get_text(url, timeout, retries, debug)
            except FetchError as e:
                log(f"[!] IPDB {t} 拉取失败，跳过该列表：{e}")
                stats["failed"] = stats.get("failed", 0) + 1
                continue
            addrs = cf_sample_addresses(text, cf_sample, debug)
            stats["cf_sampled"] += len(addrs)
            log(f"    [IPDB {t}] 官方网段采样 {len(addrs)} 个地址（各来自不同 /24）")
            for a in addrs:
                rows.append({"ip": a, "port": "443", "protocol": "https",
                             "country": "", "_rank": 0, "_official": True})
            continue

        params = {"type": t}
        if use_country and t in ("bestproxy", "bestcf"):
            params["country"] = "true"
        url = f"{IPDB_API_BASE.rstrip('/')}/?" + urllib.parse.urlencode(params)
        try:
            text = http_get_text(url, timeout, retries, debug)
        except FetchError as e:
            # 单个列表失败不影响其他列表：proxy 大列表在国内直连经常读不完，
            # 但 bestproxy / cfv4 通常没问题，不能因为一个超时就全盘放弃。
            log(f"[!] IPDB {t} 拉取失败，跳过该列表：{e}")
            stats["failed"] = stats.get("failed", 0) + 1
            continue
        got = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            stats["lines"] += 1
            ip, _, cc = line.partition("#")
            ip = ip.strip()
            if not ip:
                continue
            if "/" in ip:                 # 保险：万一混进网段，直接跳过不展开
                stats["cidr_skipped"] += 1
                continue
            got += 1
            row = {"ip": ip, "port": "443", "protocol": "https",
                   "country": cc.strip().upper()}
            if t == "bestproxy":
                # 优选名单次优先：截断（-max）时不会被随机丢掉
                row["_rank"] = 1
            rows.append(row)
        log(f"    [IPDB {t}] +{got} 条")
    return rows, stats


# ==================== 第三方 IP 列表（GitHub / 自建 txt） ====================
# 社区维护的 CF 反代 IP 列表。实测对比：zip.cm.edu.kg 的 443 条目从联通直连
# 8 个里 7 个可用，而 IPDB 的 bestproxy 池几乎全是死 IP——源的质量差别极大，
# 所以支持多源、方便横向对比很重要。
#
# 注意：这些列表里大量条目在非 443 端口（8443/2053/2083/2087/2096）。
# ip.py 只测 443，所以默认只保留 443 的条目（zip 的 14635 条里仍有 8358 条是 443）。
# 实测 8443 的条目里约 1/4 在 443 上也能用，其余不行——过滤是有损但必要的。
LIST_SOURCES = {
    "zip":      "https://zip.cm.edu.kg/all.txt",
    "luuaiyan": "https://raw.githubusercontent.com/luuaiyan/CloudflareProxyIP/main/CF-ProxyIP.csv",
    "xgonce":   "https://raw.githubusercontent.com/xgonce/Cloudflare_IP/main/result.csv",
    "wwuyi":    "https://raw.githubusercontent.com/Wwuyi123/CF-Proxyip/main/ips/all_ips.txt",
    "wwuyi_c":  "https://raw.githubusercontent.com/Wwuyi123/CF-Proxyip/main/proxyip_with_country.txt",
    "muhaip":   "https://raw.githubusercontent.com/muhaip2/ProxyIP/main/ProxyIP.txt",
}

# 默认用哪个源：填名字（见 LIST_SOURCES）或完整 URL，逗号分隔可组合多个。
LIST_URLS = "zip"

IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def resolve_list_urls(spec):
    """把 'zip,muhaip' 或完整 URL 解析成 URL 列表。"""
    out = []
    for item in as_list(spec):
        out.append(LIST_SOURCES.get(item.lower(), item))
    return out


def parse_plain_list(text):
    """解析第三方列表的各种纯文本格式，返回 rows（与其它源同构）。

    支持：
        IP
        IP:PORT
        IP:PORT#CC                 (zip.cm.edu.kg)
        IP#速度(MB/s)CC国家         (Wwuyi123 proxyip_with_country.txt)
        IP,PORT,CC,ISP             (muhaip2)
    """
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = IPV4_RE.search(line)
        if not m:
            continue
        ip = m.group(0)
        rest = line[m.end():]

        port = "443"
        pm = re.match(r"[:,\s]+(\d{1,5})", rest)
        if pm:
            port = pm.group(1)

        cc = ""
        if "#" in line:
            tail = re.sub(r"\([^)]*\)", "", line.split("#", 1)[1])   # 去掉 (MB/s)
            cm = re.search(r"([A-Za-z]{2})", tail)
            if cm:
                cc = cm.group(1).upper()
        elif pm:                                     # IP,PORT,CC,ISP
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 3 and re.fullmatch(r"[A-Za-z]{2}", parts[2]):
                cc = parts[2].upper()

        rows.append({"ip": ip, "port": port, "protocol": "https",
                     "country": cc if len(cc) == 2 else ""})
    return rows


def list_fetch(urls, timeout, retries, debug=False):
    """从一组第三方列表 URL 抓取候选 IP。CSV 走表头解析，纯文本走行解析。"""
    stats = {"failed": 0, "sources": 0}
    rows = []
    for url in urls:
        try:
            text = http_get_text(url, timeout, retries, debug)
        except FetchError as e:
            log(f"[!] 列表拉取失败，跳过：{url}（{e}）")
            stats["failed"] += 1
            continue
        # 有表头且能识别出 ip 列 → 当 CSV 处理，否则按纯文本处理
        parsed = []
        head = text.lstrip("\ufeff").split("\n", 1)[0] if text.strip() else ""
        if "," in head and not IPV4_RE.search(head):
            try:
                parsed = read_fofa_export_text(text)
            except FetchError:
                parsed = []
        if not parsed:
            parsed = parse_plain_list(text)
        stats["sources"] += 1
        log(f"    [LIST] {url.rsplit('/', 1)[-1]} +{len(parsed)} 条")
        rows.extend(parsed)
    return rows, stats


# ==================== ASN 段扫描（-source asn） ====================
# 思路：反代大量寄生在便宜 VPS 上，所以按「服务商 ASN」定向取段比全网乱扫高效得多。
# 段数据来自 RIPE Stat 的公开 BGP 数据（免费、无 key）：
#   https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS45102
#
# 关键设计：**采样而不是全扫**。阿里云 AS45102 展开是 4.3 万个 /24，
# 全扫既不礼貌也没必要——按 /24 采样 N 个，每个 /24 取一个 IP。
#
# ⚠ 合规提醒：扫描你并不拥有的第三方网段，在很多司法辖区和服务商 ToS 下
#   属于灰色甚至违规行为。本工具只做「TCP 连接 + 一次 TLS 握手 + 一次
#   /cdn-cgi/trace 请求」，是尽可能轻的探测，但仍然请你：
#     1) 优先用已经公开的列表（-source list），不要重复造轮子
#     2) 只在确实需要时小批量扫（-asn-sample 建议 50~200）
#     3) 不要提高并发、不要连续长时间扫同一段
ASN_GROUPS = {
    # ========== 超大规模云（IP 极多，但反代很少跑在贵机器上）==========
    # amazon 一家就占全部候选的 47%（95 万个 /24）。扫它性价比最低，
    # 而且 AWS/Azure/GCP 的滥用检测很激进，容易把 VPS 本身搞进黑名单。
    "amazon":       ["AS16509", "AS14618", "AS8987"],
    "microsoft":    ["AS8075", "AS8068", "AS8069"],
    "google":       ["AS15169", "AS396982"],
    "softbank":     ["AS17676"],
    "kddi":         ["AS2516"],
    "ntt":          ["AS2914"],
    "akamai":       ["AS20940"],
    "softlayer":    ["AS36351"],          # IBM Cloud

    # ========== 中国厂商的【国际】ASN（大陆 ASN 在末尾 _cn 组，默认不扫）==========
    "alibaba":      ["AS45102", "AS24429"],
    "tencent":      ["AS132203", "AS139341"],
    "huawei":       ["AS136907"],
    "ucloud":       ["AS135377", "AS138915"],
    "yunify":       ["AS134366"],

    # ========== 主流 VPS / 云（反代重灾区，性价比最高）==========
    "oracle":       ["AS31898", "AS54253"],
    "vultr":        ["AS20473"],
    "digitalocean": ["AS14061"],
    "linode":       ["AS63949"],
    "hetzner":      ["AS24940", "AS213230"],
    "ovh":          ["AS16276"],
    "contabo":      ["AS51167", "AS40021", "AS141995"],
    "scaleway":     ["AS12876"],
    "upcloud":      ["AS202053", "AS25697"],
    "kamatera":     ["AS44709", "AS41436", "AS25052"],
    "ionos":        ["AS8560", "AS15418"],
    "netcup":       ["AS197540"],
    "leaseweb":     ["AS28753", "AS19148"],
    "gcore":        ["AS199524", "AS202422", "AS48052"],
    "aeza":         ["AS210644", "AS216246"],
    "melbicom":     ["AS56630", "AS8849"],
    "frantech":     ["AS53667"],          # BuyVM
    "hosthatch":    ["AS63473"],
    "sharktech":    ["AS46844"],
    "psychz":       ["AS40676"],
    "multacom":     ["AS35916"],          # CloudCone 等
    "colocrossing": ["AS36352"],          # RackNerd 等
    "zenlayer":     ["AS21859", "AS29752", "AS4229", "AS62610"],
    "worldstream":  ["AS49981"],
    "serverius":    ["AS50673"],
    "hostwinds":    ["AS54290"],
    "interserver":  ["AS19318"],
    "greencloud":   ["AS202602"],
    "bandwagon":    ["AS25820"],          # 搬瓦工 IT7（CN2 GIA）

    # ========== 小众但线路好的（三网优化 / CN2 GIA / 9929）==========
    # 这些厂商规模小、IP 少，但正是「优质线路反代」的高发区，
    # 而且 IP 少意味着扫得快、撞车概率低。
    "dmit":         ["AS54574", "AS906"],       # DMIT（CN2 GIA 顶级）
    "gigsgigs":     ["AS134520"],               # GigsGigsCloud
    "akile":        ["AS61112"],                # Akile
    "evoxt":        ["AS212083", "AS149440"],   # Evoxt
    "bytevirt":     ["AS212336"],               # ByteVirt
    "zgocloud":     ["AS197767"],               # ZgoCloud
    "vmiss":        ["AS400464"],               # VMISS
    "cloudie":      ["AS55933", "AS924"],       # Cloudie
    "kurun":        ["AS8796"],                 # Kurun / Fast Data
    "timeweb":      ["AS9123"],                 # TimeWeb
    "vdsina":       ["AS216071"],               # VDSINA

    # ========== CDN（节点多、线路好，值得一试）==========
    "fastly":       ["AS54113"],
    "bunny":        ["AS200325"],
    "sakura":       ["AS9370", "AS9371"],  # 日本

    # ========== 中国大陆（默认不扫；用户要求排除大陆 IP）==========
    # 这些是大陆机房，做不了境外反代。要扫就显式写进 -asns。
    "alibaba_cn":   ["AS37963", "AS45104"],
    "tencent_cn":   ["AS45090", "AS132591"],
    "huawei_cn":    ["AS55990"],
    "ucloud_cn":    ["AS59077"],
    "yunify_cn":    ["AS59078"],
}

# 便捷档位：不用一个个列厂商名
ASN_PRESETS = {
    # 便宜 VPS 集中营 —— 反代绝大多数在这里，约 22 万个 /24，性价比最高
    "vps": ["alibaba", "tencent", "huawei", "ucloud", "yunify",
            "oracle", "vultr", "digitalocean", "linode", "hetzner", "ovh",
            "contabo", "scaleway", "upcloud", "kamatera", "ionos", "netcup",
            "leaseweb", "gcore", "aeza", "melbicom", "frantech", "hosthatch",
            "sharktech", "psychz", "multacom", "colocrossing", "zenlayer",
            "worldstream", "serverius", "hostwinds", "interserver",
            "greencloud", "bandwagon", "sakura",
            # 小众优质线路厂商
            "dmit", "gigsgigs", "akile", "evoxt", "bytevirt", "zgocloud",
            "vmiss", "cloudie", "kurun", "timeweb", "vdsina"],
    # 除大陆外的全部厂商（含超大规模云）—— 约 204 万个 /24，一轮约 4 小时
    "all": [g for g in ASN_GROUPS if not g.endswith("_cn")],
    # 只要小众优质线路 —— 约 4000 个 /24，几十秒扫完，可以高频刷
    "niche": ["dmit", "gigsgigs", "akile", "evoxt", "bytevirt", "zgocloud",
              "vmiss", "cloudie", "kurun", "timeweb", "vdsina",
              "bandwagon", "greencloud", "zenlayer", "melbicom", "aeza",
              "frantech", "hosthatch", "colocrossing", "multacom"],
}
# 一个 ASN 的 /24 横跨它所有海外区域（AS45102 的 4.3 万个 /24 覆盖美/欧/日/新/港），
# 采样后按地区【排除】——用户要的是「除掉大陆和 CF 官方，其余全要」，
# 所以默认是黑名单模式（排 CN），而不是白名单。
ASN_EXCLUDE_REGIONS = "CN"   # 排除这些地区，逗号分隔；空 = 不排除
ASN_REGIONS = ""             # 只保留这些地区（白名单）；空 = 不启用
GEO_API = "http://ip-api.com/batch"   # 免费、无 key、100 IP/请求、15 请求/分钟
GEO_BATCH = 100
# 地区批量查询上限。免费接口 15 请求/分钟，几万个 IP 要跑几十分钟不现实；
# 超过这个数就跳过预筛（大陆 IP 靠 ASN 层面的 _cn 分组已经排除掉了）。
GEO_MAX = 3000

ASN_API = "https://stat.ripe.net/data/announced-prefixes/data.json"
ASNS = ""                # 例："alibaba,vultr" 或 "AS45102,AS20473"
ASN_SAMPLE = 100         # 采样多少个 /24（每个 /24 一个 IP）
ASN_MAX_SUBNETS = 200000  # 安全阀：单个 ASN 展开超过这个数就只取前 N 个再采样

# ==================== 推送通知（每轮结束推到手机） ====================
# 渠道见 notify.py：bark / pushdeer / ntfy / serverchan / telegram /
#                  wecom / dingtalk / feishu / webhook
NOTIFY_CHANNEL = ""            # 例 "bark"
NOTIFY_TARGET = ""             # 各渠道的 key / webhook 地址
NOTIFY_TIMEOUT = 15
NOTIFY_ONLY_WITH_RESULT = True  # 没有可用 IP 时不推送（免得白刷屏）

# 测哪些端口。CF 支持的 HTTPS 端口是这 6 个：
#   443 / 2053 / 2083 / 2087 / 2096 / 8443
# 只测 443 会丢掉近一半的反代（公开列表里 443 只占 57%，其余都在这些端口上）。
# 留空字符串表示不限制（列表源里是什么端口就测什么）。
PORTS = "443"

# 两套输出的地区白名单。ip.py 用它决定第二套列表写哪些地区；
# fetch_ips.py 用它算出地区版文件名后缀，好在读结果时把地区版 CSV 排除掉
# （不排除的话，地区版是后写的、mtime 更新，会被当成主结果读出来）。
OUTPUT_REGIONS = "HK,JP,SG,KR,TW"
CHUNK_SIZE = 20000
# 逐 ASN 流水线里每个子批的大小。峰值内存 ≈ 这个数 x 250 字节
# （5 万 -> 约 12MB）。调小更省内存，调大吞吐略高。
SUB_BATCH = 50000
# 逐网段处理时，小网段合并到至少这么多候选再一起测。
# 一个 /24 只有 254 个 IP，用 800 并发去跑它并发根本用不满。
# 2000 个候选：800 并发跑 stage0 约 4 秒就出一批结果，
# 配合 on_found 回调，池子能持续被喂新数据。
PREFIX_MIN_BATCH = 2000

# ==================== 全量扫描 ====================
# 每个 /24 是 254 个独立主机（unicast），不是 anycast。
# 抽样 1 个 /24 只能发现 1/254 的反代 —— 实测密度约 0.066%，
# 抽样 18.2 万 IP 只能找到约 120 个反代，全量 4650 万 IP 能找到约 3 万个。
# 代价是每轮约 50 小时（stage0 预筛后），适合 24 小时常驻的 VPS。
FULL_SCAN = False          # true = 每个 /24 的 254 个地址全测
OUTPUT_SPLIT = True

# 扫描线程数与循环间隔也放进配置，这样 Web 面板能直接控制，
# 不用去改 systemd unit 文件。
THREADS = 20
LOOP = 1800

# 进度上报节流用（避免把 status.json 刷爆）
_prog_last = {}

def asn_prefixes(asn, timeout, retries, debug=False):
    """查一个 ASN 宣告的 IPv4 网段，返回 ipaddress 网络对象列表。"""
    asn = str(asn).strip().upper()
    if not asn.startswith("AS"):
        asn = "AS" + asn
    url = f"{ASN_API}?resource={urllib.parse.quote(asn)}"
    text = http_get_text(url, timeout, retries, debug)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise FetchError(f"{asn} 返回的不是 JSON：{e}")
    if data.get("status") != "ok":
        raise FetchError(f"{asn} 查询失败：{data.get('message') or data.get('status')}")
    nets = []
    for item in (data.get("data") or {}).get("prefixes") or []:
        prefix = item.get("prefix") or ""
        if ":" in prefix:            # ip.py 只支持 IPv4
            continue
        try:
            nets.append(ipaddress.ip_network(prefix, strict=False))
        except ValueError:
            continue
    return nets


def asn_fetch(asns, sample, timeout, retries, debug=False):
    """把若干个 ASN 展开成 /24，按 /24 采样 sample 个地址。

    每个 /24 只取一个：同一 /24 内的地址路由行为一致，多取纯属浪费，
    而且会成倍增加对别人网段的探测次数。
    """
    stats = {"asns": 0, "failed": 0, "subnets": 0}
    nets24 = []
    for idx, asn in enumerate(asns, 1):
        set_progress("asn", "抓取 · 查询 ASN 宣告网段", idx, len(asns), current=asn)
        try:
            nets = asn_prefixes(asn, timeout, retries, debug)
        except FetchError as e:
            log(f"[!] {asn} 查询失败，跳过：{e}")
            stats["failed"] += 1
            continue
        before = len(nets24)
        for net in nets:
            if net.prefixlen >= 24:
                nets24.append(net)
            else:
                try:
                    need = ASN_MAX_SUBNETS - len(nets24)
                    if need <= 0:
                        break
                    nets24.extend(itertools.islice(net.subnets(new_prefix=24), need))
                except ValueError:
                    continue
        stats["asns"] += 1
        log(f"    [ASN {asn}] 网段 {len(nets)} 个 -> /24 {len(nets24) - before} 个")

    stats["subnets"] = len(nets24)
    if not nets24:
        return [], stats

    # sample=0 → 全量（不采样）。阿里云国际展开是 4.3 万个 /24，全扫一遍
    # 在这个量级下是可行的（一个 /24 只探 1 个 IP），但要心里有数。
    if sample and sample > 0:
        picks = random.sample(nets24, min(sample, len(nets24)))
    else:
        picks = nets24
        log(f"    [ASN] 全量模式：{len(picks):,} 个 /24 全部探测"
            f"（并发由 -threads 控制，建议 VPS 上开到 100~200）")

    rows = []
    for n in picks:
        if n.num_addresses >= 2:
            addr = str(n.network_address + random.randint(1, n.num_addresses - 1))
        else:
            addr = str(n.network_address)
        rows.append({"ip": addr, "port": "443", "protocol": "https", "country": ""})
    log(f"    [ASN] 从 {len(nets24):,} 个 /24 中取出 {len(rows):,} 个地址")
    return rows, stats


def geo_tag(rows, timeout=30, debug=False):
    """用 ip-api.com 批量接口给 IP 打地区标签（就地写入 country 字段）。

    免费接口限制：100 个 IP/请求、15 请求/分钟，所以每批之间 sleep 一下。
    失败不影响主流程——筛不掉就都留着，交给 ip.py 实测。
    """
    ips = [r for r in rows if r.get("ip")]
    tagged = 0
    for i in range(0, len(ips), GEO_BATCH):
        batch = ips[i:i + GEO_BATCH]
        payload = json.dumps([{"query": r["ip"]} for r in batch]).encode("utf-8")
        try:
            req = urllib.request.Request(
                f"{GEO_API}?fields=query,countryCode,city,as",
                data=payload, headers={"Content-Type": "application/json",
                                       "User-Agent": "cloudflare-sni-proxy-tester/fetch_ips"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as e:                       # noqa: BLE001
            log(f"[!] 地区批量查询失败（这批 {len(batch)} 个将不做筛选）：{e}")
            continue
        by_ip = {d.get("query"): d for d in data if isinstance(d, dict)}
        for r in batch:
            d = by_ip.get(r["ip"])
            if d and d.get("countryCode"):
                r["country"] = str(d["countryCode"]).upper()
                if d.get("city"):
                    r["city"] = str(d["city"])
                tagged += 1
        if i + GEO_BATCH < len(ips):
            time.sleep(4.5)                          # 15 请求/分钟 → 每 4.5s 一批
        set_progress("geo", "抓取 · 地区标注（ip-api）",
                     min(i + GEO_BATCH, len(ips)), len(ips),
                     current=f"{min(i + GEO_BATCH, len(ips))}/{len(ips)} 个地址")
    if debug:
        log(f"[DEBUG] 地区标注成功 {tagged}/{len(ips)}")
    return tagged


def resolve_asns(spec):
    """把 'all' / 'vps' / 'alibaba,tencent' / 'AS45102' 解析成 ASN 列表。

    厂商名会自动展开成该厂商的【全部】ASN —— 只查一个会漏掉一大半网段
    （阿里云只查 AS45102 就漏了 2/3 的 IP 空间）。
    """
    out, seen = [], set()
    for item in as_list(spec):
        key = item.strip().lower()
        if key in ASN_PRESETS:
            group = [a for g in ASN_PRESETS[key] for a in ASN_GROUPS.get(g, [g])]
        elif key in ASN_GROUPS:
            group = ASN_GROUPS[key]
        else:
            a = item.strip().upper()
            group = [a if a.startswith("AS") else "AS" + a]
        for asn in group:
            if asn not in seen:
                seen.add(asn)
                out.append(asn)
    return out


# ==================== 本地过滤 ====================
def _parse_cidrs(s):
    nets = []
    for c in as_list(s):
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            log(f"[!] 无效网段已忽略：{c}")
    return nets


def _load_skip_ips(path):
    """从 ip.txt / csv 里提取已收录的 IP，跳过它们避免重复测速。"""
    if not path or not os.path.exists(path):
        return set()
    found = set()
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line):
                    found.add(m.group(0))
    except OSError:
        return set()
    return found


# ==================== FOFA 网页版导出 CSV 导入 ====================
# 没有 API 权限时，可以在 fofa.info 网页版查询后直接「导出 CSV」，
# 用 -import-csv 把它转成 ip.py 能吃的规范格式（列名/去重/过滤都对齐 API 路径）。
HEADER_ALIASES = {
    "ip": "ip", "主机": "ip", "ip地址": "ip", "地址": "ip",
    "port": "port", "端口": "port",
    "protocol": "protocol", "协议": "protocol",
    "title": "title", "标题": "title",
    "domain": "domain", "域名": "domain",
    "country": "country", "country_name": "country_full", "国家": "country",
    "归属地": "country", "cf归属国": "country", "地区": "country",
    "city": "city", "城市": "city",
    "link": "link", "链接": "link", "链接地址": "link",
    "org": "org", "as_organization": "org", "组织": "org",
    "asn": "asn", "as_number": "asn",
}


def _looks_like_ipv4(s):
    try:
        return ipaddress.ip_address(str(s).strip()).version == 4
    except ValueError:
        return False


def read_fofa_export(path):
    """读 FOFA 网页版导出的 CSV（文件版），返回与 API 路径同构的 rows。"""
    content = None
    for enc in ("utf-8-sig", "utf-8", "gb18030", "gbk"):
        try:
            with open(path, "r", encoding=enc, newline="") as f:
                content = f.read()
            break
        except UnicodeDecodeError:
            continue
        except OSError as e:
            raise FetchError(f"无法读取 {path}: {e}")
    if content is None:
        raise FetchError(f"无法识别 {path} 的编码")
    return read_fofa_export_text(content)


def read_fofa_export_text(content):
    """解析带表头的 CSV 文本（FOFA 导出、第三方 CSV 列表通用）。

    兼容：BOM、# 开头的注释/表头行、完全没有表头、中英文列名，
    以及在列名不是 ip 时按内容识别哪一列装着 IPv4。
    """
    lines = [ln for ln in content.splitlines()
             if ln.strip() and not ln.lstrip().startswith("#")]
    table = [row for row in csv.reader(lines) if any(c.strip() for c in row)]
    if not table:
        return []

    first = [c.strip() for c in table[0]]
    has_header = not any(_looks_like_ipv4(c) for c in first)

    if has_header:
        cols = [HEADER_ALIASES.get(c.strip().lower(), "") for c in first]
        body = table[1:]
    else:
        width = max(len(r) for r in table)
        scores = [sum(1 for r in table[:200] if i < len(r) and _looks_like_ipv4(r[i]))
                  for i in range(width)]
        best = scores.index(max(scores)) if scores and max(scores) else 0
        cols = ["ip" if i == best else "" for i in range(width)]
        body = table

    if "ip" not in cols:
        raise FetchError("这份 CSV 里找不到 IP 列，无法解析")

    rows = []
    for r in body:
        # 先把标准字段填齐：CSV 里没出现的列也要有键，下游才能无脑 .get()/.取用
        d = {"ip": "", "port": "", "protocol": "", "title": "", "domain": "",
             "country": "", "city": "", "link": "", "org": ""}
        for i, name in enumerate(cols):
            if name and i < len(r):
                d[name] = r[i].strip()
        # 两字母国家码优先（ip.py 靠它画国旗），country_name 只作兜底
        if not d.get("country") and d.get("country_full"):
            d["country"] = d["country_full"]
        # 非两字母码（如「荷兰 北荷兰省 阿姆斯特丹」这种中文地名）不能当国家码用，
        # 直接清空——第三阶段 ipinfo 会查到真正的两字母码。
        if not re.fullmatch(r"[A-Za-z]{2}", (d.get("country") or "").strip()):
            d["country"] = ""
        if d.get("ip"):
            rows.append(d)
    return rows


def normalize(rows, require_ports, exclude_nets, skip_ips, exclude_asns=None, limit=0):
    """去重 + 剔除私网/保留地址 + 端口过滤 + 网段/ASN 排除，返回 (kept, stats)。

    require_ports 是允许的端口集合（空集合 = 不限制）。
    limit > 0 时截断到该数量：标记为 _rank 的优先保留，其余随机取样。
    """
    stats = {"total": len(rows), "bad_ip": 0, "not_public": 0, "port": 0,
             "excluded": 0, "asn": 0, "skipped": 0, "dup": 0, "truncated": 0}
    asn_black = {str(a).replace("AS", "").replace("as", "").strip()
                 for a in (exclude_asns or []) if str(a).strip()}
    kept, seen = [], set()
    for r in rows:
        ip = (r.get("ip") or "").strip()
        if not ip:
            continue
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            stats["bad_ip"] += 1
            continue
        if obj.version != 4:            # ip.py 只处理 IPv4
            stats["bad_ip"] += 1
            continue
        if (obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast
                or obj.is_reserved or obj.is_unspecified):
            stats["not_public"] += 1
            continue
        # 端口未知（例如网页版导出没带 port 列）时按 443 处理
        port_val = str(r.get("port", "")).strip() or "443"
        if require_ports and port_val not in require_ports:
            stats["port"] += 1
            continue
        # 本地再兜一层 Cloudflare 自家 ASN 过滤：网页版导出没有 API 查询的 asn!= 条件
        asn = str(r.get("asn", "")).replace("AS", "").replace("as", "").strip()
        if asn and asn in asn_black:
            stats["asn"] += 1
            continue
        if any(obj in n for n in exclude_nets):
            stats["excluded"] += 1
            continue
        if ip in skip_ips:
            stats["skipped"] += 1
            continue
        # 去重键是 ip:port —— 同一个 IP 的不同端口是两个不同的反代入口，
        # 只按 IP 去重会把 8443 上的可用反代当成 443 的重复项丢掉
        dedup_key = f"{ip}:{port_val}"
        if dedup_key in seen:
            stats["dup"] += 1
            continue
        seen.add(dedup_key)

        port = port_val
        row = {
            "ip": ip,
            "port": port,
            "protocol": (r.get("protocol") or "https").strip(),
            "title": (r.get("title") or "").strip(),
            "domain": (r.get("domain") or "").strip(),
            "country": (r.get("country") or "").strip().upper(),
            "city": (r.get("city") or "").strip(),
            "link": (r.get("link") or "").strip(),
            "org": (r.get("org") or "").strip(),
        }
        if not row["link"]:             # FOFA 未返回 link 时本地合成，保持列结构一致
            row["link"] = f"https://{ip}" + ("" if port == "443" else f":{port}")
        if "_rank" in r:
            row["_rank"] = r["_rank"]
        kept.append(row)

    # -max 截断：按 _rank 分层
    #   rank 0 = Cloudflare 官方 IP 采样（用户显式指定的，数量有界，必须保住）
    #   rank 1 = bestproxy 优选反代
    #   rank 2 = 全量反代池（随机取样，多轮下来覆盖整个池子）
    if limit and len(kept) > limit:
        head = sorted([r for r in kept if r.get("_rank", 2) < 2],
                      key=lambda x: x["_rank"])
        tail = [r for r in kept if r.get("_rank", 2) >= 2]
        random.shuffle(tail)
        chosen = (head + tail)[:limit]
        stats["truncated"] = len(kept) - len(chosen)
        kept = chosen
    for r in kept:
        r.pop("_rank", None)
    return kept, stats


CSV_HEADER = ["ip", "port", "protocol", "title", "domain", "country", "city", "link", "org"]


def open_csv_writer(path):
    """打开一个增量写 CSV 的 writer（调用方负责 close）。"""
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    f = open(path, "w", encoding="utf-8-sig", newline="")
    w = csv.DictWriter(f, fieldnames=CSV_HEADER)
    w.writeheader()
    return f, w


def merge_stats(dst, src):
    """把一批的统计累加进总统计。"""
    for k, v in (src or {}).items():
        if isinstance(v, int):
            dst[k] = dst.get(k, 0) + v
    return dst


def write_csv(path, rows):
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_HEADER)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in CSV_HEADER})


# ==================== 与 ip.py 的衔接 ====================
def detect_proxy():
    """检测会让 curl 真正走代理的环境变量。

    **故意不检查 Windows 注册表里的 WinINET 系统代理**：curl.exe 不读注册表，
    只认 http_proxy / https_proxy / all_proxy 环境变量。注册表里的 ProxyEnable
    只影响浏览器和用 WinINET 的程序。实测过：注册表 ProxyEnable=1、但 TUN 已关时，
    ip.py 的 curl 依然是直连的（28/40 通过、colo 分布正常）。
    把注册表代理当告警会制造假警报，所以单独放在 detect_sysproxy() 里只做提示。
    """
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
              "ALL_PROXY", "all_proxy"):
        v = os.environ.get(k)
        if v:
            return f"环境变量 {k}={v}"
    return None


def detect_sysproxy():
    """Windows 注册表里的系统代理（只影响浏览器，不影响 curl，仅作提示）。"""
    if os.name != "nt":
        return None
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        ) as key:
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            if not enabled:
                return None
            try:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
            except OSError:
                server = "(未读取到地址)"
            return f"{server}"
    except OSError:
        return None


def detect_route_hijack():
    """检测默认路由是否被 TUN / fake-IP 接管。

    Clash 的 TUN 模式会把 0.0.0.0/0 指向虚拟网卡，NextHop 落在 fake-IP 保留段
    (198.18.0.0/15)。此时 ping / tracert / curl 全被劫持在**网络层**，
    `curl --noproxy` 也绕不过去——只关掉「系统代理」开关是没用的，必须退出整个程序。

    实测症状：任何国家的反代 IP 都返回 colo=HKG、延迟被拉平到 45ms 左右，
    tracert 只剩 1 跳（目标自己就是第一跳），第三阶段线路分析全部 Unknown。
    """
    if os.name != "nt":
        return None
    ps = ("Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
          "ForEach-Object { $_.NextHop + '|' + $_.InterfaceAlias }")
    try:
        p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
        text = (p.stdout or b"").decode("utf-8", errors="replace")
    except Exception:
        return None

    fake = ipaddress.ip_network("198.18.0.0/15")     # Clash fake-IP 保留段
    for line in text.splitlines():
        line = line.strip()
        if "|" not in line:
            continue
        hop, _, alias = line.partition("|")
        hop, alias = hop.strip(), alias.strip()
        try:
            if ipaddress.ip_address(hop) in fake:
                return f"默认路由被 fake-IP 接管：{hop}（{alias}）"
        except ValueError:
            pass
        if alias and re.search(r"tunnel|meta|clash|tap|wireguard|sing-box|utun", alias, re.I):
            return f"默认路由走隧道网卡：{alias}"
    return None


def detect_tun():
    """检测活动中的隧道类虚拟网卡（Clash TUN / WireGuard / TAP 等）。

    这类网卡会把 ping 和 tracert 一起接管，比系统代理更隐蔽，
    必须和代理一起关掉，否则第三阶段的线路分析全是隧道内的假数据。
    """
    if os.name != "nt":
        return []
    ps = ("Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and "
          "$_.InterfaceDescription -match 'Tunnel|Meta|TAP|WireGuard|sing-box'} | "
          "Select-Object -ExpandProperty Name")
    try:
        p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=20)
        text = (p.stdout or b"").decode("utf-8", errors="replace")
        return [ln.strip() for ln in text.splitlines() if ln.strip()]
    except Exception:
        return []


def env_report():
    """给 run.bat 用的极简环境报告，格式固定为 KEY=VALUE。"""
    return [f"PROXY={detect_proxy() or ''}",
            f"TUN={','.join(detect_tun())}",
            f"ROUTE={detect_route_hijack() or ''}"]


def run_tester(csv_path, extra_args):
    """调用 ip.py 实测。返回 (退出码, 可用数, 优质数)。

    顺便把 ip.py 的输出逐行透传（保持实时可见），并从里面抠出
    「第一阶段完成：N/M」「第二阶段完成：N/M」这两个数字，给推送用。
    """
    proxy = detect_proxy()          # 环境变量代理：curl 真的会走
    sysproxy = detect_sysproxy()    # 注册表代理：curl 不读，仅提示
    tuns = detect_tun()
    hijack = detect_route_hijack()
    if proxy or hijack or (tuns and not sysproxy):
        log("")
        log("!" * 68)
        if hijack:
            log(f"[!] {hijack}")
            log("[!] 这是 TUN 模式的 fake-IP 劫持，发生在网络层，")
            log("[!] curl --noproxy 绕不过去，只关「系统代理」开关也没用。")
        if proxy:
            log(f"[!] 检测到代理环境变量：{proxy}（curl 会走它）")
        if tuns and not sysproxy:
            log(f"[!] 检测到隧道网卡：{', '.join(tuns)}")
        log("[!] 此时 ping / tracert / curl 会走代理，任何国家的 IP 都可能被")
        log("[!] 拉平成同一个结果，无法区分优劣。请完全退出代理工具再重跑。")
        log("!" * 68)
    elif sysproxy:
        log(f"[*] 提示：注册表里系统代理仍是开着的（{sysproxy}），"
            f"但 curl 不读注册表、路由也没被劫持，本次测量是直连的。")

    extra_args = list(extra_args)
    # 上游只做「发现」：确认是不是真反代就够了，不做质量筛选。
    # VPS 在海外，它测出来的延迟/速度对国内家用网络没有参考价值，
    # 质量排序是下游（家里 NAS）的活。用 -stage1 只交回真反代。
    if UPSTREAM_STAGE1_ONLY and "-stage1" not in extra_args:
        extra_args = ["-stage1", "-o", STAGE1_CSV] + extra_args
        log("[*] 上游模式：只做 stage1（可用性），不做质量筛选")
    cmd = [sys.executable, os.path.join(HERE, "ip.py"), "-i", csv_path] + extra_args
    log(f"\n[*] 调用测试脚本：{' '.join(cmd)}\n")

    avail = qual = None
    try:
        p = subprocess.Popen(cmd, cwd=HERE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True,
                             encoding="utf-8", errors="replace", bufsize=1)
    except OSError as e:
        log(f"[!] 调用 ip.py 失败：{e}")
        return 1, None, None

    for line in p.stdout:
        line = line.rstrip("\n")
        print(line, flush=True)
        m = re.search(r"第一阶段完成：(\d+)/(\d+)", line)
        if m:
            avail = (int(m.group(1)), int(m.group(2)))
        m = re.search(r"第二阶段完成：(\d+)/(\d+)", line)
        if m:
            qual = (int(m.group(1)), int(m.group(2)))

        # ---- 实时上报进度给 Web 面板 ----
        # 形如：12:34:56 [availability 150/300] 1.2.3.4 | PASS ...
        m = re.search(r"\[(\w+) (\d+)/(\d+)\]\s+(\S+)", line)
        if m:
            stage, done, total = m.group(1), int(m.group(2)), int(m.group(3))
            cur = m.group(4)
            now = time.time()
            # 节流：每 3 秒或最后一条才写一次，别把磁盘刷爆
            if done == total or now - _prog_last.get("t", 0) > 3:
                _prog_last["t"] = now
                keys = {"availability": ("s1", "第一阶段 · 可用性检查"),
                        "speed/latency": ("s2", "第二阶段 · 延迟与测速"),
                        "traceroute": ("s3", "第三阶段 · 线路分析")}
                k, nm = keys.get(stage, (stage, stage))
                # 当前 IP 可能是 "1.2.3.4" 或 "1.2.3.4:8443"
                cur_ip = cur.split(":")[0]
                set_progress(k, nm, done, total, ip=cur_ip,
                             extra={"last_line": line[:160],
                                    "port": cur.split(":")[1] if ":" in cur else "443"})
        elif line.startswith("[*]") or "阶段" in line:
            write_status(last_line=line[:160])
    p.wait()
    return p.returncode, avail, qual


def send_notification(round_no, avail, qual, loop_secs=0):
    """一轮结束后推送结果到手机。没配置渠道就静默跳过。"""
    ch = (NOTIFY_CHANNEL or "").strip()
    tgt = (NOTIFY_TARGET or "").strip()
    if not ch or not tgt:
        return
    try:
        import notify as _n
        _n.NOTIFY_CHANNEL = ch
        _n.NOTIFY_TARGET = tgt
        _n.NOTIFY_TIMEOUT = NOTIFY_TIMEOUT

        summary = read_final_summary(limit=200)
        rows = summary.get("rows") or []
        if NOTIFY_ONLY_WITH_RESULT and not rows:
            log("[*] 本轮没有可用 IP，按配置跳过推送")
            return

        n_avail = avail[0] if avail else None
        n_total = avail[1] if avail else None
        n_qual = qual[0] if qual else len(rows)

        head = f"第 {round_no} 轮完成" if round_no else "扫描完成"
        lines = [head + f" · {datetime.now():%m-%d %H:%M}"]
        if n_total is not None:
            lines.append(f"候选 {n_total} → 反代可用 {n_avail} → 优质 {n_qual}")
        else:
            lines.append(f"优质 {n_qual}")
        lines.append("")

        body = _n.build_summary(
            round_no=None, available=n_avail, quality=n_qual, rows=rows)
        text = "\n".join(lines) + body

        ok, msg = _n.send(f"CF 反代 IP · {head}", text)
        log(f"[*] 推送{'成功' if ok else '失败'}（{ch}）：{msg}")
    except Exception as e:                       # noqa: BLE001
        log(f"[!] 推送出错（不影响扫描）：{e}")


# ==================== 磁盘占用控制（1GB 小硬盘 VPS 必需） ====================
# 日志是最大的增长点：全量扫描一轮能写上百 MB（20 万候选 × 每行 70 字节）。
# 策略：日志只留最新 N 个、结果只留最新 N 份、超过 KEEP_DAYS 天的日期目录整个删。
KEEP_LOGS = 5          # 保留最新的几个日志文件
KEEP_RESULTS = 20      # 保留最新的几份 bestips-*.csv
KEEP_DAYS = 7          # 超过这么多天的 output/{date} 目录整个删掉
MIN_FREE_MB = 300      # 可用空间低于这个值就激进清理


def _free_mb(path):
    try:
        return shutil.disk_usage(path).free / 1024 / 1024
    except Exception:                            # noqa: BLE001
        return None


def _dir_size(path):
    total = 0
    for dirpath, _d, files in os.walk(path):
        for fn in files:
            try:
                total += os.path.getsize(os.path.join(dirpath, fn))
            except OSError:
                pass
    return total


def cleanup_outputs(aggressive=False):
    """清理日志和旧结果，返回一份清理报告。

    顺序很重要：**先删旧日期目录，再轮转文件**。
    反过来的话，删目录里的文件会更新目录 mtime，等到判断"目录是否过期"时
    它就变成"刚刚修改过"了，永远删不掉（这个坑实测踩过）。
    而且判断过期优先用目录名里的日期（output/{YYYY-MM-DD}），比 mtime 可靠得多。
    """
    outdir = os.path.join(HERE, "output")
    if not os.path.isdir(outdir):
        return {"freed_mb": 0.0, "logs": 0, "results": 0, "free_mb": _free_mb(HERE)}

    freed = 0
    keep_days = 1 if aggressive else KEEP_DAYS

    # ---- 第一步：删过期的日期目录（趁里面的文件还没被删、mtime 还没被动过）----
    cutoff = time.time() - keep_days * 86400
    try:
        entries = os.listdir(outdir)
    except OSError:
        entries = []
    for name in entries:
        p = os.path.join(outdir, name)
        if not os.path.isdir(p):
            continue
        old = False
        try:                                     # 优先按目录名解析日期
            d = datetime.strptime(name, "%Y-%m-%d")
            old = d.timestamp() < cutoff
        except ValueError:
            try:                                 # 名字不是日期就退回 mtime
                old = os.path.getmtime(p) < cutoff
            except OSError:
                continue
        if old:
            freed += _dir_size(p)
            shutil.rmtree(p, ignore_errors=True)

    # ---- 第二步：轮转日志和结果文件 ----
    keep_logs = 1 if aggressive else KEEP_LOGS
    keep_res = 3 if aggressive else KEEP_RESULTS
    logs, results = [], []

    for dirpath, _d, files in os.walk(outdir):
        for fn in files:
            p = os.path.join(dirpath, fn)
            try:
                mt, sz = os.path.getmtime(p), os.path.getsize(p)
            except OSError:
                continue
            if fn.endswith(".log"):
                logs.append((mt, sz, p))
            elif fn.startswith("bestips") and fn.endswith(".csv"):
                results.append((mt, sz, p))
            elif fn.endswith(".tmp"):
                try:                             # 残留临时文件直接删
                    os.remove(p)
                    freed += sz
                except OSError:
                    pass

    for lst, keep in ((logs, keep_logs), (results, keep_res)):
        lst.sort(reverse=True)
        for _mt, sz, p in lst[keep:]:
            try:
                os.remove(p)
                freed += sz
            except OSError:
                pass

    return {"freed_mb": round(freed / 1024 / 1024, 2),
            "logs": len(logs), "results": len(results),
            "free_mb": round(_free_mb(HERE) or 0, 1)}


def disk_guard():
    """每轮开跑前看一眼磁盘，低于阈值就先激进清理并告警。"""
    free = _free_mb(HERE)
    if free is None:
        return None
    if free < MIN_FREE_MB:
        log("")
        log(f"[!] 可用空间只剩 {free:.0f} MB（阈值 {MIN_FREE_MB} MB），先清理 ...")
        st = cleanup_outputs(aggressive=True)
        log(f"[*] 清理完成：释放 {st['freed_mb']} MB，现在可用 {st['free_mb']} MB")
        free = st["free_mb"]
        if free < MIN_FREE_MB / 3:
            log("[!] 空间依然紧张，建议：")
            log("    - 调小 -asn-sample（每轮候选少，日志就少）")
            log("    - 确认 ip.py 带了 -quiet（逐条进度日志是磁盘杀手）")
            log("    - 调小 config.ini 的 LOG_MAX_BYTES")
    return free


def read_status():
    """读当前 status.json。"""
    path = os.path.join(HERE, "output", "status.json")
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            return json.load(f) or {}
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}


def cidr24(ip):
    """/24 网段，界面上用来显示「当前扫到哪个段」。"""
    p = str(ip or "").split(".")
    return ".".join(p[:3]) + ".0/24" if len(p) == 4 else ""


def set_progress(key, name, done=None, total=None, current="", ip="", cidr="", extra=None):
    """上报某一层的进度给 Web 面板。

    status.json 里维护一个 progress 字典，每层一个 key：
      asn   抓取 · 查询 ASN 网段     current = 当前 ASN
      geo   抓取 · 地区标注
      s1    第一阶段 · 可用性        ip = 当前 IP，cidr = 当前 /24
      s2    第二阶段 · 延迟与测速
      s3    第三阶段 · 线路分析
    面板上就能并排显示多条进度条。
    """
    st = read_status()
    prog = st.get("progress") or {}
    d = {"name": name}
    if done is not None:
        d["done"] = done
    if total is not None:
        d["total"] = total
    if done is not None and total:
        d["pct"] = round(done * 100.0 / total, 1)
    if current:
        d["current"] = current
    if ip:
        d["ip"] = ip
        d["cidr"] = cidr or cidr24(ip)
    elif cidr:
        d["cidr"] = cidr
    if extra:
        d.update(extra)
    prog[key] = d
    write_status(progress=prog, phase="running")


def clear_progress(*keys):
    """清掉指定层的进度（阶段切换、开新一轮时用）。"""
    st = read_status()
    prog = st.get("progress") or {}
    for k in keys:
        prog.pop(k, None)
    write_status(progress=prog)


# ==================== 累积 IP 池 ====================
# 为什么需要池子而不是每轮覆盖：
#   这个系统的分工是「上游慢而全地发现、下游快而准地挑」。
#   上游 5~7 天才跑一轮，如果每轮覆盖输出，那么某一轮赶上网络抖动、
#   被限流、或者只跑了一部分就重启，池子就会【缩水】——
#   下游拿到的反而比上一轮少，DNS 里会出现空窗。
#
#   正确做法：每轮的结果【并进】池子，记录 last_seen，
#   只有连续 N 天没再被确认可用的才淘汰。这样池子只会越来越大、
#   越来越准，单轮波动不影响下游。
POOL_ENABLED = True
POOL_FILE = "./output/pool.csv"
POOL_MAX_AGE_DAYS = 30      # 超过这么多天没再出现的条目才淘汰

# 替换模式下的安全阀：新结果不到旧池子的这个比例时，改成并集而不是替换。
# 理由：全量扫描正常情况下每轮结果量级稳定，如果某轮突然只剩几个，
# 更可能是【瞬时故障】（网络抖动、上游限流、部分 ASN 查询失败），
# 而不是「反代真的都死了」。这时替换会把几千个可用 IP 一次清空。
# 0 = 关闭这个保护（严格按用户要求「扫完即替换」）。
POOL_MIN_KEEP_RATIO = 0.1

# 上游只保留 stage1 的结果。
#   stage1 通过 = 它【确实是】反代（客观事实，跟测量点无关）
#   stage2 通过 = 它【在这台 VPS 上】快、不丢包（主观，跟测量点强相关）
# 上游 VPS 在海外机房，测出来的延迟/速度对国内家用网络没有参考价值，
# 质量排序是下游（家里 NAS）的活。所以上游池子里只放"所有真反代"。
UPSTREAM_STAGE1_ONLY = True

# 池子更新方式：
#   auto    全量扫完 -> 替换；中途中断 -> 并集（见下）
#   replace 永远替换
#   merge   永远并集
# 为什么中断时要并集：全量扫描时「没出现 = 测了且失败」，可以做差集；
# 但只扫了一部分时「没出现」可能只是没扫到，做差集会误杀。
# 这时只能把新发现的并进去，不能删旧的。
POOL_MODE = "auto"

# 上游 stage1 的结果落这里，然后被读进池子
STAGE1_CSV = "./output/stage1.csv"

POOL_HEADER = ["ip", "port", "first_seen", "last_seen", "seen_count",
               "latency", "loss", "speed", "score",
               "cfcountry", "country", "city", "route", "colo"]


def _pool_path():
    return POOL_FILE if os.path.isabs(POOL_FILE) else os.path.join(HERE, POOL_FILE)


def load_pool():
    """读池子。返回 {('ip','port'): row}。"""
    path = _pool_path()
    out = {}
    if not os.path.exists(path):
        return out
    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                ip = (row.get("ip") or "").strip()
                port = (row.get("port") or "443").strip() or "443"
                if ip:
                    out[(ip, port)] = row
    except (OSError, csv.Error):
        pass
    return out


def _fnum(v):
    try:
        return float(str(v).replace("ms", "").replace("%", "").replace("MB/s", "").strip())
    except (TypeError, ValueError):
        return None


def update_pool(rows, complete=True):
    """用这一轮的结果更新池子。返回 (池子总数, 新增, 更新, 删除)。

    complete=True（整轮扫完了）：
        全量扫描下每个 IP 都测过，「没出现在结果里」= 测了且失败 = 确定死亡。
        所以直接【替换】—— 旧池子里没被这轮确认的全部丢掉。
        这正是用户要的语义：第二轮扫的时候已经不能用了，留着没意义。
    complete=False（中途崩了/被重启）：
        只扫了一部分，「没出现」可能只是没扫到，做差集会误杀。
        这时只能把新发现的【并】进去，不能删旧的。
    """
    if not POOL_ENABLED:
        return 0, 0, 0, 0

    mode = POOL_MODE
    if mode == "auto":
        mode = "replace" if complete else "merge"

    # 安全阀：新结果比旧池子小太多时，怀疑是瞬时故障，改成并集
    old_n = len(load_pool()) if mode == "replace" else 0
    n_new = len([r for r in (rows or []) if (r.get("ip") or "").strip()])
    if (mode == "replace" and POOL_MIN_KEEP_RATIO > 0 and old_n >= 20
            and n_new < old_n * POOL_MIN_KEEP_RATIO):
        log(f"[!] 本轮只找到 {n_new} 个，而池子里原有 {old_n} 个"
            f"（不足 {POOL_MIN_KEEP_RATIO*100:.0f}%）。")
        log("    更可能是瞬时故障而不是反代真的都死了，本轮改成【并集】以免清空池子。")
        log("    确认要严格替换的话，把 config.ini 的 POOL_MIN_KEEP_RATIO 设成 0。")
        mode = "merge"

    old_pool = load_pool()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    new_pool = {}
    added = updated = 0

    for r in rows or []:
        ip = (r.get("ip") or "").strip()
        if not ip:
            continue
        port = str(r.get("port") or "443").strip() or "443"
        key = (ip, port)
        prev = old_pool.get(key)
        if prev:
            updated += 1
            first = prev.get("first_seen") or now
            seen = int(prev.get("seen_count") or 1) + 1
        else:
            added += 1
            first = now
            seen = 1
        new_pool[key] = {
            "ip": ip, "port": port,
            "first_seen": first, "last_seen": now, "seen_count": str(seen),
            "cfcountry": str(r.get("cfcountry") or (prev or {}).get("cfcountry") or ""),
            "colo": str(r.get("colo") or (prev or {}).get("colo") or ""),
            "country": str(r.get("country") or (prev or {}).get("country") or ""),
            "city": str(r.get("city") or (prev or {}).get("city") or ""),
            "latency": str(r.get("latency") or ""),
            "loss": str(r.get("loss") or ""),
            "speed": str(r.get("speed") or ""),
            "score": str(r.get("score") or ""),
            "route": str(r.get("route") or ""),
        }

    # merge 模式：旧池子里这轮没确认的也保留
    dropped = 0
    if mode == "merge":
        for key, row in old_pool.items():
            if key not in new_pool:
                new_pool[key] = row
    else:
        dropped = len(old_pool) - updated

    # 过期淘汰（两种模式都做，防止池子无限膨胀）
    if POOL_MAX_AGE_DAYS:
        cutoff = datetime.now() - timedelta(days=POOL_MAX_AGE_DAYS)
        for key in list(new_pool.keys()):
            ls = (new_pool[key].get("last_seen") or "").strip()
            try:
                if datetime.strptime(ls, "%Y-%m-%d %H:%M:%S") < cutoff:
                    del new_pool[key]
                    dropped += 1
            except ValueError:
                pass

    _write_pool(new_pool)
    log(f"[*] 池子更新（{mode}）：共 {len(new_pool)} 个"
        f"（新增 {added}，确认 {updated}，移除 {dropped}）")
    return len(new_pool), added, updated, dropped


def _write_pool(pool):
    """原子写池子（临时文件 + os.replace），中途崩了不会写坏。"""
    path = _pool_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=POOL_HEADER, extrasaction="ignore")
            w.writeheader()
            for row in pool.values():
                w.writerow(row)
        os.replace(tmp, path)
    except OSError as e:
        log(f"[!] 写池子失败：{e}")


# 兼容旧名字
def merge_pool(rows, prune=True):
    return update_pool(rows, complete=False)


def pool_summary():
    """池子概览：总数、按地区分布、按新鲜度分布。给面板和推送用。"""
    pool = load_pool()
    if not pool:
        return {"total": 0}
    now = datetime.now()
    dist, fresh = {}, {"今天": 0, "3天内": 0, "7天内": 0, "更早": 0}
    for row in pool.values():
        cc = (row.get("country") or "??").upper()
        dist[cc] = dist.get(cc, 0) + 1
        try:
            age = (now - datetime.strptime(row.get("last_seen") or "",
                                           "%Y-%m-%d %H:%M:%S")).days
        except ValueError:
            age = 999
        if age <= 0:
            fresh["今天"] += 1
        elif age <= 3:
            fresh["3天内"] += 1
        elif age <= 7:
            fresh["7天内"] += 1
        else:
            fresh["更早"] += 1
    return {"total": len(pool), "by_country": dist, "by_freshness": fresh}


# ==================== 每日请求额度守卫 ====================
# 每次可用性检查 = 1 个请求打到 AVAILABILITY_HOST（你自己的域名），
# 每次测速 = 1 个请求。如果那个域名有每日额度（比如 Cloudflare Worker
# 免费版 10 万次/天），跑爆了会导致后续所有检查失败。
# 这里按天计数，额度不够就跳过本轮并告警，而不是把额度烧光。
DAILY_REQUEST_LIMIT = 0        # 每天请求上限，0 = 不限制
REQUEST_COUNT_FILE = "./output/request_count.json"
# 每轮请求数估算系数：候选数 × 这个值（1 = 只算可用性检查，
# 1.5 ≈ 再加上约 50% 通过第一阶段后的测速请求）
REQUEST_EST_FACTOR = 1.5


def _today():
    return datetime.now().strftime("%Y-%m-%d")


def load_request_count():
    """读今天的请求计数；跨天自动归零。"""
    path = REQUEST_COUNT_FILE if os.path.isabs(REQUEST_COUNT_FILE) \
        else os.path.join(HERE, REQUEST_COUNT_FILE)
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            d = json.load(f) or {}
    except (OSError, json.JSONDecodeError):
        d = {}
    if d.get("date") != _today():
        return {"date": _today(), "used": 0}
    return {"date": d.get("date"), "used": int(d.get("used") or 0)}


def add_request_count(n):
    """给今天的计数加上 n 个请求。"""
    path = REQUEST_COUNT_FILE if os.path.isabs(REQUEST_COUNT_FILE) \
        else os.path.join(HERE, REQUEST_COUNT_FILE)
    cur = load_request_count()
    cur["used"] = int(cur.get("used") or 0) + max(0, int(n))
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cur, f, ensure_ascii=False)
        os.replace(tmp, path)
    except OSError:
        pass
    return cur["used"]


def budget_check(planned):
    """额度够不够跑这一轮？返回 (是否放行, 已用, 上限, 剩余)。"""
    if not DAILY_REQUEST_LIMIT:
        return True, 0, 0, -1
    cur = load_request_count()
    used = cur["used"]
    remaining = DAILY_REQUEST_LIMIT - used
    return (used + planned <= DAILY_REQUEST_LIMIT), used, DAILY_REQUEST_LIMIT, remaining


# ==================== 状态文件（给 Web UI 读） ====================
STATUS_FILE = "./output/status.json"


def write_status(**kw):
    """把当前状态写进 output/status.json，供 webui.py 展示。

    用「读-改-写 + 原子替换」，不依赖进程内共享状态，
    所以 Web UI 和扫描进程可以完全解耦（甚至分开重启）。
    """
    try:
        path = STATUS_FILE if os.path.isabs(STATUS_FILE) else os.path.join(HERE, STATUS_FILE)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        cur = {}
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    cur = json.load(f) or {}
            except (OSError, json.JSONDecodeError):
                cur = {}
        cur.update(kw)
        cur["pid"] = os.getpid()
        cur["updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur["updated_ts"] = time.time()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cur, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except OSError:
        pass


def read_stage1_results(path=None):
    """读上游 stage1 的结果文件（ip.py -stage1 写的）。

    格式：ip, port, protocol, cfcountry, colo
    这些就是「所有确认是真反代的 IP」—— 上游池子的内容。
    """
    if path is None:
        path = STAGE1_CSV if os.path.isabs(STAGE1_CSV) else os.path.join(HERE, STAGE1_CSV)
    out = []
    if not os.path.exists(path):
        return out
    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                ip = (row.get("ip") or "").strip()
                if not ip:
                    continue
                out.append({
                    "ip": ip,
                    "port": str(row.get("port") or "443").strip() or "443",
                    "cfcountry": (row.get("cfcountry") or "").strip().upper(),
                    "colo": (row.get("colo") or "").strip().upper(),
                })
    except (OSError, csv.Error) as e:
        log(f"[!] 读 stage1 结果失败：{e}")
    return out


def read_pool_rows(limit=500, region=None, max_age_days=None):
    """从池子里读结果，按分数排序。给 Web 面板和 API 用。

    region: 只要这些地区（大写集合），None = 不限
    max_age_days: 只要最近这么多天出现过的
    """
    pool = load_pool()
    if not pool:
        return []
    cutoff = None
    if max_age_days:
        cutoff = datetime.now() - timedelta(days=max_age_days)
    rows = []
    for row in pool.values():
        cc = (row.get("country") or "").upper()
        if region and cc not in region:
            continue
        if cutoff is not None:
            try:
                if datetime.strptime(row.get("last_seen") or "",
                                     "%Y-%m-%d %H:%M:%S") < cutoff:
                    continue
            except ValueError:
                continue
        rows.append(row)
    # 按 score 升序（score = 延迟 x 丢包惩罚，越小越好），没有 score 的排后面
    rows.sort(key=lambda r: (_fnum(r.get("score")) is None,
                             _fnum(r.get("score")) or 99999))
    return rows[:limit]


def read_final_summary(limit=200):
    """读最近的优选结果（ip.txt + 最新一份 bestips csv），给 Web UI 展示。"""
    out = {"ip_txt": [], "ip_txt_file": "", "csv_file": "", "rows": []}
    outdir = os.path.join(HERE, "output")

    # ip.txt：Windows 上在项目根目录，容器里被 sed 改到了 output/{date}/ 下
    cands = [os.path.join(HERE, "ip.txt")]
    if os.path.isdir(outdir):
        for d in sorted(os.listdir(outdir), reverse=True):
            p = os.path.join(outdir, d)
            if os.path.isdir(p):
                cands.append(os.path.join(p, "ip.txt"))
    for p in cands:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8-sig") as f:
                    out["ip_txt"] = [ln.strip() for ln in f if ln.strip()][:limit]
                out["ip_txt_file"] = p
                break
            except OSError:
                pass

    # 最新的 bestips-*.csv（**主 CSV**）
    # 注意要排除地区版 bestips-*-<tag>.csv —— 它是后写的、mtime 更新，
    # 不排除的话会被当成主结果读出来，导致「全量」列表只剩地区那几个。
    region_tag = "".join(sorted(
        x.strip().upper() for x in re.split(r"[,;\s]+", OUTPUT_REGIONS) if x.strip()
    )).lower()
    newest, newest_mtime = None, 0.0
    for root in (outdir, HERE):
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                if not (fn.startswith("bestips") and fn.endswith(".csv")):
                    continue
                if region_tag and fn.endswith(f"-{region_tag}.csv"):
                    continue                     # 地区版，跳过
                p = os.path.join(dirpath, fn)
                try:
                    mt = os.path.getmtime(p)
                except OSError:
                    continue
                if mt > newest_mtime:
                    newest, newest_mtime = p, mt
    if newest:
        out["csv_file"] = newest
        try:
            with open(newest, "r", encoding="utf-8-sig", newline="") as f:
                out["rows"] = list(csv.DictReader(f))[:limit]
        except (OSError, csv.Error):
            pass
    return out


# ==================== 逐网段生成器 ====================
# 用户要的是「层层展开」的进度：厂商 -> ASN -> 网段 -> IP。
# 原来的 iter_asn_batches 是按 SUB_BATCH 切块的，切点跟网段边界无关，
# 所以报不出「当前在查哪个网段」。
#
# 这个生成器按【网段】切：每个网段单独一批 yield，
# 调用方就能报出「第几个网段 / 共几个」「这个网段下测了多少 IP」。
# 一个网段通常含 1~256 个 /24（实测 AS45102 平均 108 个），
# 全量展开是 250~65000 个 IP，作为一批大小合适。


def count_24s(nets):
    """数一段网段里有多少个 /24。O(网段数)，不展开。

    /20 算 16 个，/25 及更小的算 1 个（它们本身就在同一个 /24 里）。
    """
    total = 0
    for n in nets:
        pl = n.prefixlen
        total += (1 << (24 - pl)) if pl <= 24 else 1
    return total

def sample_24s(nets, k, weights=None, total=None):
    """从网段列表里随机取 k 个 /24 的首地址（int）。不展开成 /24 对象。

    按每个网段含多少个 /24 加权，所以大网段被选中的概率天然更高，
    和「先展开成 /24 列表再随机抽」是同一个分布。

    **无放回**：同一个 /24 不会返回两次。有放回的话会浪费扫描名额
    （重复的地址会在后面的去重里被丢掉，等于少扫了几个）。
    """
    if not nets or k <= 0:
        return []
    if weights is None:
        weights = [(1 << (24 - n.prefixlen)) if n.prefixlen <= 24 else 1 for n in nets]
    if total is None:
        total = sum(weights)
    if total <= 0:
        return []

    # 累积权重 + 二分查找：每个样本 O(log n) 而不是 O(n)
    import bisect
    cum = []
    acc = 0
    for w in weights:
        acc += w
        cum.append(acc)

    k = min(k, total)          # 不可能取到比总数还多
    out, seen = [], set()
    # 取满 k 个就停；重复太多次（k 接近 total 时）就退出，避免空转
    guard = 0
    limit = max(k * 30, 1000)
    while len(out) < k and guard < limit:
        guard += 1
        r = random.randrange(total)
        i = bisect.bisect_right(cum, r)
        if i >= len(nets):
            i = len(nets) - 1
        # 在这个网段里选第 (r - 前面累计) 个 /24
        base_off = (cum[i - 1] if i > 0 else 0)
        idx = r - base_off
        base = int(nets[i].network_address) + idx * 256
        if base in seen:
            continue
        seen.add(base)
        out.append(base)
    return out

def provider_of(asn):
    """ASN 号 -> 厂商名。用于面板显示「当前是哪个厂商」。"""
    a = str(asn).upper().strip()
    if not a.startswith("AS"):
        a = "AS" + a
    for name, members in ASN_GROUPS.items():
        if a in members:
            return name
    return ""


def iter_prefix_batches(asns, sample, timeout, retries, debug=False):
    """逐个网段产出 (provider, asn, prefix_str, n24, [候选 dict])。

    sample=0 表示全量（每个 /24 的 254 个地址）。
    网段列表缓存到临时文件，不常驻内存。
    """
    import ipaddress
    import tempfile

    counts = {}
    cache = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".nets",
                                        delete=False, prefix="cfip-nets-")
    cache_path = cache.name
    try:
        # ---- 第一遍：查每个 ASN 的网段，只留数量 + 写临时文件 ----
        for idx, asn in enumerate(asns, 1):
            prov = provider_of(asn)
            set_progress("asn", "厂商 ASN（总进度）", idx, len(asns), current=asn,
                         extra={"cur_asn": asn, "provider": prov})
            try:
                nets = asn_prefixes(asn, timeout, retries, debug)
            except Exception as e:               # noqa: BLE001
                log(f"    [ASN {asn}] 查询失败：{e}")
                counts[asn] = 0
                continue
            n24 = count_24s(nets)
            counts[asn] = n24
            cache.write(asn + "\t" + ",".join(str(n) for n in nets) + "\n")
            log(f"    [ASN {asn}] 网段 {len(nets)} 个 -> /24 {n24:,} 个")
            del nets
        cache.close()

        grand = sum(counts.values())
        if grand <= 0:
            return
        log(f"[*] 共 {grand:,} 个 /24"
            + ("（全量模式，不采样）" if not sample else f"（目标采样 {sample} 个）"))

        # ---- 第二遍：逐个 ASN -> 逐个网段 yield ----
        with open(cache_path, "r", encoding="utf-8") as fh:
            for line in fh:
                asn, _, netstr = line.rstrip("\n").partition("\t")
                n24_total = counts.get(asn, 0)
                if n24_total <= 0 or not netstr:
                    yield provider_of(asn), asn, "", 0, 0, 0, []
                    continue
                prov = provider_of(asn)
                nets = [ipaddress.ip_network(x) for x in netstr.split(",") if x]

                # 采样模式下，算出这个 ASN 要抽多少个 /24
                if sample and sample > 0:
                    k_asn = min(max(1, round(sample * n24_total / grand)), n24_total)
                else:
                    k_asn = 0

                total_prefixes = len(nets)
                for pi, n in enumerate(nets, 1):   # pi = 第几个网段
                    addrs = []
                    if sample and sample > 0:
                        # 按这个网段占 ASN 的比例分配名额
                        w = (1 << (24 - n.prefixlen)) if n.prefixlen <= 24 else 1
                        k = max(1, round(k_asn * w / n24_total)) if n24_total else 1
                        addrs = sample_24s([n], min(k, w))
                    else:
                        if n.prefixlen <= 24:
                            step = 1 << (24 - n.prefixlen)
                            base = int(n.network_address)
                            addrs = [base + i * 256 for i in range(step)]
                        else:
                            addrs = [int(n.network_address)]

                    cands = []
                    for base in addrs:
                        if FULL_SCAN:
                            for host in range(1, 255):
                                cands.append({"ip": str(ipaddress.IPv4Address(base + host)),
                                              "port": "443", "protocol": "https",
                                              "country": ""})
                        else:
                            cands.append({"ip": str(ipaddress.IPv4Address(base + random.randint(1, 254))),
                                          "port": "443", "protocol": "https", "country": ""})
                    n24_this = (1 << (24 - n.prefixlen)) if n.prefixlen <= 24 else 1
                    yield prov, asn, str(n), n24_this, pi, total_prefixes, cands
                    del cands, addrs
                del nets
    finally:
        try:
            os.remove(cache_path)
        except OSError:
            pass


# ==================== 逐 ASN 端到端流水线 ====================
# 原来的做法：先把【所有】候选写进 ip.csv，再交给 ip.py 去测。
# vps 档位全量 = 181,871 个 /24 x 254 = 4620 万个候选，
# 按实测每行 218 字节算，ip.csv 要 10GB —— 而用户的盘只有 3GB（可用 1.6GB）。
# 实测跑 21 分钟写了 151MB 就把盘写满，服务崩溃重启，反复 7 次。
#
# 改成逐 ASN 处理：这个 ASN 的候选生成出来 -> stage0 -> stage1 ->
# 只把【通过的结果】追加到 stage1.csv -> 候选全部释放。
# 峰值磁盘占用 = 结果文件（约 3 万个反代 x 40 字节 = 1.2MB），
# 峰值内存 = 单个 ASN 的候选数（最大约 12 万个，约 30MB）。


# ==================== 系统资源看门狗 ====================
# 实测踩过：扫描把 726MB 的机器榨干，SSH 连上立刻被断开，
# 只能硬重启。事后查内核日志是 OOM（cfip 的 python3 吃了 600MB）。
# 光靠降并发不够 —— 得让脚本自己知道「系统快撑不住了」，主动让路。
#
# 两道闸：
#   1. 内存闸：可用内存低于阈值就暂停，等它回升
#   2. 并发闸：按可用内存给并发数封顶，不让人手填的大数字生效
SYS_GUARD_ENABLED = True
SYS_MIN_FREE_MB = 150        # 可用内存低于这个值就暂停（给 sshd 留活路）
SYS_GUARD_MAX_WAIT = 900     # 最多等这么久（秒），超了也继续（免得永久卡住）
# 每个并发连接的内核内存预算（KB）。socket 缓冲压到 16KB 后，
# 收发各 16KB + 内核结构约 8KB ≈ 40KB。取 64KB 留余量。
PER_CONN_KB = 64
# 并发上限还要受临时端口数约束（每次连接占一个）
MAX_PORT_FRACTION = 0.5      # 最多用一半临时端口，留一半给系统自己


def mem_available_mb():
    """系统可用内存（MB）。Linux 读 /proc/meminfo，其他平台返回 None。"""
    try:
        with open("/proc/meminfo", "r", encoding="ascii", errors="replace") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / 1024.0
    except (OSError, ValueError, IndexError):
        pass
    return None


def _port_range_size():
    """临时端口总数（决定并发上限）。"""
    try:
        with open("/proc/sys/net/ipv4/ip_local_port_range", "r") as f:
            lo, hi = (int(x) for x in f.read().split()[:2])
        return hi - lo + 1
    except (OSError, ValueError):
        return 28232


def safe_concurrency(requested):
    """按可用内存和临时端口给并发数封顶。

    返回 (最终并发, 说明)。人手填太大时会被自动压下来并打日志 ——
    宁可慢一点，也不能把机器搞到连不上。
    """
    if not SYS_GUARD_ENABLED:
        return requested, "看门狗已关闭"
    notes = []
    cap = requested

    mem = mem_available_mb()
    if mem is not None:
        # 只让扫描用「可用内存 - 保留量」这部分
        usable = max(0, mem - SYS_MIN_FREE_MB)
        by_mem = int(usable * 1024 / PER_CONN_KB)
        if by_mem < cap:
            notes.append(f"内存 {mem:.0f}MB 可用 -> 最多 {by_mem}")
            cap = by_mem

    ports = _port_range_size()
    by_port = int(ports * MAX_PORT_FRACTION)
    if by_port < cap:
        notes.append(f"临时端口 {ports} 个 -> 最多 {by_port}")
        cap = by_port

    # 内核 socket 表限制。这两个默认值很多系统只有 4096：
    #   tcp_max_orphans   —— 孤儿 socket 上限，超了内核直接 RST 并告警
    #   tcp_max_tw_buckets—— TIME_WAIT 桶上限，超了立刻回收
    # 并发超过它们的一半就很容易触发，所以按一半封顶。
    for key, label in (("net.ipv4.tcp_max_orphans", "孤儿 socket"),
                       ("net.ipv4.tcp_max_tw_buckets", "TIME_WAIT 桶")):
        v = _read_sysctl_int(key)
        if v:
            by_kernel = int(v * 0.5)
            if by_kernel < cap:
                notes.append(f"{label}上限 {v} -> 最多 {by_kernel}")
                cap = by_kernel

    cap = max(50, cap)          # 再保守也别低于 50，否则没法干活
    return cap, "；".join(notes) if notes else ""


def _read_sysctl_int(key):
    try:
        with open("/proc/sys/" + key.replace(".", "/"), "r") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return 0


def sys_guard(tag=""):
    """等系统缓过来再继续。返回等了多久（秒）。"""
    if not SYS_GUARD_ENABLED:
        return 0
    waited = 0
    while waited < SYS_GUARD_MAX_WAIT:
        mem = mem_available_mb()
        if mem is None or mem >= SYS_MIN_FREE_MB:
            return waited
        if waited == 0:
            log(f"[!] 可用内存只剩 {mem:.0f}MB（低于 {SYS_MIN_FREE_MB}MB），"
                f"暂停扫描让系统缓一缓{('（' + tag + '）') if tag else ''}")
        time.sleep(15)
        waited += 15
    log(f"[!] 等了 {waited} 秒内存还没回来，继续扫描（可能一直卡着）")
    return waited


# ==================== 断点续跑 ====================
# vps 档位全量要跑 12 小时。用户的机器实测崩过 7 次（磁盘写满那次），
# 一次意外重启就前功尽弃 —— 12 小时的扫描白跑。
# 这里把「哪些 ASN 已经扫完」记到状态文件，重启后接着扫。
#
# 关键设计：
#   - 状态里带一个【配置指纹】，配置变了（档位/全量/端口/ASN 列表不同）
#     就当作新一轮，不续跑 —— 否则会拿旧配置的结果凑数。
#   - 每扫完一个 ASN 就落一次状态，最多丢一个 ASN 的进度。
#   - 续跑时用追加模式打开 stage1.csv.new，不重写已找到的结果。
#   - 全部跑完才把 .new 提升成正式文件，并删掉状态。
SCAN_STATE_FILE = "./output/scan_state.json"


def _scan_state_path():
    return SCAN_STATE_FILE if os.path.isabs(SCAN_STATE_FILE) else os.path.join(HERE, SCAN_STATE_FILE)


def scan_fingerprint(asns, sample):
    """这一轮扫描的配置指纹。变了就不续跑。"""
    import hashlib
    parts = [
        "|".join(sorted(asns)),
        str(sample),
        str(FULL_SCAN),
        str(PORTS),
        str(SUB_BATCH),
    ]
    return hashlib.sha1("::".join(parts).encode("utf-8")).hexdigest()[:16]


def load_scan_state():
    path = _scan_state_path()
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            return json.load(f) or {}
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}


def save_scan_state(state):
    path = _scan_state_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False)
        os.replace(tmp, path)
    except OSError as e:
        log(f"[!] 写扫描状态失败：{e}")


def clear_scan_state():
    try:
        os.remove(_scan_state_path())
    except OSError:
        pass


def run_asn_pipeline(asns, sample, extra_run_args, round_no=1, on_found=None):
    """逐网段完成「生成 -> 预筛 -> 可用性检查」，结果追加到 STAGE1_CSV。

    on_found: 可选回调。每测完一批就把【新找到的真反代】交给它，
              调用方可以立刻写进池子 —— 不用等整轮跑完（一轮 24 小时，
              等完再写的话下游这 24 小时拿到的都是旧数据，
              而且第 23 小时崩了就全白费）。
    """
    """逐网段完成「生成 -> 预筛 -> 可用性检查」，结果追加到 STAGE1_CSV。

    进度分四级报给面板，层层展开：
        provider  厂商（总进度）
          asn     这个厂商下第几个 ASN
            prefix  这个 ASN 下第几个网段
              ip    这个网段内的 IP 测了多少

    小网段会合并到至少 PREFIX_MIN_BATCH 个候选再一起测 ——
    一个 /24 只有 254 个 IP，用 800 并发去跑它并发根本用不满，
    而且每个网段单独起一次事件循环也有开销。网段级进度照常逐个上报。

    返回 (本轮找到的反代数, 是否完整跑完)。
    """
    import ip as ipt

    stage1_path = STAGE1_CSV if os.path.isabs(STAGE1_CSV) else os.path.join(HERE, STAGE1_CSV)
    os.makedirs(os.path.dirname(stage1_path), exist_ok=True)

    want_asn = {r.upper() for r in as_list(ASN_REGIONS)}
    drop_asn = {r.upper() for r in as_list(ASN_EXCLUDE_REGIONS)}
    asn_ports = as_list(PORTS) or ["443"]
    exclude_nets = _parse_cidrs(FOFA_EXCLUDE_CIDRS)
    skip_ips = _load_skip_ips(FOFA_SKIP_FILE)

    tmp_path = stage1_path + ".new"
    total_asns = len(asns)
    started = time.time()
    seen_keys = set()
    asn_done = 0
    cum_scanned = 0
    found = 0
    pending, pending_prefixes = [], []

    # 上游模式只跑 stage0/stage1，把不跑的阶段标成「已跳过」
    if UPSTREAM_STAGE1_ONLY:
        for _k, _n in (("s2", "stage2 · 延迟与测速（上游跳过，交给下游）"),
                       ("s3", "stage3 · 线路分析（上游跳过，交给下游）")):
            set_progress(_k, _n, 0, 0, extra={"skipped": True})

    log(f"\n[*] 逐网段流水线：{total_asns} 个 ASN，"
        f"{'全量（每个 /24 的 254 个地址）' if FULL_SCAN else f'采样 {sample} 个 /24'}")

    # ---- 断点续跑 ----
    fp = scan_fingerprint(asns, sample)
    state = load_scan_state()
    done_asns = set()
    if state.get("fingerprint") == fp and os.path.exists(tmp_path):
        done_asns = set(state.get("done") or [])
        if done_asns:
            log(f"[*] 发现上次的进度：已完成 {len(done_asns)}/{total_asns} 个 ASN，"
                f"从断点继续（配置没变）")
    elif state.get("fingerprint") and state.get("fingerprint") != fp:
        log("[*] 配置变了（档位/全量/端口/ASN 列表不同），当作新一轮重新扫")
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        clear_scan_state()

    resuming = bool(done_asns) and os.path.exists(tmp_path)
    # 关键：真正要扫的是【去掉已完成的】那些 ASN。
    # 重写这个函数时漏了这一步，导致加载了断点却还是从头扫（实测踩过）。
    asns_todo = [a for a in asns if a not in done_asns]
    if done_asns:
        log(f"[*] 本轮要扫 {len(asns_todo)} 个 ASN"
            f"（跳过已完成的 {len(done_asns)} 个：{', '.join(sorted(done_asns)[:5])}"
            f"{'…' if len(done_asns) > 5 else ''}）")
    if not asns_todo:
        log("[*] 所有 ASN 都已扫完，直接进入收尾")
    if resuming:
        try:
            with open(tmp_path, "r", encoding="utf-8-sig") as f:
                found = max(0, sum(1 for _ in f) - 1)
            log(f"[*] 已有 {found} 个反代记录，继续追加")
        except OSError:
            found = 0

    def flush_state():
        save_scan_state({"fingerprint": fp, "done": sorted(done_asns),
                         "started": state.get("started") or
                         datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                         "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                         "found": found})

    def process_batch(batch, label, asn, prov, prefix):
        """测一批候选，返回通过列表。"""
        nonlocal cum_scanned
        if not batch:
            return []
        # 这两条不是「IP 数到第几个」，而是「这一批 IP 走完了没有 + 结果」：
        #   ip0  把这一批候选全 TCP 连一遍，看有多少端口是开的
        #   ip1  对端口开着的那部分做 TLS+trace，看有多少是真反代
        # 所以名字里带上动作，note 里带上结果数字。
        set_progress("ip0", "① TCP 端口检查（" + label + "）", 0, len(batch),
                     extra={"asn": asn, "prefix": prefix,
                            "note": f"本批 {len(batch):,} 个候选 IP"})
        set_progress("ip1", "② 可用性检查（是否真反代）", 0, 0,
                     extra={"asn": asn, "prefix": prefix,
                            "note": "等 ① 筛出端口开着的再开始"})
        kept = []
        for i in range(0, len(batch), 20000):
            rows, _st = normalize(batch[i:i + 20000], set(asn_ports), exclude_nets,
                                  skip_ips, [], 0)
            kept.extend(rows)
        if not kept:
            set_progress("ip0", "① TCP 端口检查（" + label + "）", 0, 0,
                         extra={"asn": asn, "prefix": prefix,
                                "note": "本批候选都被过滤规则排除了"})
            return []
        total_kept = len(kept)

        # IP 级进度分两条，跟实际阶段一一对应 ——
        #   ip0 = stage0 纯 TCP 连通性（不验证是不是 CF，所以快）
        #   ip1 = stage1 可用性检查（TLS + /cdn-cgi/trace，慢得多）
        # 原来两条共用一个进度条，看着「飞快跑到 100% 又重置」，
        # 容易误以为没在测 IP。分开之后一眼能看出当前在哪一步。
        #
        # 节流：每 2 秒或结束时才写一次 status.json，
        # 否则每个 IP 都写一次盘，扫描本身就被拖慢了
        last_tick0 = [0.0]
        last_tick1 = [0.0]

        def tick0(done, total, ip, ok, _lbl=label):
            now = time.time()
            if done < total and now - last_tick0[0] < 2.0:
                return
            last_tick0[0] = now
            set_progress("ip0", "① TCP 端口检查（" + _lbl + "）", done, total,
                         ip=ip, extra={"asn": asn, "prefix": prefix})

        def tick1(done, total, ip, ok, _lbl=label):
            now = time.time()
            if done < total and now - last_tick1[0] < 2.0:
                return
            last_tick1[0] = now
            set_progress("ip1", "② 可用性检查（是否真反代）", done, total,
                         ip=ip, extra={"asn": asn, "prefix": prefix,
                                       "passed": bool(ok)})

        alive = kept
        alive0 = total_kept        # stage0 关掉时 stage1 的分母就是全部候选
        if ipt.STAGE0_ENABLED:
            conc, why = safe_concurrency(ipt.STAGE0_CONCURRENCY)
            if conc < ipt.STAGE0_CONCURRENCY:
                log(f"[!] stage0 并发从 {ipt.STAGE0_CONCURRENCY} 压到 {conc}（{why}）")
            alive = ipt.stage0_tcp_filter(kept, ipt.STAGE0_TIMEOUT, conc,
                                          on_progress=tick0)
            del kept
            if not alive:
                set_progress("ip0", "① TCP 端口检查（" + label + "）",
                             total_kept, total_kept,
                             extra={"asn": asn, "prefix": prefix,
                                    "note": f"本批 {total_kept:,} 个候选，"
                                            f"端口开着的 0 个 —— 全部淘汰"})
                set_progress("ip1", "② 可用性检查（是否真反代）", 0, 0,
                             extra={"asn": asn, "prefix": prefix,
                                    "note": "① 已经全部筛掉，无需检查"})
                return []
            set_progress("ip0", "① TCP 端口检查（" + label + "）",
                         total_kept, total_kept,
                         extra={"asn": asn, "prefix": prefix,
                                "note": f"本批 {total_kept:,} 个候选，"
                                        f"端口开着的 {len(alive):,} 个"})
            cum_scanned += len(alive)
            alive0 = len(alive)

        set_progress("ip1", "② 可用性检查（是否真反代）", 0, alive0,
                     extra={"asn": asn, "prefix": prefix,
                            "note": f"对 ① 筛出的 {alive0:,} 个做 TLS+trace"})
        conc1, why1 = safe_concurrency(ipt.ASYNCIO_CONCURRENCY)
        if conc1 < ipt.ASYNCIO_CONCURRENCY:
            log(f"[!] stage1 并发从 {ipt.ASYNCIO_CONCURRENCY} 压到 {conc1}（{why1}）")
        passed = ipt.stage1_async(alive, conc1, ipt.CURL_TIMEOUT_SEC,
                                  on_progress=tick1)
        del alive
        # alive0 已经是 int（stage0 通过数），不要再 len()
        set_progress("ip1", "② 可用性检查（是否真反代）", alive0, alive0,
                     extra={"asn": asn, "prefix": prefix, "found": len(passed),
                            "note": f"检查了 {alive0:,} 个，"
                                    f"真反代 {len(passed):,} 个"})
        return passed

    # 关键：续跑时先把【已经找到的结果】并进池子。
    # 池子原来只在整轮跑完时才更新，而一轮 24 小时 ——
    # 中途重启的话，这些反代永远进不了池子，下游拉 /api/ips 拿到空的。
    # 实测踩过：断点显示已找到 539 个，但池子个数是 0。
    if resuming and POOL_ENABLED and on_found is not None:
        try:
            existing = read_stage1_results(tmp_path)
            if existing:
                on_found(existing)
                log(f"[*] 已把断点里的 {len(existing)} 个反代补进池子")
        except Exception as e:                   # noqa: BLE001
            log(f"[!] 补写池子失败（不影响扫描）：{e}")

    with open(tmp_path, "a" if resuming else "w",
              encoding="utf-8-sig", newline="") as fh:
        wr = csv.writer(fh)
        if not resuming:
            wr.writerow(["ip", "port", "protocol", "cfcountry", "colo"])

        last_asn = None
        asn_done = len(done_asns)      # 面板显示累计进度，从已完成的数起
        for (prov, asn, prefix, n24_this, pidx, ptotal,
             cands) in iter_prefix_batches(asns_todo, sample, FOFA_TIMEOUT,
                                           FOFA_RETRIES, DEBUG):
            # ---- 换 ASN：落一次断点，更新上面两级的进度 ----
            if asn != last_asn:
                if last_asn is not None:
                    done_asns.add(last_asn)
                    flush_state()
                last_asn = asn
                asn_done += 1
                sys_guard(f"ASN {asn}")
                set_progress("provider", "厂商（总进度）", asn_done, total_asns,
                             current=prov or "未归类",
                             extra={"provider": prov, "asn": asn})
                set_progress("asn", "厂商 ASN（总进度）", asn_done, total_asns,
                             current=asn, extra={"cur_asn": asn, "provider": prov,
                                                 "cum_scanned": cum_scanned,
                                                 "cum_found": found})
                if asn_done % 5 == 0 or asn_done == total_asns:
                    el = time.time() - started
                    log(f"[*] 进度 {asn_done}/{total_asns} 个 ASN，"
                        f"已找到 {found} 个反代，耗时 {el/60:.1f} 分钟")

            if not cands:
                continue

            # ---- 网段级进度：逐个上报 ----
            set_progress("prefix", asn + " · 网段（子网）进度", pidx, ptotal,
                         current=prefix or "—",
                         extra={"asn": asn, "provider": prov, "prefix": prefix,
                                "n24": n24_this})

            # ---- 小网段合并 ----
            pending.extend(cands)
            pending_prefixes.append(prefix or asn)
            del cands
            if len(pending) < PREFIX_MIN_BATCH and pidx < ptotal:
                continue

            label = ("、".join(pending_prefixes[:2])
                     + ("…" if len(pending_prefixes) > 2 else ""))
            batch, pending = pending, []
            pending_prefixes = []
            passed = process_batch(batch, label, asn, prov, prefix)
            del batch

            fresh = []
            for r in passed:
                key = "%s:%s" % (r["ip"], r.get("port", "443"))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                wr.writerow([r["ip"], r.get("port", "443"), "https",
                             r.get("cfcountry", ""), r.get("colo", "")])
                found += 1
                fresh.append({"ip": r["ip"], "port": r.get("port", "443"),
                              "cfcountry": r.get("cfcountry", ""),
                              "colo": r.get("colo", "")})
            fh.flush()
            del passed
            # 立刻把这批新发现交给调用方（写池子），不等整轮结束
            if fresh and on_found is not None:
                try:
                    on_found(fresh)
                except Exception as e:           # noqa: BLE001
                    log(f"[!] 增量写池子失败（不影响扫描）：{e}")
            del fresh

        # 循环结束：冲掉最后一批 + 落最后一个 ASN 的断点
        if pending:
            passed = process_batch(pending, "最后一批", last_asn or "", "", "")
            fresh = []
            for r in passed:
                key = "%s:%s" % (r["ip"], r.get("port", "443"))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                wr.writerow([r["ip"], r.get("port", "443"), "https",
                             r.get("cfcountry", ""), r.get("colo", "")])
                found += 1
                fresh.append({"ip": r["ip"], "port": r.get("port", "443"),
                              "cfcountry": r.get("cfcountry", ""),
                              "colo": r.get("colo", "")})
            fh.flush()
            if fresh and on_found is not None:
                try:
                    on_found(fresh)
                except Exception as e:           # noqa: BLE001
                    log(f"[!] 增量写池子失败（不影响扫描）：{e}")
            del fresh
        if last_asn is not None:
            done_asns.add(last_asn)
            flush_state()

    os.replace(tmp_path, stage1_path)
    clear_scan_state()
    log(f"[*] 逐网段流水线完成：{total_asns} 个 ASN，"
        f"找到 {found} 个反代 -> {stage1_path}")
    return found, True


def iter_asn_batches(asns, sample, timeout, retries, debug=False, sub_batch=50000):
    """逐个 ASN 产出 (asn, [候选 dict])，边产边释放。

    和 iter_asn_candidates 的区别：那个是一条条 yield 候选，
    这个是一整个 ASN 一批 yield —— 这样调用方可以「处理完这个 ASN
    就丢掉它的候选」，不需要把 4620 万个候选落盘或留在内存。

    sample=0 表示全量（该 ASN 的所有 /24 都产出）。
    """
    import ipaddress
    import tempfile

    # ---- 第一遍：查网段 -> 只留数量 + 写临时文件（约 1~2MB）----
    counts = {}
    cache = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".nets",
                                        delete=False, prefix="cfip-nets-")
    cache_path = cache.name
    try:
        for idx, asn in enumerate(asns, 1):
            set_progress("asn", "抓取 · 查询 ASN 宣告网段", idx, len(asns), current=asn)
            try:
                nets = asn_prefixes(asn, timeout, retries, debug)
            except Exception as e:               # noqa: BLE001
                log(f"    [ASN {asn}] 查询失败：{e}")
                counts[asn] = 0
                continue
            n24 = count_24s(nets)
            counts[asn] = n24
            cache.write(asn + "\t" + ",".join(str(n) for n in nets) + "\n")
            log(f"    [ASN {asn}] 网段 {len(nets)} 个 -> /24 {n24:,} 个")
            del nets
        cache.close()

        grand = sum(counts.values())
        if grand <= 0:
            return
        log(f"[*] 共 {grand:,} 个 /24"
            + ("（全量模式，不采样）" if not sample else f"（目标采样 {sample} 个）"))

        # ---- 第二遍：逐个 ASN 读回来，采样/展开后整批 yield ----
        with open(cache_path, "r", encoding="utf-8") as fh:
            for line in fh:
                asn, _, netstr = line.rstrip("\n").partition("\t")
                n24 = counts.get(asn, 0)
                if n24 <= 0 or not netstr:
                    yield asn, []
                    continue
                nets = [ipaddress.ip_network(x) for x in netstr.split(",") if x]
                if sample and sample > 0:
                    k = min(max(1, round(sample * n24 / grand)), n24)
                    addrs = sample_24s(nets, k)
                else:
                    addrs = []
                    for n in nets:
                        if n.prefixlen <= 24:
                            step = 1 << (24 - n.prefixlen)
                            base = int(n.network_address)
                            addrs.extend(base + i * 256 for i in range(step))
                        else:
                            addrs.append(int(n.network_address))
                del nets

                # 关键：ASN 内部还要再分批。
                # 一个大 ASN（vps 档位的 AS45102 有 12.3 万个 /24）全量展开是
                # 3140 万个候选，一次性建成列表会吃掉几个 GB。
                # 按 sub_batch 切块 yield，峰值只跟块大小有关。
                out = []
                for base in addrs:
                    if FULL_SCAN:
                        for host in range(1, 255):
                            out.append({"ip": str(ipaddress.IPv4Address(base + host)),
                                        "port": "443", "protocol": "https", "country": ""})
                    else:
                        out.append({"ip": str(ipaddress.IPv4Address(base + random.randint(1, 254))),
                                    "port": "443", "protocol": "https", "country": ""})
                    if len(out) >= sub_batch:
                        yield asn, out
                        out = []
                del addrs
                if out:
                    yield asn, out
                del out
    finally:
        try:
            os.remove(cache_path)
        except OSError:
            pass


def iter_asn_candidates(asns, sample, timeout, retries, debug=False, stats=None):
    """逐个 ASN 产出候选 dict，边产边释放。峰值内存只跟单个 ASN 的网段数有关。

    sample=0 表示全量（所有 /24 都产出）。

    为什么要先缓存网段再采样：
      按占比分配采样名额需要先知道每个 ASN 有多少 /24，这就得先查一遍网段；
      但网段列表不能常驻内存（18 万个 /24 展开后约 35MB）。
      所以第一遍把网段【写成文本存到临时文件】（约 1~2MB），第二遍读回来采样。
      这样 ASN API 还是只查一遍，内存也不会涨。
    """
    import ipaddress
    import tempfile

    counts = {}
    cache = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".nets",
                                        delete=False, prefix="cfip-nets-")
    cache_path = cache.name
    try:
        # ---- 第一遍：查网段 -> 只留数量 + 写临时文件 ----
        for idx, asn in enumerate(asns, 1):
            set_progress("asn", "抓取 · 查询 ASN 宣告网段", idx, len(asns), current=asn)
            try:
                nets = asn_prefixes(asn, timeout, retries, debug)
            except Exception as e:               # noqa: BLE001
                log(f"    [ASN {asn}] 查询失败：{e}")
                counts[asn] = 0
                continue
            n24 = count_24s(nets)
            counts[asn] = n24
            # 存成 "asn<TAB>net1,net2,..." 一行，读回来是 O(网段数)
            cache.write(asn + "\t" + ",".join(str(n) for n in nets) + "\n")
            log(f"    [ASN {asn}] 网段 {len(nets)} 个 -> /24 {n24:,} 个")
            del nets
        cache.close()

        grand = sum(counts.values())
        if grand <= 0:
            return
        log(f"[*] 共 {grand:,} 个 /24，开始流式采样"
            + ("（全量模式，不采样）" if not sample else f"（目标 {sample} 个）"))

        # ---- 第二遍：从临时文件读回网段，采样后立即产出 ----
        picked_total = 0
        with open(cache_path, "r", encoding="utf-8") as fh:
            for line in fh:
                asn, _, netstr = line.rstrip("\n").partition("\t")
                n24 = counts.get(asn, 0)
                if n24 <= 0 or not netstr:
                    continue
                nets = [ipaddress.ip_network(x) for x in netstr.split(",") if x]
                if sample and sample > 0:
                    # 按占比分配名额；至少给 1 个，免得小 ASN 永远抽不到
                    k = max(1, round(sample * n24 / grand))
                    k = min(k, n24)
                    addrs = sample_24s(nets, k)
                else:
                    addrs = []
                    for n in nets:
                        if n.prefixlen <= 24:
                            step = 1 << (24 - n.prefixlen)
                            base = int(n.network_address)
                            addrs.extend(base + i * 256 for i in range(step))
                        else:
                            addrs.append(int(n.network_address))
                del nets
                for base in addrs:
                    if FULL_SCAN:
                        # 全量：这个 /24 的 254 个可用地址（跳过 .0 / .255）全产出
                        for host in range(1, 255):
                            picked_total += 1
                            yield {"ip": str(ipaddress.IPv4Address(base + host)),
                                   "port": "443", "protocol": "https", "country": ""}
                    else:
                        picked_total += 1
                        yield {"ip": str(ipaddress.IPv4Address(base + random.randint(1, 254))),
                               "port": "443", "protocol": "https", "country": ""}
                del addrs
        log(f"[*] {'全量展开' if FULL_SCAN else '采样'}完成，"
        f"共 {picked_total:,} 个候选地址"
        + ("（每个 /24 全部 254 个地址）" if FULL_SCAN else ""))
        if stats is not None:
            stats["asns"] = len([a for a, c in counts.items() if c > 0])
    finally:
        try:
            os.remove(cache_path)
        except OSError:
            pass


# ==================== 单轮流水线 ====================
def run_once(a, source, extra_run_args, round_no=1, loop_secs=0):
    """抓取一轮候选 IP -> 写 ip.csv ->（可选）调用 ip.py。"""
    template = FOFA_QUERY_TEMPLATE or QUERY_PRESETS.get(FOFA_PRESET, QUERY_PRESETS["proxy"])
    regions = [r.upper() for r in as_list(FOFA_REGIONS)]
    exclude_asns = as_list(FOFA_EXCLUDE_ASNS)
    csv_path = FOFA_CSV_OUTPUT
    if not os.path.isabs(csv_path):
        csv_path = os.path.abspath(csv_path)

    log("=" * 68)
    log("候选 IP 抓取 -> ip.py 实测 自动化流水线")
    if loop_secs:
        log(f"第 {round_no} 轮 | 每 {loop_secs} 秒一轮 | {datetime.now():%Y-%m-%d %H:%M:%S}")
    log("=" * 68)
    log(f"source        = {source}")
    log(f"require port  = {FOFA_REQUIRE_PORT or '(不过滤)'}")
    log(f"exclude asns  = {', '.join(exclude_asns) or '(无)'}")
    log(f"max ips       = {a.max if a.max else '(不限制)'}")
    log(f"output csv    = {csv_path}")
    if source == "ipdb":
        log(f"ipdb base     = {IPDB_API_BASE}")
        log(f"ipdb types    = {IPDB_TYPES}")
        log(f"cf official   = {f'采样 {IPDB_CF_SAMPLE} 个官方 IP' if IPDB_CF_SAMPLE else '不采样'}")
    elif source == "list":
        log(f"list urls     = {LIST_URLS}")
        log(f"list regions  = {LIST_REGIONS or '(不筛选)'}")
    elif source == "asn":
        log(f"asns          = {ASNS or '(未指定)'}")
        log(f"asn sample    = 共采样 {ASN_SAMPLE} 个 /24（跨所有 ASN）" if ASN_SAMPLE
            else "asn sample    = 全量（不采样）")
    elif source == "fofa":
        log(f"preset        = {FOFA_PRESET if not FOFA_QUERY_TEMPLATE else '自定义 -query'}")
        log(f"template      = {template}")
        log(f"regions       = {', '.join(regions) or '(无)'}")
        log(f"per-region    = {FOFA_MAX_PER_REGION} 条，单页 {FOFA_PAGE_SIZE}")
        log(f"api base      = {FOFA_API_BASE}")
        log(f"key           = {'已配置 ' + FOFA_KEY[:4] + '***' + FOFA_KEY[-4:] if len(FOFA_KEY) > 8 else '(未配置)'}")
    log("")

    # ---- dry-run：只打印查询，不联网 ----
    if a.dry_run:
        log("[*] dry-run：不联网抓取。\n")
        if source == "ipdb":
            for t in as_list(IPDB_TYPES):
                q = "&country=true" if (IPDB_COUNTRY and t in ("bestproxy", "bestcf")) else ""
                log(f"  【IPDB {t}】 {IPDB_API_BASE.rstrip('/')}/?type={t}{q}")
            if IPDB_CF_SAMPLE:
                log(f"  【官方 IP】 {IPDB_API_BASE.rstrip('/')}/?type=cfv4"
                    f"  ->  按不同 /24 采样 {IPDB_CF_SAMPLE} 个地址")
        elif source == "list":
            for u in resolve_list_urls(LIST_URLS):
                log(f"  【LIST】 {u}")
        elif source == "asn":
            for asn in resolve_asns(ASNS):
                log(f"  【ASN】 {asn}  ->  {ASN_API}?resource={asn}  "
                    f"（展开 /24 后采样 {ASN_SAMPLE} 个）")
        elif source == "fofa":
            log("[*] 以下语法可直接粘贴到 https://fofa.info 搜索框：\n")
            for region, q in human_query(regions, template, FOFA_EXTRA_QUERY, exclude_asns):
                log(f"  【{region or 'ALL'}】 {q}\n")
        else:
            log(f"  【CSV】 {a.import_csv}")
        log("[*] dry-run 结束：未抓取，未写出 CSV。")
        return 0

    # ---- 抓取 ----
    raw_rows = []
    if a.self_test:
        log("[*] self-test：使用内置样例（Cloudflare 官方任播 IP），不联网抓取。")
        raw_rows = list(SELF_TEST_ROWS)
    elif source == "csv":
        if not a.import_csv:
            log("[!] -source csv 需要配合 -import-csv <文件> 使用。")
            return 5
        src = a.import_csv
        if not os.path.isabs(src):
            src = os.path.abspath(src)
        log(f"[*] 导入 CSV：{src}")
        try:
            raw_rows = read_fofa_export(src)
        except FetchError as e:
            log(f"[!] {e}")
            return 5
        log(f"[*] 从文件读到 {len(raw_rows)} 行")
    elif source == "ipdb":
        log(f"[*] 从 IPDB 抓取：{IPDB_TYPES}")
        try:
            raw_rows, _ = ipdb_fetch(as_list(IPDB_TYPES), IPDB_COUNTRY,
                                     IPDB_TIMEOUT, IPDB_RETRIES,
                                     IPDB_CF_SAMPLE, DEBUG)
        except FetchError as e:
            log(f"[!] IPDB 抓取失败：{e}")
            return 3
        if not raw_rows:
            log("[!] IPDB 没返回任何 IP，稍后重试或检查 -ipdb-types。")
            return 4
    elif source == "list":
        urls = resolve_list_urls(LIST_URLS)
        if not urls:
            log("[!] -source list 需要指定 -list-urls（名字或 URL），可用名字：")
            log(f"    {', '.join(sorted(LIST_SOURCES))}")
            return 5
        log(f"[*] 从第三方列表抓取：{len(urls)} 个源")
        raw_rows, lstat = list_fetch(urls, LIST_TIMEOUT, FOFA_RETRIES, DEBUG)
        if not raw_rows:
            log("[!] 所有列表都为空或拉取失败。")
            return 4
        want = {r.upper() for r in as_list(LIST_REGIONS)}
        if want:
            before = len(raw_rows)
            # 有地区标注的按清单筛；没标注的（纯 IP 列表）保留，不能凭空丢掉
            raw_rows = [r for r in raw_rows
                        if not (r.get("country") or "").strip()
                        or (r.get("country") or "").upper() in want]
            log(f"[*] 地区筛选 {','.join(sorted(want))}：{before} -> {len(raw_rows)} 条")
    elif source == "asn":
        asns = resolve_asns(ASNS)
        if not asns:
            log("[!] -source asn 需要指定 -asns（名字或 AS 号）。可用名字：")
            log(f"    {', '.join(sorted(ASN_GROUPS))}")
            return 5
        log(f"[*] 查询 {len(asns)} 个 ASN 的宣告网段，"
            f"{'全量（不采样）' if not ASN_SAMPLE else f'共采样 {ASN_SAMPLE} 个 /24'}")

        # ---- 逐 ASN 端到端处理，不落地大文件 ----
        # 原来先把所有候选写 ip.csv（vps 全量要 10GB），磁盘只有 3GB，实测崩了 7 次。
        # 增量写池子：每测完一批就把新发现并进去。
        # 一轮 24 小时，等整轮跑完再写的话下游这 24 小时拿到的都是旧数据；
        # 而且中途崩了这一轮就全白费。
        # 节流：最多每 30 秒写一次盘（池子大了每次读+写要几 MB）。
        _inc = {'t': 0.0, 'n': 0}

        def _on_found(rows):
            now = time.time()
            _inc['n'] += len(rows)
            if now - _inc['t'] < 30.0 and _inc['n'] < 100:
                return
            _inc['t'] = now
            _inc['n'] = 0
            update_pool(rows, complete=False)   # 并集，只增不减

        found, complete = run_asn_pipeline(asns, ASN_SAMPLE, extra_run_args, round_no,
                                           on_found=_on_found)
        write_status(candidates=found, kept=found, source="asn",
                     asns=ASNS, asn_sample=ASN_SAMPLE, phase="fetched")

        # ---- 池子 ----
        if POOL_ENABLED:
            pool_rows = read_stage1_results() if UPSTREAM_STAGE1_ONLY else []
            if pool_rows:
                update_pool(pool_rows, complete=complete)
            else:
                log("[!] 本轮没找到反代，池子保持不变（不做空替换）")

        final = read_final_summary()
        write_status(phase="done", final=final,
                     pool=pool_summary() if POOL_ENABLED else None)
        send_notification(round_no, (found, found), found, loop_secs)
        return 0

    else:                                    # fofa
        if not FOFA_KEY:
            log("[!] 未配置 FOFA API key。三种配置方式（任选其一）：")
            log("    1) config.ini 里填 FOFA_KEY = \"你的key\"")
            log("    2) 环境变量 FOFA_KEY=你的key")
            log("    3) 命令行 python fetch_ips.py -key 你的key")
            log("    key 获取地址：https://fofa.info/personalData")
            log("    不想用 FOFA：python fetch_ips.py -source ipdb（免费免 key）")
            return 2
        log("[*] 校验 API 凭据与可用字段 ...")
        try:
            fields = resolve_fields(FOFA_FIELDS, FOFA_TIMEOUT, FOFA_RETRIES, DEBUG)
        except FetchError as e:
            log(f"[!] FOFA 不可用：{e}")
            log("    常见原因：key 错误/已过期、账号无 API 查询权限、免费额度已用尽。")
            return 3
        log(f"[*] 凭据有效，可用字段：{fields}\n")
        for region in regions:
            log(f"[*] 抓取 {region or 'ALL'} ...")
            try:
                raw_rows.extend(fetch_region(
                    region, template, FOFA_EXTRA_QUERY, exclude_asns, fields,
                    FOFA_MAX_PER_REGION, FOFA_PAGE_SIZE, a.full or FOFA_FULL,
                    FOFA_DELAY, FOFA_TIMEOUT, FOFA_RETRIES, DEBUG))
            except FetchError as e:
                log(f"[!] {region} 抓取失败：{e}（已跳过该地区，继续后面的）")

    # ---- 归一化 / 写出 ----
    exclude_nets = _parse_cidrs(FOFA_EXCLUDE_CIDRS)
    skip_ips = _load_skip_ips(FOFA_SKIP_FILE)
    if skip_ips:
        log(f"[*] 已从 {FOFA_SKIP_FILE} 载入 {len(skip_ips)} 个 IP 用于去重跳过")

    # 允许的端口集合：PORTS 为空则不限制（列表源里是什么端口就测什么）
    want_ports = {p.strip() for p in as_list(PORTS)} if PORTS.strip() else set()
    rows, stats = normalize(raw_rows, want_ports, exclude_nets,
                            skip_ips, exclude_asns, limit=a.max or 0)

    log("")
    log(f"[*] 原始 {stats['total']} 条 -> 保留 {len(rows)} 条唯一 IP")
    log(f"    剔除：端口不符 {stats['port']}、CF自家ASN {stats['asn']}、"
        f"非公网 {stats['not_public']}、无效/非IPv4 {stats['bad_ip']}、"
        f"命中排除网段 {stats['excluded']}、已收录跳过 {stats['skipped']}、重复 {stats['dup']}")
    if stats.get("truncated"):
        log(f"    按 -max {a.max} 截断，丢弃 {stats['truncated']} 条")

    if not rows:
        log("[!] 没有抓到可用 IP。可换数据源、换地区，或放宽过滤后重试。")
        return 4

    write_csv(csv_path, rows)
    log(f"[*] 已写出 {len(rows)} 个 IP -> {csv_path}")

    dist = {}
    for r in rows:
        dist[r["country"]] = dist.get(r["country"], 0) + 1
    if dist:
        top = sorted(dist.items(), key=lambda kv: -kv[1])[:10]
        log("[*] 地区分布：" + "  ".join(f"{k or '??'}={v}" for k, v in top))

    write_status(phase="tested" if not (a.run or FOFA_RUN) else "testing",
                 candidates=stats["total"], kept=len(rows),
                 countries={k or "??": v for k, v in dist.items()},
                 csv=csv_path)

    if a.run or FOFA_RUN:
        rc, avail, qual = run_tester(csv_path, extra_run_args)
        final = read_final_summary()
        # 这一轮是否【扫全了】。只有扫全了才能做差集（替换）：
        # 全量扫描下「没出现在结果里」= 测了且失败 = 确定死亡；
        # 中途中断时「没出现」可能只是没扫到，做差集会误杀。
        complete = (rc == 0)
        if POOL_ENABLED:
            if UPSTREAM_STAGE1_ONLY:
                pool_rows = read_stage1_results()
            else:
                pool_rows = final.get("rows") or []
            update_pool(pool_rows, complete=complete)
        write_status(phase="done", test_rc=rc, final=final,
                     pool=pool_summary() if POOL_ENABLED else None)
        send_notification(round_no, avail, qual, loop_secs)
        return rc

    log("")
    log(f"[*] 下一步：python ip.py -i {os.path.basename(csv_path)}")
    log("    或直接：python fetch_ips.py -run")
    return 0


# ==================== Main ====================
def apply_cli(a, quiet_banner=False):
    """把命令行参数套到全局配置上（优先级：命令行 > 环境变量 > config.ini）。

    抽成函数是因为循环模式下每轮都会重读 config.ini，
    重读之后必须再把命令行覆盖套一遍，否则命令行会被配置盖掉。
    """
    global FOFA_KEY, FOFA_EMAIL, FOFA_REGIONS, FOFA_CSV_OUTPUT, FOFA_PRESET
    global FOFA_QUERY_TEMPLATE, FOFA_MAX_PER_REGION, FOFA_FIELDS, DEBUG, IPDB_TYPES
    global IPDB_CF_SAMPLE, LIST_URLS, LIST_REGIONS, ASNS, ASN_SAMPLE, ASN_REGIONS
    global ASN_EXCLUDE_REGIONS, NOTIFY_CHANNEL, NOTIFY_TARGET, PORTS, THREADS, LOOP
    global OUTPUT_REGIONS, OUTPUT_SPLIT, CHUNK_SIZE, FULL_SCAN

    if a.debug:
        DEBUG = True
    if a.key:
        FOFA_KEY = a.key.strip()
    if a.email:
        FOFA_EMAIL = a.email.strip()
    if a.regions:
        FOFA_REGIONS = a.regions
    if a.size is not None:
        FOFA_MAX_PER_REGION = max(1, a.size)
    if a.output:
        FOFA_CSV_OUTPUT = a.output
    if a.preset:
        FOFA_PRESET = a.preset
    if a.query:
        FOFA_QUERY_TEMPLATE = a.query.strip()
    if a.fields:
        FOFA_FIELDS = a.fields.strip()
    if a.ipdb_types is not None:
        IPDB_TYPES = a.ipdb_types.strip()
    if a.list_urls is not None:
        LIST_URLS = a.list_urls.strip()
    if a.list_regions is not None:
        LIST_REGIONS = a.list_regions.strip()
    if a.asns is not None:
        ASNS = a.asns.strip()
    if a.asn_sample is not None:
        # 注意不能用 max(1, ...)：0 是有意义的值，表示「全量不采样」。
        # 写成 max(1, 0) 会把全量模式悄悄变成「只取 1 个」。
        ASN_SAMPLE = max(0, a.asn_sample)
        if ASN_SAMPLE > 2000 and not quiet_banner:
            log(f"[!] -asn-sample {ASN_SAMPLE} 偏大。扫描第三方网段请克制，建议 50~200；")
            log("    真要全量扫就填 0（表示不采样、扫全部 /24）。")
    if a.asn_regions is not None:
        ASN_REGIONS = a.asn_regions.strip()
    if a.asn_exclude_regions is not None:
        ASN_EXCLUDE_REGIONS = a.asn_exclude_regions.strip()
    if a.ports is not None:
        PORTS = a.ports.strip()
    if getattr(a, "full_scan", False):
        FULL_SCAN = True
    if a.cf_sample is not None:
        IPDB_CF_SAMPLE = max(0, a.cf_sample)
        if IPDB_CF_SAMPLE > 200 and not quiet_banner:
            log(f"[!] -cf-sample {IPDB_CF_SAMPLE} 偏大。官方网段采样建议 10~50，")
            log("    采样再多也是在同一个 anycast 网络里打转，收益递减还费时间。")


def main():
    global FOFA_KEY, FOFA_EMAIL, FOFA_REGIONS, FOFA_CSV_OUTPUT, FOFA_PRESET
    global FOFA_QUERY_TEMPLATE, FOFA_MAX_PER_REGION, FOFA_FIELDS, DEBUG, IPDB_TYPES
    global IPDB_CF_SAMPLE, LIST_URLS, LIST_REGIONS, ASNS, ASN_SAMPLE, ASN_REGIONS
    global ASN_EXCLUDE_REGIONS, NOTIFY_CHANNEL, NOTIFY_TARGET, PORTS

    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("-config", default=None)
    pre_args, _ = pre.parse_known_args()
    config_path = pre_args.config or DEFAULT_CONFIG_FILE
    if not os.path.isabs(config_path):
        config_path = os.path.abspath(config_path)

    cfg = load_config(config_path)
    apply_config(cfg)
    apply_env()

    p = argparse.ArgumentParser(
        description="多源候选 IP -> ip.csv -> ip.py 自动化流水线",
        epilog="提示：-- 之后的参数会原样透传给 ip.py。")
    p.add_argument("-config", default=None, help="配置文件路径，默认 ./config.ini")
    p.add_argument("-source", default="auto", choices=["auto", "ipdb", "list", "asn", "fofa", "csv"],
                   help="数据源：list（第三方列表）/ asn（扫服务商网段）/ ipdb / fofa / csv / auto")
    p.add_argument("-asns", default=None,
                   help=f"ASN 段扫描目标：{', '.join(sorted(ASN_GROUPS))}（厂商名会自动展开成它全部 ASN），"
                        f"或直接写 AS 号，逗号分隔")
    p.add_argument("-asn-sample", type=int, default=None, metavar="N",
                   help=f"每个 ASN 采样多少个 /24，默认 {ASN_SAMPLE}（建议 50~200）")
    p.add_argument("-asn-regions", default=None,
                   help=f"ASN 采样后只保留这些地区（白名单），默认 '{ASN_REGIONS}'（空=不启用）")
    p.add_argument("-asn-exclude-regions", default=None,
                   help=f"ASN 采样后排除这些地区（黑名单），默认 '{ASN_EXCLUDE_REGIONS}'")
    p.add_argument("-once", action="store_true",
                   help="只跑一轮就退出（忽略配置里的 LOOP）。"
                        "Web 面板的「立即跑一轮」和定时任务用这个。")
    p.add_argument("-full-scan", action="store_true",
                   help="每个 /24 的 254 个地址全部测（而不是只抽 1 个）。"
                        "反代是 unicast、每个 IP 独立，抽样会漏掉 254/255。"
                        "代价：vps 档位一轮约 50 小时")
    p.add_argument("-ports", default=None,
                   help=f"测哪些端口，逗号分隔。CF 的 HTTPS 端口是 "
                        f"443,2053,2083,2087,2096,8443。默认 '{PORTS}'，空=不限制。"
                        f"注意是乘法：6 个端口 = 探测点数 ×6")
    p.add_argument("-list-urls", default=None,
                   help=f"第三方列表源：{', '.join(sorted(LIST_SOURCES))}，或完整 URL，逗号分隔")
    p.add_argument("-list-regions", default=None,
                   help=f"第三方列表只保留这些地区，默认 {LIST_REGIONS}，传空字符串=不筛选")
    p.add_argument("-max", type=int, default=None,
                   help="最多取多少个候选 IP（在过滤后截断），防止过量测速")
    p.add_argument("-loop", type=int, default=0, metavar="SECONDS",
                   help="每 N 秒自动跑一轮，0=只跑一次。容器/定时任务用")
    p.add_argument("-ipdb-types", default=None,
                   help=f"IPDB 列表类型，; 分隔，默认 {IPDB_TYPES}")
    p.add_argument("-cf-sample", type=int, default=None, metavar="N",
                   help=f"从 Cloudflare 官方网段采样 N 个 IP 一起测（建议 10~50），"
                        f"默认 {IPDB_CF_SAMPLE}，0=不采样官方 IP")
    p.add_argument("-preset", default=None, choices=sorted(QUERY_PRESETS),
                   help=f"FOFA 查询预设，默认 {FOFA_PRESET}")
    p.add_argument("-query", default=None, help="自定义 FOFA 语法模板（覆盖 preset）")
    p.add_argument("-regions", default=None, help=f"地区列表，逗号分隔，例：HK,JP；默认 {FOFA_REGIONS}")
    p.add_argument("-size", type=int, default=None, help=f"每个地区抓取上限，默认 {FOFA_MAX_PER_REGION}")
    p.add_argument("-o", "--output", default=None, help=f"输出 CSV，默认 {FOFA_CSV_OUTPUT}")
    p.add_argument("-key", default=None, help="FOFA API key（也可写进 config.ini 或环境变量 FOFA_KEY）")
    p.add_argument("-email", default=None, help="FOFA 账号邮箱（老账号需要）")
    p.add_argument("-fields", default=None, help="自定义 FOFA 返回字段")
    p.add_argument("-full", action="store_true", help="搜索全部历史数据（默认只搜一年内）")
    p.add_argument("-run", action="store_true", help="抓取完成后自动调用 ip.py")
    p.add_argument("-dry-run", action="store_true", help="只打印将要执行的查询，不联网抓取")
    p.add_argument("-self-test", action="store_true", help="不联网抓取，用内置样例验证整条链路")
    p.add_argument("-check-env", action="store_true",
                   help="只输出环境报告（代理/隧道网卡），供 run.bat 调用")
    p.add_argument("-import-csv", default=None,
                   help="导入 FOFA 网页版「导出 CSV」的结果文件（没有 API 权限时用）")
    p.add_argument("-debug", action="store_true", help="打印调试信息")
    a, passthrough = p.parse_known_args()

    # 供 run.bat 调用的轻量环境探测：只输出 KEY=VALUE，不带横幅
    if a.check_env:
        for line in env_report():
            print(line)
        return 0

    apply_cli(a, quiet_banner=True)

    # 清掉 -run 之后可能被 argparse 吞掉的 "--" 分隔符
    passthrough = [x for x in passthrough if x != "--"]
    extra_run_args = passthrough + ([x for x in FOFA_RUN_ARGS.split() if x] if FOFA_RUN_ARGS else [])
    # 透传参数里没写 -threads 就用配置里的 THREADS，
    # 这样 Web 面板改线程数就能生效，不用动 systemd unit。
    if "-threads" not in extra_run_args and THREADS:
        extra_run_args += ["-threads", str(THREADS)]
    if "-d" not in extra_run_args:
        extra_run_args += ["-d", "5"]
    if "-log" not in extra_run_args:
        extra_run_args += ["-log", "-quiet"]
    if "-chunk-size" not in extra_run_args and CHUNK_SIZE:
        extra_run_args += ["-chunk-size", str(CHUNK_SIZE)]

    source = a.source
    if source == "auto":
        if a.import_csv:
            source = "csv"
        elif LIST_URLS.strip():
            # 实测：第三方列表的 443 条目可用率远高于 IPDB 的池子
            # （zip 的 443 条目 8 个里 7 个可用，IPDB bestproxy 几乎全是死 IP）
            source = "list"
        elif IPDB_TYPES.strip():
            source = "ipdb"
        else:
            source = "fofa"

    # 循环间隔：-once 最高优先（一次性跑），其次命令行 -loop，最后配置 LOOP。
    # 注意不能写成 max(0, a.loop or LOOP) —— 那样任何一次不带 -loop 的调用
    # 都会被配置里的 LOOP 变成常驻循环，一次性跑就永远不返回了（踩过）。
    if a.once:
        interval = 0
    elif a.loop is not None:
        interval = max(0, a.loop)
    else:
        interval = max(0, LOOP)
    round_no = 0
    st0 = cleanup_outputs()
    log(f"[*] 磁盘：可用 {st0['free_mb']} MB，清理释放 {st0['freed_mb']} MB "
        f"（日志保留 {KEEP_LOGS} 个 / 结果保留 {KEEP_RESULTS} 份）")
    write_status(state="starting", source=source, loop=interval,
                 asns=ASNS, asn_sample=ASN_SAMPLE, free_mb=st0["free_mb"])
    while True:
        round_no += 1
        if round_no > 1:
            # 每轮重读 config.ini —— 这样在 Web 面板改的设置下一轮就生效，
            # 不用重启服务。重读后要把命令行覆盖再套一遍（它优先级最高）。
            try:
                apply_config(load_config(config_path))
                apply_env()
                apply_cli(a, quiet_banner=True)
                if a.once:
                    interval = 0
                elif a.loop is not None:
                    interval = max(0, a.loop)
                else:
                    interval = max(0, LOOP)
                log(f"[*] 已重新加载 config.ini（间隔 {interval}s，"
                    f"档位 {ASNS}，采样 {ASN_SAMPLE}，端口 {PORTS}）")
            except Exception as e:               # noqa: BLE001
                log(f"[!] 重读配置失败，沿用上一轮的配置：{e}")
        disk_guard()
        try:
            rc = run_once(a, source, extra_run_args, round_no, interval)
        except KeyboardInterrupt:
            log("\n[*] 已中断。")
            write_status(state="stopped", round=round_no, last_rc=0)
            return 0
        stc = cleanup_outputs()
        write_status(round=round_no, last_rc=rc,
                     state="sleeping" if interval > 0 else "finished",
                     next_run_in=interval, free_mb=stc["free_mb"])
        if interval <= 0:
            return rc
        log("")
        log(f"[*] 本轮结束（退出码 {rc}），{interval} 秒后开始下一轮。Ctrl+C 停止。")
        log(f"[*] 磁盘：可用 {stc['free_mb']} MB（本轮清理释放 {stc['freed_mb']} MB）")
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            log("\n[*] 已停止。")
            write_status(state="stopped", round=round_no)
            return 0


if __name__ == "__main__":
    sys.exit(main())
