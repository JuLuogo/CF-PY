#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cloudflare SNI Proxy IP Tester - Windows/Ubuntu."""
import argparse, csv, ipaddress, json, os, platform, re, subprocess, sys, threading, time, urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

# ==================== 默认配置（可被 config.ini 覆盖） ====================
DEFAULT_CONFIG_FILE = "./config.ini"

# 强制 stdout/stderr 用 UTF-8。
# 很多 VPS 没配 locale（LANG 为空），Python 会退回 C locale，stdout 变成
# latin-1，一 print 中文就 UnicodeEncodeError 直接崩。
# 在代码里兜住比依赖 systemd unit 里的环境变量可靠得多。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

token = ""       # ipinfo token
downloadBytes = 1024 * 1024 * 20
previousCountry = "HK"
hops = 40

DEFAULT_INPUT = "./ip.csv"
DEFAULT_IP_OUTPUT = "./ip.txt"
DEFAULT_CSV_OUTPUT = "{path}/bestips-{date}{num}.csv"
OUTPUT_FOLDER_PATH = "./output/{date}"
DEFAULT_THREADS = 2
MAX_IO_THREADS = 100
DEFAULT_SPEED_WORKERS = 5

SPEED_TEST_URL = "https://speed.cloudflare.com/__down?during=download&bytes={bytes}"
AVAILABILITY_URL = "https://www.cloudflare.com/cdn-cgi/trace"
AVAILABILITY_HOST = "www.cloudflare.com"

PING_COUNT = 4
PING_TIMEOUT_SEC = 2
CURL_TIMEOUT_SEC = 5
SPEED_TEST_TIMEOUT = 20
MAX_LATENCY_MS = 300.0
MIN_SPEED_MBPS = 1.0
TRACEROUTE_TIMEOUT = 35
DEBUG = False
LOG_FILE = None

# ---- 日志体积控制（1GB 小硬盘 VPS 必需） ----
# 逐条进度日志是磁盘杀手：20 万个候选一轮能写十几 MB，全量扫描能写上百 MB。
# PROGRESS_EVERY > 1 时抽样输出（比如每 500 条一行），日志体积直接降两个数量级。
PROGRESS_EVERY = 1
# 日志文件上限，超过就砍掉前半部分只留尾部 1/4。
LOG_MAX_BYTES = 8 * 1024 * 1024
_log_writes = 0

# ---- 丢包与排序（为 24 小时批量优选设计） ----
# 丢包超过 MAX_LOSS_PCT 直接淘汰。丢包比延迟更致命：
# 一次 TLS 握手要几个来回，5% 丢包就能让握手频繁重传、体感极差。
MAX_LOSS_PCT = 30.0
# 排序综合评分 = 延迟 × (1 + 丢包率/100 × LOSS_PENALTY)
#   0% 丢包 → 分数 = 延迟
#  10% 丢包 → 分数 = 延迟 × 1.5
#  30% 丢包 → 分数 = 延迟 × 2.5
# 系数越大越"嫌弃"丢包。5 是个温和的默认值。
LOSS_PENALTY = 5.0
# 最终只保留排序后的前 N 个（0 = 不限制）。150~200 个足够推 DNS 分流用。
TOP_N = 200
# 排序模式：
#   "score"   = 按 延迟+丢包 综合评分升序（批量优选场景，推荐）
#   "country" = 原版逻辑：先把 previousCountry 的排前面，再按速度降序
SORT_MODE = "score"

ONLY_OUTPUT_BEST_ROUTE = False

# ==================== 两套输出 ====================
# 需求：维护两套列表 ——
#   第一套：所有可用 IP，完全不限制地区
#   第二套：只保留指定地区的 IP
# 两者都写成文件，Web 面板和 API 各自提供。
OUTPUT_REGIONS = "HK,JP,SG,KR,TW"   # 第二套的地区白名单
OUTPUT_SPLIT = True                 # 是否额外产出第二套（关掉就只出全量）

# 线路缓存：traceroute 结果按 /24 网段缓存到本地文件，避免重复 tracert
ROUTE_CACHE_FILE = "./route_cache.json"
ROUTE_CACHE_PREFIXLEN = 24

# 手工覆盖规则：优先级高于缓存与 traceroute
IP_OVERRIDE_FILE = "./ip_override.json"

# 用户规则：高级线路覆盖普通线路
ROUTE_PREFIX_RULES = {
    "CN2": [("59.43.", 100)],
    "163": [("202.97.", 60)],
    "169": [("219.158.", 70)],
    "ANet": [("218.105.", 80), ("210.", 80)],
    "CMI": [("221.183.", 80)],
    "CMIN2": [("223.120.", 100)],
}
AS_ROUTE_MAP = {
    "4809": "CN2", "4134": "163", "4837": "169",
    "9929": "ANet", "58453": "CMI", "9808": "CMIN2",
}
HIGH_END_ROUTE_NAMES = {"CN2", "CMIN2"}
HIGH_END_ASNS = {"4809", "9929", "9808"}
ROUTE_PRIORITY = {"Unknown": 0, "163": 60, "169": 70, "ANet": 80,
                  "CMI": 80, "CN2": 100, "CMIN2": 100}
COLO_CITY_MAP = {"NRT":"Tokyo","KIX":"Osaka","LAX":"Los Angeles","SJC":"San Jose",
                 "SEA":"Seattle","DFW":"Dallas","IAD":"Washington","ORD":"Chicago",
                 "MIA":"Miami","SIN":"Singapore","AMS":"Amsterdam","FRA":"Frankfurt",
                 "LHR":"London","HKG":"Hong Kong"}
MAINLAND_CN_CODES = {"CN"}

# ==================== 线程安全状态 ====================
print_lock = threading.Lock()
log_lock = threading.Lock()
cache_lock = threading.RLock()
ip_info_cache = {}

# 手工覆盖规则：[(ip_network, {country/city/route/asn/as_name})]
override_networks = []
override_lock = threading.RLock()

# 线路缓存：{cidr_str: {"route":..., "country_seq":[...], "route_asns":[...]}}
route_cache = {}
route_cache_lock = threading.RLock()


# ==================== 日志 ====================
def _cap_log():
    """日志文件超过上限就砍掉前面的部分，只留尾部 1/4。

    1GB 小硬盘上，全量扫描一轮能写上百 MB 日志，不设上限会直接爆盘。
    """
    try:
        if not LOG_FILE or os.path.getsize(LOG_FILE) <= LOG_MAX_BYTES:
            return
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        keep = lines[-(len(lines) // 4 or 200):]
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.writelines(keep)
    except OSError:
        pass


def log(msg):
    """控制台始终打印；仅在 LOG_FILE 非空时写日志文件。"""
    global _log_writes
    line = f"{datetime.now():%H:%M:%S} {msg}"
    with print_lock:
        print(line, flush=True)
    if LOG_FILE:
        with log_lock:
            try:
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                _log_writes += 1
                if _log_writes % 500 == 0:
                    _cap_log()
            except OSError:
                pass


def progress(stage, done, total, msg):
    """逐条进度。PROGRESS_EVERY > 1 时抽样输出，避免小硬盘被日志撑爆。"""
    if PROGRESS_EVERY > 1 and (done % PROGRESS_EVERY) and done != total:
        return
    log(f"[{stage} {done}/{total}] {msg}")


def valid_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def public_ip(ip):
    try:
        x = ipaddress.IPv4Address(ip)
        return not (x.is_private or x.is_loopback or x.is_link_local or x.is_multicast or x.is_reserved or x.is_unspecified)
    except ValueError:
        return False


def run_command(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        raw = p.stdout or b""
        text = None
        for enc in ("utf-8", "gb18030", "cp936", "big5", "cp1252"):
            try:
                text = raw.decode(enc)
                break
            except UnicodeDecodeError:
                pass
        if text is None:
            text = raw.decode("utf-8", errors="replace")
        if DEBUG:
            log(f"[DEBUG] RC={p.returncode} CMD={' '.join(cmd)} OUT={text[:500]}")
        return p.returncode == 0, text
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except FileNotFoundError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)


def parse_threads(v):
    if str(v).lower() == "max":
        return MAX_IO_THREADS
    try:
        return max(1, int(v))
    except (ValueError, TypeError):
        print(f"[!] 无效线程数 {v}，使用 {DEFAULT_THREADS}", file=sys.stderr)
        return DEFAULT_THREADS


def flag(cc):
    cc = (cc or "").upper()
    if not re.fullmatch(r"[A-Z]{2}", cc):
        return cc
    return "".join(chr(ord(c) + 0x1F1E6 - ord("A")) for c in cc)


def fmt_latency(v):
    return f"{v:.1f}ms"


def fmt_speed(v):
    return f"{v:.1f}MB/s"


# ==================== 配置读取 ====================
def strip_comment(line):
    out = []
    quote = None
    esc = False
    for ch in line:
        if esc:
            out.append(ch)
            esc = False
            continue
        if ch == "\\":
            out.append(ch)
            esc = True
            continue
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        else:
            if ch in ("'", '"'):
                quote = ch
                out.append(ch)
            elif ch == "#":
                break
            else:
                out.append(ch)
    return "".join(out)


def parse_config_value(v):
    v = v.strip()
    if v == "":
        return ""
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        return v[1:-1]
    low = v.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("none", "null"):
        return None
    if re.fullmatch(r"[0-9+\-*/().\s]+", v):
        try:
            return eval(v, {"__builtins__": None}, {})
        except Exception:
            pass
    return v


def load_config(path):
    cfg = {}
    if not os.path.exists(path):
        print(f"[!] 配置文件不存在: {path}，使用内置默认配置")
        return cfg

    lines = None
    for enc in ("utf-8-sig", "utf-8", "gb18030", "gbk"):
        try:
            with open(path, "r", encoding=enc) as f:
                lines = f.readlines()
            break
        except UnicodeDecodeError:
            continue
        except OSError as e:
            print(f"[!] 读取配置文件失败: {e}")
            return cfg

    if lines is None:
        print("[!] 无法识别配置文件编码，使用内置默认配置")
        return cfg

    for line in lines:
        line = strip_comment(line).strip()
        if not line or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip()
        if v.endswith(";"):
            v = v[:-1].strip()
        cfg[k] = parse_config_value(v)
    return cfg


def apply_config(cfg):
    global token, downloadBytes, previousCountry, hops, ONLY_OUTPUT_BEST_ROUTE
    global OUTPUT_REGIONS, OUTPUT_SPLIT
    global USE_NATIVE_SOCKET, EXTRA_HTTP_PORTS, SOCK_BUF_BYTES, SOCK_BUF_ENABLED
    global USE_ASYNCIO, ASYNCIO_CONCURRENCY
    global STAGE0_ENABLED, STAGE0_TIMEOUT, STAGE0_CONCURRENCY
    global DEFAULT_INPUT, DEFAULT_IP_OUTPUT, DEFAULT_CSV_OUTPUT, OUTPUT_FOLDER_PATH
    global DEFAULT_THREADS, MAX_IO_THREADS, DEFAULT_SPEED_WORKERS
    global SPEED_TEST_URL, AVAILABILITY_URL, AVAILABILITY_HOST
    global PING_COUNT, PING_TIMEOUT_SEC, CURL_TIMEOUT_SEC, SPEED_TEST_TIMEOUT
    global MAX_LATENCY_MS, MIN_SPEED_MBPS, TRACEROUTE_TIMEOUT, DEBUG, LOG_FILE
    global MAX_LOSS_PCT, LOSS_PENALTY, TOP_N, SORT_MODE
    global PROGRESS_EVERY, LOG_MAX_BYTES
    global ROUTE_CACHE_FILE, ROUTE_CACHE_PREFIXLEN, IP_OVERRIDE_FILE

    if "token" in cfg:
        token = str(cfg["token"])
    if "downloadBytes" in cfg:
        try:
            downloadBytes = int(cfg["downloadBytes"])
        except Exception:
            pass
    if "previousCountry" in cfg:
        prev = cfg["previousCountry"]
        if prev is None or str(prev).strip() == "":
            previousCountry = "HK"
        else:
            previousCountry = str(prev).strip().upper()
    else:
        previousCountry = "HK"
    if "hops" in cfg:
        try:
            hops = int(cfg["hops"])
        except Exception:
            pass
    if "ONLY_OUTPUT_BEST_ROUTE" in cfg:
        ONLY_OUTPUT_BEST_ROUTE = bool(cfg["ONLY_OUTPUT_BEST_ROUTE"])
    if "OUTPUT_REGIONS" in cfg:
        OUTPUT_REGIONS = str(cfg["OUTPUT_REGIONS"] or "").strip().strip('"')
    if "OUTPUT_SPLIT" in cfg:
        OUTPUT_SPLIT = bool(cfg["OUTPUT_SPLIT"])
    if "USE_NATIVE_SOCKET" in cfg:
        USE_NATIVE_SOCKET = bool(cfg["USE_NATIVE_SOCKET"])
    if "HTTP_PORTS" in cfg:
        EXTRA_HTTP_PORTS = {int(x) for x in re.split(r"[,;\s]+", str(cfg["HTTP_PORTS"]).strip().strip('"'))
                            if x.strip().isdigit()}
    if "SOCK_BUF_BYTES" in cfg:
        SOCK_BUF_BYTES = max(2048, int(cfg["SOCK_BUF_BYTES"]))
    if "SOCK_BUF_ENABLED" in cfg:
        SOCK_BUF_ENABLED = bool(cfg["SOCK_BUF_ENABLED"])
    if "USE_ASYNCIO" in cfg:
        USE_ASYNCIO = bool(cfg["USE_ASYNCIO"])
    if "STAGE0_ENABLED" in cfg:
        STAGE0_ENABLED = bool(cfg["STAGE0_ENABLED"])
    if "STAGE0_TIMEOUT" in cfg:
        STAGE0_TIMEOUT = float(cfg["STAGE0_TIMEOUT"])
    if "STAGE0_CONCURRENCY" in cfg:
        STAGE0_CONCURRENCY = max(1, int(cfg["STAGE0_CONCURRENCY"]))
    if "ASYNCIO_CONCURRENCY" in cfg:
        ASYNCIO_CONCURRENCY = max(1, int(cfg["ASYNCIO_CONCURRENCY"]))
    if "DEFAULT_INPUT" in cfg:
        DEFAULT_INPUT = str(cfg["DEFAULT_INPUT"])
    if "DEFAULT_IP_OUTPUT" in cfg:
        DEFAULT_IP_OUTPUT = str(cfg["DEFAULT_IP_OUTPUT"])
    if "DEFAULT_CSV_OUTPUT" in cfg:
        DEFAULT_CSV_OUTPUT = str(cfg["DEFAULT_CSV_OUTPUT"])
    if "OUTPUT_FOLDER_PATH" in cfg:
        OUTPUT_FOLDER_PATH = str(cfg["OUTPUT_FOLDER_PATH"])
    if "DEFAULT_THREADS" in cfg:
        try:
            DEFAULT_THREADS = int(cfg["DEFAULT_THREADS"])
        except Exception:
            pass
    if "MAX_IO_THREADS" in cfg:
        try:
            MAX_IO_THREADS = int(cfg["MAX_IO_THREADS"])
        except Exception:
            pass
    if "DEFAULT_SPEED_WORKERS" in cfg:
        try:
            DEFAULT_SPEED_WORKERS = int(cfg["DEFAULT_SPEED_WORKERS"])
        except Exception:
            pass
    if "SPEED_TEST_URL" in cfg:
        SPEED_TEST_URL = str(cfg["SPEED_TEST_URL"])
    if "AVAILABILITY_URL" in cfg:
        AVAILABILITY_URL = str(cfg["AVAILABILITY_URL"])
    if "AVAILABILITY_HOST" in cfg:
        AVAILABILITY_HOST = str(cfg["AVAILABILITY_HOST"])
    if "PING_COUNT" in cfg:
        try:
            PING_COUNT = int(cfg["PING_COUNT"])
        except Exception:
            pass
    if "PING_TIMEOUT_SEC" in cfg:
        try:
            PING_TIMEOUT_SEC = int(cfg["PING_TIMEOUT_SEC"])
        except Exception:
            pass
    if "CURL_TIMEOUT_SEC" in cfg:
        try:
            CURL_TIMEOUT_SEC = int(cfg["CURL_TIMEOUT_SEC"])
        except Exception:
            pass
    if "SPEED_TEST_TIMEOUT" in cfg:
        try:
            SPEED_TEST_TIMEOUT = int(cfg["SPEED_TEST_TIMEOUT"])
        except Exception:
            pass
    if "MAX_LATENCY_MS" in cfg:
        try:
            MAX_LATENCY_MS = float(cfg["MAX_LATENCY_MS"])
        except Exception:
            pass
    if "MIN_SPEED_MBPS" in cfg:
        try:
            MIN_SPEED_MBPS = float(cfg["MIN_SPEED_MBPS"])
        except Exception:
            pass
    if "MAX_LOSS_PCT" in cfg:
        try:
            MAX_LOSS_PCT = float(cfg["MAX_LOSS_PCT"])
        except Exception:
            pass
    if "LOSS_PENALTY" in cfg:
        try:
            LOSS_PENALTY = float(cfg["LOSS_PENALTY"])
        except Exception:
            pass
    if "TOP_N" in cfg:
        try:
            TOP_N = int(cfg["TOP_N"])
        except Exception:
            pass
    if "SORT_MODE" in cfg:
        mode = str(cfg["SORT_MODE"]).strip().lower()
        if mode in ("score", "country"):
            SORT_MODE = mode
    if "TRACEROUTE_TIMEOUT" in cfg:
        try:
            TRACEROUTE_TIMEOUT = int(cfg["TRACEROUTE_TIMEOUT"])
        except Exception:
            pass
    if "DEBUG" in cfg:
        DEBUG = bool(cfg["DEBUG"])
    if "LOG_FILE" in cfg:
        LOG_FILE = cfg["LOG_FILE"]
    if "PROGRESS_EVERY" in cfg:
        try:
            PROGRESS_EVERY = max(1, int(cfg["PROGRESS_EVERY"]))
        except Exception:
            pass
    if "LOG_MAX_BYTES" in cfg:
        try:
            LOG_MAX_BYTES = max(64 * 1024, int(cfg["LOG_MAX_BYTES"]))
        except Exception:
            pass
    if "ROUTE_CACHE_FILE" in cfg:
        ROUTE_CACHE_FILE = str(cfg["ROUTE_CACHE_FILE"])
    if "ROUTE_CACHE_PREFIXLEN" in cfg:
        try:
            ROUTE_CACHE_PREFIXLEN = int(cfg["ROUTE_CACHE_PREFIXLEN"])
        except Exception:
            pass
    if "IP_OVERRIDE_FILE" in cfg:
        IP_OVERRIDE_FILE = str(cfg["IP_OVERRIDE_FILE"])


# ==================== 路径工具 ====================
def _ensure_parent(path):
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)


def _next_available(path):
    """如果 path 存在，返回在文件名后加 ' (x)' 的不冲突路径。"""
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    for i in range(1, 10000):
        cand = f"{base} ({i}){ext}"
        if not os.path.exists(cand):
            return cand
    return f"{base} ({int(time.time())}){ext}"


def resolve_output_path(template, output_folder, date_str):
    """解析输出路径模板。

    支持 {path} -> output_folder；{date} -> date_str；{num} -> 冲突时填充 " (x)"。
    不含 {path} 的相对路径相对于当前工作目录（主程序启动目录）解析。
    """
    if template is None or str(template).strip() == "":
        return None
    s = str(template)
    if "{path}" in s:
        s = s.replace("{path}", output_folder)
    elif not os.path.isabs(s):
        # 无 {path} 的相对路径 → 相对 CWD
        s = os.path.abspath(s)
    s = s.replace("{date}", date_str)
    s = os.path.normpath(s)

    if "{num}" in s:
        base = s.replace("{num}", "")
        _ensure_parent(base)
        return _next_available(base)
    _ensure_parent(s)
    return s


# ==================== IP Override ====================
def load_ip_override(path):
    """从 JSON 加载手工覆盖规则。

    格式：{ "cidr": {"country":"", "city":"", "route":"", "asn":"", "as_name":""} }
    支持 IPv4/IPv6 CIDR；文件不存在时返回 0，不报错。
    """
    global override_networks
    with override_lock:
        override_networks = []
        if not path or not os.path.exists(path):
            return 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[!] IP覆盖文件加载失败: {e}", file=sys.stderr)
            return 0
        if not isinstance(data, dict):
            print("[!] IP覆盖文件格式错误：顶层必须是对象", file=sys.stderr)
            return 0
        n = 0
        for cidr, ov in data.items():
            if not isinstance(ov, dict):
                continue
            try:
                net = ipaddress.ip_network(str(cidr), strict=False)
            except ValueError:
                print(f"[!] 无效CIDR，已忽略: {cidr}", file=sys.stderr)
                continue
            norm = {
                "country": str(ov.get("country", "") or "").upper(),
                "city": str(ov.get("city", "") or ""),
                "route": str(ov.get("route", "") or ""),
                "asn": str(ov.get("asn", "") or "").replace("AS", "").strip(),
                "as_name": str(ov.get("as_name", "") or ""),
            }
            override_networks.append((net, norm))
            n += 1
        return n


def override_for(ip):
    """返回命中覆盖规则的字段字典；未命中返回 None。"""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return None
    with override_lock:
        for net, data in override_networks:
            if obj in net:
                return dict(data)
    return None


# ==================== 线路缓存 ====================
def ip_segment(ip, prefixlen=ROUTE_CACHE_PREFIXLEN):
    try:
        return str(ipaddress.ip_network(f"{ip}/{prefixlen}", strict=False))
    except ValueError:
        return None


def load_route_cache(path):
    """读取线路缓存；新格式优先使用 country_seq；兼容旧格式（只有 tour）。"""
    with route_cache_lock:
        if not os.path.exists(path):
            return 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                n = 0
                for k, v in data.items():
                    if not isinstance(v, dict) or not v.get("route"):
                        continue
                    if isinstance(v.get("country_seq"), list):
                        seq = [str(x).upper() for x in v["country_seq"] if x]
                    elif v.get("tour") and str(v["tour"]) != "None":
                        # 旧格式兼容：tour 已去 CN 且已按当时 target 截断，
                        # 只能近似作为 country_seq 使用。
                        seq = [x.upper() for x in str(v["tour"]).split("→") if x]
                    else:
                        seq = []
                    route_cache[k] = {
                        "route": str(v.get("route", "")),
                        "country_seq": seq,
                        "route_asns": list(v.get("route_asns") or [])
                    }
                    n += 1
                return n
        except Exception as e:
            print(f"[!] 线路缓存加载失败: {e}", file=sys.stderr)
        return 0


def save_route_cache(path):
    with route_cache_lock:
        if not route_cache:
            return
        try:
            _ensure_parent(path)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(route_cache, f, ensure_ascii=False, indent=2, sort_keys=True)
            os.replace(tmp, path)
        except OSError as e:
            print(f"[!] 线路缓存保存失败: {e}", file=sys.stderr)


def cache_lookup(ip):
    seg = ip_segment(ip)
    if not seg:
        return None
    with route_cache_lock:
        entry = route_cache.get(seg)
        return dict(entry) if entry else None


def cache_store(ip, route, country_seq, route_asns):
    """存 country_seq（原始连续去重序列，未按 target 截断）。"""
    if route in (None, "", "Unknown", "Skipped"):
        return
    seg = ip_segment(ip)
    if not seg:
        return
    with route_cache_lock:
        route_cache[seg] = {
            "route": route,
            "country_seq": [str(c).upper() for c in (country_seq or []) if c],
            "route_asns": list(route_asns or [])
        }


# ==================== IPInfo ====================
def ipinfo_lite(ip, timeout=5):
    ov = override_for(ip)
    if ov:
        return {"asn": ov.get("asn", ""), "as_name": ov.get("as_name", ""),
                "country": ov.get("country", "").upper(),
                "city": ov.get("city", ""), "route": ov.get("route", "")}
    with cache_lock:
        if ip in ip_info_cache:
            return dict(ip_info_cache[ip])
    info = {"asn": "", "as_name": "", "country": "", "city": "", "route": ""}
    try:
        req = urllib.request.Request(
            f"https://api.ipinfo.io/lite/{ip}?token={token}",
            headers={"User-Agent": "Cloudflare-SNI-IP-Tester/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
        info.update({
            "asn": str(data.get("asn", "")).upper().replace("AS", "", 1),
            "as_name": str(data.get("as_name", "")),
            "country": str(data.get("country_code", "")).upper(),
            "city": str(data.get("city", "") or "")
        })
    except Exception as e:
        if DEBUG:
            log(f"[DEBUG] IPInfo {ip}: {e}")
    with cache_lock:
        ip_info_cache[ip] = dict(info)
    return info


def ipinfo_city(ip, timeout=5):
    info = ipinfo_lite(ip, timeout)
    if info.get("city"):
        return info
    try:
        req = urllib.request.Request(
            f"https://ipinfo.io/{ip}/json",
            headers={"User-Agent": "Cloudflare-SNI-IP-Tester/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
        if data.get("city"):
            info["city"] = str(data["city"])
        if data.get("country") and not info.get("country"):
            info["country"] = str(data["country"]).upper()
    except Exception as e:
        if DEBUG:
            log(f"[DEBUG] IPInfo city {ip}: {e}")
    with cache_lock:
        ip_info_cache[ip] = dict(info)
    return info


# ==================== CSV ====================
def _open_csv_any_encoding(path):
    """按可能的编码依次尝试打开 CSV。返回 (file, reader, 列名映射)。"""
    for enc in ("utf-8-sig", "utf-8", "gb18030", "gbk"):
        try:
            f = open(path, "r", encoding=enc, newline="")
            break
        except UnicodeDecodeError:
            continue
        except FileNotFoundError:
            print(f"[!] CSV不存在: {path}", file=sys.stderr)
            sys.exit(1)
    else:
        print("[!] 无法读取CSV编码", file=sys.stderr)
        sys.exit(1)

    reader = csv.DictReader(f)
    if not reader.fieldnames:
        f.close()
        print("[!] CSV缺少表头", file=sys.stderr)
        sys.exit(1)
    names = [x.strip().lower() for x in reader.fieldnames]
    cols = {
        "ip": next((reader.fieldnames[i] for i, n in enumerate(names) if n == "ip"), None),
        "country": next((reader.fieldnames[i] for i, n in enumerate(names)
                         if n in {"country", "country_code", "cc"}), None),
        "city": next((reader.fieldnames[i] for i, n in enumerate(names) if n == "city"), None),
        "port": next((reader.fieldnames[i] for i, n in enumerate(names) if n == "port"), None),
    }
    if not cols["ip"]:
        f.close()
        print("[!] CSV中没有ip列", file=sys.stderr)
        sys.exit(1)
    return f, reader, cols


def _row_to_item(row, cols):
    """CSV 一行 -> 候选 dict。无效返回 None。"""
    ip = (row.get(cols["ip"]) or "").strip()
    if not valid_ip(ip):
        return None
    # 端口：CSV 里没有 port 列或为空就默认 443。
    # CF 支持的 HTTPS 端口是 443/2053/2083/2087/2096/8443，
    # 只测 443 会丢掉近一半的反代（公开列表里 443 只占 57%）。
    port = "443"
    if cols["port"]:
        pv = (row.get(cols["port"]) or "").strip()
        if pv.isdigit() and 1 <= int(pv) <= 65535:
            port = pv
    return {
        "ip": ip,
        "port": port,
        "input_country": (row.get(cols["country"]) or "").strip().upper() if cols["country"] else "",
        "input_city": (row.get(cols["city"]) or "").strip() if cols["city"] else "",
    }


def iter_ips_chunked(path, chunk_size=20000):
    """流式读 CSV：一次产出一批候选，峰值内存只跟 chunk_size 有关。

    18 万个候选全读进来再测，光输入列表就 42MB；分批后只有一批在内存里。
    去重键 ip:port 用一个字符串集合维持（比 dict 轻得多）。
    """
    f, reader, cols = _open_csv_any_encoding(path)
    seen = set()
    buf = []
    with f:
        for row in reader:
            item = _row_to_item(row, cols)
            if item is None:
                continue
            key = f"{item['ip']}:{item['port']}"
            if key in seen:
                continue
            seen.add(key)
            buf.append(item)
            if len(buf) >= chunk_size:
                yield buf
                buf = []
    if buf:
        yield buf


def count_ips(path):
    """只数有多少条（不建列表），用来打日志。"""
    n = 0
    for chunk in iter_ips_chunked(path, 50000):
        n += len(chunk)
    return n


def load_ips(path):
    """一次性读全部候选（保留给需要随机访问的场景；主流程走 iter_ips_chunked）。"""
    out = []
    seen = set()
    for chunk in iter_ips_chunked(path, 50000):
        for item in chunk:
            key = f"{item['ip']}:{item['port']}"
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
    return out


# 每批提交多少个任务。一次性把 18 万个 Future 丢进线程池会吃掉上百 MB
# （每个 Future + 字典条目约 500 字节），小内存 VPS 上会把同机的其它服务
# 挤到 OOM。分批提交后峰值内存只跟批大小有关，跟总任务数无关。
TASK_BATCH = 2000


def submit_batched(ex, fn, items, batch=TASK_BATCH):
    """分批提交任务，边完成边产出 (item, result_or_exception)。

    用法跟 as_completed 一样，但内存占用有上界。
    """
    total = len(items)
    for start in range(0, total, batch):
        chunk = items[start:start + batch]
        fmap = {ex.submit(fn, x): x for x in chunk}
        for fut in as_completed(fmap):
            x = fmap[fut]
            try:
                yield x, fut.result(), None
            except Exception as e:               # noqa: BLE001
                yield x, None, e
        del fmap


# ==================== stage0：快速 TCP 预筛 ====================
# 为什么需要这一级：
#   实测随机云厂商 IP 里 90% 是黑洞（发 SYN 完全无响应），只能干等超时。
#   4650 万个 IP（vps 档位全量 = 18.2 万 /24 × 254）按 4 秒超时、800 并发算，
#   光等黑洞就要 58 小时。
#
#   stage0 只做一件事：TCP 三次握手，成功就放行。不做 TLS、不发请求，
#   所以单次开销极小，超时可以压到 1.5 秒，并发可以开到几千。
#   黑洞被快速筛掉，后面的 TLS+trace 只作用在真正活着的 IP 上。
#
# 代价：只连 TCP 不能判断是不是反代，所以它只是「预筛」不是「筛选」——
# 端口开着但不是反代的 IP 依然会被 stage1 淘汰，只是不用在 stage0 就淘汰。
STAGE0_ENABLED = True
STAGE0_TIMEOUT = 1.5        # 秒。黑洞靠这个值淘汰，调小更快但可能误杀慢线路
STAGE0_CONCURRENCY = 800    # 纯 TCP 连接很轻，但别开太大 ——
                            # 实测 3000 并发时内核 socket 缓冲吃掉 1.2GB，
                            # 726MB 的机器被榨干，SSH 都连不上。
                            # 会被 fetch_ips.safe_concurrency() 按内存和内核表再压一次。


async def _tcp_probe(addr, port, sem, timeout):
    """只做 TCP 连接，成功返回 True。"""
    import asyncio
    async with sem:
        w = None
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(addr, int(port or 443)), timeout)
            return True
        except (OSError, asyncio.TimeoutError, ValueError):
            return False
        finally:
            if w is not None:
                try:
                    w.close()
                except OSError:
                    pass


def stage0_tcp_filter(items, timeout=STAGE0_TIMEOUT, concurrency=STAGE0_CONCURRENCY,
                      on_progress=None):
    """快速 TCP 预筛：只留下端口真的开着的。"""
    import asyncio

    total = len(items)
    log(f"\n[*] stage0 预筛：TCP 连通性，{total} IP，"
        f"并发 {concurrency}，超时 {timeout}s")
    BATCH = max(concurrency * 4, 2000)
    out = []
    done = 0

    async def _run():
        nonlocal done
        for start in range(0, total, BATCH):
            chunk = items[start:start + BATCH]
            sem = asyncio.Semaphore(concurrency)
            res = await asyncio.gather(*[
                _tcp_probe(x["ip"], str(x.get("port") or "443"), sem, timeout)
                for x in chunk])
            for x, ok in zip(chunk, res):
                done += 1
                if ok:
                    out.append(x)
                if done % max(1, BATCH // 4) == 0 or done == total:
                    progress("s0", done, total,
                             f"{x['ip']} | {'open' if ok else 'blackhole'}")
                # 回调给调用方（fetch_ips 的逐网段流水线用它更新 IP 级进度）
                if on_progress is not None:
                    on_progress(done, total, x["ip"], ok)

    asyncio.run(_run())
    log(f"[*] stage0 完成：{len(out)}/{total} 端口开着"
        f"（筛掉 {total - len(out)} 个黑洞/拒绝，省下后面的 TLS 开销）")
    return out


# ==================== asyncio 版可用性检查 ====================
# 为什么单核 VPS 上 asyncio 明显更快：
#   线程池版每个在飞的请求占一个 OS 线程。1 核上开 500 个线程，
#   内核光做上下文切换就忙不过来，Python 的 GIL 还会让它们互相等。
#   asyncio 是单线程事件循环，500 个并发连接也只是 500 个 socket，
#   没有线程栈、没有上下文切换 —— 单核上这是数量级的差别。
#   （多核机器上两者差不多，实测都是 ~230 个/秒，瓶颈在网络 RTT。）
USE_ASYNCIO = True          # False 就退回线程池
ASYNCIO_CONCURRENCY = 300   # 单核建议 200~500；线程池模式别开这么高


def _tune_asyncio_sock(writer):
    """给 asyncio 的底层 socket 压缓冲。"""
    if not SOCK_BUF_ENABLED:
        return
    import socket as _socket
    try:
        sock = writer.get_extra_info("socket")
        if sock is not None:
            for opt in (_socket.SO_RCVBUF, _socket.SO_SNDBUF):
                try:
                    sock.setsockopt(_socket.SOL_SOCKET, opt, SOCK_BUF_BYTES)
                except OSError:
                    pass
    except Exception:                            # noqa: BLE001
        pass


async def _start_tls(reader, writer, host):
    """在已建立的裸连接上做 TLS 握手，返回新的 (reader, writer)。"""
    import asyncio
    loop = asyncio.get_running_loop()
    transport = writer.transport
    protocol = transport.get_protocol()
    new_transport = await loop.start_tls(
        transport, protocol, _SSL_CTX, server_hostname=host)
    protocol._transport = new_transport
    return reader, writer


def _ssl_ctx():
    import ssl as _ssl
    c = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    # 连的是任意第三方 IP，证书必然是别人的，所以不校验 ——
    # 判断的是「这个 IP 有没有把 SNI=host 的流量反代到 CF」，不是证书对不对。
    c.check_hostname = False
    c.verify_mode = _ssl.CERT_NONE
    try:
        c.set_ciphers("DEFAULT@SECLEVEL=1")
    except _ssl.SSLError:
        pass
    return c


_SSL_CTX = None


async def availability_async(ip, timeout, port, sem, req, host):
    """asyncio 版可用性检查。语义和 availability() 完全一致。

    HTTP 端口（80/8080/2052…）走明文，不建 TLS —— 拿 TLS 去连 80 永远连不通。
    """
    import asyncio
    use_tls = not port_uses_http(port)
    async with sem:
        w = None
        try:
            # 关键：先建裸连接 -> 压缓冲 -> 再包 TLS。
            # asyncio.open_connection(ssl=...) 会一次性做完，没机会插进去设缓冲。
            if use_tls:
                raw_r, raw_w = await asyncio.wait_for(
                    asyncio.open_connection(ip, int(port or 443)), timeout=timeout)
                _tune_asyncio_sock(raw_w)
                r, w = await asyncio.wait_for(
                    _start_tls(raw_r, raw_w, host), timeout=timeout)
            else:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(ip, int(port or 80)), timeout=timeout)
                _tune_asyncio_sock(w)
            w.write(req)
            await w.drain()
            data = await asyncio.wait_for(r.read(8192), timeout=timeout)
        except (OSError, asyncio.TimeoutError, ValueError):
            return None
        except Exception:                        # noqa: BLE001  ssl 各种异常
            return None
        finally:
            if w is not None:
                try:
                    w.close()
                except OSError:
                    pass

    info = {}
    for line in data.decode("utf-8", "replace").splitlines():
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip().lower(), v.strip()
        if k == "loc":
            info["cfcountry"] = v.upper()
        elif k == "colo":
            info["colo"] = v.upper()
    return info if info.get("cfcountry") else None


def stage1_async(items, concurrency, timeout, on_progress=None):
    """asyncio 版第一阶段。接口和 stage1() 一致，返回通过列表。"""
    import asyncio

    global _SSL_CTX
    if _SSL_CTX is None:
        _SSL_CTX = _ssl_ctx()

    total = len(items)
    log(f"\n[*] 第一阶段：可用性，{total} IP，asyncio 并发 {concurrency}")
    host = AVAILABILITY_HOST
    path = urlparse(AVAILABILITY_URL).path or "/cdn-cgi/trace"
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"User-Agent: cfip/1.0\r\nConnection: close\r\n\r\n").encode()

    # 分批喂给事件循环：一次把 18 万个协程全建出来会吃掉大量内存，
    # 分批后峰值只跟批大小有关。
    BATCH = max(concurrency * 4, 1000)
    out = []
    done = 0

    async def _batch(chunk):
        sem = asyncio.Semaphore(concurrency)
        return await asyncio.gather(*[
            availability_async(x["ip"], timeout, str(x.get("port") or "443"),
                               sem, req, host) for x in chunk])

    async def _run():
        nonlocal done
        for start in range(0, total, BATCH):
            chunk = items[start:start + BATCH]
            results = await _batch(chunk)
            for x, cf in zip(chunk, results):
                done += 1
                addr = x["ip"]
                if on_progress is not None:
                    on_progress(done, total, addr, bool(cf))
                port = str(x.get("port") or "443")
                tag = addr if port == "443" else f"{addr}:{port}"
                if not cf:
                    progress("availability", done, total,
                             f"{tag} | DROP: Cloudflare trace不可用")
                    continue
                y = dict(x)
                y.update(cf)
                out.append(y)
                progress("availability", done, total,
                         f"{tag} | PASS cfcountry={y.get('cfcountry', '')} "
                         f"colo={y.get('colo', '-')}")

    asyncio.run(_run())
    log(f"[*] 第一阶段完成：{len(out)}/{total}")
    return out


# ==================== Stage 1 ====================
# ==================== 原生 socket 实现（替代 curl 子进程）====================
# 为什么要有这套：
#   原来每测一个 IP 就 fork+exec 一个 curl。18 万个 IP 就是 18 万次进程创建，
#   实测在单核 VPS 上进程创建速率 19 个/秒、同时挂着 60 个 curl 进程，
#   CPU 全耗在 fork/exec 上，吞吐只有 11 个 IP/秒。
#   改用原生 socket 后没有进程创建，同一个连接流程走完就关，开销只剩网络本身。
USE_NATIVE_SOCKET = True   # False 就退回 curl（兼容排查用）

# ==================== socket 缓冲区上限（关键）====================
# 内核给每个 TCP socket 默认预留 208KB 收 + 208KB 发 = 416KB。
# 并发 3000 时就是 3000 x 416KB = 【1.2 GB 内核内存】——
# 而用户的机器总共只有 726MB。这些内存在内核 slab 里，不算进进程 RSS，
# 所以 OOM killer 不一定触发，但内核已经分配不出内存给 sshd，
# 表现就是「SSH 连上立刻被断开」（实测踩过，重启才恢复）。
#
# 我们每次只交换几百字节的 HTTP 响应，8KB 缓冲完全够。
# 显式设小之后每连接内核内存从 416KB 降到 16KB，降 26 倍。
SOCK_BUF_BYTES = 16384      # 收发各 16KB（内核会翻倍，实际约 32KB/连接）
SOCK_BUF_ENABLED = True

# CF 的端口分两类，必须走不同协议 —— 拿 HTTPS 去连 80 永远连不通。
#   HTTPS: 443 2053 2083 2087 2096 8443
#   HTTP : 80  8080 8880 2052 2082 2086 2095
# 不在表里的端口（比如 25565 这种非标口）默认按 HTTPS 试，
# 想强制走 HTTP 就用 config.ini 的 HTTP_PORTS 覆盖。
CF_HTTP_PORTS = {80, 8080, 8880, 2052, 2082, 2086, 2095}
CF_HTTPS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}
EXTRA_HTTP_PORTS = set()      # 用户额外指定要按 HTTP 测的端口


def port_uses_http(port):
    """这个端口该用明文 HTTP 还是 HTTPS。"""
    try:
        p = int(str(port or "443").strip())
    except (TypeError, ValueError):
        return False
    if p in EXTRA_HTTP_PORTS:
        return True
    if p in CF_HTTP_PORTS:
        return True
    if p in CF_HTTPS_PORTS:
        return False
    return False              # 非标端口默认按 HTTPS


def _tune_sock(sock):
    """把 socket 收发缓冲压到 SOCK_BUF_BYTES。

    必须在 connect 之后、发数据之前调 —— 太晚内核已经按默认值分配了。
    """
    if not SOCK_BUF_ENABLED:
        return
    import socket as _socket
    for opt in (_socket.SO_RCVBUF, _socket.SO_SNDBUF):
        try:
            sock.setsockopt(_socket.SOL_SOCKET, opt, SOCK_BUF_BYTES)
        except OSError:
            pass


def _http_get_via(ip, port, host, path, timeout, max_bytes=16384, use_tls=True):
    """对指定 IP 发一个 HTTPS GET，SNI/Host 用 host。返回响应体 bytes 或 None。

    用原生 socket + ssl，不创建子进程。
    """
    import socket as _socket
    import ssl as _ssl

    port = int(port or 443)
    if not use_tls:
        return _http_get_plain(ip, port, host, path, timeout, max_bytes)
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    # 我们连的是任意第三方 IP，证书必然是别人的，所以不校验 ——
    # 我们要判断的是「这个 IP 有没有把 SNI=host 的流量反代到 CF」，
    # 而不是「证书对不对」。这跟 curl -k 的行为一致。
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    except _ssl.SSLError:
        pass

    req = (f"GET {path} HTTP/1.1\r\n"
           f"Host: {host}\r\n"
           f"User-Agent: cfip/1.0\r\n"
           f"Accept: */*\r\n"
           f"Connection: close\r\n\r\n").encode()

    sock = None
    try:
        sock = _socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        _tune_sock(sock)
        tls = ctx.wrap_socket(sock, server_hostname=host)
        try:
            tls.sendall(req)
            buf = bytearray()
            while len(buf) < max_bytes:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                buf += chunk
                # 响应头读完、body 够长就可以提前收工（省一个 RTT 的等待）
                if b"\r\n\r\n" in buf and len(buf) > 256:
                    break
        finally:
            try:
                tls.close()
            except OSError:
                pass
        raw = bytes(buf)
    except (OSError, _ssl.SSLError, ValueError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    # 去掉响应头，只留 body（Connection: close 也可能是 chunked，做个兜底）
    idx = raw.find(b"\r\n\r\n")
    body = raw[idx + 4:] if idx >= 0 else raw
    if b"transfer-encoding: chunked" in raw[:idx if idx >= 0 else 0].lower():
        # 简单解码：<hex 长度>\r\n<数据>\r\n...
        out = bytearray()
        rest = body
        while True:
            nl = rest.find(b"\r\n")
            if nl < 0:
                break
            try:
                n = int(rest[:nl].split(b";")[0], 16)
            except ValueError:
                break
            if n == 0:
                break
            out += rest[nl + 2:nl + 2 + n]
            rest = rest[nl + 2 + n + 2:]
        body = bytes(out)
    return body


def _http_get_plain(ip, port, host, path, timeout, max_bytes=16384):
    """明文 HTTP GET（端口 80/8080 这类）。不建 TLS，开销更小。"""
    import socket as _socket

    req = (f"GET {path} HTTP/1.1\r\n"
           f"Host: {host}\r\n"
           f"User-Agent: cfip/1.0\r\n"
           f"Accept: */*\r\n"
           f"Connection: close\r\n\r\n").encode()
    sock = None
    try:
        sock = _socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        _tune_sock(sock)
        sock.sendall(req)
        buf = bytearray()
        while len(buf) < max_bytes:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf and len(buf) > 256:
                break
        raw = bytes(buf)
    except (OSError, ValueError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    idx = raw.find(b"\r\n\r\n")
    return raw[idx + 4:] if idx >= 0 else raw


def availability_http(ip, timeout=CURL_TIMEOUT_SEC, port="80"):
    """明文 HTTP 版可用性检查（端口 80/8080/2052 等）。"""
    path = urlparse(AVAILABILITY_URL).path or "/cdn-cgi/trace"
    body = _http_get_via(ip, port, AVAILABILITY_HOST, path, timeout, use_tls=False)
    if not body:
        return None
    info = {}
    for line in body.decode("utf-8", "replace").splitlines():
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip().lower(), v.strip()
        if k == "loc":
            info["cfcountry"] = v.upper()
        elif k == "colo":
            info["colo"] = v.upper()
    return info if info.get("cfcountry") else None


def availability_native(ip, timeout=CURL_TIMEOUT_SEC, port="443"):
    """可用性检查的原生实现：连 ip:port，SNI 用 AVAILABILITY_HOST，
    取 /cdn-cgi/trace，看里面有没有 loc=。"""
    path = urlparse(AVAILABILITY_URL).path or "/cdn-cgi/trace"
    body = _http_get_via(ip, port, AVAILABILITY_HOST, path, timeout)
    if not body:
        return None
    info = {}
    for line in body.decode("utf-8", "replace").splitlines():
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip().lower(), v.strip()
        if k == "loc":
            info["cfcountry"] = v.upper()
        elif k == "colo":
            info["colo"] = v.upper()
    return info if info.get("cfcountry") else None


def availability(ip, timeout=CURL_TIMEOUT_SEC, port="443"):
    """可用性检查。端口默认 443，也支持 CF 的其它 HTTPS 端口（2053/2083/2087/2096/8443）。

    注意 URL 里也要带端口 —— 只改 --resolve 不改 URL 的话，
    curl 还是会去连 443，测出来的结果和端口对不上。
    """
    if port_uses_http(port):
        return availability_http(ip, timeout, port)
    if USE_NATIVE_SOCKET:
        return availability_native(ip, timeout, port)
    port = str(port or "443")
    suffix = "" if port == "443" else f":{port}"
    cmd = ["curl", "-sS", "-k",
           "--connect-timeout", str(timeout),
           "--max-time", str(timeout),
           "--resolve", f"{AVAILABILITY_HOST}:{port}:{ip}",
           AVAILABILITY_URL.replace(f"https://{AVAILABILITY_HOST}",
                                    f"https://{AVAILABILITY_HOST}{suffix}", 1)]
    ok, out = run_command(cmd, timeout + 3)
    if not ok:
        return None
    info = {}
    for line in out.splitlines():
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip().lower()
        v = v.strip()
        if k == "loc":
            info["cfcountry"] = v.upper()
        elif k == "colo":
            info["colo"] = v.upper()
    return info if info.get("cfcountry") else None


def stage1_streaming(path, threads, chunk_size=20000):
    """流式第一阶段：分批读 CSV -> 分批测 -> 只累积通过的那些。

    为什么：18 万个候选全读进内存再测，光输入列表就 42MB，加上
    Future/结果对象峰值上百 MB。分批后同时只有一批在内存里，
    通过的（通常只占少数）累积下来交给第二阶段。
    """
    out = []
    seen_total = 0
    t0 = time.time()
    log(f"\n[*] 第一阶段：流式读取 {os.path.basename(path)}，"
        f"每批 {chunk_size} 个，并发 "
        f"{max(ASYNCIO_CONCURRENCY, threads) if USE_ASYNCIO else threads}")
    for chunk in iter_ips_chunked(path, chunk_size):
        seen_total += len(chunk)
        # stage0：先把黑洞筛掉，后面的 TLS 只作用在活着的 IP 上
        if STAGE0_ENABLED:
            before = len(chunk)
            chunk = stage0_tcp_filter(chunk, STAGE0_TIMEOUT, STAGE0_CONCURRENCY)
            if not chunk:
                log(f"[*] 本批 {before} 个全被 stage0 筛掉，跳过 TLS 阶段")
                continue
        if USE_ASYNCIO:
            passed = stage1_async(chunk, max(ASYNCIO_CONCURRENCY, threads), CURL_TIMEOUT_SEC)
        else:
            passed = _stage1_threaded(chunk, threads)
        out.extend(passed)
        del chunk, passed
        rate = seen_total / max(0.001, time.time() - t0)
        log(f"[*] 第一阶段进度：已测 {seen_total:,} 个，"
            f"累计通过 {len(out):,} 个（{rate:.0f} 个/秒）")
    log(f"[*] 第一阶段完成：{len(out)}/{seen_total}")
    return out


def stage1(items, threads):
    """对一批候选跑第一阶段（内存里已有全部候选时用）。"""
    if USE_ASYNCIO:
        return stage1_async(items, max(ASYNCIO_CONCURRENCY, threads), CURL_TIMEOUT_SEC)
    return _stage1_threaded(items, threads)


def _stage1_threaded(items, threads):
    total = len(items)
    done = 0
    out = []
    log(f"\n[*] 第一阶段：可用性，{total} IP，{threads}线程")

    def _check(x):
        return availability(x["ip"], CURL_TIMEOUT_SEC, str(x.get("port") or "443"))

    with ThreadPoolExecutor(max_workers=threads, thread_name_prefix="avail") as ex:
        for x, cf, err in submit_batched(ex, _check, items):
            done += 1
            ip = x["ip"]
            port = str(x.get("port") or "443")
            tag = ip if port == "443" else f"{ip}:{port}"
            if err is not None:
                progress("availability", done, total, f"{tag} | DROP exception={err}")
                continue
            if not cf:
                progress("availability", done, total, f"{tag} | DROP: Cloudflare trace不可用")
                continue
            y = dict(x)
            y.update(cf)
            out.append(y)
            progress("availability", done, total,
                     f"{tag} | PASS cfcountry={y.get('cfcountry', '')} colo={y.get('colo', '-')}")
    log(f"[*] 第一阶段完成：{len(out)}/{total}")
    return out


# ==================== Stage 2 ====================
ms_re = re.compile(r"(?<![\w.])(\d+(?:[.,]\d+)?)\s*ms\b", re.I)


def extract_ms(output):
    vals = []
    for line in output.splitlines():
        low = line.lower()
        if "average" in low or "平均" in line:
            continue
        if re.search(r"(?:time|时间)\s*<\s*1\s*ms\b", line, re.I):
            vals.append(1.0)
        for m in ms_re.finditer(line):
            try:
                v = float(m.group(1).replace(",", "."))
                if 0 <= v <= 600000:
                    vals.append(v)
            except ValueError:
                pass
    return vals


# 丢包率：优先读 ping 自己的汇总行（最准，各语言/各平台都认）；
# 读不到就按"收到几个回包 / 发了几个"反推。
#   Windows 英文: (0% loss)        中文: (0% 丢失)
#   Linux:        0% packet loss
LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)\s*%\s*(?:packet\s+)?(?:loss|丢失)", re.I)


def extract_loss(output, received, sent):
    m = LOSS_RE.search(output or "")
    if m:
        try:
            return max(0.0, min(100.0, float(m.group(1))))
        except ValueError:
            pass
    if sent:
        return max(0.0, min(100.0, (sent - received) * 100.0 / sent))
    return None


def ping_stats(ip):
    """返回 (平均延迟ms, 丢包率%)；延迟拿不到时返回 (None, None)。

    丢包率是这套筛选里最关键的一项：一次 TLS 握手要几个来回，
    5% 丢包就会让握手反复重传，实际体感比 200ms 延迟还差。
    """
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", str(PING_COUNT), "-w", str(PING_TIMEOUT_SEC * 1000), ip]
    else:
        cmd = ["ping", "-c", str(PING_COUNT), "-W", str(PING_TIMEOUT_SEC), ip]
    ok, out = run_command(cmd, PING_COUNT * PING_TIMEOUT_SEC + 3)
    vals = extract_ms(out)
    if not vals:
        return None, None
    latency = sum(vals) / len(vals)
    return latency, extract_loss(out, len(vals), PING_COUNT)


def ping_latency(ip):
    """兼容旧调用：只要延迟。"""
    return ping_stats(ip)[0]


def speed_test(ip, bytes_to_download, port="443"):
    null = "NUL" if platform.system().lower() == "windows" else "/dev/null"
    port = str(port or "443")
    url = SPEED_TEST_URL
    range_args = []
    if "{bytes}" in url:
        url = url.format(bytes=bytes_to_download)
    else:
        # 不含 {bytes} 的链接用 --range 限流，避免滥用
        range_args = ["--range", f"0-{max(0, bytes_to_download - 1)}"]

    host = urlparse(url).hostname or "speed.cloudflare.com"
    # 非 443 端口时 URL 也要带端口，否则 curl 还是连 443
    if port != "443":
        url = url.replace(f"https://{host}", f"https://{host}:{port}", 1)
    cmd = ["curl", "-o", null, "-sS", "-w", "%{speed_download}",
           "--connect-timeout", str(CURL_TIMEOUT_SEC),
           "--max-time", str(SPEED_TEST_TIMEOUT)]
    cmd += range_args
    cmd += ["--resolve", f"{host}:{port}:{ip}", url]

    ok, out = run_command(cmd, SPEED_TEST_TIMEOUT + 5)
    if not ok:
        return None
    vals = re.findall(r"(?<![\w.])\d+(?:\.\d+)?(?:[eE][+-]?\d+)?(?![\w.])", out.strip())
    try:
        bps = float(vals[-1])
        return bps / (1024 * 1024) if bps > 0 else None
    except (IndexError, ValueError):
        return None


def speed_worker(item, speed_bytes, sem):
    ip = item["ip"]
    port = str(item.get("port") or "443")
    latency, loss = ping_stats(ip)
    if latency is None:
        return ip, None, "DROP: ping无有效ms响应"
    if loss is not None and loss > MAX_LOSS_PCT:
        return ip, None, f"DROP: 丢包 {loss:.0f}% > {MAX_LOSS_PCT:.0f}%"
    if latency > MAX_LATENCY_MS:
        return ip, None, f"DROP: latency {latency:.1f}ms > {MAX_LATENCY_MS:.0f}ms"
    with sem:
        speed = speed_test(ip, speed_bytes, port)
    if speed is None:
        return ip, None, "DROP: speed test失败"
    if speed < MIN_SPEED_MBPS:
        return ip, None, f"DROP: speed {speed:.1f}MB/s < {MIN_SPEED_MBPS:.1f}MB/s"
    y = dict(item)
    y.update(latency=latency, loss=loss, speed=speed)
    return ip, y, "PASS"


def fmt_loss(v):
    return "n/a" if v is None else f"{v:.0f}%"


def stage2(items, threads, speed_bytes):
    total = len(items)
    done = 0
    out = []
    speed_workers = max(1, min(DEFAULT_SPEED_WORKERS, threads, total))
    log(f"\n[*] 第二阶段：延迟+速度，{total} IP，任务线程 {threads}，下载并发 {speed_workers}")
    sem = threading.Semaphore(speed_workers)

    def _check(x):
        return speed_worker(x, speed_bytes, sem)

    with ThreadPoolExecutor(max_workers=threads, thread_name_prefix="speed") as ex:
        for x, res_t, err in submit_batched(ex, _check, items):
            done += 1
            ip = x["ip"]
            if err is not None:
                res, reason = None, f"DROP: exception={err}"
            else:
                _, res, reason = res_t
            if res:
                out.append(res)
                progress("speed/latency", done, total,
                         f"{ip} | PASS latency={fmt_latency(res['latency'])} "
                         f"loss={fmt_loss(res.get('loss'))} speed={fmt_speed(res['speed'])}")
            else:
                progress("speed/latency", done, total, f"{ip} | {reason}")
    log(f"[*] 第二阶段完成：{len(out)}/{total}")
    return out


# ==================== Traceroute ====================
def parse_trace(output, target):
    out = []
    seen = set()
    for line in output.splitlines():
        for cand in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line):
            if cand != target and public_ip(cand) and cand not in seen:
                seen.add(cand)
                out.append(cand)
                break
    return out


def traceroute_once(ip):
    if platform.system().lower() == "windows":
        cmd = ["tracert", "-d", "-w", "1000", "-h", str(hops), ip]
    else:
        cmd = ["traceroute", "-n", "-w", "2", "-q", "1", "-m", str(hops), ip]
    ok, out = run_command(cmd, TRACEROUTE_TIMEOUT)
    if not ok and platform.system().lower() != "windows" and \
            ("not found" in out.lower() or "no such file" in out.lower()):
        ok, out = run_command(["tracepath", "-n", "-m", str(hops), ip], TRACEROUTE_TIMEOUT)
    return parse_trace(out, ip) if ok else []


# ==================== Route ====================
def route_prefix(ip):
    for route, rules in ROUTE_PREFIX_RULES.items():
        for prefix, _ in rules:
            if ip.startswith(prefix):
                return route
    return None


def route_asn(asn):
    return AS_ROUTE_MAP.get(str(asn).replace("AS", "").strip())


def better(a, b):
    if not b:
        return a
    if not a:
        return b
    return b if ROUTE_PRIORITY.get(b, 0) > ROUTE_PRIORITY.get(a, 0) else a


def route_by_prefix(hops_list):
    r = None
    for ip in hops_list:
        r = better(r, route_prefix(ip))
    return r


def query_hop_asns(hops_list, workers):
    result = {}
    targets = list(dict.fromkeys(hops_list))
    workers = max(1, min(workers, len(targets))) if targets else 1
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="asn") as ex:
        fmap = {ex.submit(ipinfo_lite, ip): ip for ip in targets}
        for fut in as_completed(fmap):
            ip = fmap[fut]
            try:
                result[ip] = fut.result()
            except Exception:
                result[ip] = {}
    return result


def route_by_asn(hops_list, lookup):
    r = None
    for ip in hops_list:
        r = better(r, route_asn(lookup.get(ip, {}).get("asn", "")))
    return r


def extract_country_sequence(hops_list, lookup):
    """从 hops 提取连续去重后的原始 country 序列（保留 CN，不按 target 截断）。

    这是缓存里保存的“线路指纹”，可在任意 target 下重算 tour，避免跨 IP 复用错位。
    """
    raw = []
    for ip in hops_list:
        info = lookup.get(ip) or ipinfo_lite(ip)
        c = (info.get("country") or "").upper()
        if c:
            raw.append(c)
    seq = []
    for c in raw:
        if not seq or seq[-1] != c:
            seq.append(c)
    return seq


def tour_from_sequence(seq, target):
    """用 country 序列和当前 target 实时计算绕路字符串。

    与旧 tour_countries 的展示逻辑保持一致：
    - 去掉中国大陆 CN 节点（中转绕境内 CN 不算绕路）；
    - 在目标国家出现处截断（后面的国家属于目标国内，不算绕路）；
    - 抑制 A-X-A 式的单点 GeoIP 抖动；
    - 未出现任何绕路则返回 "None"。
    """
    target = (target or "").upper()
    seq = [c for c in (seq or []) if c and c not in MAINLAND_CN_CODES]
    if target in seq:
        seq = seq[:seq.index(target)]
    stable = []
    for i, c in enumerate(seq):
        if 0 < i < len(seq) - 1 and seq[i - 1] == seq[i + 1]:
            continue
        if not stable or stable[-1] != c:
            stable.append(c)
    return "→".join(c for c in stable if c != target) or "None"


def tour_countries(hops_list, target, lookup):
    return tour_from_sequence(extract_country_sequence(hops_list, lookup), target)


def analyze_trace(hops_list, target, threads, force_asn=False):
    if not hops_list:
        return "Unknown", "None", {}
    route = route_by_prefix(hops_list)
    lookup = {}
    if route is None and force_asn:
        lookup = query_hop_asns(hops_list, max(1, min(threads, 20)))
        route = route_by_asn(hops_list, lookup) or "Unknown"
    if not lookup:
        lookup = query_hop_asns(hops_list, max(1, min(threads, 20)))
    if route is None:
        route = route_by_asn(hops_list, lookup) or "Unknown"
    return route, tour_countries(hops_list, target, lookup), lookup


def trace_worker(item, threads, skiptr):
    res = dict(item)
    ip = res["ip"]
    info = ipinfo_city(ip)
    country = (info.get("country") or res.get("input_country")
               or res.get("cfcountry") or "").upper()
    city = info.get("city") or res.get("input_city") \
        or COLO_CITY_MAP.get(res.get("colo", ""), res.get("colo", ""))
    res.update(country=country, city=city)
    if skiptr:
        res.update(route="Skipped", tour="None",
                   route_confidence="skipped", traceroute_hops=[])
        return res

    # 1) 手工覆盖优先级最高：命中则直接采用，不走缓存、不做 traceroute
    ov = override_for(ip)
    if ov and ov.get("route"):
        override_asns = [ov["asn"]] if ov.get("asn") else []
        res.update(route=ov["route"],
                   tour="None",
                   route_confidence="override",
                   traceroute_hops=[],
                   route_asns=override_asns)
        return res

    # 2) 其次查本地线路缓存（按 /24 网段），命中则跳过 tracert
    cached = cache_lookup(ip)
    if cached:
        # 用当前 IP 的 country 从 country_seq 重算 tour，
        # 避免把过去某个 target 下的截断结果错用到当前 IP。
        tour = tour_from_sequence(cached.get("country_seq", []), country)
        res.update(route=cached.get("route", "Unknown"),
                   tour=tour,
                   route_confidence="cached",
                   traceroute_hops=[],
                   route_asns=cached.get("route_asns", []))
        return res

    # 3) 都没有 → 实际 traceroute
    hs = traceroute_once(ip)
    route, tour, lookup = analyze_trace(hs, country, threads, False)
    if route == "Unknown":
        time.sleep(0.3)
        hs = traceroute_once(ip)
        route, tour, lookup = analyze_trace(hs, country, threads, False)

    if route == "Unknown" and hs:
        lookup = query_hop_asns(hs, max(1, min(threads, 20)))
        route = route_by_asn(hs, lookup) or "Unknown"
        tour = tour_countries(hs, country, lookup)

    confidence = "high" if route_by_prefix(hs) else ("medium" if route != "Unknown" else "unknown")
    route_asns = sorted({
        str((lookup.get(h, {}) or {}).get("asn", "")).replace("AS", "").strip()
        for h in hs if (lookup.get(h, {}) or {}).get("asn")
    })
    res.update(route=route, tour=tour, route_confidence=confidence,
               traceroute_hops=hs, route_asns=route_asns)

    # 写入缓存：存 country_seq（原始序列，未按 target 截断）
    if hs:
        country_seq = extract_country_sequence(hs, lookup)
    else:
        country_seq = []
    cache_store(ip, route, country_seq, route_asns)
    return res


def stage3(items, threads, skiptr):
    total = len(items)
    done = 0
    out = []
    log(f"\n[*] 第三阶段：{'跳过traceroute' if skiptr else 'traceroute线路分析'}，{total} IP，{threads}线程")

    def _trace(x):
        return trace_worker(x, threads, skiptr)

    with ThreadPoolExecutor(max_workers=threads, thread_name_prefix="trace") as ex:
        for x, r, err in submit_batched(ex, _trace, items):
            done += 1
            ip = x["ip"]
            if err is not None:
                r = dict(x)
                r.update(route="Skipped" if skiptr else "Unknown",
                         tour="None", route_confidence="unknown")
                log(f"[traceroute {done}/{total}] {ip} | ERROR {err}")
            out.append(r)
            progress("traceroute", done, total,
                     f"{ip} | route={r.get('route')} tour={r.get('tour')} "
                     f"target={r.get('country')} confidence={r.get('route_confidence')}")
    return out


# ==================== 输出 ====================
def ip_score(r):
    """综合评分 = 延迟(ms) × (1 + 丢包率/100 × LOSS_PENALTY)。越小越好。

    这样 30ms/0% 丢包 会排在 30ms/20% 丢包 前面，而 250ms/0% 也不会
    被 40ms/25% 挤掉——纯按延迟排会把高丢包的低延迟 IP 排到最前面，
    纯按丢包排又会把 280ms/0% 排到 30ms/1% 前面，都不对。
    """
    lat = float(r.get("latency") or 0.0)
    loss = float(r.get("loss") or 0.0)
    return lat * (1.0 + loss / 100.0 * LOSS_PENALTY)


def sort_key(r):
    if SORT_MODE == "score":
        # 主键综合评分升序；同分再比原始延迟，最后用速度做兜底区分
        return (ip_score(r), float(r.get("latency") or 0.0),
                -float(r.get("speed") or 0.0))
    cc = (r.get("cfcountry") or "").upper()
    return (0 if cc == previousCountry.upper() else 1, cc,
            -float(r["speed"]), float(r["latency"]))


def _fmt_line(r, rank):
    route = (r.get("route") or "Unknown").strip()
    tour = r.get("tour", "None")
    rd = route if tour == "None" else f"{route}绕" + "、".join(
        flag(c) for c in tour.split("→"))
    # 非 443 端口要标出来，否则下游按 443 去连会连不上
    port = str(r.get("port") or "443")
    addr = r["ip"] if port == "443" else f"{r['ip']}:{port}"
    line = f"{addr}#{flag(r.get('country', ''))} ({rd})"
    city = (r.get("city") or "").strip()
    if city:
        line += f" {city}"
    return line + f" {rank}"


def _is_high_end(r):
    route = (r.get("route") or "Unknown").strip()
    route_asns = {str(x).replace("AS", "").strip() for x in (r.get("route_asns") or [])}
    return route in HIGH_END_ROUTE_NAMES or bool(HIGH_END_ASNS.intersection(route_asns))


def _write_csv(path, rows):
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["rank", "ip", "port", "score", "latency", "loss",
                    "speed", "cfcountry", "route", "tour", "country", "city"])
        for i, r in enumerate(rows, 1):
            w.writerow([i, r["ip"], r.get("port", "443"), f"{ip_score(r):.1f}",
                        fmt_latency(r["latency"]), fmt_loss(r.get("loss")),
                        fmt_speed(r["speed"]), r.get("cfcountry", ""),
                        r.get("route", ""), r.get("tour", "None"),
                        r.get("country", ""), r.get("city", "")])


def _write_txt(path, rows, only_best):
    lines = []
    rank = 0
    for r in rows:
        if only_best and not _is_high_end(r):
            continue
        rank += 1
        lines.append(_fmt_line(r, rank))
    with open(path, "w", encoding="utf-8-sig") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
    return len(lines)


def outputs(results, outtxt, outcsv, only_best):
    """写两套结果。

    第一套（全量）—— 所有通过筛选的 IP，不限制地区。这是主列表。
    第二套（地区）—— 只保留 OUTPUT_REGIONS 白名单里的地区。
    两套各有 .txt 和 .csv，Web 面板和 API 分别提供。
    """
    results = sorted(results, key=sort_key)

    # Top-N：只留排名最靠前的 N 个。推 DNS 分流用不了几百个，
    # 输出太长反而不好维护。0 = 不限制。
    if TOP_N and len(results) > TOP_N:
        log(f"[*] 排序后共 {len(results)} 个，按 TOP_N={TOP_N} 截取前 {TOP_N} 个"
            f"（排序模式 {SORT_MODE}）")
        results = results[:TOP_N]

    # ---------- 第一套：全量，不限制地区 ----------
    _write_csv(outcsv, results)
    n_all = _write_txt(outtxt, results, only_best)
    log(f"[*] [全量] {outtxt}（{n_all} 条）  {outcsv}")

    # ---------- 第二套：只要白名单地区 ----------
    if not OUTPUT_SPLIT:
        return
    want = {x.strip().upper() for x in re.split(r"[,;\s]+", OUTPUT_REGIONS) if x.strip()}
    if not want:
        log("[*] OUTPUT_REGIONS 为空，跳过地区列表")
        return
    sub = [r for r in results if (r.get("country") or "").strip().upper() in want]
    tag = "".join(sorted(want)).lower()
    sub_txt = re.sub(r"\.txt$", "", outtxt) + f"-{tag}.txt"
    sub_csv = re.sub(r"\.csv$", "", outcsv) + f"-{tag}.csv"
    _write_csv(sub_csv, sub)
    n_sub = _write_txt(sub_txt, sub, only_best)
    log(f"[*] [地区 {','.join(sorted(want))}] {sub_txt}（{n_sub} 条）  {sub_csv}")

    # 顺便打一份地区分布，方便一眼看出哪个地区多
    dist = {}
    for r in results:
        cc = (r.get("country") or "??").upper()
        dist[cc] = dist.get(cc, 0) + 1
    if dist:
        top = sorted(dist.items(), key=lambda kv: -kv[1])[:12]
        log("[*] 地区分布：" + "  ".join(f"{c}={n}" for c, n in top))


# ==================== Main ====================
def main():
    global DEBUG, LOG_FILE, downloadBytes, DEFAULT_INPUT, PROGRESS_EVERY

    # 预解析 -config，用于加载配置文件
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("-config", default=None)
    pre_args, _ = pre.parse_known_args()
    config_path = pre_args.config if pre_args.config else DEFAULT_CONFIG_FILE
    if config_path and not os.path.isabs(config_path):
        config_path = os.path.abspath(config_path)

    cfg = load_config(config_path)
    apply_config(cfg)

    # 完整参数解析
    p = argparse.ArgumentParser(description="Cloudflare SNI Proxy IP Tester")
    p.add_argument("-threads", default=None,
                   help=f"测试延迟/速度的线程数，默认{DEFAULT_THREADS}，可填 max")
    p.add_argument("-i", "--input", default=None,
                   help="输入CSV文件，默认 ./ip.csv")
    p.add_argument("-o", "--output", default=None,
                   help="CSV输出路径（不做 {path}/{date}/{num} 等替换）")
    p.add_argument("-d", "--download-size", type=float, default=None,
                   help="测速文件大小（单位 MB），默认 20")
    p.add_argument("-chunk-size", type=int, default=20000,
                   help="流式第一阶段的批大小（默认 20000）。调小更省内存，"
                        "调大吞吐略高；峰值内存只跟这个值有关。")
    p.add_argument("-skiptr", "--skiptr", action="store_true",
                   help="跳过 traceroute 线路分析")
    p.add_argument("-stage1", "--stage1-only", action="store_true",
                   help="只跑第一阶段（可用性检查）就结束。"
                        "用于「VPS 先扫出哪些 IP 真的反代了 CF，再拿到本机测质量」的两段式流程")
    p.add_argument("-config", default=None,
                   help="配置文件路径，默认 ./config.ini")
    p.add_argument("-log", action="store_true",
                   help="启用日志文件输出（写入 OUTPUT_FOLDER_PATH）")
    p.add_argument("-quiet", action="store_true",
                   help="精简日志：只输出每 N 条的抽样进度和阶段小结。"
                        "小硬盘 VPS 上强烈建议开启（配合 PROGRESS_EVERY）")
    p.add_argument("-debug", action="store_true",
                   help="调试模式：显示剔除原因及系统命令输出")
    a = p.parse_args()

    # 应用命令行覆盖（CLI > config > default）
    if a.debug:
        DEBUG = True
    if a.quiet:
        PROGRESS_EVERY = max(PROGRESS_EVERY, 200)
    if a.input is not None:
        DEFAULT_INPUT = a.input
    if a.download_size is not None:
        if a.download_size <= 0:
            print("[!] -d 必须大于0", file=sys.stderr)
            sys.exit(2)
        downloadBytes = int(a.download_size * 1024 * 1024)

    threads = parse_threads(a.threads if a.threads is not None else DEFAULT_THREADS)

    if downloadBytes <= 0:
        print("[!] downloadBytes必须大于0", file=sys.stderr)
        sys.exit(2)

    # 准备输出目录（{date} 格式：YYYY-MM-DD）
    date_str = datetime.now().strftime("%Y-%m-%d")
    output_folder = OUTPUT_FOLDER_PATH.replace("{date}", date_str)
    if not os.path.isabs(output_folder):
        output_folder = os.path.abspath(output_folder)
    os.makedirs(output_folder, exist_ok=True)

    # 日志文件：由 -log 或 config 中 LOG_FILE 非空触发；
    # 控制台打印不受影响（在 log() 中始终执行）。
    # 文件名：log-YYYY-MM-DD-HH-MM-SS{num}.log，位置：OUTPUT_FOLDER_PATH
    log_enabled = a.log or (
        LOG_FILE is not None
        and LOG_FILE is not False
        and str(LOG_FILE).strip() != ""
    )
    if log_enabled:
        ts = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        log_path = os.path.join(output_folder, f"log-{ts}.log")
        LOG_FILE = _next_available(log_path)
    else:
        LOG_FILE = None

    # 解析 ip.txt 输出路径（仅从 config 获取，CLI 不提供此项）
    out_ip = resolve_output_path(DEFAULT_IP_OUTPUT, output_folder, date_str)

    # 解析 CSV 输出路径
    # -o 时按字面使用（不做 {path}/{date}/{num} 替换）
    # 否则从 config 的 DEFAULT_CSV_OUTPUT 解析（支持三个占位符）
    if a.output is not None:
        out_csv = a.output
        if not os.path.isabs(out_csv):
            out_csv = os.path.abspath(out_csv)
        _ensure_parent(out_csv)
    else:
        out_csv = resolve_output_path(DEFAULT_CSV_OUTPUT, output_folder, date_str)

    # 加载手工覆盖规则（优先级最高）
    n_override = load_ip_override(IP_OVERRIDE_FILE)

    # 加载线路缓存（traceroute 命中缓存则跳过实际 tracert）
    n_cache = load_route_cache(ROUTE_CACHE_FILE)

    log("=" * 60)
    log(f"OS={platform.system()} {platform.release()} threads={threads} "
        f"downloadBytes={downloadBytes} skiptr={a.skiptr}")
    log(f"output_folder = {output_folder}")
    log(f"ip_output     = {out_ip}")
    log(f"csv_output    = {out_csv}")
    log(f"log_file      = {LOG_FILE}")
    log(f"ip_override   = {IP_OVERRIDE_FILE}（已加载 {n_override} 条）")
    log(f"route_cache   = {ROUTE_CACHE_FILE}（已加载 {n_cache} 条）")
    log("=" * 60)

    # 流式：不再先把 18 万个候选全读进内存，而是边读边测
    total_candidates = count_ips(DEFAULT_INPUT)
    if not total_candidates:
        log("[!] 没有候选 IP")
        return
    log(f"[*] 加载 {total_candidates} 个唯一IP（流式）")

    available = stage1_streaming(DEFAULT_INPUT, threads,
                                 max(500, a.chunk_size))
    if not available:
        log("[!] 无可用IP")
        return

    # ---- 两段式流程的第一段：只交回「真的反代了 CF」的 IP ----
    # 延迟/速度/线路这些结论跟测量点强相关，在 VPS 上测出来的对家用网络
    # 没有参考价值。所以 VPS 只负责发现，质量测量留给目标网络（本机 NAS）。
    if a.stage1_only:
        with open(out_csv, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ip", "port", "protocol", "cfcountry", "colo"])
            for x in available:
                w.writerow([x["ip"], 443, "https",
                            x.get("cfcountry", ""), x.get("colo", "")])
        log("")
        log(f"[*] 第一阶段结果已保存：{out_csv}（{len(available)} 个可用反代）")
        log("[*] 下一步：把这个文件拿到目标网络（家里 NAS）上再跑一遍完整测试：")
        log(f"    python ip.py -i {os.path.basename(out_csv)} -threads 20 -d 5")
        return

    quality = stage2(available, threads, downloadBytes)
    if not quality:
        log("[!] 无IP通过延迟/速度筛选")
        return

    final = stage3(quality, threads, a.skiptr)

    save_route_cache(ROUTE_CACHE_FILE)
    log(f"[*] 线路缓存已保存：{ROUTE_CACHE_FILE}（共 {len(route_cache)} 条）")

    outputs(final, out_ip, out_csv, ONLY_OUTPUT_BEST_ROUTE)
    log(f"[*] 完成：最终 {len(final)} 个IP")


if __name__ == "__main__":
    main()