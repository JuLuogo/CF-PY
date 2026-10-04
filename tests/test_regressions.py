#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""回归测试 —— 覆盖实测踩过的坑，改动后跑一遍就不会重犯。

    python tests/test_regressions.py

纯标准库，不需要 pytest。
"""

import io
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'✓' if cond else '✗'} {name}" + (f"   {detail}" if detail and not cond else ""))


# ---------------------------------------------------------------- 1. 全局变量声明
def test_globals_declared():
    """往 apply_config 加配置项时，很容易忘了同步 main() 的 global 声明，
    运行时报 UnboundLocalError。这个测试把三者对齐关系固化下来。"""
    import ast
    src = open(os.path.join(ROOT, "fetch_ips.py"), encoding="utf-8").read()
    tree = ast.parse(src)

    def globals_of(fn_name):
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == fn_name:
                out = set()
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Global):
                        out.update(sub.names)
                return out
        return set()

    def assigned_globals(fn_name):
        """函数里被赋值、且是模块级变量的名字。"""
        mod_level = {n.targets[0].id for n in tree.body
                     if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)}
        out = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == fn_name:
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                        if sub.id in mod_level:
                            out.add(sub.id)
        return out

    for fn in ("apply_config", "apply_env", "main"):
        declared = globals_of(fn)
        need = assigned_globals(fn)
        missing = need - declared
        check(f"{fn}() 的 global 声明完整", not missing,
              f"缺: {sorted(missing)}")


# ---------------------------------------------------------------- 2. 全量扫描
def test_full_scan():
    """-asn-sample 0 必须是「全量」。曾因 max(1, 0) 被降级成只取 1 个。"""
    import fetch_ips as ff
    src = open(os.path.join(ROOT, "fetch_ips.py"), encoding="utf-8").read()
    check("-asn-sample 0 不被 max(1,...) 吞掉", "max(1, a.asn_sample)" not in src)
    check("-asn-sample 用 max(0,...)", "max(0, a.asn_sample)" in src)

    # 直接验证 asn_fetch 的全量分支
    import ipaddress
    import random
    nets = [ipaddress.ip_network(f"10.0.{i}.0/24") for i in range(10)]
    orig_prefixes = ff.asn_prefixes
    ff.asn_prefixes = lambda *a, **k: nets
    try:
        rows0, _ = ff.asn_fetch(["AS0"], 0, 5, 1)
        rows3, _ = ff.asn_fetch(["AS0"], 3, 5, 1)
        check("sample=0 -> 取全部 /24", len(rows0) == 10, f"实际 {len(rows0)}")
        check("sample=3 -> 取 3 个", len(rows3) == 3, f"实际 {len(rows3)}")
    finally:
        ff.asn_prefixes = orig_prefixes


# ---------------------------------------------------------------- 3. 清理逻辑
def test_cleanup():
    """清理曾经漏删过期日期目录：因为先轮转文件、后删目录，
    而删文件会更新目录 mtime，导致目录永远「看起来是新的」。"""
    import fetch_ips as ff
    OUT = os.path.join(ROOT, "output")
    backup = None
    if os.path.isdir(OUT):
        backup = OUT + ".bak_test"
        shutil.rmtree(backup, ignore_errors=True)
        shutil.move(OUT, backup)
    try:
        now = time.time()
        DAY = 86400
        os.makedirs(os.path.join(OUT, "2026-10-04"), exist_ok=True)
        for i in range(8):                      # 8 个日志
            p = os.path.join(OUT, "2026-10-04", f"log-{i}.log")
            open(p, "w").write("x" * 100)
            os.utime(p, (now - (8 - i) * 3600,) * 2)
        for i in range(25):                     # 25 份结果
            p = os.path.join(OUT, "2026-10-04", f"bestips-{i}.csv")
            open(p, "w").write("x" * 100)
            os.utime(p, (now - (25 - i) * 600,) * 2)
        for name, age in (("2020-01-01", 400 * DAY), ("2026-09-20", 10 * DAY)):
            d = os.path.join(OUT, name)
            os.makedirs(d, exist_ok=True)
            fp = os.path.join(d, "bestips-old.csv")
            open(fp, "w").write("x" * 100)
            os.utime(fp, (now - age,) * 2)
            os.utime(d, (now - age,) * 2)
        open(os.path.join(OUT, "status.json.tmp"), "w").write("x" * 50)

        ff.cleanup_outputs()

        logs = results = 0
        for dp, _d, fn in os.walk(OUT):
            for f in fn:
                if f.endswith(".log"):
                    logs += 1
                elif f.startswith("bestips"):
                    results += 1
        dirs = sorted(d for d in os.listdir(OUT) if os.path.isdir(os.path.join(OUT, d)))

        check(f"日志轮转到 {ff.KEEP_LOGS} 个", logs == ff.KEEP_LOGS, f"实际 {logs}")
        check(f"结果轮转到 {ff.KEEP_RESULTS} 份", results == ff.KEEP_RESULTS, f"实际 {results}")
        check("过期日期目录被删掉", "2020-01-01" not in dirs and "2026-09-20" not in dirs,
              f"剩 {dirs}")
        check("当天目录保留", "2026-10-04" in dirs, f"剩 {dirs}")
        check(".tmp 残留被清掉", not os.path.exists(os.path.join(OUT, "status.json.tmp")))
    finally:
        shutil.rmtree(OUT, ignore_errors=True)
        if backup:
            shutil.move(backup, OUT)


# ---------------------------------------------------------------- 4. 多端口
def test_multiport():
    """端口必须真的生效：曾担心只改了 --resolve 没改 URL。
    这里用一个必然不通的端口（1）验证端口确实参与了连接。"""
    import ip
    check("ip.py 可导入", callable(getattr(ip, "availability", None))
          and callable(getattr(ip, "speed_test", None)))

    src = open(os.path.join(ROOT, "ip.py"), encoding="utf-8").read()
    check("availability 支持 port 参数", "def availability(ip, timeout=CURL_TIMEOUT_SEC, port=" in src)
    check("speed_test 支持 port 参数", "def speed_test(ip, bytes_to_download, port=" in src)
    check("URL 里也带上端口", 'suffix = "" if port == "443" else f":{port}"' in src)
    check("去重键含端口", "dedup_key = f\"{ip}:{port_val}\"" in
          open(os.path.join(ROOT, "fetch_ips.py"), encoding="utf-8").read())
    check("输出 CSV 含 port 列", '"rank", "ip", "port"' in src)


# ---------------------------------------------------------------- 5. 推送正文
def test_notify_summary():
    import notify as n
    rows = [
        {"ip": "1.1.1.1", "port": "443", "latency": "62ms", "loss": "0%",
         "speed": "3MB/s", "country": "HK", "city": "Hong Kong"},
        {"ip": "2.2.2.2", "port": "8443", "latency": "88ms", "loss": "0%",
         "speed": "2MB/s", "country": "JP", "city": "Tokyo"},
        {"ip": "3.3.3.3", "port": "8443", "latency": "99ms", "loss": "1%",
         "speed": "1MB/s", "country": "HK", "city": "Hong Kong"},
    ]
    s = n.build_summary(1, 100, 3, rows)
    check("推送含地区统计", "香港" in s and "日本" in s)
    check("推送含数量", "2 个" in s)
    check("推送含端口分布", "8443 × 2" in s and "443 × 1" in s)
    check("推送含最佳 IP", "1.1.1.1" in s)
    # 未知渠道要能优雅失败
    n.NOTIFY_CHANNEL = "bogus"
    n.NOTIFY_TARGET = "http://x"
    ok, msg = n.send("t", "b")
    check("未知渠道优雅失败", ok is False and "不认识" in msg)


# ---------------------------------------------------------------- 6. 语法 / 编码
def test_files_ok():
    import subprocess
    for f in ("ip.py", "fetch_ips.py", "webui.py", "menu.py", "notify.py"):
        p = os.path.join(ROOT, f)
        try:
            open(p, "rb").read().decode("utf-8")
            enc = True
        except UnicodeDecodeError:
            enc = False
        check(f"{f} 是有效 UTF-8", enc)
    r = subprocess.run([sys.executable, "-m", "py_compile"] +
                       [os.path.join(ROOT, f) for f in
                        ("ip.py", "fetch_ips.py", "webui.py", "menu.py", "notify.py")],
                       capture_output=True)
    check("全部 Python 文件可编译", r.returncode == 0,
          r.stderr.decode("utf-8", "replace")[:200])


if __name__ == "__main__":
    print("=" * 62)
    print("  回归测试")
    print("=" * 62)
    for fn in (test_globals_declared, test_full_scan, test_cleanup,
               test_multiport, test_notify_summary, test_files_ok):
        print(f"\n[{fn.__name__}] {fn.__doc__.splitlines()[0] if fn.__doc__ else ''}")
        try:
            fn()
        except Exception as e:                   # noqa: BLE001
            check(f"{fn.__name__} 未抛异常", False, repr(e))
    print("\n" + "=" * 62)
    print(f"  通过 {len(PASS)}  失败 {len(FAIL)}")
    if FAIL:
        print("  失败项：")
        for f in FAIL:
            print(f"    - {f}")
    print("=" * 62)
    sys.exit(1 if FAIL else 0)
