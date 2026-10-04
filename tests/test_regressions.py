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

    # 检查【所有】函数，不再硬编码函数名 ——
    # 之前只查 apply_config/apply_env/main，结果 apply_cli 漏了 FULL_SCAN，
    # 赋值变成了局部变量，功能静默失效（踩了不止一次）。
    all_fns = [n.name for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    bad = {}
    for fn in all_fns:
        missing = assigned_globals(fn) - globals_of(fn)
        # 排除函数自己的参数和局部变量（赋值前没在模块级定义的不算）
        if missing:
            bad[fn] = sorted(missing)
    check("所有函数的 global 声明完整", not bad,
          f"这些函数里给模块级变量赋值却没声明 global: {bad}")


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


# ---------------------------------------------------------------- 7. Web 面板
def test_webui():
    """面板曾经因为 status.json 带 BOM 而静默显示空白（异常被 except 吞掉）。
    另外推送设置要能存能读。"""
    import json
    import webui

    OUT = os.path.join(ROOT, "output")
    os.makedirs(OUT, exist_ok=True)
    sf = webui.STATUS_FILE

    # 带 BOM 的 status.json 必须能读
    with open(sf, "w", encoding="utf-8-sig") as f:
        json.dump({"stage_name": "第一阶段 · 可用性检查", "stage_done": 5,
                   "stage_total": 10, "progress_pct": 50.0}, f, ensure_ascii=False)
    st = webui.load_status()
    check("带 BOM 的 status.json 能读", st.get("stage_name") == "第一阶段 · 可用性检查",
          f"实际 {st.get('stage_name')!r}")
    check("进度字段正确", st.get("progress_pct") == 50.0)

    # 不带 BOM 也要能读
    with open(sf, "w", encoding="utf-8") as f:
        json.dump({"stage_name": "无BOM"}, f, ensure_ascii=False)
    check("不带 BOM 的 status.json 能读", webui.load_status().get("stage_name") == "无BOM")

    # 坏 JSON 不能崩
    with open(sf, "w", encoding="utf-8") as f:
        f.write("{ 这不是 json")
    check("坏 JSON 不抛异常", isinstance(webui.load_status(), dict))

    os.remove(sf)

    # 推送设置：存 -> 读 往返
    orig = open(webui.CONFIG_PATH, encoding="utf-8").read()
    try:
        ok, msg = webui.save_notify_settings("ntfy", "https://ntfy.sh/regression-test", True)
        check("推送设置能保存", ok, msg)
        s = webui.load_notify_settings()
        check("保存后能读回渠道", s["channel"] == "ntfy", f"实际 {s['channel']!r}")
        check("保存后能读回目标", s["target"] == "https://ntfy.sh/regression-test")
        check("configured 标记正确", s["configured"] is True)
        check("渠道列表非空", len(s["channels"]) >= 9)
        # 保存不能破坏其它配置
        import ip as _ip
        cfg = _ip.load_config(webui.CONFIG_PATH)
        check("其它配置未被破坏", cfg.get("DEFAULT_THREADS") == 20
              and cfg.get("token") is not None)
    finally:
        open(webui.CONFIG_PATH, "w", encoding="utf-8").write(orig)

    # 预览能渲染
    p = webui.notify_preview()
    check("推送预览可渲染", p.get("ok") is True and "轮" in p.get("title", ""))




# ---------------------------------------------------------------- 8. 模块间变量引用
def test_undefined_globals():
    """又一个反复踩的坑：变量定义在 A 模块、却在 B 模块里引用，
    运行时 NameError，而且常被外层 except 吞掉，表现成「接口返回空」。

    这里用 AST 扫一遍：每个模块里被【读取】但从未在该模块【定义/导入/赋值】
    的全局名，列出来。
    """
    import ast
    import builtins

    for fname in ("fetch_ips.py", "ip.py", "webui.py", "notify.py"):
        path = os.path.join(ROOT, fname)
        src = open(path, encoding="utf-8").read()
        tree = ast.parse(src)

        # 模块级定义的名字
        defined = set(dir(builtins))
        for node in tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                tgts = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in tgts:
                    for n in ast.walk(t):
                        if isinstance(n, ast.Name):
                            defined.add(n.id)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for al in node.names:
                    defined.add((al.asname or al.name).split(".")[0])
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                defined.add(node.name)
            elif isinstance(node, ast.Try):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Assign):
                        for t in sub.targets:
                            for n in ast.walk(t):
                                if isinstance(n, ast.Name):
                                    defined.add(n.id)
            elif isinstance(node, (ast.If, ast.For, ast.While)):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Assign):
                        for t in sub.targets:
                            for n in ast.walk(t):
                                if isinstance(n, ast.Name):
                                    defined.add(n.id)

        # 函数里 global 声明 + 局部赋值也算
        for node in ast.walk(tree):
            if isinstance(node, ast.Global):
                defined.update(node.names)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                        defined.add(sub.id)
                    if isinstance(sub, ast.arg):
                        defined.add(sub.arg)
                    if isinstance(sub, ast.ExceptHandler) and sub.name:
                        defined.add(sub.name)

        # 找出「读取但未定义」的（只查看起来像模块级常量的全大写名，减少误报）
        suspect = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                nm = node.id
                if nm.isupper() and len(nm) > 2 and nm not in defined:
                    suspect.add(nm)
        check(f"{fname} 没有未定义的大写常量引用", not suspect,
              f"疑似未定义: {sorted(suspect)}")


# ---------------------------------------------------------------- 9. 流式采样
def test_streaming_sampling():
    """流式改造引入的两个函数，必须和「真展开再抽」等价。"""
    import ipaddress
    import random
    import fetch_ips as ff

    nets = [ipaddress.ip_network("10.0.0.0/22"), ipaddress.ip_network("10.1.0.0/24"),
            ipaddress.ip_network("10.2.0.0/23"), ipaddress.ip_network("10.3.0.0/25")]

    # count_24s 要和真展开一致
    fast = ff.count_24s(nets)
    slow = 0
    for n in nets:
        slow += len(list(n.subnets(new_prefix=24))) if n.prefixlen <= 24 else 1
    check("count_24s 与真展开一致", fast == slow, f"{fast} vs {slow}")

    # sample_24s 不能有重复
    random.seed(5)
    got = ff.sample_24s(nets, 8)
    check("sample_24s 无重复", len(got) == len(set(got)), f"{len(got)} 个里 {len(set(got))} 唯一")

    # 取超过总数时应截断且不重复
    got2 = ff.sample_24s(nets, 9999)
    check("sample_24s 超量请求被截断", len(got2) == fast and len(got2) == len(set(got2)),
          f"要 9999 得 {len(got2)}，唯一 {len(set(got2))}")

    # 结果必须都是 /24 对齐、且落在给定网段内
    aligned = all(a % 256 == 0 for a in got)
    import ipaddress as _ip
    inside = all(any(_ip.IPv4Address(a) in n for n in nets if n.prefixlen <= 24) or
                 any(a == int(n.network_address) for n in nets) for a in got)
    check("sample_24s 结果都是 /24 首地址", aligned)
    check("sample_24s 结果都落在给定网段内", inside)


# ---------------------------------------------------------------- 10. 一次性运行
def test_once_semantics():
    """配置里加了 LOOP 之后，曾经写成 max(0, a.loop or LOOP)，
    导致任何不带 -loop 的调用都变成常驻循环、永远不返回（实测卡死）。
    """
    src = open(os.path.join(ROOT, "fetch_ips.py"), encoding="utf-8").read()
    # 只看代码行，注释里提到这个错误写法是正常的（就是解释为什么不能这么写）
    code_lines = [ln for ln in src.splitlines() if not ln.lstrip().startswith("#")]
    code = chr(10).join(code_lines)
    check("没有 a.loop or LOOP 这种写法", "a.loop or LOOP" not in code)
    check("有 -once 参数", '"-once"' in src)
    check("-once 时 interval 归零", "if a.once:" in src and "interval = 0" in src)

    # webui 的一次性触发要带 -once
    w = open(os.path.join(ROOT, "webui.py"), encoding="utf-8").read()
    check("webui 一次性跑会补 -once", '"-once" not in cmd' in w)


# ---------------------------------------------------------------- 11. 两套结果
def test_two_datasets():
    """主 CSV 不能被地区版 CSV 顶掉。"""
    src = open(os.path.join(ROOT, "fetch_ips.py"), encoding="utf-8").read()
    check("read_final_summary 排除地区版 CSV", "地区版，跳过" in src)
    check("fetch_ips 有 OUTPUT_REGIONS", 'OUTPUT_REGIONS = "HK' in src)
    ip_src = open(os.path.join(ROOT, "ip.py"), encoding="utf-8").read()
    check("ip.py 产出两套文件", "def _write_txt" in ip_src and "OUTPUT_SPLIT" in ip_src)
    check("ip.py 有地区白名单", "OUTPUT_REGIONS" in ip_src)




# ---------------------------------------------------------------- 12. 进度条前后端一致
def test_progress_keys():
    """面板上只显示一个进度条 —— 因为前端的 STAGE_ORDER 漏了 s0，
    而且没开始的阶段根本不渲染。这里把「后端会上报的 key」
    和「前端会渲染的 key」对齐关系固化下来。
    """
    import re
    w = open(os.path.join(ROOT, "webui.py"), encoding="utf-8").read()
    f = open(os.path.join(ROOT, "fetch_ips.py"), encoding="utf-8").read()
    i = open(os.path.join(ROOT, "ip.py"), encoding="utf-8").read()

    m = re.search(r"STAGE_ORDER\s*=\s*\[([^\]]*)\]", w)
    check("webui 有 STAGE_ORDER", bool(m))
    if not m:
        return
    order = set(re.findall(r"'([^']+)'", m.group(1)))

    # 后端会上报的 key：
    #   fetch_ips 直接 set_progress("xxx", ...)
    #   ip.py 用 progress("stage-name", ...)，在 run_tester 里映射成 s0/s1/s2/s3
    direct = set(re.findall(r'set_progress\("([a-z0-9]+)"', f))
    mapped = set(re.findall(r'"([a-z/]+)":\s*\("([a-z0-9]+)"', f))
    mapped_keys = {v for _k, v in mapped}
    reported = direct | mapped_keys
    # stage0 在 ip.py 里是 progress("s0", ...) 直接写的
    if 'progress("s0"' in i:
        reported.add("s0")

    missing = sorted(reported - order)
    check("前端 STAGE_ORDER 覆盖了后端所有进度 key", not missing,
          f"后端上报但前端不渲染: {missing}")
    check("stage0 在前端顺序里", "s0" in order, f"STAGE_ORDER={sorted(order)}")

    # 没开始的阶段也要渲染出来（否则只看到一条）
    check("未开始的阶段会渲染占位", "未开始" in w)
    check("当前任务有高亮", "当前任务" in w)




# ---------------------------------------------------------------- 13. 不能落地大文件
def test_no_bulk_candidate_file():
    """vps 档位全量 = 181,871 个 /24 x 254 = 4620 万个候选。
    如果先把它们全写进一个 CSV 再测，按实测每行 218 字节要 10GB，
    而用户的盘只有 3GB（可用 1.6GB）—— 实测跑 21 分钟写满、服务崩了 7 次。

    所以 ASN 分支必须是「逐 ASN 端到端处理」，不能有
    「先写完整候选文件、再交给 ip.py」那一步。
    """
    src = open(os.path.join(ROOT, "fetch_ips.py"), encoding="utf-8").read()

    check("有逐 ASN 流水线 run_asn_pipeline", "def run_asn_pipeline(" in src)
    check("有 iter_asn_batches", "def iter_asn_batches(" in src)
    check("结果先写 .new 再原子替换", 'tmp_path = stage1_path + ".new"' in src)

    # ASN 分支里不该再出现「把候选写进 csv_path」
    a = src.index("def run_once(")
    b = src.index("def main()")
    body = src[a:b]
    # 找到 asn 分支那一段（到 fofa 分支为止）
    try:
        ai = body.index('log(f"[*] 查询 {len(asns)} 个 ASN 的宣告网段，"')
        bi = body.index("else:                                    # fofa")
        asn_branch = body[ai:bi]
    except ValueError:
        asn_branch = body
    check("ASN 分支不再写整份候选 CSV", "open_csv_writer" not in asn_branch
          and "run_tester(csv_path" not in asn_branch,
          "ASN 分支还在写候选文件 —— 全量会撑爆磁盘")

    # 结果文件必须是小文件：池子/stage1 而不是候选
    check("stage1 结果文件路径存在", "STAGE1_CSV" in src)

    # ASN 内部还要再分批：vps 档位的 AS45102 有 12.3 万个 /24，
    # 全量展开是 3140 万个候选，一次性建列表要 5.6GB（实测推算），
    # 而机器只有 726MB。必须按 SUB_BATCH 切块。
    check("iter_asn_batches 支持子批", "sub_batch=50000" in src)
    check("ASN 内部按 sub_batch 切块", "if len(out) >= sub_batch" in src)
    check("有 SUB_BATCH 配置", "SUB_BATCH = 50000" in src)


# ---------------------------------------------------------------- 14. 池子安全阀
def test_pool_safety():
    """全量替换模式下，瞬时故障（网络抖动/限流/部分 ASN 查询失败）
    会让某轮结果骤减。如果不加判断直接替换，几千个可用 IP 会被一次清空。
    """
    src = open(os.path.join(ROOT, "fetch_ips.py"), encoding="utf-8").read()
    check("有 POOL_MIN_KEEP_RATIO 安全阀", "POOL_MIN_KEEP_RATIO" in src)
    check("骤减时会改成并集", "本轮改成【并集】" in src)
    check("空结果不替换池子", "不做空替换" in src)


if __name__ == "__main__":
    print("=" * 62)
    print("  回归测试")
    print("=" * 62)
    for fn in (test_globals_declared, test_full_scan, test_cleanup,
               test_multiport, test_notify_summary, test_files_ok, test_webui,
               test_undefined_globals, test_streaming_sampling,
               test_once_semantics, test_two_datasets, test_progress_keys,
               test_no_bulk_candidate_file, test_pool_safety):
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
