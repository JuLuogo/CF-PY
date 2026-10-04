#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run.bat 调用的交互式菜单。

bat 本身保持纯 ASCII（cmd.exe 解析 UTF-8 批处理会在中途切换代码页时切碎
中文字节），所有中文界面都由 Python 输出，编码稳定可控。
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable

LINE = "=" * 60
HASH = "#" * 56

BANNER = f"""
{LINE}
   Cloudflare 反代 IP 一键优选
   IPDB / FOFA 抓取  +  ip.py 实测
{LINE}
"""

MENU = """
    [1] 第三方反代IP列表 抓取 + 实测      免费免 key（推荐，质量最好）
    [2] IPDB 抓取 + 实测                  免费免 key
    [3] FOFA API 全自动抓取 + 实测        需要 API key
    [4] 导入 FOFA 网页版导出的 CSV        不需要 key
    [5] 生成 FOFA 查询语法                不联网，手动去网页查
    [6] 自检                             不抓取，验证脚本链路
    [7] 编辑 config.ini                   改地区 / 测速大小 / 数据源
    [0] 退出
"""


class Quit(Exception):
    pass


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def ask(prompt, default=""):
    try:
        v = input(prompt)
    except (EOFError, KeyboardInterrupt):
        raise Quit()
    v = v.strip()
    return v if v else default


def run(cmd):
    print()
    try:
        return subprocess.call(cmd, cwd=HERE)
    except OSError as e:
        print(f"   [X] 无法启动子进程: {e}")
        return 1


def check_proxy():
    """测速前必须确认代理和 TUN 都关了，否则数据全是假的。"""
    try:
        import fetch_ips as ff
        proxy = ff.detect_proxy()
        tuns = ff.detect_tun()
        hijack = ff.detect_route_hijack()
    except Exception as e:
        print(f"   [!] 环境检测跳过（{e}）")
        return True
    if not proxy and not tuns and not hijack:
        return True

    print(f"\n   {HASH}")
    print("   [!] 检测到代理 / 隧道还在生效：")
    if hijack:
        print(f"         路由劫持 : {hijack}")
    if proxy:
        print(f"         系统代理 : {proxy}")
    if tuns:
        print(f"         隧道网卡 : {', '.join(tuns)}")
    print("\n       TUN 模式的 fake-IP 是在网络层劫持的，curl --noproxy 也绕不过去，")
    print("       只关「系统代理」开关同样没用——任何国家的 IP 都会被拉平成同一个")
    print("       结果（全部 colo=HKG、延迟接近），根本区分不出好坏。")
    print("\n       请**完全退出** Clash / v2ray 等工具，确认默认路由回到物理网卡。")
    print(f"   {HASH}")
    return ask("\n   已经退出了就回车继续，输入 n 返回菜单: ", "y").lower() != "n"


# 模式函数返回这个哨兵 = 用户中途放弃 / 该模式自己已经打印了总结，
# 此时跳过通用的「结束」小结块，直接回菜单。
NO_SUMMARY = object()


def mode_list(threads):
    print("\n   --- 第三方反代IP列表 抓取（免费免 key）---")
    print("\n   内置源（实测 443 条目可用率 8/8）：")
    print("     zip       zip.cm.edu.kg       14635 条 / 443端口 8358 条 / 74 国")
    print("     luuaiyan  CloudflareProxyIP   2051 条")
    print("     xgonce    Cloudflare_IP       1750 条（每 6 小时更新，自带测速）")
    print("     wwuyi     CF-Proxyip          462 条")
    print("     muhaip    ProxyIP             7320 条（已停更）")
    src = ask("\n   用哪些源（逗号分隔）[默认 zip,wwuyi,luuaiyan]: ", "zip,wwuyi,luuaiyan")
    reg = ask("   只保留哪些地区（留空=不筛选）[默认 HK,JP,SG,KR,TW]: ", "HK,JP,SG,KR,TW")
    n = ask("   本轮测多少个候选 [默认 40]: ", "40")
    if not n.isdigit() or int(n) <= 0:
        print(f"\n   [X] 候选数量无效: {n}")
        return NO_SUMMARY
    threads = ask(f"   测速线程数 [默认 {threads}]: ", threads)
    if not check_proxy():
        return NO_SUMMARY
    print("\n   开始抓取并实测，这一步比较久，请勿关闭窗口 ...")
    return run([PY, "fetch_ips.py", "-source", "list", "-list-urls", src,
                "-list-regions", reg, "-max", n, "-run", "--", "-threads", threads])


def mode_ipdb(threads):
    print("\n   --- IPDB 全自动抓取（免费免 key）---")
    print("\n   数据源: https://ipdb.api.030101.xyz/")
    print("     bestproxy  已优选的反代 IP，带地区标注")
    print("     proxy      全量反代池，700+ 条，每 10 分钟刷新")
    print("     cfv4       Cloudflare 官方 IP（按不同 /24 采样）")
    print("\n   只靠第三方反代会失效/被限速，配上官方 IP 做兜底更稳。")
    n = ask("\n   本轮测多少个候选 [默认 100]: ", "100")
    if not n.isdigit() or int(n) <= 0:
        print(f"\n   [X] 候选数量无效: {n}")
        return NO_SUMMARY
    cf = ask("   其中从 CF 官方网段采样多少个（建议 10~50，0=不测）[默认 30]: ", "30")
    if not cf.isdigit():
        print(f"\n   [X] 官方 IP 数量无效: {cf}")
        return NO_SUMMARY
    threads = ask(f"   测速线程数 [默认 {threads}]: ", threads)
    if not check_proxy():
        return NO_SUMMARY
    print("\n   开始抓取并实测，这一步比较久，请勿关闭窗口 ...")
    return run([PY, "fetch_ips.py", "-source", "ipdb", "-max", n, "-cf-sample", cf,
                "-run", "--", "-threads", threads])


def mode_api(regions, threads):
    print("\n   --- FOFA API 全自动抓取 ---")
    regions = ask(f"\n   想优选的地区，逗号分隔 [默认 {regions}]: ", regions)
    print("\n   API key 获取地址: https://fofa.info/personalData")
    key = ask("   粘贴 API key，直接回车则用 config.ini 里已填的: ", "")
    threads = ask(f"\n   测速线程数 [默认 {threads}]: ", threads)
    if not check_proxy():
        return NO_SUMMARY
    cmd = [PY, "fetch_ips.py", "-source", "fofa"]
    if key:
        cmd += ["-key", key]
    cmd += ["-regions", regions, "-run", "--", "-threads", threads]
    print("\n   开始抓取并实测，这一步比较久，请勿关闭窗口 ...")
    return run(cmd)


def mode_csv(drag, threads):
    print("\n   --- 导入 FOFA 网页版导出的 CSV ---")
    print("\n   提示: 也可以直接把 CSV 文件拖到 run.bat 上，一步到位。")
    path = drag
    if not path and os.path.exists(os.path.join(HERE, "fofa_export.csv")):
        path = "fofa_export.csv"
    path = ask("\n   请输入 CSV 文件路径: ", path).strip('"').strip("'")
    if not os.path.isfile(path):
        print(f"\n   [X] 找不到文件: {path}")
        return NO_SUMMARY
    print(f"\n   已选择: {path}")
    threads = ask(f"\n   测速线程数 [默认 {threads}]: ", threads)
    if not check_proxy():
        return NO_SUMMARY
    print("\n   开始清洗并实测，这一步比较久，请勿关闭窗口 ...")
    return run([PY, "fetch_ips.py", "-source", "csv", "-import-csv", path,
                "-run", "--", "-threads", threads])


def mode_syntax(regions):
    print("\n   --- 生成 FOFA 查询语法 ---")
    regions = ask(f"\n   想优选的地区 [默认 {regions}]: ", regions)
    out = os.path.join(HERE, "fofa_queries.txt")
    print()
    try:
        with open(out, "w", encoding="utf-8") as f:
            subprocess.call([PY, "fetch_ips.py", "-source", "fofa",
                             "-dry-run", "-regions", regions],
                            cwd=HERE, stdout=f, stderr=subprocess.STDOUT)
        with open(out, "r", encoding="utf-8") as f:
            print(f.read())
    except OSError as e:
        print(f"   [X] 生成失败: {e}")
        return NO_SUMMARY
    print(f"   {'-' * 56}")
    print("   语法已同时保存到 fofa_queries.txt（方便复制）")
    print("\n   下一步:")
    print("     1. 打开 https://fofa.info 并登录")
    print("     2. 把上面某个地区的整行语法粘进搜索框，回车")
    print("     3. 右上角「导出」选 CSV，下载下来")
    print("     4. 回到本菜单选 [2] 导入，或把 CSV 拖到 run.bat 上")
    print(f"   {'-' * 56}")
    return NO_SUMMARY


def mode_selftest():
    print("\n   --- 自检: 不抓取 FOFA，用内置样例验证整条链路 ---")
    if not check_proxy():
        return NO_SUMMARY
    tmp = os.path.join(HERE, "_selftest.csv")
    code = run([PY, "fetch_ips.py", "-self-test", "-o", tmp,
                "-run", "--", "-skiptr", "-d", "1", "-threads", "2"])
    try:
        if os.path.exists(tmp):
            os.remove(tmp)
    except OSError:
        pass
    return code


def mode_config():
    cfg = os.path.join(HERE, "config.ini")
    if not os.path.exists(cfg):
        print("\n   [X] 没有找到 config.ini。")
        return 1
    print("\n   正在打开 config.ini，改完保存关闭记事本即可回到菜单。")
    try:
        subprocess.call(["notepad", cfg])
    except OSError:
        print(f"   [!] 打不开记事本，请手动编辑: {cfg}")
    return 0


def main():
    regions = "HK,JP,KR,SG,TW,US"
    threads = "20"
    drag = sys.argv[1] if len(sys.argv) > 1 else ""

    while True:
        clear()
        print(BANNER)
        print(MENU)
        mode = ask("   请输入序号后回车: ")

        if mode in ("0", "q", "Q", "exit"):
            return 0

        try:
            if mode == "1":
                res = mode_list(threads)
            elif mode == "2":
                res = mode_ipdb(threads)
            elif mode == "3":
                res = mode_api(regions, threads)
            elif mode == "4":
                res = mode_csv(drag, threads)
                drag = ""          # 拖拽参数只用一次
            elif mode == "5":
                res = mode_syntax(regions)
            elif mode == "6":
                res = mode_selftest()
            elif mode == "7":
                mode_config()
                continue
            else:
                print("\n   输入无效，请重新选择。")
                ask("\n   回车返回菜单: ")
                continue
        except Quit:
            raise

        if res is NO_SUMMARY:
            continue

        print(f"\n   {LINE}")
        print("   结束")
        if os.path.exists(os.path.join(HERE, "ip.txt")):
            print("      优选结果 : ip.txt")
        if os.path.isdir(os.path.join(HERE, "output")):
            print("      详细表格 : output\\ 目录")
        print(f"   {LINE}")
        if ask("\n   回车返回菜单，输入 q 退出: ").lower() == "q":
            return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Quit:
        print()
        sys.exit(0)
