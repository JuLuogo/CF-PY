cd /opt/cfip
cat > /tmp/final.py <<'PY'
import sys, time
sys.path.insert(0, "/opt/cfip")
import ip

ip.PROGRESS_EVERY = 0
ip.log = lambda *a, **k: None

# 2000 个样本：模拟真实扫描的混合比例（30% 黑洞 + 70% 快速失败/可用）
GOOD = ["103.101.0.73", "103.109.234.61", "103.201.131.197", "103.195.191.121",
        "91.90.193.24", "101.32.169.108", "110.10.178.240"]
BLACKHOLE = ["8.209.186.193", "47.254.136.174", "43.121.16.19"]
N = 2000
items = []
for i in range(N):
    if i % 10 < 3:
        items.append({"ip": BLACKHOLE[i % len(BLACKHOLE)], "port": "443"})
    else:
        items.append({"ip": GOOD[i % len(GOOD)], "port": "443"})

print("  样本 %d 个（30%% 黑洞 + 70%% 可用），超时 5s" % N)
print("  预期耗时 ≈ 黑洞数 x 超时 / 并发")
print()
print("  %-24s %-10s %-12s %-10s %s" % ("模式", "耗时", "吞吐", "命中", "CPU秒"))
print("  " + "-" * 66)

def run(use_async, conc, label, tmo=5):
    ip.USE_ASYNCIO = use_async
    ip.ASYNCIO_CONCURRENCY = conc
    ip.CURL_TIMEOUT_SEC = tmo
    c0 = time.process_time()
    t0 = time.time()
    out = ip.stage1(items, conc)
    dt = time.time() - t0
    cpu = time.process_time() - c0
    print("  %-24s %-10s %-12s %-10s %.2f" % (
        label, "%.1fs" % dt, "%.1f/s" % (N/dt), "%d" % len(out), cpu))
    return dt

d1 = run(False, 60,  "线程池  60 线程")
d2 = run(False, 200, "线程池 200 线程")
d3 = run(False, 400, "线程池 400 线程")
d4 = run(True,  60,  "asyncio  60 并发")
d5 = run(True,  200, "asyncio 200 并发")
d6 = run(True,  400, "asyncio 400 并发")
d7 = run(True,  800, "asyncio 800 并发")

print()
print("  --- 再看超时的作用（asyncio 400 并发）---")
run(True, 400, "asyncio 400 超时 3s", 3)
run(True, 400, "asyncio 400 超时 5s", 5)
run(True, 400, "asyncio 400 超时 10s", 10)

print()
print("  结论：")
print("    线程池最好  %.1fs" % min(d1, d2, d3))
print("    asyncio 最好 %.1fs" % min(d4, d5, d6, d7))
print("    提速 %.1f 倍" % (min(d1, d2, d3) / min(d4, d5, d6, d7)))
PY
python3 /tmp/final.py
