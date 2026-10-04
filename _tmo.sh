cd /opt/cfip
cat > /tmp/tmo.py <<'PY'
import sys, time
sys.path.insert(0, "/opt/cfip")
import ip

ip.PROGRESS_EVERY = 0
ip.log = lambda *a, **k: None
ip.USE_ASYNCIO = True
ip.ASYNCIO_CONCURRENCY = 200

# 只用已知可用的 IP，各测 10 次
GOOD = ["103.101.0.73", "101.32.169.108", "103.109.234.61", "103.201.131.197",
        "103.195.191.121", "91.90.193.24", "110.10.178.240", "8.209.186.193",
        "47.254.136.174", "43.121.16.19"]
ITEMS = [{"ip": a, "port": "443"} for a in (GOOD * 10)]
N = len(ITEMS)

print("  纯好 IP %d 个（10 个地址 x 10 次），理论命中应 100%%" % N)
print()
print("  %-10s %-10s %-12s %-10s %s" % ("超时", "耗时", "吞吐", "命中率", "CPU秒"))
print("  " + "-" * 58)

for tmo in (3, 5, 8, 12, 20):
    ip.CURL_TIMEOUT_SEC = tmo
    c0 = time.process_time()
    t0 = time.time()
    out = ip.stage1(ITEMS, 200)
    dt = time.time() - t0
    cpu = time.process_time() - c0
    hit = len(out)
    print("  %-10s %-10s %-12s %-10s %.2f" % (
        f"{tmo}s", f"{dt:.2f}s", f"{N/dt:.1f}/s", f"{hit}/{N} ({hit*100//N}%)", cpu))

print()
print("  如果命中率随超时明显上升 -> 就是超时太短，不是代码问题")
PY
python3 /tmp/tmo.py
