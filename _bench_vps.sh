TS=$(date +%s)
BASE="https://ghproxy.net/https://raw.githubusercontent.com/JuLuogo/CF-PY/main"

echo "===== 1) 更新代码（带防缓存）====="
cd /opt/cfip || exit 1
for f in ip.py fetch_ips.py webui.py notify.py config.ini; do
  if [ "$f" = "config.ini" ]; then
    # config.ini 不覆盖，只补新键
    continue
  fi
  curl -fsSL --max-time 30 "$BASE/$f?t=$TS" -o "$f.new" 2>/dev/null && mv "$f.new" "$f" \
    && echo "  ✓ $f ($(wc -c < $f) bytes)" || { rm -f "$f.new"; echo "  ✗ $f"; }
done
chmod +x *.py

echo
echo "===== 2) 给 config.ini 补性能相关的键 ====="
add_key() { grep -q "^$1" config.ini || { echo "$1 = $2" >> config.ini; echo "  + $1 = $2"; }; }
add_key USE_NATIVE_SOCKET true
add_key USE_ASYNCIO true
add_key ASYNCIO_CONCURRENCY 300
add_key OUTPUT_REGIONS '"HK,JP,SG,KR,TW"'
add_key OUTPUT_SPLIT true
grep -E '^(USE_NATIVE_SOCKET|USE_ASYNCIO|ASYNCIO_CONCURRENCY|OUTPUT_REGIONS|OUTPUT_SPLIT|THREADS|ASN_SAMPLE)' config.ini | sed 's/^/    /'

echo
echo "===== 3) 停掉扫描，保证基准测试干净 ====="
systemctl stop cfip
sleep 2
echo "  cfip: $(systemctl is-active cfip)"
echo "  核数: $(nproc)"

echo
echo "===== 4) 基准测试：1 核上 asyncio vs 线程池 ====="
cd /opt/cfip
cat > /tmp/bench.py <<'PY'
import os, sys, time, statistics
sys.path.insert(0, "/opt/cfip")
import ip

ip.PROGRESS_EVERY = 0
ip.log = lambda *a, **k: None

# 用一批真实的反代 IP（从上次扫到的候选里取），再混一些必然不通的
GOOD = ["103.101.0.73", "101.32.169.108", "103.109.234.61", "103.201.131.197",
        "103.195.191.121", "91.90.193.24", "110.10.178.240", "8.209.186.193",
        "47.254.136.174", "43.121.16.19"]
DEAD = ["192.0.2.%d" % i for i in range(1, 21)]
ITEMS = [{"ip": a, "port": "443"} for a in (GOOD * 10)] + \
        [{"ip": a, "port": "443"} for a in DEAD]

print(f"  样本 {len(ITEMS)} 个（{len(GOOD)*10} 好 + {len(DEAD)} 死）")
print()
print(f"  {'模式':<26} {'耗时':>8} {'吞吐':>12} {'命中':>8} {'CPU秒':>8}")
print("  " + "-" * 66)

def run(use_async, conc, label):
    ip.USE_ASYNCIO = use_async
    ip.ASYNCIO_CONCURRENCY = conc
    c0 = time.process_time()
    t0 = time.time()
    out = ip.stage1(ITEMS, conc)
    dt = time.time() - t0
    cpu = time.process_time() - c0
    print(f"  {label:<26} {dt:7.2f}s {len(ITEMS)/dt:10.1f}/s {len(out):7d} {cpu:7.2f}s")
    return dt

run(False, 60,  "线程池  60 线程")
run(False, 200, "线程池 200 线程")
run(False, 400, "线程池 400 线程")
run(True,  60,  "asyncio  60 并发")
run(True,  200, "asyncio 200 并发")
run(True,  400, "asyncio 400 并发")
run(True,  800, "asyncio 800 并发")
PY
python3 /tmp/bench.py

echo
echo "===== 5) 恢复扫描 ====="
systemctl start cfip
sleep 3
echo "  cfip: $(systemctl is-active cfip)"
