cd /opt/cfip
echo "=== 部署的 process_batch 里 ip0/ip1 相关代码 ==="
python3 - <<'PY'
import io
s = io.open('/opt/cfip/fetch_ips.py', encoding='utf-8').read()
a = s.index('def process_batch(')
b = s.index('def run_asn_pipeline(') if 'def run_asn_pipeline(' in s[a:] else a + 5000
seg = s[a:a+4200]
for i, line in enumerate(seg.split(chr(10)), 1):
    if any(k in line for k in ('tick0', 'tick1', 'ip0', 'ip1', 'alive0',
                               'stage0_tcp', 'stage1_async', 'on_progress')):
        print("%4d: %s" % (i, line.rstrip()))
PY
echo
echo "=== 关键：on_progress 到底传的是哪个 ==="
grep -n "on_progress=" /opt/cfip/fetch_ips.py | sed 's/^/  /'
echo
echo "=== tick1 函数体 ==="
python3 - <<'PY'
import io
s = io.open('/opt/cfip/fetch_ips.py', encoding='utf-8').read()
a = s.index('def tick1(')
print(s[a:a+420])
PY
