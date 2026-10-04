TOKEN=$(grep -oP '(?<=-token )\S+' /etc/systemd/system/cfip-web.service | head -1)
PORT=$(grep -oP '(?<=-port )\d+' /etc/systemd/system/cfip-web.service | head -1)

get_done() {
  curl -sS --max-time 8 "http://127.0.0.1:${PORT}/api/status?token=${TOKEN}" 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); p=(d.get('progress') or {}).get('s1') or {}; print(p.get('done') or 0)" 2>/dev/null
}

A=$(get_done)
sleep 30
B=$(get_done)
RATE=$(( (B - A) / 30 ))
echo "  30 秒内: $A -> $B"
echo "  实际速率: ${RATE} 个/秒"
echo
TOTAL=181751
LEFT=$(( TOTAL - B ))
if [ "$RATE" -gt 0 ]; then
  ETA=$(( LEFT / RATE ))
  echo "  剩余 $LEFT 个，预计还需 $(( ETA / 60 )) 分 $(( ETA % 60 )) 秒"
fi
echo
echo "  === 与调优前对比 ==="
echo "    调优前: 11.3 个/秒  ->  18 万要 4.5 小时"
echo "    调优后: ${RATE} 个/秒"
echo
echo "  === 面板进度数据 ==="
curl -sS --max-time 8 "http://127.0.0.1:${PORT}/api/status?token=${TOKEN}" -o /tmp/s.json
python3 - <<'PY'
import json
d = json.load(open('/tmp/s.json'))
prog = d.get('progress') or {}
if not prog:
    print('    (还没有 progress 数据)')
for k in ('asn', 'geo', 's1', 's2', 's3'):
    p = prog.get(k)
    if not p:
        continue
    out = '    %-5s %-26s %s/%s (%.1f%%)' % (
        k, p.get('name', ''), p.get('done'), p.get('total'), p.get('pct', 0))
    if p.get('current'):
        out += '  cur=' + str(p['current'])
    if p.get('ip'):
        out += '  ip=' + str(p['ip'])
    if p.get('cidr'):
        out += '  cidr=' + str(p['cidr'])
    print(out)
PY
echo
echo "  === 资源 ==="
free -m | sed 's/^/    /'
ps -o pid,pcpu,rss,cmd -C python3 2>/dev/null | grep -E "fetch_ips|ip.py" | awk '{printf "    PID %-8s CPU %-6s RSS %.0fMB\n", $1, $2"%", $3/1024}'
