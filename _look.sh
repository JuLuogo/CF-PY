TOKEN=$(grep -oP '(?<=-token )\S+' /etc/systemd/system/cfip-web.service | head -1)
PORT=$(grep -oP '(?<=-port )\d+' /etc/systemd/system/cfip-web.service | head -1)

echo "===== 面板上现在实际显示的东西（逐条打印原始数据）====="
curl -sS --max-time 8 "http://127.0.0.1:${PORT}/api/status?token=${TOKEN}" -o /tmp/s.json
python3 - <<'PY'
import json
d = json.load(open('/tmp/s.json'))
print("  state =", d.get('state'), " round =", d.get('round'))
print()
prog = d.get('progress') or {}
print("  progress 里的每一条（原始 key 和全部字段）:")
for k in sorted(prog.keys()):
    p = prog[k]
    print("  " + "=" * 70)
    print("  key = %s" % k)
    for kk, vv in p.items():
        print("      %-14s = %s" % (kk, vv))
PY

echo
echo "===== 连续采样 3 次，看哪个数字在动 ====="
for i in 1 2 3; do
  sleep 20
  curl -sS --max-time 8 "http://127.0.0.1:${PORT}/api/status?token=${TOKEN}" -o /tmp/s$i.json 2>/dev/null
  python3 - <<PY
import json
try:
    d = json.load(open('/tmp/s$i.json'))
except Exception:
    print("  [$i] fail"); raise SystemExit
p = d.get('progress') or {}
out = []
for k in ('provider','asn','prefix','ip0','ip1'):
    v = p.get(k) or {}
    out.append("%s %s/%s" % (k, v.get('done'), v.get('total')))
print("  [$i] " + " | ".join(out))
for k in ('ip0','ip1'):
    v = p.get(k) or {}
    if v.get('ip'):
        print("        %s.ip = %s   cidr=%s" % (k, v['ip'], v.get('cidr','')))
PY
done

echo
echo "===== 日志里 ip0/ip1 对应的真实动作 ====="
journalctl -u cfip -n 200 --no-pager 2>/dev/null | grep -E "stage0 完成|第一阶段完成|stage0 预筛|逐网段|进度" | tail -8 | sed 's/^/  /'
echo
echo "  最近 6 行原始日志:"
journalctl -u cfip -n 6 --no-pager 2>/dev/null | tail -6 | sed 's/^/    /'
