cd /opt/cfip || exit 1

echo "===== 1) 更新脚本 ====="
TS=$(date +%s)
BASE="https://ghproxy.net/https://raw.githubusercontent.com/JuLuogo/CF-PY/main"
for f in ip.py fetch_ips.py webui.py notify.py; do
  curl -fsSL --max-time 30 "$BASE/$f?t=$TS" -o "$f.new" 2>/dev/null && mv "$f.new" "$f" \
    && echo "  ✓ $f ($(wc -c < $f) bytes)" || { rm -f "$f.new"; echo "  ✗ $f"; }
done
chmod +x *.py

echo
echo "===== 2) 应用调优后的参数 ====="
set_key() {
  if grep -q "^$1" config.ini; then
    sed -i "s|^$1 = .*|$1 = $2|" config.ini
  else
    echo "$1 = $2" >> config.ini
  fi
}
set_key ASYNCIO_CONCURRENCY 800
set_key CURL_TIMEOUT_SEC 4
set_key USE_ASYNCIO true
set_key USE_NATIVE_SOCKET true
set_key OUTPUT_REGIONS '"HK,JP,SG,KR,TW"'
set_key OUTPUT_SPLIT true
grep -E '^(ASYNCIO_CONCURRENCY|CURL_TIMEOUT_SEC|USE_ASYNCIO|USE_NATIVE_SOCKET|OUTPUT_REGIONS|ASN_SAMPLE|THREADS)' config.ini | sed 's/^/    /'

echo
echo "===== 3) 重启服务 ====="
systemctl restart cfip cfip-web
sleep 5
for s in cfip cfip-web; do
  systemctl is-active --quiet $s && echo "  ✓ $s active" || echo "  ✗ $s 没起来"
done

echo
echo "===== 4) 观察 60 秒，看新配置下的速度 ====="
sleep 55
echo "  --- 最新日志 ---"
journalctl -u cfip -n 4 --no-pager | tail -4 | sed 's/^/    /'
echo
echo "  --- 资源占用 ---"
ps -o pid,pcpu,rss,cmd -C python3 2>/dev/null | grep -E "fetch_ips|ip.py|webui" | awk '{printf "    %-8s CPU %-6s RSS %.1fMB  %s\n", $1, $2"%", $3/1024, substr($0, index($0,$4), 40)}'
echo
echo "  --- 内存总览 ---"
free -m | sed 's/^/    /'
echo
echo "  --- 进度（面板数据）---"
TOKEN=$(grep -oP '(?<=-token )\S+' /etc/systemd/system/cfip-web.service | head -1)
PORT=$(grep -oP '(?<=-port )\d+' /etc/systemd/system/cfip-web.service | head -1)
curl -sS --max-time 8 "http://127.0.0.1:${PORT}/api/status?token=${TOKEN}" -o /tmp/st.json
python3 - <<'PY'
import json
d = json.load(open('/tmp/st.json'))
prog = d.get('progress') or {}
for k in ('asn', 'geo', 's1', 's2', 's3'):
    p = prog.get(k)
    if not p:
        continue
    line = '    %-6s %-28s %s/%s (%.1f%%)' % (k, p.get('name', ''), p.get('done'),
                                              p.get('total'), p.get('pct', 0))
    if p.get('current'):
        line += '  当前=' + str(p['current'])
    if p.get('ip'):
        line += '  IP=' + str(p['ip']) + '  段=' + str(p.get('cidr', ''))
    print(line)
PY
