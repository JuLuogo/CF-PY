cd /opt/cfip || exit 1
SHA=ac1995c

echo "===== 部署 ====="
curl -fsSL --max-time 30 "https://cdn.jsdelivr.net/gh/JuLuogo/CF-PY@${SHA}/webui.py" -o webui.py.new \
  && mv webui.py.new webui.py && echo "  ✓ webui.py ($(stat -c%s webui.py))" || echo "  ✗"
chmod +x *.py; rm -rf __pycache__
systemctl restart cfip-web
sleep 4
systemctl is-active --quiet cfip-web && echo "  ✓ cfip-web" || echo "  ✗"

echo
echo "===== 实测六种访问方式（从 VPS 本机）====="
TOKEN=$(grep -oP '(?<=-token )\S+' /etc/systemd/system/cfip-web.service | head -1)
PORT=$(grep -oP '(?<=-port )\d+' /etc/systemd/system/cfip-web.service | head -1)
B="http://127.0.0.1:${PORT}"

echo "  1) 不带 token:"
curl -sS --max-time 6 "$B/api/ips" | python3 -c "import sys,json; d=json.load(sys.stdin); print('     错误:', d.get('error')); [print('       ', x) for x in (d.get('怎么传') or [])]"
echo "  2) URL 参数:"
echo "     $(curl -sS --max-time 6 "$B/api/ips?token=${TOKEN}" | head -2 | tr '\n' ' ')"
echo "  3) Authorization 头:"
echo "     $(curl -sS --max-time 6 -H "Authorization: Bearer ${TOKEN}" "$B/api/ips" | head -2 | tr '\n' ' ')"
echo "  4) X-Token 头:"
echo "     $(curl -sS --max-time 6 -H "X-Token: ${TOKEN}" "$B/api/ips" | head -2 | tr '\n' ' ')"
echo "  5) 大写 /API/IPS:"
echo "     $(curl -sS --max-time 6 "$B/API/IPS?token=${TOKEN}" | head -2 | tr '\n' ' ')"
echo "  6) 池子概览:"
curl -sS --max-time 6 "$B/api/pool?token=${TOKEN}" | python3 -c "
import sys, json
d = json.load(sys.stdin); s = d.get('summary') or {}
print('     总数:', s.get('total'))
print('     地区:', s.get('by_country'))
print('     新鲜度:', s.get('by_freshness'))
"
echo "  7) 地区版:"
echo "     $(curl -sS --max-time 6 "$B/api/ips?set=region&token=${TOKEN}" | head -2 | tr '\n' ' ')"

echo
echo "===== 汇总 ====="
echo "  扫描: $(systemctl is-active cfip)  重启数: $(systemctl show cfip -p NRestarts --value)"
journalctl -u cfip -n 3 --no-pager 2>/dev/null | tail -3 | sed 's/^/    /'
echo
free -m | sed 's/^/  /'
