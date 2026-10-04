cd /opt/cfip
cat > /tmp/which.py <<'PY'
import socket, ssl, sys, time
sys.path.insert(0, "/opt/cfip")
import ip

GOOD = ["103.101.0.73", "101.32.169.108", "103.109.234.61", "103.201.131.197",
        "103.195.191.121", "91.90.193.24", "110.10.178.240", "8.209.186.193",
        "47.254.136.174", "43.121.16.19"]

print("  逐个 IP：TCP 连通性 + TLS + trace 结果")
print()
print("  %-18s %-14s %-14s %-10s %s" % ("IP", "TCP连接", "TLS握手", "trace", "说明"))
print("  " + "-" * 74)

for a in GOOD:
    # 1) 纯 TCP 连接
    t0 = time.time()
    tcp_ok = tls_ok = trace_ok = False
    note = ""
    s = None
    try:
        s = socket.create_connection((a, 443), timeout=6)
        tcp_ok = True
        tcp_t = time.time() - t0
    except socket.timeout:
        note = "TCP 超时（黑洞，无响应）"
        tcp_t = time.time() - t0
    except ConnectionRefusedError:
        note = "TCP 拒绝（端口没开，正常）"
        tcp_t = time.time() - t0
    except OSError as e:
        note = f"TCP 错误 {type(e).__name__}"
        tcp_t = time.time() - t0

    if tcp_ok and s:
        # 2) TLS
        t1 = time.time()
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            t = ctx.wrap_socket(s, server_hostname=ip.AVAILABILITY_HOST)
            tls_ok = True
            tls_t = time.time() - t1
            # 3) trace
            t.sendall(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: " +
                      ip.AVAILABILITY_HOST.encode() + b"\r\nConnection: close\r\n\r\n")
            d = t.recv(4096)
            trace_ok = b"loc=" in d
            t.close()
        except Exception as e:
            note = f"TLS 失败 {type(e).__name__}"
            tls_t = time.time() - t1
    else:
        tls_t = 0

    try:
        if s: s.close()
    except OSError:
        pass

    print("  %-18s %-14s %-14s %-10s %s" % (
        a,
        ("OK %.2fs" % tcp_t) if tcp_ok else ("失败 %.1fs" % tcp_t),
        ("OK %.2fs" % tls_t) if tls_ok else "—",
        "有 loc" if trace_ok else "无",
        note))

print()
print("  说明：TCP 超时 = 这个 IP 从你 VPS 出发被黑洞，只能干等到超时。")
print("        TCP 拒绝 = 快速失败，不浪费时间（真实扫描里大多数是这种）。")
PY
python3 /tmp/which.py
