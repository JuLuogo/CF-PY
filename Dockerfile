# Cloudflare 反代 IP 优选 —— 全平台容器
#
# 这个项目是纯标准库实现（不需要 pip install 任何东西），所以镜像只装三个
# 外部命令就够了，体积很小。
FROM python:3.12-slim

# ip.py 依赖这三个外部命令，缺一不可：
#   curl        —— 可用性检查 / 测速（用 --resolve 把域名指到指定 IP）
#   ping        —— 延迟测量
#   traceroute  —— 阶段三的线路分析（判断 163 / CN2 / CMI / 169 等）
# tzdata 是为了让 TZ=Asia/Shanghai 生效（否则 output/{date} 会按 UTC 分目录）
# tini 做 init，正确处理 docker stop 的 SIGTERM —— -loop 模式下很重要
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl \
      iputils-ping \
      traceroute \
      ca-certificates \
      tzdata \
      tini \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY ip.py fetch_ips.py webui.py config.ini ip_override.json ./

# 容器里把 ip.txt 也放进 output/ 下，这样只需要挂载一个目录就能拿到全部产物。
# （Windows 上用 run.bat 时仍然是项目根目录的 ./ip.txt，不受影响）
RUN sed -i 's|^DEFAULT_IP_OUTPUT *=.*|DEFAULT_IP_OUTPUT = "{path}/ip.txt"|' config.ini \
 && mkdir -p /app/output \
 && python -c "import ip,sys; c=ip.load_config('/app/config.ini'); print('ip_output =', c.get('DEFAULT_IP_OUTPUT'))"

ENV PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
    TZ=Asia/Shanghai \
    ASNS=alibaba,tencent,bandwagon \
    ASN_SAMPLE=200 \
    ASN_REGIONS=HK,JP,SG

# 默认：每 30 分钟一轮，扫阿里云国际/腾讯云国际/搬瓦工，
# 采样后只保留香港/日本/新加坡，测完直接调 ip.py 实测。
# -threads 20 是并发上限，按需调整；-d 5 = 每次测速只下载 5MB，别贪多。
# -quiet 是小硬盘必需：逐条进度日志一轮能写十几 MB，精简后只写每 200 条一行。
CMD ["-source", "asn", "-loop", "1800", "-run", "--", "-threads", "20", "-d", "5", "-log", "-quiet"]

ENTRYPOINT ["/usr/bin/tini", "--", "python", "fetch_ips.py"]
