The readme doc is only available in Chinese cuz only Chinese users need this script （i think?

这是一个面向中国大陆用户测试CF SNI代理的python脚本，适配Windows&ubuntu。
该项目使用了生成式AI。

## 前言：

众所周知，CF对大陆访问不友好，但某些神奇的服务又将带有优质线路的cf反代暴露在公网，可能又由于某些原因没有配置好，于是被扫了，我们便可以利用这些ip提速访问cf网站时的速度。
该项目会对输入的反代ip进行多方位测试以确保实际场景可用性。

本项目没有针对80、2xxx端口的反代做支持。

本人因为自身原因没法管这个项目，故不接受任何PR。你可以fork这个项目，改完把仓库地址发在issue中。

**⚠本条道路属于见光死类型，如果你想让这条路活得得久一点，就不要滥用本项目和优质反代ip！**

请你把反代ip想象成某种程度上的公共资源：你在用，别人也在用。
人多不光导致拥挤；用得多了服务提供商也可能会注意到异常。
所以不要长时间、大流量滥用单个反代ip，比如拿去开机场。

## 环境要求 
OS: Windows or Ubuntu（未测试）
    With Python & tracepath/tracert/traceroute & curl & ping

测试环境：Windows 11 with Python & tracert & curl & ping，只保证Windows环境下的可用性。

纯标准库实现，**不需要 pip install 任何东西**。

## Linux 一键安装（VPS 上 24 小时跑）

一行命令，装完就跑：

```bash
curl -fsSL https://raw.githubusercontent.com/JuLuogo/CF-PY/main/install.sh | bash
```

安装向导会问你四个问题（**全部回车 = 推荐配置**）：

| 问题 | 选项 |
| --- | --- |
| 怎么运行 | `[1]` systemd 常驻服务（推荐）`[2]` Docker 容器 `[3]` 只跑一次看看 |
| 扫哪些厂商 | `[1]` **niche** 小众优质线路（约 4000 网段，几十秒一轮）`[2]` **vps** 主流便宜 VPS（约 22 万）`[3]` **all** 除大陆外全部（约 204 万，一轮约 4 小时） |
| 采样 / 间隔 / 并发 | 默认 300 / 1800 秒 / 50 线程 |
| Web 控制台 | 是否启用、端口、口令、只本机还是对外开放 |

脚本会自动：识别发行版（apt/yum/apk）→ 装 `python3 curl iputils-ping traceroute` → 拉代码 → 写配置 → 装 systemd 服务 → 启动。

装完常用命令：

```bash
systemctl status cfip          # 运行状态
journalctl -u cfip -f          # 实时日志
systemctl restart cfip         # 重启
ls /opt/cfip/output/           # 结果：ip.txt / bestips-*.csv
```

> 仓库地址已指向 `JuLuogo/CF-PY`。要装到别的 fork 上用环境变量覆盖：
> `CFIP_REPO=https://github.com/你/仓库 bash install.sh`

## Web 控制台

纯标准库实现（`http.server`），不需要装任何东西：

```bash
python3 webui.py                                   # 只监听 127.0.0.1:8080
python3 webui.py -host 0.0.0.0 -port 8080 -token 你的口令
# 浏览器打开 http://<VPS_IP>:8080/?token=你的口令
```

能看到：

- **实时进度条**：当前阶段（抓取 / 第一阶段可用性 / 第二阶段测速 / 第三阶段线路）、已完成 X/Y、百分比
- **运行状态**：是否在跑、第几轮、候选数、保留数、可用磁盘、上次更新时间、最后一行日志
- **优选结果**：按 延迟+丢包 综合评分排序的表格（排名/端口/评分/延迟/丢包/速度/线路/地区/城市）
- **推送设置**：选渠道、填目标、保存到 config.ini、一键发测试推送
- **推送内容预览**：点一下就看到下一轮会推什么（含各地区数量、端口分布、最佳 IP）
- **ip.txt**：直接可复制的最终列表
- **日志**：尾部 200 行实时日志
- **立即跑一轮**：按钮触发一次单轮扫描

推送设置改完**点保存就写进 config.ini**（只动 `NOTIFY_*` 三个键，不碰其它配置），下一轮生效；想立刻验证就点「发测试推送」，会真的发到你手机。

**安全设计**：默认只监听 `127.0.0.1`（只有本机能访问）。要对外暴露必须显式 `-host 0.0.0.0` **并且**给 `-token`，否则脚本直接拒绝启动 —— 没有 token 的公开面板等于把控制权交出去。所有 API 都校验 token。

只监听本机时，用 SSH 端口转发访问最安全：

```bash
ssh -L 8080:127.0.0.1:8080 root@你的VPS
# 然后本地浏览器开 http://127.0.0.1:8080/?token=你的口令
```

### 对外 API（给其他服务消费）

面板同时是一个 **IP 供给接口**，别的服务只需要拉这个，不用关心扫描是怎么跑的：

```bash
# 一行一个 IP（默认，最省事）
curl "http://127.0.0.1:8080/api/ips?token=你的口令"

# /etc/hosts 风格（喂给 dnsmasq / AdGuard）
curl "http://127.0.0.1:8080/api/ips?token=你的口令&format=hosts&domain=cf.example.com"

# 带过滤：延迟 ≤100ms、丢包 ≤5%、只要港日新
curl "http://127.0.0.1:8080/api/ips?token=你的口令&max_latency=100&max_loss=5&country=HK,JP,SG"

# CSV / JSON
curl "http://127.0.0.1:8080/api/ips?token=你的口令&format=csv"
curl "http://127.0.0.1:8080/api/ips?token=你的口令&format=json&limit=50"
```

| 参数 | 说明 |
| --- | --- |
| `format` | `text`（默认）/ `json` / `csv` / `hosts` |
| `limit` | 最多返回几个，默认 200 |
| `max_latency` | 延迟上限（ms） |
| `max_loss` | 丢包率上限（%） |
| `min_speed` | 速度下限（MB/s） |
| `country` | 只要这些地区，逗号分隔，如 `HK,JP,SG` |
| `domain` | `format=hosts` 时用的域名 |

JSON 格式会带上每个 IP 的延迟/丢包/速度/评分/线路，方便下游自己再排一次序。

## 小硬盘 VPS 的磁盘控制

1GB 可用空间的机器必须管住日志，否则几天就满。**逐条进度日志是最大的杀手**：

| `PROGRESS_EVERY` | 全量扫描一轮日志 | 一天 48 轮 |
| --- | --- | --- |
| `1`（逐条） | **133.5 MB** | **6.4 GB** ← 几小时就爆盘 |
| `200`（默认） | 0.7 MB | 32 MB |
| `1000` | 0.1 MB | 6 MB |

四道防线（都在 `config.ini`）：

| 配置 | 默认 | 作用 |
| --- | --- | --- |
| `PROGRESS_EVERY` | 200 | 每 N 条才写一行进度 |
| `LOG_MAX_BYTES` | 8 MB | 单个日志上限，超了砍掉前半只留尾部 1/4 |
| `KEEP_LOGS` / `KEEP_RESULTS` | 5 / 20 | 只留最新的 N 个日志、N 份结果 |
| `KEEP_DAYS` / `MIN_FREE_MB` | 7 / 300 | 超过 7 天的日期目录整个删；可用空间低于 300MB 触发激进清理 |

清理在**每轮开始前和结束后各跑一次**，状态写进 `output/status.json`，Web 面板上能直接看到可用空间。

算一笔账：日志上限 8MB × 保留 5 个 = **40 MB**，加上结果和 `ip.csv`，总占用稳定在 **100 MB 以内**。1GB 空间绰绰有余。

> 不需要外接数据库 —— 结果就是一个小 CSV + 一个 ip.txt，用文件反而是最省事、最不容易坏的方案。

## 一键运行（run.bat）

Windows 上双击 `run.bat` 即可，中文界面由 `menu.py` 输出：

```
    Cloudflare 反代 IP 一键优选
    IPDB / FOFA 抓取  +  ip.py 实测

    [1] 第三方反代IP列表 抓取 + 实测      免费免 key（推荐，质量最好）
    [2] IPDB 抓取 + 实测                  免费免 key
    [3] FOFA API 全自动抓取 + 实测        需要 API key
    [4] 导入 FOFA 网页版导出的 CSV        不需要 key
    [5] 生成 FOFA 查询语法                不联网，手动去网页查
    [6] 自检                             不抓取，验证脚本链路
    [7] 编辑 config.ini                   改地区 / 测速大小 / 数据源
    [0] 退出
```

也可以把 FOFA 导出的 CSV **直接拖到 `run.bat` 上**，会自动跳到模式 4。

脚本会在实测前检查代理和 TUN 虚拟网卡，检测到了会拦下来让你确认——这是有意为之，理由见下面的警告。

> `run.bat` 本身是**纯 ASCII** 的，这不是偷懒：cmd.exe 解析批处理文件时用的是控制台代码页，一个含中文的 UTF-8 批处理只要中途 `chcp` 切了代码页，cmd 记录的字节偏移就会错位，后面的行会被从中间切断（实测会报 `'#...' is not recognized` 这类错）。所以中文界面全部放进 `menu.py` 由 Python 输出，编码稳定可控。

## 工作流程
（可选）自动搜反代IP（第三方列表/ASN/IPDB/FOFA） -> 导入ip csv -> 提取ip并去重 -> 检查可用性 -> 测试延迟、速度 -> 筛选优质ip -> 使用ipinfo查询ip本身对应国家 -> traceroute分析线路 -> 生成 bestips-{date}.csv 以及 ip.txt

## 推荐架构：VPS 发现 + 本机测质量

延迟和丢包**跟测量点强相关**。在 VPS 上测出来的「这个 IP 50ms」对家里的宽带毫无参考价值。所以分成两段：

```
┌─ VPS（境外/香港，24 小时跑）─────────────────────┐
│  只做发现：哪些 IP 真的反代了 CF                  │
│  python ip.py -i candidates.csv -stage1 \        │
│         -threads 200 -o available.csv            │
│  → 产出 available.csv（纯 IP 列表，不含任何质量结论）│
└──────────────────────────────────────────────────┘
                    ↓  把 available.csv 拿回本地
┌─ 本机 / NAS（真实家宽，电信·联通·移动）──────────┐
│  做质量测量 + 排序：                              │
│  python ip.py -i available.csv -threads 20 -d 5  │
│  → ip.txt（按 延迟+丢包 排序，Top 200）           │
└──────────────────────────────────────────────────┘
                    ↓
              推送到 DNS 做分流
```

`-stage1` 只跑可用性检查就结束，**不 ping、不测速、不 traceroute**——那些在 VPS 上做纯属浪费。这样 VPS 那一段可以开到很高并发（`-threads 200`），几分钟扫完几万个 IP。

### 筛选与排序规则

第二阶段按「延迟 + 丢包」综合评分排序：

```
评分 = 延迟(ms) × (1 + 丢包率/100 × LOSS_PENALTY)

 0% 丢包 → 分数 = 延迟
10% 丢包 → 分数 = 延迟 × 1.5
30% 丢包 → 分数 = 延迟 × 2.5
```

淘汰线（都可在 `config.ini` 调）：

| 配置 | 默认 | 作用 |
| --- | --- | --- |
| `MAX_LATENCY_MS` | 300 | 延迟超了直接淘汰 |
| `MAX_LOSS_PCT` | 30 | 丢包超了直接淘汰 |
| `MIN_SPEED_MBPS` | 1.0 | 速度下限 |
| `TOP_N` | 200 | 最终只留前 N 个 |
| `LOSS_PENALTY` | 5.0 | 越大越"嫌弃"丢包 |
| `SORT_MODE` | `score` | `score`=综合评分 / `country`=原版逻辑 |

**为什么不能只看延迟**：纯按延迟排会把「40ms 但丢包 25%」排到最前面；纯按丢包排又会把「280ms 零丢包」排到「30ms 丢包 1%」前面。都不对。

**为什么丢包比延迟重要**：一次 TLS 握手要几个来回，5% 丢包就会让握手反复重传，体感比 200ms 延迟还差。实测 `1.1.1.1` 就出现过 295ms / **75% 丢包**——旧逻辑里它延迟 295<300 能过关，现在会被直接淘汰。

输出的 `bestips-*.csv` 带 `rank / score / latency / loss / speed`，按分数升序，直接可以拿去生成 DNS 记录。

## Docker 部署（VPS 上 24 小时跑）

```bash
docker compose up -d        # 启动
docker compose logs -f      # 看日志
docker compose down         # 停止
```

产物落在宿主机 `./output/`（含 `ip.txt` 和 `bestips-*.csv`）。

**镜像自动构建**：推到 GitHub 后 `.github/workflows/docker.yml` 会自动构建并推送到 GHCR（amd64 + arm64 双架构）。首次推送后要去仓库的 Packages 页面把包设为 **Public**，否则 VPS 上拉取需要先 `docker login ghcr.io`。

**⚠ `network_mode: host` 不是可选项**：

- bridge 模式下容器流量走 Docker NAT，`ping`/`traceroute` 第一跳会变成 `172.17.0.1`，阶段三的线路分析完全失真
- host 网络**只在 Linux 上有效**。Docker Desktop（Win/macOS）跑在虚拟机里，测到的是虚拟机那条路径，不能代表宿主机

容器配置全走环境变量，不用改 `config.ini`：

```yaml
environment:
  TZ: Asia/Shanghai
  ASNS: "vps"                      # 档位或厂商名，会自动展开成全部 ASN
  ASN_SAMPLE: "300"                # 每个 ASN 采样多少个 /24（0 = 全量）
  ASN_EXCLUDE_REGIONS: "CN"        # 排除大陆，其余全要
```

## 自动获取反代 IP（第三方列表 / ASN / IPDB / FOFA）

`ip.py` 只负责**测试**，不含**找 IP** 的环节。`fetch_ips.py` 补上了这一环：从数据源抓候选 IP，写成 `ip.py` 能直接吃的 `ip.csv`，一条命令跑完整个流程。

四个数据源（`-source`）：`list`（默认）/ `asn` / `ipdb` / `fofa` / `csv`。

### 路线 A：第三方列表（零成本，可用率最高）

社区维护的 CF 反代 IP 列表：

| 源 | 条数 | 443 端口 | 说明 |
| --- | --- | --- | --- |
| `zip` | 14,635 | 8,358 | zip.cm.edu.kg，74 国地区标注 |
| `muhaip` | 7,320 | 1,447 | 已停更 |
| `luuaiyan` | 2,051 | 全部 | |
| `xgonce` | 1,750 | 1,578 | 每 6 小时更新，自带测速结果 |
| `wwuyi` / `wwuyi_c` | 462 / 86 | 全部 | 带速度和地区 |

实测对比（同一网络、同一 SNI）：**`zip` 的 443 条目 8 个里 7 个可用**，而 IPDB 的 `bestproxy` 池 8 个里 0 个可用。

```bash
python fetch_ips.py -source list -list-urls "zip,wwuyi,luuaiyan" -max 100 -run
```

### 路线 B：ASN 段扫描（定向找新 IP）

按服务商 ASN 扫网段。段数据来自 RIPE Stat 的公开 BGP 数据（免费无 key）。

```bash
# 档位
python fetch_ips.py -source asn -asns niche -asn-sample 0 -run
# 指定厂商
python fetch_ips.py -source asn -asns "alibaba,tencent,oracle,dmit" -asn-sample 300 -run
```

**内置档位**：

| 档位 | ASN 数 | /24 数量 | 一轮耗时 |
| --- | --- | --- | --- |
| `niche` | 20 | ~4,000 | 几十秒 |
| `vps` | 55 | ~220,000 | 几分钟 |
| `all` | 70 | ~2,038,000 | 约 4 小时 |

**可用厂商名**：`alibaba` `tencent` `oracle` `huawei` `ucloud` `yunify` `bandwagon` `dmit` `gigsgigs` `akile` `evoxt` `bytevirt` `zgocloud` `vmiss` `cloudie` `kurun` `timeweb` `vdsina` `vultr` `digitalocean` `linode` `hetzner` `ovh` `contabo` `scaleway` `upcloud` `kamatera` `ionos` `netcup` `leaseweb` `gcore` `aeza` `melbicom` `frantech` `hosthatch` `sharktech` `psychz` `multacom` `colocrossing` `zenlayer` `worldstream` `serverius` `hostwinds` `interserver` `greencloud` `sakura` `amazon` `microsoft` `google` `softbank` `kddi` `ntt` `akamai` `softlayer` `fastly` `bunny`

大陆厂商单独分组（默认不扫，因为做不了境外反代）：`alibaba_cn` `tencent_cn` `huawei_cn` `ucloud_cn` `yunify_cn`

> **一家厂商往往有多个 ASN，只查一个会漏掉一大半**：阿里云只查 AS45102 → 4.3 万个 /24，实际 12.4 万（漏 2/3）；腾讯云只查 AS132203 → 1.1 万，实际 6.0 万（漏 5/6）。所以填厂商名会自动展开成它**全部** ASN（用 PeeringDB 查出来的，不是猜的）。

### 地区过滤

采样后可以按地区筛（用 ip-api.com 免费批量接口，100 IP/请求）：

```bash
# 黑名单：排除大陆，其余全要（默认）
-asn-exclude-regions "CN"

# 白名单：只要近端
-asn-regions "HK,JP,SG,KR,TW"
```

> 一个 ASN 的 /24 横跨它所有海外区域（AS45102 的 4.3 万个 /24 覆盖美/欧/日/新/港），不筛的话大部分探针浪费在无关区域。

### 路线 C：IPDB

```bash
python fetch_ips.py -source ipdb -max 100 -cf-sample 30 -run
```

`cfv4` 是 Cloudflare 官方网段，会按**不同 /24** 采样（不是全展开——15 条网段展开是 152 万个 IPv4）。`cfv6` 会被跳过，因为 `ip.py` 只支持 IPv4。

### 路线 D：FOFA

```bash
# 有 API key
python fetch_ips.py -source fofa -regions HK,JP,KR -run

# 没 API key：生成语法 → 网页查询 → 导出 CSV → 导入
python fetch_ips.py -source fofa -dry-run -regions HK,JP
python fetch_ips.py -source csv -import-csv fofa_export.csv -run
```

查询语法（可直接贴到 fofa.info 搜索框）：

```
server=="cloudflare" && port=="443" && header="Forbidden" && country=="HK" && asn!="13335" && asn!="209242"
```

- `server=="cloudflare"`：响应头 Server 是 cloudflare → 它背后接着 CF
- `header="Forbidden"`：响应状态行是 `403 Forbidden`（CF 的拒答页）
- `asn!="13335" && asn!="209242"`：**必须**排除 Cloudflare 自家 ASN，否则抓到的全是 CF 边缘节点

### 定时 / 全自动

```bash
python fetch_ips.py -source asn -asns vps -asn-sample 300 -loop 1800 -run -- -threads 50 -d 5 -log -quiet
```

### 参数

| 参数 | 说明 |
| --- | --- |
| `-source` | `list`（默认）/ `asn` / `ipdb` / `fofa` / `csv` / `auto` |
| `-max` | 最多测多少个候选（过滤后截断），防过量测速 |
| `-loop` | 每 N 秒跑一轮，0=只跑一次 |
| `-asns` | ASN 档位/厂商名/AS 号，逗号分隔 |
| `-asn-sample` | 每个 ASN 采样多少个 /24，0=全量 |
| `-asn-regions` | 白名单：只保留这些地区 |
| `-asn-exclude-regions` | 黑名单：排除这些地区（默认 CN） |
| `-list-urls` | 第三方列表源，名字或完整 URL |
| `-list-regions` | 列表源的地区过滤 |
| `-ipdb-types` | IPDB 列表类型，默认 `bestproxy;cfv4;proxy` |
| `-cf-sample` | 从 CF 官方网段采样多少个 IP，建议 10~50 |
| `-preset` | FOFA 预设：`proxy` / `relaxed` / `cert` / `trace` |
| `-regions` | FOFA 地区 |
| `-o` | 输出 CSV，默认 `./ip.csv` |
| `-import-csv` | 导入 FOFA 网页版导出的 CSV |
| `-run` | 抓完自动调用 `ip.py`；`--` 之后的参数原样透传 |
| `-dry-run` | 只打印查询，不联网 |
| `-self-test` | 不联网，用内置样例自检整条链路 |
| `-check-env` | 只输出代理 / 隧道网卡报告 |

### ⚠ 测速前必须完全退出代理（光关「系统代理」开关没用）

`ip.py` 的可用性、延迟、速度、线路四项全都依赖「本机真实出口」。这里有个**比系统代理隐蔽得多**的坑：

Clash 的 **TUN 模式**会把默认路由指向虚拟网卡，NextHop 落在 fake-IP 保留段（`198.18.0.0/15`），于是 ping / tracert / curl 全部在**网络层**被劫持——`curl --noproxy` 也绕不过去，因为劫持不在应用层。

实测到的症状：

| 现象 | 实测值 |
| --- | --- |
| 默认路由 | `0.0.0.0/0 → 198.18.0.2`（FlClash） |
| tracert | **只有 1 跳**，目标自己就是第一跳（隧道伪造的响应） |
| CF 落地 | JP / NL / IN / IT / HK / AU **所有国家的 IP 全部** `colo=HKG` |
| 延迟 | 被拉平到 45ms 左右，好坏 IP 无法区分 |
| 稳定性 | 同一 IP 两次结果不同（一次 LAX 一次超时），5s 超时大量失败 |

**结论：不是 IP 不可用，是测量被隧道打乱了。** 请**完全退出** Clash / v2ray 等工具（退出进程，不是关开关、不是切直连模式），确认默认路由回到物理网卡再跑。

脚本会自动检测这三种情况并在实测前拦下你：系统代理（注册表 / 环境变量）、隧道虚拟网卡、**默认路由被 fake-IP 接管**（`fetch_ips.py -check-env` 的 `ROUTE=` 字段）。

## 参数（覆盖config.ini）

**优先级：命令行给予 > config.ini > 脚本内置默认配置**

- -threads “测试延迟、速度”的线程数，默认2，填max时就取config.ini中的max值。
- -i 输入文件，没填默认./ip.csv
- -o csv输出，没填从config.ini中获取。#这里不支持{date}{num}等映射。
    #该工具本为自动化场景而设计，ip.txt输出是不支持关闭的。
- -d 测速文件大小，计数单位：**MB**。
- -skiptr 跳过traceroute测试（针对导入ip为中国内地ip的情况自行开启）
- -stage1 只跑第一阶段（可用性）就结束，用于「VPS 发现 + 本机测质量」两段式流程
- -quiet 精简日志，只输出抽样进度和阶段小结（小硬盘 VPS 建议开启）
- -config 后面跟配置文件路径，例如config.ini（代表./config.ini）
- -log 输出日志文件
- -debug 调试模式

## 功能实现解析

### 检查可用性
curl -sS -k --connect-timeout {timeout} --max-time {timeout} --resolve {cf-host}:443:{your-ip} https://{cf-host}/cdn-cgi/trace
有正确输出即为可用。当然，存在特殊情况。

### 测试延迟、速度
ping ... {your-ip} 解析返回延迟和丢包率
curl -w %{speed_download} ... {large-file-url}

### 去程线路分析
**如您需要使用该功能，请在config.ini中填入你的ipinfo token，默认使用lite版进行ip信息的拉取。不填token也有几率匹配到内置规则。**

traceroute/tracert/tracepath {your-ip}

带去程绕路标注(过HK线路也算绕)，但是实测有些路由器的ip没有被拉到对应的位置，这部分用了置信度辅助判断。
该功能不是特别准，仅供参考。

为了避免重复的tracert对网络环境造成负担，带有本地缓存复用功能。

主要分析：163、CN2、Anet、4837、CMI、CMIN2

## csv输入示例
| ip                  | port | protocol | title         | domain | country | city    | link                                               | org                       |
| ------------------- | ---: | -------- | ------------- | ------ | ------- | ------- | -------------------------------------------------- | ------------------------- |
| **167.179.113.223** |  443 | https    | 403 Forbidden |        | JP      | Tokyo   | [https://167.179.113.223](https://167.179.113.223) | The Constant Company, LLC |
| **108.102.223.154** |  443 | https    | 403 Forbidden |        | US      | Seattle | [https://108.102.223.154](https://108.102.223.154) | Amazon.com, Inc.          |
（ip列必须存在，存在其他输入也无所谓。）

## ip.txt 输出结果示例
1.2.3.4#JP (CN2) Tokyo 1 //电信示例1
5.6.7.8#JP (163绕HK、US) Tokyo 2 //电信示例2

## csv输出示例
| rank | ip          | score | latency | loss | speed    | cfcountry | route | tour  | country | city      |
| ---- | ----------- | ----- | ------- | ---- | -------- | --------- | ----- | ----- | ------- | --------- |
| 1    | 1.2.3.4     | 50.0  | 50ms    | 0%   | 12.8MB/s | JP        | CN2   | None  | JP      | Tokyo     |
| 2    | 5.6.7.8     | 135.8 | 120ms   | 5%   | 9.7MB/s  | JP        | 163   | HK→JP | JP      | Tokyo     |

排列优先级：`SORT_MODE=score` 时按综合评分升序；`SORT_MODE=country` 时为原版逻辑（previousCountry 优先，再按速度降序）。

表头字段注释：
rank：排名
score：综合评分 = 延迟 × (1 + 丢包率/100 × LOSS_PENALTY)，越小越好
ip：ip
latency：ping 平均延迟
loss：丢包率
speed：下载速度
cfcountry：访问/cdn-cgi/trace对应的国家/地区代码，该字段可以填充HK。
route：判断的线路类型
tour：绕路情况，没绕填充None，绕路按照上述格式填充，例：HK→JP
country：这个ip本身对应的国家
city：这个ip对应的城市

## 文件说明

| 文件 | 作用 |
| --- | --- |
| `ip.py` | 核心测试脚本（三阶段：可用性 / 延迟速度 / 线路分析） |
| `fetch_ips.py` | 多源抓取器：第三方列表 / ASN 段 / IPDB / FOFA → `ip.csv` |
| `webui.py` | Web 控制台 + 对外 IP 供给 API |
| `menu.py` + `run.bat` | Windows 一键菜单 |
| `install.sh` | Linux 一键安装（systemd / Docker） |
| `Dockerfile` + `docker-compose.yml` | 容器部署 |
| `config.ini` | 全部配置 |
| `ip_override.json` | 手工覆盖某个 IP 的国家/城市/线路判断 |

## 致谢

原始项目：[forestfirefox/cloudflare-sni-proxy-tester](https://github.com/forestfirefox/cloudflare-sni-proxy-tester)（MIT License, Copyright (c) 2026 ForestFireFox）

本仓库在原项目基础上增加了：多数据源抓取（第三方列表 / ASN 段扫描 / IPDB / FOFA）、丢包测量与综合评分排序、两段式（VPS 发现 + 本机测质量）流程、Web 控制台与对外 API、Linux 一键安装与容器化、小硬盘磁盘控制。
