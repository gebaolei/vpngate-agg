# vpngate-agg

[VPN Gate](https://www.vpngate.net/) 节点聚合 + 连通测试 + IP 纯净度检测，带一个内嵌 Web 界面。

一个 Go 二进制，前端用 `go:embed` 打在里面，状态是几个 JSON 文件 —— 拷到机器上就能跑，不需要数据库、不需要 node_modules、没有第三方依赖。

```
$ ./vpngate-agg serve
[vpngate-agg] 数据目录 data，配置 内置默认值
[vpngate-agg] 未配置登录口令，已生成随机口令：用户名 admin / 口令 7kQm2xRt4bYp3LcN（改 config 里的 auth.password 或登录后再改）
[vpngate-agg] [web] 界面已启动: :8080（本机 http://127.0.0.1:8080, http://192.168.1.20:8080）
```

## 它解决什么问题

VPN Gate 官方接口有几个不太好用的地方，这个工具把它们补齐：

| 问题 | 这里怎么做 |
| --- | --- |
| 官方接口只返回按它自己分数排的前 ~100 个节点 | 官方主站 + `sites.aspx` 上列出的全部官方镜像站一起拉，合并成上千节点的本地池；缺席的先留 7 天，TCP 节点缺席 24 小时且连负 3 轮才提前剔除。池子有容量上限（`max_nodes`，默认 1500）：超出就先请走硬伤的，再按推荐分从低到高删 |
| 「能不能连上」只有官方自己那个不可信的 Ping | 自己测：TCP 握手 + OpenVPN 硬重置握手（TCP/UDP），保留 8 次历史，算 EWMA 延迟、失败连击和置信度 |
| 不知道节点是志愿者家宽还是机房 VPS | 参照 [`IPQuality`](https://github.com/xykt/IPQuality) 的多源思路做 IP 纯净度：内置 VPN Gate 自营网段规则 + 多个外部来源投票，给出 0-100 分、类型、风险因子和「谁说了什么」 |
| 想按「可达 + 家宽 + 延迟低」筛一批出来用 | 界面筛选/排序 + `export` 导出 `.ovpn`（或 JSON），接口也能直接拉 |

## 功能

- **聚合官方两个源**（主站 + `sites.aspx` 上的全部镜像站，每轮全抓），各自独立失败、独立记状态；带数量合理性下限（`min_nodes`）和骤降保护（`max_drop_pct`），上游抽风时保留上一轮的池子而不是把列表清空。
- **池子容量上限**（`sources.max_nodes`，默认 1500，0 = 不限）：每轮刷新并入后、启动时、以及界面上改上限时，超出部分会被请出去 —— 先走硬伤的（已判定不可达、纯净度说是机房/代理/Tor、本轮名单里没有、从没测过的空壳），还超就按推荐分从低到高删。以前可选的第三方名单能一次倒进几千个节点，那个源已整段移除；现在靠上限控住规模。
- **探测整个池子**，不是只测本轮新名单：默认 6 小时一轮，跑完再隔一小时补测一轮「说不清」的 TCP 节点。
- **连通测试**：TCP 连接 + OpenVPN 硬重置包（`\x38` 报文）识别服务指纹，UDP 也测；结论分「可达 / 不可达 / 说不清」三种 —— **TCP 握手超时算不可达**（`tcp_timeout_seconds` 就是可用门槛），UDP 无回包只算说不清。
- **IP 纯净度**：多来源加权投票 + 因子标签（代理 / VPN / Tor / 机房 / 移动网 / 滥用 / 机器人 / 流媒体封锁 / 滥用置信分），证据不足时结论会向中性收缩，缓存 7 天。
- **志愿者家宽判定**：来源给了类型就算「来源认定」，没给时用 ASN / 运营商名推导（界面上挂虚线「推导」标记）；自营机房（`public-vpn-*`、`219.100.37.0/24`）单独识别，默认不进池。界面上可以直接筛「只要家宽」。
- **界面**：登录 + CSRF、筛选/排序/分页、节点详情（含各来源原始响应）、SSE 实时进度（刷新/探测/纯净度三条流水线）、一键导出、深色适配。无框架、无 CDN、无内联脚本，CSP 是 `default-src 'self'`。分两页（顶栏 tab，hash 路由 `#/` 与 `#/nodes`）：
  - **总览**：六个统计卡片 + 左边「国家分布」气泡图 + 右边「数据源与任务」。两块面板等高、整页正好占满一屏（100dvh 扣掉顶栏）：屏幕矮的时候右面板在内部滚，页面本身不滚、底部不留白。气泡图是等距柱状投影 + 气泡，国家坐标是一张内置表（约 180 条，几 KB）—— 世界轮廓 SVG 要 150KB 起，还要清洗非 ISO 区域，不值得。底图是大陆 + 国界轮廓，由 `tools/gen_worldmap.py` 从 Natural Earth 110m（公共领域）压成 SVG path 打进二进制（约 92KB，带 `?v=` 长缓存）—— 投影必须和前端 `mapPx/mapPy` 一致，生成脚本写错一次南半球就整块看不见，所以测试里按日本/澳洲/智利南端/好望角/英国五个地标钉住了。气泡大小恒为节点数，上色可切换：节点数 / 可达数 / 家宽数 / 中位延迟（计数型指标按当轮有坐标国家的最大值开平方归一化，再不按比例给国家上色，所以小国家不会以 100% 抢走标签；延迟取最快的前六名）。点国家气泡（或地图下面那排「国家排行」条）就跳到节点列表并按它筛选。
  - **节点列表**：筛选区 + 表格 + 分页 + 详情抽屉。卡片里有四张可点（可达 / 延迟 / 纯净度 / 家宽），点进去顺手把对应筛选选好。
- **CLI**：`refresh` / `probe` / `purity` / `export` / `passwd` / `sources` / `version`，能不开界面就干活，方便塞进 cron。

## 快速开始

### 二进制

懒人路径：仓库的 [Releases](https://github.com/gebaolei/vpngate-agg/releases) 里有编好的 6 个平台包（linux amd64/arm64/arm、darwin arm64/amd64、windows amd64），解开就跑：

```bash
tar -xzf vpngate-agg-v0.2.0-linux-amd64.tar.gz && ./vpngate-agg serve
sha256sum -c SHA256SUMS          # 同一级目录下跑
```

自己编：

```bash
make build                      # → bin/vpngate-agg
./bin/vpngate-agg serve
```

没配口令时会生成一个随机口令并打在日志里（用户名默认 `admin`）。想固定口令：

```bash
./bin/vpngate-agg passwd               # 生成随机口令
./bin/vpngate-agg passwd '你自己的口令'  # 或直接设
```

### Docker

```bash
docker run -d --name vpngate-agg -p 8080:8080 -v vpngate-agg-data:/data vpngate-agg
docker logs -f vpngate-agg      # 随机口令在这里
```

或者用 `example/compose.yaml`：

```bash
cd example && docker compose up -d --build
```

数据在 named volume `vpngate-data:/data`。改成 bind mount 的话记得 `chown -R 10001:10001 宿主目录`，容器里的进程是 10001。

### 从源码

```bash
git clone <本仓库> && cd vpngate-agg
make check      # gofmt + go vet + go test
make run
```

## 命令行

```
vpngate-agg [-config 路径] <子命令> [参数]
```

`-config` 放在子命令前后都行。

| 子命令 | 说明 |
| --- | --- |
| `serve` | 起 Web 界面 + 定时流水线（默认子命令，Ctrl-C / SIGTERM 会先落盘再退出） |
| `refresh` | 拉一轮节点源，写盘后退出 |
| `probe` | 跑一轮连通测试 |
| `purity` | 跑一轮 IP 纯净度检测 |
| `export` | 导出 `.ovpn`（`-out 文件`，不给就写 stdout；`-list` 只打清单） |
| `passwd` | 设登录口令，不带参数则生成随机口令（`-user` 改用户名） |
| `sources` | 看各来源最近一次拉取的时间、拿到多少节点（含被关掉的源） |
| `version` / `help` | 版本 / 帮助 |

`probe` / `purity` / `export` 的公共筛选参数：

| 参数 | 说明 |
| --- | --- |
| `-limit N` | 本轮上限，`0` 用配置里的值 |
| `-force` | 忽略冷却：刚测过的重测、长期失败的重试、缓存没过期也重查 |
| `-country JP,US` | 只处理这些国家（大小写不敏感） |
| `-proto tcp,udp` | 只处理这些协议 |
| `-selection` | `all` / `fresh`（本轮名单）/ `suspect`（历史可疑）；`purity` 是 `all` / `fresh` / `unchecked` |
| `-all` | 等价于 `-force -limit 0`（`probe`） |
| `-concurrency N` | 并发数（`probe`） |
| `-no-handshake` | 只测 TCP 连通，不发 OpenVPN 握手包（`probe`） |

`export` 额外支持 `-q`、`-level stable,reachable`、`-min-purity`、`-max-ping`、`-ping-source best|local|upstream|cloudflare`、`-residential`、`-own-only`、`-fresh`、`-limit`。

例子：

```bash
vpngate-agg refresh
vpngate-agg probe -limit 200
vpngate-agg probe -country JP -proto udp -force -limit 50
vpngate-agg purity -limit 100
vpngate-agg export -country JP -proto udp -limit 10 -min-purity 80 -out jp.ovpn
vpngate-agg export -residential -list
```

## 判定口径

这部分最容易误解，写在前面。

### 可达档位

| 档位（`health.level`） | 界面 | 什么时候是这个值 |
| --- | --- | --- |
| `stable` | 稳定 | 最近可达，成功率 ≥ 80% |
| `reachable` | 可达 | 最近可达，但成功率不到 80% |
| `unknown` | 状态未知 | 测过但没拿到明确结论：UDP 不回硬重置包、探测被中断，以及升级前存下的、没记 proto 的老样本 |
| `flaky` | 抖动 | 明确否定结论只来了一次；或者以前连上过、最近一次说不清 |
| `down` | 不可达 | 明确的否定结论（连接被拒 / 网络不可达 / 被本地策略拦截 / **TCP 握手超时**）**连续两次** |
| `untested` | 未测 | 一次都没测过 |

关键点：**UDP 不回包不等于「节点死了」**。实测 SoftEther 的 UDP 监听基本不回硬重置包，家宽 NAT 也常直接丢 —— 所以 UDP 节点大量落在「状态未知」是设计如此，不是坏了。按失败算的话半池子 UDP 会被长期误标成死亡。

TCP 则相反：**握手超时算不可达**。`tcp_timeout_seconds`（默认 5 秒）就是「能不能用」的门槛 —— 5 秒内完不成三次握手的端口，会话也建不起来，加大超时也没意义。把它挂在「说不清」里只会让一个连不上的节点在池子里白躺一周、每轮还占一次探测额度。所以 TCP 超时和收到 RST 一样计入明确失败（判定在 `model.NegativeVerdict`，界面文案单独写「超时不可达」，因为「端口拒接」和「连不到 5 秒」对排查是两回事）。老快照里没记 proto 的历史样本仍按「说不清」处理，不追溯定罪。

同理，筛选参数 `?level=down` 和界面上的徽章用的是后端算好的同一个值，不会出现「标着已挂、按已挂筛却筛不出」。

### 延迟

界面上「延迟」那一列只报本机实测，五种状态分得很清：

| 情况 | 延迟列 |
| --- | --- |
| 还没测过 | `–` + 「待测试」 |
| 测过、连上过 | 实测值 + 「实测」 |
| 测过、但拿不出延迟（UDP 无回包 / 探测被中断） | `–` + 「未测出延迟」 |
| 不可达：端口拒接 / 网络不可达 | `–` + 「已判定不可达」（作废的历史值在 title 和详情面板里） |
| 不可达：TCP 握手超时 | `–` + 「超时不可达」（同上不给数字：≥超时门槛本身不是延迟） |

四个口径（界面上的「延迟口径」下拉，接口和导出也用它）：

- `best`（默认）：本机实测 EWMA（α=0.4），没有就看最近一次成功的 RTT。**不兜底官方 Ping，也不用 Cloudflare 观测** —— 延迟列显示的数与 `sort=ping` / `max_ping` / 推荐分用的数必须是同一个值，否则就是「列上写着待测试，却按官方 44ms 排在前面」
- `local`：本机实测，优先最近一次成功的值，没有才退 EWMA
- `upstream`：官方 CSV 里的 Ping —— 别人那张网看到的，口径不明、通常偏小（实测快照里官方值中位 21 ms，而我们这边同一个节点能测到 3077 ms）；要它就得显式选
- `cloudflare`：Cloudflare Worker 观测到的 TCP 建连耗时。它来自已经移除的第三方源，**现在只读不写**：只能看到盘上留下的旧观测（超过 7 天的界面上标「已停更」），只当历史参考

EWMA 只由成功的探测喂出来，**不清空也不按时间衰减** —— 所以「历史上很快、现在已挂」的节点会带着一个很好看的旧数字。所以四个口径都一样：**已判定不可达（`level=down`）的节点不参与按延迟排序和 `max_ping` 筛选**（节点还在结果里，只是排到末尾）。

一处刻意的不一致：总览页的「中位延迟」卡片和地图的国家中位延迟**仍然兜底官方 Ping**（走 `store.pingOf`）。因为实测只覆盖少数节点（快照里 74/269），拿它算全盘中位数会让卡片和地图按延迟上色时大片变成「没数据」——列表关心「这个节点你能不能用」，卡片关心「这个国家整体大概多远」。

### 推荐分

列表默认按推荐分排（0-100）。它是个粗糙但可解释的加总：

- 档位：`stable` +40 / `reachable` +32 / `unknown` +18 / `flaky` +12 / `untested` +10 / `down` +4
- 延迟：≤80ms +30，≤150ms +26，≤300ms +20，≤600ms +12，更慢 +4，没有数据 +8（取哪个口径由 `best` 等决定：默认只看本机实测，官方 Ping 不算；已判定不可达的节点也按「没有数据」那一档，不吃历史延迟的加分）
- 纯净度：`score × 0.3`，没测过给 +12（不因没测就被压到底）
- 志愿者家宽 +8；Cloudflare 也观测到可达 +4
- VPN Gate 自营机房 −6；Cloudflare 观测不可达 −6；超过 48 小时没在官方名单里出现 −4

Cloudflare 那两项只算**一周内**的观测：那份数据来自已移除的第三方源，现在只读不写，
不能让一条半年前的结论一直按住一个早就修好的节点（超过一周就当作没有观测）。

### IP 纯净度

分数 0-100，越高越像普通住宅宽带：`excellent` ≥85（极纯净）、`good` 70-84（纯净）、`fair` 50-69（一般）、`poor` 30-49、`bad` <30。

做法：

1. 内置规则**永远参与**：VPN Gate 自营网段和 `public-vpn-*` 这类主机名直接判机房/自营（免费的外部来源只看得到一个普通日本 IP，纠不回来）。
2. 外部来源各给一份「类型 + 风险因子 + 该家自己的风险分（归一到 0-100）」，按来源可信度加权投票。权重：`scamalytics` / `ipqualityscore` 1.2 > `ipregistry` 1.15 > `ipquery` / `ipinfo` / `builtin` 1.0 > `abuseipdb` 0.85（它只反映举报历史）> 未知来源 0.8。
3. Tor / 机房这类硬因子给分数设上限，单个来源说「机房」不足以定案，来源之间矛盾时结论向中性收缩。
4. 界面上逐个来源列出「谁说了什么」，包括原始响应（截断到 `purity.raw_keep_bytes`），免得只看一个总分无从核对。

来源清单：

| 名称 | 是否需要 key | 说明 |
| --- | --- | --- |
| `builtin` | 否 | 内置 VPN Gate 网段/主机名规则，永远开 |
| `ipquery` | 否（有 key 更好） | 免费，默认开 |
| `ipinfo` | 是 | `IPINFO_TOKEN` |
| `scamalytics` | 是 | `SCAMALYTICS_KEY` |
| `ipqualityscore` | 是 | `IPQUALITYSCORE_KEY` |
| `ipregistry` | 是 | `IPREGISTRY_KEY` |
| `abuseipdb` | 是 | `ABUSEIPDB_KEY` |

规则是：免费的默认开，要 key 的「有了 key 才开」，`purity.providers` 里显式写 `true`/`false` 优先。

### 家宽 / 机房怎么定的

先说一件实测出来的事：**VPN Gate 官方名单里没有家宽标识**。主站 API 和镜像站都是同 15 列（`HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64`），英中日文网页列表里也搜不到住宅相关标记。官方唯一给的「类型」其实是**自营机房**：`public-vpn-*` 主机名和 `219.100.37.0/24`（SoftEther 放在筑波大学学术网里的机器）。所以家宽只能我们自己判：

| 证据 | 结论 | 界面标记 |
| --- | --- | --- |
| 外部来源直接给类型（`ipinfo` 的 `type`、`ipregistry` 的 usage 等） | 按来源的类型判 | 实心类型标签，依据写来源名 |
| 没有任何来源给类型，但 ASN 在内置的消费级宽带表里（AS4766 Korea Telecom、AS9318 SK Broadband、AS2516 KDDI…） | 推定为住宅宽带 | 类型标签 + 虚线「推导」，依据写 `ASxxxx` |
| 只有运营商名命中家宽关键词（`SK Broadband`、`SoftBank`、`AIS Fibre`…） | 推定为住宅宽带，**置信度扣 12 分** | 同上，依据写关键词 |
| 有任一反证：来源明确说机房 / 代理 / VPN / Tor，或组织名里带政企、专线、学校、政府、`cloud`、`hosting` | 不推导，留在「类型未知」 | 未知 |

几条底线：

- **推导只填类型，不改风险分**。它不能把一个脏 IP 洗干净，也不能给分数加分 —— 类型之外没有任何新信息。
- **反证优先**。组织名里出现 `backbone` / `transit` / `polytechnic` 就一律不推，留在未知。「未知」是诚实的答案，把政企专线叫成家宽是错得离谱的答案。
- 统计卡把家宽拆成三个数：**来源认定 N · 推导 M · 类型未知 K**。只有免费 `ipquery` 时类型基本全靠推导（它连免费响应都不给 `type`），这时候的「家宽 55%」要读成「大概率是 55%」。想要真类型就配 `IPINFO_TOKEN` 之类的 key。
- 缓存里的结论是**汇总规则**算出来的，规则改了（比如新增这套推导）会在启动时拿缓存里已经存的各来源结论**离线重算**（`purity.json` 的 `merge_ver`），不产生任何外部请求；重算完还会同步回节点池。不这么做的后果是界面顶着一周前的旧结论 —— 缓存 TTL 正好是一周。

自营机房节点要不要留是 `sources.keep_vpngate_own`（界面设置页也有开关）：默认关，因为要家宽出口的人不想要官方机房出口；想要「全局出口稳、别掉线」的人可以打开。关掉以后新抓到的不进池，池里已有的下一轮清掉，刷新日志和 `sources` 命令里会写「自营机房剔除 N」。

## 数据来源

| 来源 | 地址 | 拿到什么 | 注意 |
| --- | --- | --- | --- |
| 官方主站 | `https://www.vpngate.net/api/iphone/` | CSV，含 `.ovpn` 正文（base64），约前 100 名 | 实时但量少 |
| 官方镜像站 | `sites.aspx` 上列出的 `IP:PORT`，接口路径同为 `/api/iphone/` | 同上 | 实测 6 个里 4 个在同一 `/24`，按 `/24` 去重；默认 `max_mirrors: 0` = 去重后每轮全抓（填 >0 才限个数，那时额外按 location 轮转）；镜像站对 gzip 有 bug，这里禁用压缩 |

第三方名单（`GeorgeXie2333/vpngate-list-mirror`）已经**整段移除**：那不是 VPN Gate 官方数据，和官方拉高度重叠，累积池还会一次多出一千多个节点，把一轮探测拖得很久；节点量不该由别人的项目决定。升级时旧 `config.json` 里残留的 `sources.cdn` 段会被忽略（不报错），旧 `pool.json` 里的 `cdn_commit` 和第三方遗留节点照常加载，下一轮就按「本轮名单里没有」走过期和淘汰。盘上留下的 Cloudflare 观测只读不写，界面上标「已停更」。

合并规则：优先级高的先写（官方主站 > 官方镜像），之后「更强的源」才能覆盖某个字段（比如官方主站的实时字段覆盖镜像里的旧值），缺的字段补上，不会整条覆盖。

### 缺席与淘汰

名单是滚动的，今天不在不等于死了；但一个早就连不上的 TCP 节点在池子里躺满一周，每轮都白占一次探测额度。所以淘汰分两条（`keep_days` / `purge_absent_hours` / `purge_fail_rounds`）：

- 本轮名单里没出现的节点先留下（探测从整个池子挑，不是只测新名单），连续缺席满 `keep_days`（7 天）才过期删除；
- 缺席从「第一次缺席」计时（`absent_since`），重新出现就清零；缺席满 `purge_absent_hours`（24 小时）且**连续 `purge_fail_rounds`（3）轮明确失败**的 TCP 节点提前剔除；
- 「明确失败」是 `refused` / `unreachable` / `blocked` / **TCP 超时**：在 `tcp_timeout_seconds` 里连不上就是不可用，一样计入连击。UDP 不回包不算（SoftEther 对硬重置包本来静默），所以 UDP 不提前剔除；本轮连上就把连击清零；
- 六小时一轮是正式轮，一轮跑完再隔一小时对「说不清」的 TCP 节点补测一轮，补测轮**不计入连负轮数**，否则一轮被数两次、淘汰提前一倍；
- 只从旧第三方池（`LastSource` 以 `-pool` 结尾）见到的遗留节点不能证明它现在还在名单上，不参与「本轮出现」认定，也不提前剔除；
- 被删节点的 `.ovpn` 文本等下一次刷新才清（配置按内容寻址，删早了会误伤同 SHA 的其他节点）；
- 自营机房节点（`public-vpn-*` / `219.100.37.0/24`）走另一条路：`keep_vpngate_own=false`（默认）时新抓的不进池、池里已有的下一轮清掉。这不算节点坏了，所以计数单独叫「自营机房剔除」，跟过期、淘汰分开显示。

对上游算礼貌：官方镜像并发默认 2（上限 6）；探测并发默认 64（上限 512），每轮上限 `max_nodes_per_round`；纯净度全局令牌桶默认 40 次/分钟（带 key 的来源放宽 3 倍）。

### 池子容量上限

上面两条只管「多久没见」，不管「池子多大」。官方主站 + 全部镜像一轮就能给到几千个，而探测一轮、写盘、拉纯净度都随池子线性变贵，所以 `sources.max_nodes` 说清「这个池子最多养多少个节点」（默认 1500，**0 = 不限**）。

超出上限时一次裁到位，分两刀：

1. **硬伤的先生**：已判定不可达的 → 纯净度说是机房 / 代理 / Tor / CDN 的（自营机房看 `keep_vpngate_own`，你说留着就不动）→ 从没测过、本轮名单里也没有的空壳 → 本轮名单里没有的（按缺席多久排，越久越先走）；
2. **还超就择优**：按推荐分从低到高删。

两个细节：

- 同一档里先删「本轮名单里没有」的：删了不会下一轮又被抓回来，池子是真变小；删「名单里还有」的等于白删，还白白丢掉我们攒的探测历史。
- 分档而不是只按分数排：纯按分数排序会让「从没测过的空壳」比「明确已死」活得久。

三个地方走同一套规则：每轮刷新并入后、`serve` 启动时（旧版本升上来、或停机期间把上限改小了）、以及界面上改上限时（当场裁一次，不用等下一轮）。只读命令（`sources`）不动池子。界面上会提示一声，日志里有「容量裁掉 N」，`sources` 子命令能看到当前数与上限。

## 配置

优先级：**命令行 flag > 环境变量 > `config.json` > 内置默认值**。

配置文件查找顺序：`-config 路径` → `VPNGATE_AGG_CONFIG` → `<data_dir>/config.json` → `./config.json`（取第一个存在的）。界面上改开关/参数时写回的就是 `<data_dir>/config.json`，所以重启后会读回来 —— 之前只找当前目录，会出现「界面上改了、一重启就丢」。没有配置文件也能跑（`config.example.json` 就是全部默认值，复制一份改就行）。缺的字段保留默认值，所以只写你想改的那几项即可。

### 主要配置项

| 组 | 字段 | 默认 | 说明 |
| --- | --- | --- | --- |
| 顶层 | `listen` | `:8080` | 监听地址 |
| | `data_dir` | `data` | 状态目录 |
| | `title` | VPN Gate 节点聚合中心 | 界面标题 |
| | `log_level` | `info` | `debug`/`info`/`warn`/`error` |
| `auth` | `username` / `password` | `admin` / 空 | 口令写明文，首次启动转成 PBKDF2 存进 `credentials.json` 并清空这一项；空则启动时生成随机口令 |
| | `session_hours` | 168 | 登录有效期 |
| | `cookie_secure` | false | https（含反代结束 TLS）时打开 |
| | `disable_auth` | false | 纯内网自用可彻底关掉 |
| `sources` | `refresh_interval_minutes` | 60 | 定时拉取间隔 |
| | `keep_days` | 7 | 缺席节点在池里保留的天数，超过就过期删除 |
| | `purge_absent_hours` / `purge_fail_rounds` | 24 / 3 | TCP 节点缺席满这么久、且连负这么多轮明确失败就提前剔除；前者填 0 关掉提前剔除 |
| | `keep_vpngate_own` | false | 保留 VPN Gate 自营机房节点（`public-vpn-*`、`219.100.37.0/24`）。默认不保留：那是官方自己的机房出口，不是志愿者家宽 |
| | `vpngate.enabled` | true | 官方主站是必开来源：界面和接口都不给关，只有这里能关（部署在连不上 `www.vpngate.net` 的网络里，不想每轮白等一次超时） |
| | `vpngate.min_nodes` / `max_drop_pct` | 20 / 50 | 数量合理性下限、比上一轮骤降的百分比，触发就保留旧池子 |
| | `mirrors.max_mirrors` | 0 | 0 = 每轮把去重后的镜像全抓（默认）；>0 才限个数并按 location 轮转 |
| | `max_nodes` | 1500 | 池子容量上限：超出先请走硬伤的（已判定不可达 / 机房代理Tor / 本轮名单里没有 / 从没测过），再按推荐分从低到高删。填 0 = 不限；界面设置页也能改，改小了当场裁一次 |
| `probe` | `enabled` / `interval_minutes` | true / **360** | 定时探测（6 小时一轮，每轮测整个池子） |
| | `concurrency` | 64 | 并发（上限 512） |
| | `tcp_timeout_seconds` / `udp_timeout_seconds` / `handshake_seconds` | 5 / 4 / 4 | 各类超时。TCP 那个同时是可用性门槛：到点连不上就判不可达、并计入淘汰 |
| | `handshake` | true | 关掉只测 TCP 连通 |
| | `history_keep` | 8 | 每个节点保留多少次历史 |
| | `selection` | `all` | 测哪些：`all`（整个池子）/ `fresh`（只测本轮名单）/ `suspect`（只测可疑的） |
| | `unknown_retry_minutes` | 60 | 正式轮结束后隔这么久补测一轮「说不清」的 TCP 节点；填 0 关掉；补测轮不算淘汰轮数 |
| | `skip_down_for_hours` | 12 | 长期失败就先放过，给上游减负 |
| `purity` | `enabled` / `interval_minutes` | true / 720 | 定时检测（12 小时一轮） |
| | `ttl_hours` | 168 | 结论缓存有效期 |
| | `requests_per_minute` | 40 | 全局令牌桶 |
| | `min_providers` | 1 | 少于这么多个来源就当结论不可信 |
| | `raw_keep_bytes` | 900 | 每个来源保留多少原始响应给界面核对 |
| | `providers` / `keys` | — | 来源开关 / API key |
| | `prefer_residential` | true | 家宽在排序里加权（不改结论本身） |
| `api` | `enabled` / `token` | **false** / 空 | 对外只读接口 `GET /vpngate/api/iphone/`。token 至少 16 字符；`enabled=true` 而 token 为空直接拒绝启动（不把接口裸开） |
| | `include_config` | true | 响应里带不带 `OpenVPN_ConfigData_Base64`。这是上限：`false` 时 `?config=1` 也要不回来 |
| | `max_nodes` / `rate_per_minute` | 500 / 30 | 单次响应节点上限（更大用 `offset` 翻页）／按来源 IP 每分钟限流，0=不限 |

### 环境变量

只覆盖「部署时真的会变的」那些，其余走配置文件。

| 变量 | 覆盖 |
| --- | --- |
| `VPNGATE_AGG_CONFIG` | 配置文件路径 |
| `VPNGATE_AGG_LISTEN` / `_DATA_DIR` / `_TITLE` / `_LOG_LEVEL` | 顶层 |
| `VPNGATE_AGG_USER` / `_PASSWORD` / `_PBKDF2` / `_COOKIE_SECURE` / `_DISABLE_AUTH` | 登录 |
| `VPNGATE_AGG_REFRESH_MINUTES` | 拉取间隔 |
| `VPNGATE_AGG_MAX_NODES` | 池子容量上限（0 = 不限） |
| `VPNGATE_AGG_PROBE_ENABLED` / `_PROBE_INTERVAL` / `_PROBE_CONCURRENCY` | 探测 |
| `VPNGATE_AGG_KEEP_VPNGATE_OWN` | 是否保留官方自营机房节点 |
| `VPNGATE_AGG_PURITY_ENABLED` / `_PURITY_RPM` | 纯净度 |
| `IPQUERY_KEY` / `IPINFO_TOKEN` / `SCAMALYTICS_KEY` / `IPQUALITYSCORE_KEY` / `IPREGISTRY_KEY` / `ABUSEIPDB_KEY` | 纯净度来源的 API key |
| `VPNGATE_AGG_API_ENABLED` / `_API_TOKEN` / `_API_INCLUDE_CONFIG` / `_API_MAX_NODES` / `_API_RATE_PER_MIN` | 对外只读接口 |

布尔型接受 `1/true/yes/on` 和 `0/false/no/off`。

## 数据目录

```
data/
├── pool.json              # 节点池快照（原子写：临时文件 + rename；损坏会把旧的挪成 .bak 再重建）
├── configs/<sha256>.ovpn  # .ovpn 正文按内容寻址，同内容不重复存
├── purity.json            # 纯净度结论缓存（按 IP，TTL 7 天）
├── vpngate-mirrors.json   # 官方镜像站列表缓存（默认 12 小时）
├── credentials.json       # 用户名 + PBKDF2；存在就优先于 config 里的明文口令
└── session.key            # 会话签名密钥（丢了大家重新登录一次）
```

- 节点 ID 是 `v1:` + SHA256（规范化主机名 + IP），不是官方给的序号 —— 上游改序号/重排不会导致本地历史错位。
- `pool.json` 里的 `config_local` 只说「抓取那一轮有没有拿到正文」，正文本身是按 sha 内容寻址在 `configs/` 里。启动读盘时会按磁盘实况回填这个标记（否则旧第三方源时代留下的节点会被当成缺正文，界面上点一下就走一次无谓回源）。
- 备份就把整个目录拷走；只想重置探测/纯净度结论，删 `pool.json`（探测历史会没）或 `purity.json`（只丢纯净度）都行。
- 全部时间戳存 UTC，界面按浏览器本地时区显示。

## HTTP 接口

**对外接口（`/vpngate/*`、`/healthz`）的完整文档见 [docs/API.md](docs/API.md)** —— 参数、逐列说明、鉴权、限流、坑与 curl 样例都在那里。

下面这张表是**界面专用接口**（`/api/*`）的索引：属于内部契约，跟着前端走，字段可能增删，第三方不要接。

两套共用同一个端口、同一个节点池，但不共用凭据 —— 第三方脚本不该去借用浏览器登录态。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/healthz` | 不要登录，给探针用；返回版本、节点数、是否有任务在跑 |
| POST | `/api/login` / `/api/logout` | 登录 / 退出；登录返回 csrf token |
| GET | `/api/session` | 当前登录状态。**未登录也回 200**，只是 `authed:false`；顺带拿到 csrf token |
| POST | `/api/password` | 改口令 |
| GET | `/api/stats` | 汇总统计 + 国家分布 + 各来源状态。国家分布 `countries[]` 带 `code`/`name`/`nodes`/`alive`/`med_ping_ms`/`med_purity`/`residential`，国家分布图就是按它画的 |
| GET | `/api/nodes` | 列表，支持 `q`/`country`/`proto`/`level`/`min_purity`/`max_purity`/`max_ping`/`ping_source`/`residential`/`purity_only`/`fresh`/`probed`/`ids`/`sort`/`dir`/`offset`/`limit`；参数不合法 422 |
| GET | `/api/nodes/{id}` | 详情（含探测历史、纯净度各来源原始响应、`.ovpn` 正文） |
| POST | `/api/nodes/{id}/probe` / `/purity` | 单节点重测 |
| GET | `/api/nodes/{id}/config` | 下载该节点的 `.ovpn` |
| POST | `/api/refresh` / `/api/probe` / `/api/purity` / `/api/cancel` | 手动触发/取消流水线（body 可带国家、协议、上限等） |
| GET | `/api/jobs` | 任务状态 |
| GET | `/api/settings` | 当前生效配置（API key 只回显脱敏后的） |
| POST | `/api/settings` | 改界面上开放的三类配置：节点配置（镜像开关、保留机房节点、`keep_days`、`purge_fail_rounds`、`max_nodes`）、可用性探查（开关、间隔、并发、TCP/UDP 超时、握手）、IP 纯净度（开关、每分钟限流）。立即生效并写回配置文件；改小 `max_nodes` 会当场按容量裁一次。校验或写盘失败就整个不改。官方主站不在可改范围里（必开），两个来源全关会被拒 |
| GET | `/api/export` | 导出，`format=ovpn`（默认）或 `json`，筛选参数同 `/api/nodes` |
| GET | `/api/events` | SSE：首条 `hello`，订阅时补发最近事件，25 秒一次心跳注释 |
| GET | `/vpngate/api/iphone/` | **对外只读接口**：不靠会话 cookie，用 `api.token`；字段名对齐官方 15 列。详见下面「对外只读接口」 |

要点：

- 写请求要带 CSRF：`X-CSRF-Token` 头或 `?csrf=` 查询参数（SSE 除外）。缺了 403。
- 界面设置页分三块：**节点配置**、**可用性探查**、**IP 纯净度检查**，走 `POST /api/settings`。除开关外还能改 `keep_days`、`purge_fail_rounds`、`max_nodes`（改小了当场裁一次，并广播 `pool:trim`）、探测间隔/并发、TCP/UDP 超时、纯净度每分钟限流。定时器每圈重读间隔，所以改了下一轮就是新值；纯净度限流会重建令牌桶当场生效。每轮节点数上限、握手时长、缓存 TTL、`.ovpn` 抓取等仍然只读配置文件。
- 会话是签名 Cookie（HMAC），不是服务端 session —— 多实例/重启都不会丢登录态。
- `/api/nodes` 里每个节点带算好的 `health.level`，前端不再自己推一遍规则。

### 对外只读接口：`GET /vpngate/api/iphone/`

完整文档：**[docs/API.md](docs/API.md)**。下面是要点摘要。

给外部程序用的，**字段名对齐官方 `https://www.vpngate.net/api/iphone/` 的 15 列**，调用方把 host 换掉就行（不用改解析代码）。默认关着，靠 `api.token` 鉴权（见上面「配置项」的 `api` 段）。

```bash
# 生成 token：openssl rand -hex 24
export TOK=$(cat /etc/vpngate-agg/api_token)

# 整个名单（带 .ovpn 正文，按 Score 降序 —— 跟官方同一个顺序）
curl -H "Authorization: Bearer $TOK" https://你的域名/vpngate/api/iphone/

# 只要名单、不要正文（响应体小一个数量级）
curl -H "Authorization: Bearer $TOK" 'https://你的域名/vpngate/api/iphone/?config=0&limit=500'

# 筛日本、家宽、可达的，翻页
curl -G -H "Authorization: Bearer $TOK" https://你的域名/vpngate/api/iphone/ \
  --data-urlencode 'country=JP' --data-urlencode 'residential=1' \
  --data-urlencode 'level=stable,reachable' --data-urlencode 'offset=200'
```

响应是 JSON **数组**（不带界面那套 `{"ok":true}` 壳），每一行 15 列：

```
HostName, IP, Score, Ping, Speed, CountryLong, CountryShort,
NumVpnSessions, Uptime, TotalUsers, TotalTraffic, LogType, Operator,
Message, OpenVPN_ConfigData_Base64
```

| 参数 | 说明 |
| --- | --- |
| `q` `country` `proto` `level` `min_purity` `max_purity` `max_ping` `ping_source` `residential` `purity_only` `fresh` `probed` `ids` `offset` | 跟 `/api/nodes` 完全同一套，含义见上面那张表 |
| `sort` | `score`（默认）/`ping`/`speed`/`sessions`/`hostname`/`purity`/`rtt`/`seen`/`recommend`；写别的 422（不默默退回默认排序） |
| `dir` | 说的是**这一列的值**：`desc`=从大到小。默认 `desc`，所以不写就是分数高的在前 |
| `limit` | 单次条数，上限 `api.max_nodes`（默认 500） |
| `config` | `0`/`false`/`off` 只要名单。`api.include_config=false` 时这一列永远不给，`?config=1` 也要不回来 |

行为细节：

- **鉴权**：`Authorization: Bearer <token>`，或者 `?key=<token>`（给只能填 URL 的客户端）。界面的会话 cookie 在这条路由上不好使，反过来 token 也进不了 `/api/*`。
- **状态码**：没开 `api.enabled` → **404**（不告诉外面「这里有东西但不让你进」）；token 不对 → **401**（带 `WWW-Authenticate: Bearer`）；参数错 → **422**；超速率 → **429**（带 `Retry-After`）。错误体仍是 `{"ok":false,"error":...}`。
- **正文列不是空的**：本地没有 `.ovpn` 正文的节点（缺正文的遗留节点）整行跳过，不把连不上的节点塞进名单。数量在响应头 `X-Vpngate-Agg-Skipped` 里；`?config=0` 不要正文时就不跳了。
- **响应头**：`X-Vpngate-Agg-Rows`（本次行数）/`-Skipped`/`-Total`（筛选命中总数）/`-Limit`/`-Offset`，翻页拿总数不用多打一次。
- **本地观测不走这里**：探测档位 `health.level`、纯净度分数、Cloudflare 观测只在 `/api/nodes`。这条接口只给官方那 15 列 —— 要「像官方」就不能夹私货。
- **反代**：要单独放行/限流就给这个前缀一条 `location`（跟 `/api/events` 那条互不影响）：

```nginx
location /vpngate/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  # 限流按 IP，得让它看到真的客户端
}
```

- **限流是每 IP 每分钟固定窗口**（`api.rate_per_minute`，默认 30）。401 也计数，否则乱猜 token 的循环打不着自己。同一 NAT 后面一堆机器一起拉就把这个数调大。

## 部署

### systemd

见 `example/vpngate-agg.service`（里面有安装步骤注释）。要点：`ProtectSystem=strict` 下必须把数据目录列进 `ReadWritePaths`；探测一轮要开几千个 socket，`LimitNOFILE=65536`。

### Nginx 反代

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

# SSE：必须关掉缓冲，否则进度条会整段卡住不动
location /api/events {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_read_timeout 3600s;
    chunked_transfer_encoding off;
}
```

程序会给 `/api/events` 带上 `X-Accel-Buffering: no`，Nginx 认这条；但 `proxy_read_timeout` 还是建议放宽。

HTTPS 下记得设 `auth.cookie_secure = true`（或 `VPNGATE_AGG_COOKIE_SECURE=1`）。

### cron（不想常驻）

```cron
*/60 * * * * /usr/local/bin/vpngate-agg refresh >>/var/log/vpngate-agg.log 2>&1
*/60 * * * * /usr/local/bin/vpngate-agg probe -limit 300 >>/var/log/vpngate-agg.log 2>&1
15 3 * * *  /usr/local/bin/vpngate-agg purity -limit 300 >>/var/log/vpngate-agg.log 2>&1
```

cron 模式下每次 `probe` 都算「一轮」，所以淘汰里的「连续 3 轮明确失败」是按这里跑了几次算的，不是按 6 小时 —— 上例每小时一次，等于 3 小时就够格提前剔除。嫌太激进就把 `-limit` 调大、间隔拉长，或者干脆常驻 `serve` 用默认的 6 小时节奏。

## 构建与发版

编译和打包的命令全在 Makefile 里，CI 只是调它们（不在 YAML 里另写一套 `go build`，否则本地能过、CI 红了都不知道差在哪）：

| 动作 | 命令 / 触发 | 结果 |
| --- | --- | --- |
| 提交前自查 | `make check` | gofmt + vet + `go test -count=1` |
| CI | push 到 `main` 或提 PR（`.github/workflows/ci.yml`） | 跑 `make fmt-check / vet / test`；`main` 上还产一份 linux/amd64 快照 artifact（保留 30 天） |
| 多平台打包 | `make package` | `dist/archives/` 里 6 个包 + `SHA256SUMS`（windows 有 `zip` 就出 `.zip`，否则也走 tar.gz） |
| 发版 | `git tag v0.2.0 && git push --tags`（`.github/workflows/release.yml`） | 交叉编译 + 打包 + 建 GitHub Release（附件、校验值、发版说明） |

发版这几条值得记住：

- **版本号来自 tag**，通过 `-X main.version` 注入（`VERSION := git describe --tags`）。两个 workflow 都用了 `fetch-depth: 0`：浅克隆看不到 tag，版本会退化成 commit sha，文件名、`version` 输出、Release 标题三处一起骗人。
- tag 里带 `-`（`v0.3.0-rc1`）按 semver 就是预发布，会自动标成 prerelease，不占住 latest。
- 重跑同一个 tag 不会失败：附件走 `--clobber`，说明和标题重改。
- Actions 页面手动触发（workflow_dispatch）**必须填版本号**：`gh release create` 会顺手建 tag，用 commit sha 当 tag 太容易被当成正式版。
- 想加平台只改 Makefile 的 `PLATFORMS` 一行，workflow 不用动（`CGO_ENABLED=0`，交叉编译不需要真的那台机器）。
- 发版作业会做自检：`sha256sum -c`、六个包齐不齐、把 linux/amd64 那份解开真跑一次 `version`。版本号没注入或者包不齐就直接红，不挂一份骗人的产物上去。Docker 镜像不在 CI 里构建，还是本地 `make docker`。

## 开发

```
main.go              CLI 入口、各子命令
internal/config      默认值 / 文件 / 环境变量 / 校验
internal/model       数据结构和档位规则（唯一一份判定口径）
internal/source      官方 CSV、官方镜像站的抓取与合并
internal/store       节点池（内存 + 原子 JSON）、健康度与连负轮数、缺席/淘汰判定、查询与打分
internal/probe       TCP + OpenVPN 硬重置探测、单轮调度
internal/purity      各来源适配、加权汇总、缓存
internal/app         装配、任务与调度（含一小时后的补测轮）、开关热更新落盘、事件总线
internal/web         HTTP 接口、登录/CSRF/SSE、embed 的前端
  └── static/        index.html + style.css + app.js（无框架、无构建步骤）
```

常用命令：

```bash
make            # 编译
make test       # 单元测试
make race       # 竞态检测（探测和 SSE 都是多线程）
make cover      # 覆盖率
make check      # gofmt + vet + test，提交前跑这个
make release    # 交叉编译多平台到 dist/
```

改前端时的两条硬约束：

1. **CSP 是 `default-src 'self'; style-src 'self'`**：不能有内联 `<script>`/`<style>`/`style="..."`，动态样式走 `element.style.setProperty()`，布局用 class。
2. 上游来的字符串一律 `textContent`，不要 `innerHTML`。

测试基本不碰公网：CSV / 镜像用 `internal/source/testdata`，探测用本地 `net.Listen` 和回环地址，纯净度在 HTTP 层测试里只开 `builtin`。淘汰规则（7 天过期、24h+3 轮提前剔除、TCP 超时算明确失败、UDP 无回包不算、补测轮不算）和容量裁剪（硬伤优先、同档先删不在名单里的、自营看开关）在 `internal/store` 的时间机器测试里，开关与 `max_nodes` 写回在 `internal/web` 的接口测试里。

## 已知边界

- **UDP 节点大量是「状态未知」**：SoftEther 的 UDP 监听通常不回硬重置包。这类节点不是不能用，只是无法从探测里确认；排序上会略低于实测可达的。
- **把 TCP 超时当不可达是有代价的**：如果探测机的出口对这些端口本身就丢 SYN（跨境中间盒、上游端口过滤），好节点会被判 `down` 并计入淘汰。不确定就先拿 `purge_absent_hours: 0` 关掉提前剔除（只按 `keep_days` 出池），或者换个出口对照；探测结果本身不含「为什么连不上」的路径信息，只有 `reason` 那一句。
- **容量上限是按分数请人的**：上限设得太低，会把「还没测过、但可能不错」的节点一并裁掉（探测还没覆盖到它，分数自然低）。拿不准就填大一点或者 0，看几天日志里「容量裁掉 N」再说。被裁的节点如果还在官方名单里，下一轮会被重新抓回来，只是从零开始重新攒探测历史。
- **官方接口偶尔抽风**（返回半截 CSV、数量骤降）：`min_nodes` / `max_drop_pct` 会拦下来并保留旧池子，各源的成功/失败状态在 `stats` 里能看到。
- **免费纯净度来源会限流**（429）：默认 40 次/分钟；某个来源连续失败时它只是被记为「失败」，不影响别的来源出结论，设置页里能看到每个来源的成功/失败次数。
- **探测是尽力而为**：单次 TCP 握手 + 一个握手包，不代表能完成 TLS 协商和登录。真正确认要拿导出的配置去连。
- IPv6 节点会保留（带 zone 的除外）；纯 IPv6 出站不通的机器上这些节点会一直显示连不上。

## 许可

与上游一致，自用为主。数据来源：VPN Gate 官方接口/镜像站、以及你在 `purity.keys` 里配的第三方 IP 情报接口（各自有自己的配额和条款）。
