# vpngate-agg 对外 API

> 适用版本：`vpngate-agg 0.1.0`（响应里的 `version` 字段就是这个值）。
> 本文只覆盖**对外提供服务的接口**：`/vpngate/*` 与 `/healthz`。
> 内嵌前端专用的 `/api/*`（会话 Cookie + CSRF）不在本文范围，索引见 [README 的「HTTP 接口」](../README.md#http-接口)。第三方不要接 `/api/*`：那套凭据是浏览器登录态，口令一改就断，也无法按调用方审计。

## 目录

- [快速开始](#快速开始)
- [鉴权](#鉴权)
- [`GET /vpngate/api/iphone/`](#get-vpngateapiiphone)
  - [查询参数](#查询参数)
  - [响应：官方 15 列逐列说明](#响应官方-15-列逐列说明)
  - [响应头](#响应头)
  - [`.ovpn` 正文列的行为](#ovpn-正文列的行为)
  - [状态码与限流](#状态码与限流)
- [`GET /healthz`](#get-healthz)
- [参数取值参考](#参数取值参考)
- [反代配置](#反代配置)
- [常见坑](#常见坑)
- [契约稳定性](#契约稳定性)
- [curl 速查](#curl-速查)

---

## 快速开始

```bash
# 1) 服务端开启（默认关着）
openssl rand -hex 24 > /etc/vpngate-agg/api_token
chmod 600 /etc/vpngate-agg/api_token

# 2) 调用
BASE=https://vpngate.example.com
TOK=$(cat /etc/vpngate-agg/api_token)

curl -s -H "Authorization: Bearer $TOK" "$BASE/vpngate/api/iphone/?config=0&limit=3" | jq
```

响应是一个 JSON **数组**，每一行的字段名与顺序对齐官方 `https://www.vpngate.net/api/iphone/` 的 15 列 —— 把 host 从 `www.vpngate.net` 换成你的域名，解析代码不用改。

```json
[
  {
    "HostName": "vpn176792365",
    "IP": "112.185.71.174",
    "Score": 2920244,
    "Ping": 19,
    "Speed": 446115020,
    "CountryLong": "Japan (Tokyo)",
    "CountryShort": "JP",
    "NumVpnSessions": 87,
    "Uptime": 1357723590,
    "TotalUsers": 19821038,
    "TotalTraffic": 1204377054439320,
    "LogType": "2weeks",
    "Operator": "Daiyuu Nobori_ Japan. Academic Use Only.",
    "Message": "",
    "OpenVPN_ConfigData_Base64": "IyMjIyMj...（.ovpn 正文的标准 base64）"
  }
]
```

---

## 鉴权

`api.token` 只有两个配置入口，**界面改不了**，改完要重启。

配置文件（查找顺序：`VPNGATE_AGG_CONFIG` → `<data_dir>/config.json` → `./config.json`）：

```json
{
  "api": {
    "enabled": true,
    "token": "<至少 16 字符>",
    "include_config": true,
    "max_nodes": 500,
    "rate_per_minute": 30
  }
}
```

或环境变量：

| 变量 | 对应配置 |
| --- | --- |
| `VPNGATE_AGG_API_ENABLED` | `api.enabled` |
| `VPNGATE_AGG_API_TOKEN` | `api.token` |
| `VPNGATE_AGG_API_INCLUDE_CONFIG` | `api.include_config` |
| `VPNGATE_AGG_API_MAX_NODES` | `api.max_nodes` |
| `VPNGATE_AGG_API_RATE_PER_MIN` | `api.rate_per_minute` |

优先级：环境变量 > 配置文件 > 内置默认（`enabled=false`、`include_config=true`、`max_nodes=500`、`rate_per_minute=30`）。

**启动即校验**：`enabled=true` 而 token 为空 → 进程直接拒绝启动；token 短于 16 字符同样被拒。不会把接口裸开。

**三种带法**（任一即可，比较走定长比较）：

```bash
curl -H "Authorization: Bearer $TOK" ...   # 推荐
curl -H "Authorization: $TOK" ...          # 裸 token 也认
curl "...?key=$TOK"                        # 只能填 URL 的客户端
```

> ⚠️ `?key=` 会把 token 写进反代的 access log 和浏览器历史，能用头就用头。
> ⚠️ token 是明文存的（不像登录口令那样转 PBKDF2）。程序写出的配置文件权限是 0600，但仍要防日志/备份外泄。

---

## `GET /vpngate/api/iphone/`

只读，无副作用。带不带结尾斜杠都行（两个都注册了，避免 301 丢查询参数）。

### 查询参数

| 参数 | 取值 | 说明 |
| --- | --- | --- |
| `q` | 字符串 | 模糊匹配主机名 / IP / 运营商 / 留言 / 国家 |
| `country` | `JP,KR,DE` | 国家码，逗号分隔（大小写不敏感）；`?` 表示未知 |
| `proto` | `tcp,udp` | 按 `.ovpn` 里解析出的协议 |
| `level` | `stable,reachable,unknown,flaky,down,untested` | 本服务探测出的可达档位（见[参数取值参考](#参数取值参考)） |
| `min_purity` / `max_purity` | 0–100 | IP 纯净度分数。**没测过纯净度的节点不参与这两个筛选** |
| `max_ping` | 毫秒 | 按 `ping_source` 口径（默认 `best` 只认本机实测，没测过的不参与）。**没有延迟数据的节点不参与；已判定不可达（`level=down`）的节点也不参与**（见 [`ping_source`](#ping_source--延迟口径)） |
| `ping_source` | `best`(默认) `local` `upstream` `cloudflare` | 延迟取哪个口径 |
| `residential` | `1` | 只要判定为志愿者家宽的节点 |
| `purity_only` | `1` | 只要查过纯净度的节点 |
| `fresh` | `1` | 只要最新官方名单里还在的节点 |
| `probed` | `1` | 只要有本地探测记录的节点 |
| `ids` | 逗号分隔的节点 ID | 精确取一批 |
| `sort` | `score`(默认) `ping` `speed` `sessions` `hostname` `purity` `rtt` `seen` `recommend` | 不在白名单的值 → **422**（不会默默退回默认） |
| `dir` | `desc`(默认) `asc` | 说的是**这一列的值**：`desc` = 从大到小。不写就是 Score 最高的在前，与官方名单顺序一致 |
| `limit` | 1–500 | 单次条数，上限被 `api.max_nodes` 压住 |
| `offset` | ≥0 | 翻页 |
| `config` | `0` / `false` / `no` / `off` | 只要名单、不要正文列（响应体小一个数量级） |

通用约定：一律 UTF-8；时间字段是 UTC RFC3339；带 `Accept-Encoding: gzip` 会回 gzip。

### 响应：官方 15 列逐列说明

**这一张表里的列全部是 VPN Gate 官方给出的观测**（本服务的探测与纯净度结论不在这条接口里）。

| 列 | 类型 | 含义 |
| --- | --- | --- |
| `HostName` | str | 节点主机名标签（原样） |
| `IP` | str | 规范化后的 IP |
| `Score` | int64 | 官方综合分。**默认就是按它降序返回** |
| `Ping` | int64 | 官方测的延迟（ms）。注意这是官方的原始值：**已判定不可达的节点仍然带着这个值返回** —— 它不参与排序/筛选不等于这一列被清空 |
| `Speed` | int64 | 官方测的速率（bps） |
| `CountryLong` | str | 国家全称，如 `Japan (Tokyo)` |
| `CountryShort` | str | 两位国家码，未知为 `""` |
| `NumVpnSessions` | int64 | 当前并发会话数 |
| `Uptime` | int64 | 运行秒数 |
| `TotalUsers` | int64 | 累计用户数 |
| `TotalTraffic` | int64 | 累计流量 |
| `LogType` | str | 官方给的日志策略标签，如 `2weeks` |
| `Operator` | str | 运营者（自由文本，可能含逗号） |
| `Message` | str | 节点留言（自由文本，可能含逗号） |
| `OpenVPN_ConfigData_Base64` | str | `.ovpn` 正文的标准 base64（标准表 + padding）。`?config=0` 或 `api.include_config=false` 时这一整列不出现 |

`sort`/`limit`/`offset` 生效后的语义：`limit` 内取当前页，`offset` 之后仍有的是 `X-Vpngate-Agg-Total` 报的总数。

### 响应头

| 头 | 含义 |
| --- | --- |
| `X-Vpngate-Agg-Rows` | 本次返回的行数 |
| `X-Vpngate-Agg-Skipped` | 因本地缺 `.ovpn` 正文被跳过的行数 |
| `X-Vpngate-Agg-Total` | 筛选命中的**总数**（≠ 本次返回数），翻页用 |
| `X-Vpngate-Agg-Limit` / `X-Vpngate-Agg-Offset` | 本次生效的分页参数 |
| `Cache-Control` | `private, max-age=30` |
| `Content-Type` | `application/json; charset=utf-8` |

### `.ovpn` 正文列的行为

- 正文按内容 sha256 存在本服务磁盘上，**按磁盘实况判定**，不看快照里那个可能陈旧的标记。
- 本地没有正文的节点（从没按 sha 拉取过的第三方累积池节点）**整行跳过** —— 官方格式里这一列就是可连接的配置本体，给空串等于往名单里塞一个连不上的节点。被跳过的行数在 `X-Vpngate-Agg-Skipped`。
- `?config=0` 不要正文时不跳行，**此时行数会与官方名单对齐**（统计条数时这两个数会不一样，注意）。
- `api.include_config=false` 时这一列**永远不给**，`?config=1` 也要不回来 —— 运维层面的上限，查询参数只能往下关。

### 状态码与限流

错误体统一是：

```json
{ "ok": false, "error": "缺少或错误的 api token" }
```

| 情况 | 状态码 | 备注 |
| --- | --- | --- |
| `api.enabled=false` 或 token 未配 | **404** | 不告诉外面「这里有东西但不让你进」 |
| 无 token / token 不对 | **401** | 带 `WWW-Authenticate: Bearer realm="vpngate-agg"` |
| 参数不合法、`sort` 不在白名单 | **422** | `error` 是中文且写明参数名 |
| 超过 `api.rate_per_minute` | **429** | 带 `Retry-After: 15` |
| 方法不对（如 `POST`） | **405** | 路由按方法限定。`HEAD` 会落到 GET handler，所以 `curl -I` 可用（没 body） |

限流是**每来源 IP 每分钟固定窗口**，默认 30 次，填 `0` 关掉。401 也计数 —— 否则乱猜 token 的循环打不着自己。同一 NAT 后面一堆机器一起拉就把这个数调大。

来源 IP 的取法：只有当连接来自回环/私网时才采信 `X-Forwarded-For` 的第一段 / `X-Real-IP`，公网直连时用真实 socket 地址。

---

## `GET /healthz`

免鉴权，给监控探针用。

```json
{ "ok": true, "nodes": 269, "version": "0.1.0", "dirty": false }
```

| 字段 | 含义 |
| --- | --- |
| `nodes` | 节点池总数（含已不在本轮官方名单里的历史节点） |
| `version` | 构建版本 |
| `dirty` | 是否有未落盘的改动 |

---

## 参数取值参考

### `level` —— 本服务探测出的可达档位

| 值 | 含义 |
| --- | --- |
| `stable` | 明确可达且成功率 ≥80% |
| `reachable` | 明确可达 |
| `unknown` | 只拿到「说不清」的结论（超时、UDP 无回包） |
| `flaky` | 连不上但连续失败 <2 次，或历史上成功过 |
| `down` | 明确否定结论（连接被拒 / 网络不可达 / 被本地策略拦下）**且连续 ≥2 次** |
| `untested` | 从没测过 |

**超时和 UDP 无回包算 `unknown` 不算 `down`** —— 跨境链路丢一个 SYN 太常见，而 VPN Gate 上的 SoftEther 节点对 UDP 硬重置包基本不应答，按失败算会有半池 UDP 节点被长期误标成死亡。想要「确定的坏节点」只筛 `down`，想要「别给我坏的」用 `level=stable,reachable`。

### `sort` —— 可用排序键

| 值 | 排的是什么 |
| --- | --- |
| `score`（默认） | 官方 `Score` 列 |
| `ping` | 按 `ping_source` 选的那个延迟口径 |
| `speed` | 官方 `Speed` 列 |
| `sessions` | 官方 `NumVpnSessions` 列 |
| `hostname` | 主机名（字符串序） |
| `purity` | 本服务的 IP 纯净度分数 |
| `rtt` | 本服务的本地实测延迟 |
| `seen` | 最后一次被官方名单见到 |
| `recommend` | 本服务的推荐分（可达档位 + 延迟 + 纯净度 + 新鲜度加权） |

`dir=desc` 对以上每一列都是「该列的值从大到小」；`seen` 的「大」= 越新。没测过的节点在有数据的节点之后，与方向无关。

`sort=ping` 多两条规则：

1. **默认 `best` 口径只看本机实测**（EWMA → 最近一次成功的 RTT），不兜底官方 `Ping`。没测过的节点没有延迟可排，会落到末尾；要一份「按官方延迟排」的名单就显式带 `ping_source=upstream`。
2. **已判定不可达（`level=down`）的节点不参与这一列的排序**，无论 `ping_source` 是哪个口径，它都排到末尾（升降序都是）。因为本地延迟是 EWMA，只由成功的探测喂出来，不清空也不按时间衰减 —— 不管的话「历史上很快、现在已挂」的节点会抢到 `dir=asc` 的第一名。

两种情况节点本身仍在结果里，只是排到最后（除非另加了 `level=` 筛选）。

### `ping_source` —— 延迟口径

| 值 | 来源 |
| --- | --- |
| `best`（默认） | 本机实测：EWMA → 最近一次成功的 RTT。**不兜底官方 `Ping`，也不用 Cloudflare 观测** |
| `local` | 本机实测：优先最近一次成功的值，没有才退 EWMA |
| `upstream` | 官方 `Ping` 列（显式选了才用：那是别人那张网的观测，口径不明、通常偏小） |
| `cloudflare` | 第三方 Cloudflare Worker 的 TCP 观测（只在启用第三方源时有） |

四条约定：

- 默认口径下没测过的节点在 `sort=ping` / `max_ping` 里全部不参与 —— 不是漏数据，是本服务确实没连上过它们（实测只覆盖少数节点，实测快照里 74/269）。
- **已判定不可达（`level=down`）的节点任何口径都不参与** `sort=ping` / `max_ping`。
- 以上说的都是**排序与筛选**用的延迟，不是响应里那个 `Ping` 列：那一列永远是官方的原始值，不受口径影响。
- 想要「官方口径的延迟名单」就显式 `?ping_source=upstream`（已挂的仍然不参与）。

### `purity` 分数与档位（用于 `min_purity`/`max_purity`/`sort=purity`）

| 档位 | 分数 |
| --- | --- |
| `excellent` | ≥85（住宅/家庭宽带特征） |
| `good` | 70–84 |
| `fair` | 50–69 |
| `poor` | 30–49 |
| `bad` | <30（机房/匿名网络/黑名单命中） |

分数越高越干净。注意：没查过纯净度的节点不参与 `min_purity`/`max_purity` 筛选，需要「只要查过的」再加 `purity_only=1`。

---

## 反代配置

```nginx
location /vpngate/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;   # 限流按 IP，得让它看到真实客户端
    proxy_set_header X-Real-IP $remote_addr;
}
```

- 只有当连接本身来自回环/私网时，`X-Forwarded-For` 才会被采信 —— 别把服务直接暴露在公网又指望这个头。
- 要按调用方限流/放行，就给这个前缀单独一条 `location`，与界面用的 `/api/*` 互不影响。
- 需要 TLS 就在反代结束，同时把服务端的 `auth.cookie_secure` 打开（只影响界面会话，不影响本接口）。

---

## 常见坑

1. **404 多半不是「节点不存在」**，而是对外接口没开（`api.enabled=false`）。先确认服务端配置。
2. **`sort` 写错值报 422**，不会退回默认 —— 拼错 `sort=total` 会直接失败，这是刻意的（免得调用方以为排序生效了却没生效）。
3. **`dir` 说的是列的值**：`?sort=score&dir=desc` = 分数从大到小（这也是默认）。
4. **带正文 vs 不带正文，行数会不同**：带正文时缺 `.ovpn` 的节点整行缺席，`?config=0` 时补齐。要准确条数就同时看 `X-Vpngate-Agg-Rows` 和 `-Skipped`。
5. **`limit` 最大 500**（被 `api.max_nodes` 压住，超出会被钉住而不是报错）；更多数据用 `offset` 翻页，总数在 `X-Vpngate-Agg-Total`。
6. **`sort=ping` / `max_ping` 用的是本服务自己的观测**：默认 `best` 口径只认本机实测（不兜底官方 `Ping`），已判定不可达的节点更是完全不参与。两者都是把节点排到末尾而不是删掉；而响应里的 `Ping` 列照旧是官方的原始值。要按官方延迟排，显式带 `ping_source=upstream`。
7. **`Cache-Control: private, max-age=30`**：脚本连打会被缓存挡掉，压测/调试时带 `Cache-Control: no-cache` 或每次换参数。
8. **`?key=` 会落进 access log**，能用 `Authorization` 头就用头。
9. **带正文的响应很大**：实测 269 个节点 ≈ 3.7 MB，只要名单时 ≈ 80 KB。默认会回 gzip（列表接口压完能小一个数量级），确认你的 HTTP 客户端接受并解压 gzip。
10. **本接口不含本服务的探测档位与纯净度分数**（只有参数用它们做筛选）。要把「可达/家宽」作为字段读出来，只能用界面专用的 `/api/*`（需要登录）。
11. **没有版本前缀**（没有 `/v1`）：这条接口的「版本」就是它的列契约本身，见下一节。

---

## 契约稳定性

| 什么 | 稳定性 |
| --- | --- |
| 上述 **15 个列名与含义** | **稳定契约** —— 改名、删列、改语义算破坏性变更，会先走弃用 |
| 查询参数 | 稳定；新增参数不破坏既有调用 |
| `sort=ping` / `max_ping` 的延迟口径（`best` 只认本机实测；已判定不可达的节点不参与，节点仍在结果里只是排末尾） | 稳定契约；想改这一语义会先走弃用 |
| `X-Vpngate-Agg-*` 响应头 | 半稳定；新增不另行通知，删除会先弃用 |
| `/healthz` 的字段 | 半稳定 |

调用方应按「列名 + 类型」解析，并容忍将来新增的列；不要按数组下标取列。

---

## curl 速查

```bash
BASE=https://vpngate.example.com
TOK=$(cat /etc/vpngate-agg/api_token)

# 健康检查（免鉴权）
curl -s $BASE/healthz

# 整个名单（带 .ovpn 正文，Score 降序，与官方同形）
curl -s -H "Authorization: Bearer $TOK" $BASE/vpngate/api/iphone/

# 只要名单、不要正文，顺便看列名
curl -s -H "Authorization: Bearer $TOK" "$BASE/vpngate/api/iphone/?config=0&limit=2" | jq '.[0]|keys'

# 日本 + 家宽 + 可达，按延迟升序取前 50
curl -sG -H "Authorization: Bearer $TOK" $BASE/vpngate/api/iphone/ \
  --data-urlencode country=JP --data-urlencode residential=1 \
  --data-urlencode 'level=stable,reachable' --data-urlencode sort=ping \
  --data-urlencode dir=asc --data-urlencode limit=50 --data-urlencode config=0 \
  | jq -r '.[]|"\(.HostName) \(.IP):\(.CountryShort)"'

# 只取指定几个节点
curl -s -H "Authorization: Bearer $TOK" \
  "$BASE/vpngate/api/iphone/?ids=v1:aaa…,v1:bbb…&config=0"

# 翻页：看总数不用多打一次（响应头）
curl -s -o /dev/null -D - -H "Authorization: Bearer $TOK" \
  "$BASE/vpngate/api/iphone/?country=JP&config=0" | tr -d '\r' | sed -n '/x-vpngate/Ip'

# 把正文还原成 .ovpn 文件
curl -s -H "Authorization: Bearer $TOK" "$BASE/vpngate/api/iphone/?country=JP&limit=5" \
  | jq -r '.[]|.HostName + "\t" + .OpenVPN_ConfigData_Base64' \
  | while IFS=$'\t' read -r name b64; do echo "$b64" | base64 -d > "$name.ovpn"; done

# 鉴权失败长什么样
curl -s -o /dev/null -w '%{http_code}\n' $BASE/vpngate/api/iphone/          # 401（或接口没开时 404）
```
