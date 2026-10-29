# resi-proxy-hub：家宽代理调度系统（Cloudflare Workers + D1 + VPS agent）

```
 浏览器 ──Basic Auth──▶ Cloudflare Worker (面板 + API) ◀──心跳/策略──▶ VPS agent
                              │                                        │
                          D1 (节点/策略/日志)                 VPNGate → OpenVPN(tun_rp)
                                                                       │
                                            你的程序 ──SOCKS5/HTTP(带认证)──▶ 出口 IP
```

- **控制面（Cloudflare）**：Worker 提供面板与 API，D1 存节点、策略、日志，表结构首次请求自动创建。
- **数据面（VPS）**：`agent.py` 从 VPNGate 拉节点 → 按国家筛选、TCP 预检 → 起 OpenVPN → 用 ip-api 做出口质检（过滤机房 IP）→ 在同一端口提供 SOCKS5 + HTTP 代理。
- 掉线自动切换（探测连续失败 / openvpn 退出），面板可一键换 IP、改目标国家和端口。
- 代理强制认证，凭据未配置时 agent 拒绝一切连接；DNS 经隧道解析，目标地址限制为公网 IPv4。

## 部署

### 1. Cloudflare 侧（Pages）

```bash
npm install
npx wrangler d1 create proxy-db        # 已有 D1 可跳过；database_id 填进 wrangler.toml
npm run deploy                         # 生成 src/assets.js 并部署到 Pages（首次会提示创建项目，生产分支填 main）

# 设置密钥（部署后执行，每个都会提示输入值）
npx wrangler pages secret put WEB_USER       --project-name free-ip-hub
npx wrangler pages secret put WEB_PASS       --project-name free-ip-hub
npx wrangler pages secret put AGENT_TOKEN    --project-name free-ip-hub   # 建议 openssl rand -hex 24
npx wrangler pages secret put PROXY_USER     --project-name free-ip-hub
npx wrangler pages secret put PROXY_PASS     --project-name free-ip-hub
```

也可以在 Dashboard 的 Pages 项目 → Settings → Variables and Secrets 里设置。改了 `src/` 下的 agent.py / panel.html / *.sh 之后，需要重新执行 `npm run build:assets`（`npm run deploy` 已包含）。

> 从 Workers 迁移：D1 沿用原库，数据保留；VPS 上的 agent 需把 HUB 地址改成新的 `*.pages.dev` 域名（重新执行面板里的安装命令即可），旧 Worker 确认没问题后再删除。
> 壁纸同步用的 KV 在 Pages 不会自动创建，需要时见 `wrangler.toml` 注释；不配置也不影响其它功能。
> 本项目没有默认口令：`WEB_USER/WEB_PASS` 未设置时面板返回 503。

### 2. VPS 侧

要求：海外 Linux VPS，root，开启 TUN/TAP，**OpenVPN ≥ 2.5**（Debian 11+/Ubuntu 22.04+）。

打开面板，复制「接入新节点」里的命令，在 VPS 上执行即可（安装依赖、写入 systemd 服务、自动启动）。然后在防火墙/安全组放行代理端口（默认 7920）。

### 3. 使用

面板的「可用代理列表」会给出 `socks5://用户:密码@VPS_IP:端口`，也可以直接拉取：

```bash
curl -u admin:密码 "https://你的worker域名/api/proxies"                 # 纯文本
curl -u admin:密码 "https://你的worker域名/api/proxies?format=json"     # JSON
curl -u admin:密码 "https://你的worker域名/api/proxies?scheme=http"     # HTTP 格式
curl --proxy socks5h://proxy:密码@VPS_IP:7920 https://api.ipify.org     # 验证出口
```

## 住宅 IP 扫描

agent 启动后每 16 分钟（`SCAN_INTERVAL` 环境变量，默认 960 秒）自动抓取并扫描一轮，扫描完成后若发现比当前线路更优的 IP 会自动切换（面板「定时择优换线」可关闭；手动固定的 IP 不受影响），面板也可点「立即扫描」：

1. 拉取 VPNGate 全量节点，用 ip-api 批量接口查出每个 IP 的国家 / 地区 / 城市 / ISP，并判定类型（机房 / 移动 / 住宅）。
2. 从 VPS 实测到每个 IP 的延迟：TCP 节点测握手（3 次取中位数），UDP 节点测 ICMP，都失败才退回 VPNGate 自报值（面板标「自报」）。
3. 结果上报到 Worker（D1 表 `scan_ips`），在面板「住宅 IP 扫描」区块按国家、类型、延迟筛选排序。
4. 建链时 agent 优先使用扫描出的低延迟住宅 IP，并跳过已确认的机房 IP。
5. **切换**：扫描清单每行有「切换」按钮，点击后该节点会改用这个 IP 建立隧道（固定模式下不再按国家策略和机房标记过滤）。连不上或质检失败会自动恢复自动选择；在节点行点「取消固定」也可恢复。API：`POST /api/switch {"node_id":"…","ip":"1.2.3.4"}`，`ip` 传空字符串即取消。

```bash
curl -u admin:密码 "https://你的worker域名/api/scan?type=residential&country=JP,US&max_latency=150"   # JSON
curl -u admin:密码 "https://你的worker域名/api/scan?type=residential&format=text"                      # IP:端口 列表
```

参数：`type`（all/residential/hosting）、`country`（逗号分隔国家码）、`max_latency`（ms）、`reachable=1`、`limit`。

> 老用户升级：直接重新部署 Worker（D1 会自动补列建表），VPS 上重新执行一遍面板里的安装命令即可更新 agent，并补装 `ping`。

## 路由、代理服务与系统诊断

**路由模式**（面板「路由与代理服务」）：只有「指定国家」模式需要设置目标国家（`ANY` = 全球）；「延迟优先」「速度优先」在全球范围内挑选。三种模式都会跳过面板里多选的「不连接的国家」，并优先使用已扫描确认的住宅 IP。

| 模式 | 排序依据 |
| --- | --- |
| 指定国家（`country`，默认） | VPNGate 评分 |
| 延迟优先（`latency`） | 本 VPS 实测延迟最低 |
| 速度优先（`speed`） | VPNGate 测速最高 |

「路由预览」按当前模式列出 agent 下一次会优先尝试的前 5 个 IP（基于最近一次扫描）。切换模式会让节点按新规则重新选择；手动「切换」固定的 IP 优先级最高。

**VPS 代理服务**：面板可启用 / 停用代理服务、设置最大连接数（超限直接拒绝并计数），并显示每个节点的监听状态、当前连接、累计 / 拒绝、上下行流量和已运行时长。

**系统诊断**：点「运行诊断」（agent 启动 20 秒后也会自动跑一次），检查 root / TUN / OpenVPN 版本 / 命令依赖 / 负载内存磁盘 / 时钟偏差 / DNS / VPNGate 与 ip-api 连通 / 隧道出站与隧道内 DNS / 策略路由 / 代理监听与凭据 / **代理端到端自测**（用真实凭据走一遍 SOCKS5 经隧道访问外网），并由 Cloudflare 边缘探测代理端口是否对公网开放（排查防火墙、安全组）。

```bash
curl -u admin:密码 "https://你的worker域名/api/route/preview?limit=5"   # 路由预览
curl -u admin:密码 "https://你的worker域名/api/diag"                    # 最近一次诊断结果
curl -u admin:密码 -X POST -H 'content-type: application/json' -d '{"mode":"latency","country":"JP","port":7920,"max_conns":500,"proxy_enabled":true}' "https://你的worker域名/api/policy"
```

## 状态栏与壁纸同步

- 面板顶部状态栏：**当前节点总数**（在线 / 代理就绪）、**当前可用住宅数**（可达且不在黑名单国家）、**可用国家 / 地区**、**黑名单**（即「不连接的国家」）。
- 表格自适应宽度，不再横向滚动；窄屏（≤960px）自动变成卡片。
- 壁纸与透明度存放在 Cloudflare KV（binding 名 `KV`），任意设备打开面板约 30 秒内同步。KV 是最终一致的，跨地区可能再延迟约 1 分钟。未绑定 KV 时壁纸只保存在本机，其余功能不受影响。
- API：`GET /api/bg?since=<ts>`、`POST /api/bg {"img":"data:image/...|https://...|\"\"","op":88}`。

## 目录

| 文件 | 作用 |
| --- | --- |
| `src/index.js` | Worker：路由、鉴权、心跳、策略、代理列表 |
| `src/panel.html` | 面板前端（无外部依赖，随 Worker 下发） |
| `src/agent.py` | VPS agent（仅标准库） |
| `src/install.sh` | 一键安装脚本模板 |
| `functions/[[path]].js` | Pages Functions 入口 |
| `scripts/build-assets.mjs` | 把 agent/脚本/面板打包进 `src/assets.js` |
| `wrangler.toml` | Pages / D1 / KV 绑定 |

## 已知限制

- VPNGate 是志愿者节点，**“家宽”属性靠 ip-api 的 hosting 标记过滤，只能做到尽力而为**；出口质量、稳定性、速度都有波动，不适合需要稳定 SLA 的场景。
- 扫描判定的是 VPNGate 服务器 IP；VPNGate 绝大多数节点出口 IP 与服务器 IP 相同，但不保证。真正的出口类型以建链后 `verify` 的检测为准。
- ip-api 批量接口免费额度为 15 次/分钟，每轮扫描只用 2–3 次，别把扫描间隔调得太短。
- 目前是单隧道 + 自动重选；参考项目里的“主备双隧道零中断切换”可作为下一步（在 agent 里并行维护两个 tun 设备并用 ip rule 切换）。
- ip-api 免费接口仅 HTTP、有频率限制（只在建链时调用一次）；需要更严格的 IP 质检可换成 IPinfo / IP2Location 等付费 API。
- 免费节点由第三方运营，**不要通过它传输敏感信息**。
- 请只用于合法用途，并遵守 VPNGate、Cloudflare 以及目标站点的服务条款；开放端口时务必保持认证开启，避免变成公共开放代理。
