#!/usr/bin/env python3
"""resi-agent: VPNGate -> OpenVPN -> SOCKS5/HTTP proxy, managed by the Cloudflare hub.

只依赖 Python3 标准库 + openvpn + iproute2。必须以 root 运行（SO_BINDTODEVICE / ip rule）。
"""
import asyncio, base64, csv, hmac, io, ipaddress, json, os, random, re, shutil, socket, struct, subprocess, sys, time
import urllib.request
from collections import deque
from urllib.parse import urlsplit

HUB = os.environ["HUB_URL"].rstrip("/")
TOKEN = os.environ["AGENT_TOKEN"]
NODE_ID = os.environ.get("NODE_ID") or socket.gethostname()
WORKDIR = os.environ.get("WORKDIR", "/opt/resi-agent")
ALLOW_HOSTING = os.environ.get("ALLOW_HOSTING", "0") == "1"  # 1 = 不过滤机房 IP
DEV, TABLE = "tun_rp", "100"
VPNGATE_API = "http://www.vpngate.net/api/iphone/"
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "960"))  # 自动抓取 + 择优间隔（秒），默认 16 分钟

S = dict(country="US", port=7920, user="", pw="", nonce=None, ready=False, status="starting",
         exit_ip="", cc="", isp="", hosting=False, latency=0, pin="", pin_fail="",
         mode="country", proxy_on=True, max_conns=500, skew=0, hub_rtt=0, exclude=set(), prefer=set(),
         auto_best=True, cur=None, last_ip="", want_ip="")
ROUTE_NAMES = dict(country="指定国家(评分)", latency="延迟优先", speed="速度优先")
# 代理服务统计
PROXY = dict(active=0, total=0, rejected=0, up=0, down=0, since=0, listening=False)
DIAG = dict(nonce=None, running=False, ts=0)
# 扫描状态：res = 住宅 IP -> 实测延迟；bad = 已确认的机房 IP（建链时直接跳过）
SCAN = dict(state="idle", ts=0, nonce=None, res={}, bad=set())
PENDING = deque(maxlen=200)
rotate_ev = port_ev = scan_ev = diag_ev = None  # 在 main() 里创建，兼容 Python 3.9


def log(msg):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)
    PENDING.append(line)


# ---------------------------------------------------------------- hub
def hub_post(path, obj):
    req = urllib.request.Request(
        HUB + path, data=json.dumps(obj).encode(),
        headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json",
                 "User-Agent": "resi-agent/1.0"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def apply_policy(r):
    p = r["policy"]
    country, port = str(p["country"]).upper(), int(p["port"])
    S["user"], S["pw"] = p.get("proxy_user", ""), p.get("proxy_pass", "")
    if S["nonce"] is None:
        S["nonce"] = r["rotate_nonce"]
    elif r["rotate_nonce"] != S["nonce"]:
        S["nonce"] = r["rotate_nonce"]
        log("收到面板的换 IP 指令")
        rotate_ev.set()
    if S["ready"] and country != S["country"]:
        log(f"目标国家变更 {S['country']} -> {country}")
        rotate_ev.set()
    exclude = {str(x).upper() for x in (p.get("exclude") or []) if len(str(x)) == 2 and str(x).isalpha()}
    if exclude != S["exclude"]:
        if S["ready"]:
            log("不连接的国家变更: " + (",".join(sorted(exclude)) or "无"))
            if S["status"] == "up" and not S["pin"] and S["cc"] in exclude:
                rotate_ev.set()
        S["exclude"] = exclude
    prefer = {str(x).upper() for x in (p.get("prefer") or []) if len(str(x)) == 2 and str(x).isalpha()}
    if prefer != S["prefer"]:
        if S["ready"]:
            log("优先国家变更: " + (",".join(sorted(prefer)) or "无"))
            if prefer and S["status"] == "up" and not S["pin"] and S["cc"] not in prefer:
                rotate_ev.set()
        S["prefer"] = prefer
    S["auto_best"] = bool(p.get("auto_best", True))
    pin = r.get("pin_ip") or ""
    if pin != S["pin"] and pin != S["pin_fail"]:
        S["pin"] = pin
        log(f"面板指定固定出口 {pin}" if pin else "取消固定，恢复自动选择")
        rotate_ev.set()
    sn = r.get("scan_nonce", 0)
    if SCAN["nonce"] is None:
        SCAN["nonce"] = sn
    elif sn != SCAN["nonce"]:
        SCAN["nonce"] = sn
        if SCAN["state"] != "scanning":
            log("收到面板的扫描指令")
            scan_ev.set()
    mode = p.get("mode", "country")
    if mode not in ("country", "latency", "speed"):
        mode = "country"
    if S["ready"] and mode != S["mode"]:
        log(f"路由模式变更 {S['mode']} -> {mode}")
        rotate_ev.set()
    S["mode"] = mode
    on = bool(p.get("proxy_enabled", True))
    if on != S["proxy_on"]:
        S["proxy_on"] = on
        log("代理服务已" + ("启用" if on else "停用（不再接受新连接）"))
        port_ev.set()
    S["max_conns"] = max(1, int(p.get("max_conns", 500)))
    if "now" in r:
        S["skew"] = int(r["now"]) - int(time.time() * 1000)
    dn = r.get("diag_nonce", 0)
    if DIAG["nonce"] is None:
        DIAG["nonce"] = dn
    elif dn != DIAG["nonce"]:
        DIAG["nonce"] = dn
        if not DIAG["running"]:
            log("收到面板的诊断指令")
            diag_ev.set()
    S["country"] = country
    if port != S["port"]:
        S["port"] = port
        port_ev.set()
    S["ready"] = True

def get_public_ip():
    try:
        return urllib.request.urlopen("https://api.ipify.org", timeout=8).read().decode().strip()
    except Exception:
        return ""

async def heartbeat_loop():
    loop = asyncio.get_running_loop()
    while True:
        lines = [PENDING.popleft() for _ in range(min(20, len(PENDING)))]
        body = dict(node_id=NODE_ID, status=S["status"], exit_ip=S["exit_ip"], country=S["cc"],
                    isp=S["isp"], hosting=S["hosting"], latency=S["latency"], port=S["port"], logs=lines,
                    scan_state=SCAN["state"], scan_at=SCAN["ts"], pin_ip=S["pin"], pin_fail=S["pin_fail"],
                    proxy=proxy_stats())
        try:
            t0 = time.time()
            r = await loop.run_in_executor(None, hub_post, "/api/agent/heartbeat", body)
            S["hub_rtt"] = int((time.time() - t0) * 1000)
            apply_policy(r)
            S["pin_fail"] = ""  # 面板已收到
        except Exception as e:
            print(f"heartbeat failed: {e}", flush=True)
            for l in reversed(lines):  # 放回去，下次再发
                PENDING.appendleft(l)
        await asyncio.sleep(30)


# ---------------------------------------------------------------- tunnel-bound sockets / DNS
def tun_sock(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, DEV.encode())
    return s


def _skip_name(d, i):
    while True:
        n = d[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += n + 1


def parse_a(d):
    qd, an = struct.unpack("!HH", d[4:8])
    i = 12
    for _ in range(qd):
        i = _skip_name(d, i) + 4
    for _ in range(an):
        i = _skip_name(d, i)
        t, _c, _ttl, rl = struct.unpack("!HHIH", d[i:i + 10])
        i += 10
        if t == 1 and rl == 4:
            return socket.inet_ntoa(d[i:i + 4])
        i += rl
    return None


def tun_resolve(name):
    """通过隧道向 1.1.1.1 / 8.8.8.8 查询 A 记录，避免 DNS 走本机出口泄漏。"""
    try:
        ipaddress.ip_address(name)
        return name
    except ValueError:
        pass
    labels = name.rstrip(".").encode("idna").split(b".")
    q = struct.pack("!HHHHHH", random.randrange(65536), 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(x)]) + x for x in labels) + b"\0" + struct.pack("!HH", 1, 1)
    for server in ("1.1.1.1", "8.8.8.8"):
        s = tun_sock(socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            s.sendto(q, (server, 53))
            ip = parse_a(s.recvfrom(1500)[0])
            if ip:
                return ip
        except OSError:
            pass
        finally:
            s.close()
    raise OSError("dns failed: " + name)


def ident():
    """经隧道查询出口 IP / 国家 / ISP / 是否机房（ip-api.com，仅 HTTP）。"""
    s = tun_sock()
    s.settimeout(8)
    try:
        s.connect((tun_resolve("ip-api.com"), 80))
        s.sendall(b"GET /json/?fields=status,query,countryCode,isp,hosting HTTP/1.0\r\nHost: ip-api.com\r\n\r\n")
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        return json.loads(data.split(b"\r\n\r\n", 1)[1])
    finally:
        s.close()


def probe():
    t = time.time()
    s = tun_sock()
    s.settimeout(5)
    try:
        s.connect(("1.1.1.1", 443))
        return int((time.time() - t) * 1000)
    except OSError:
        return None
    finally:
        s.close()


# ---------------------------------------------------------------- VPNGate / OpenVPN
def fetch_vpngate():
    req = urllib.request.Request(VPNGATE_API, headers={"User-Agent": "Mozilla/5.0"})
    raw = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "ignore")
    lines = [l for l in raw.splitlines() if l and not l.startswith("*")]
    lines[0] = lines[0].lstrip("#")
    out = []
    for row in csv.DictReader(io.StringIO("\n".join(lines))):
        try:
            text = base64.b64decode(row["OpenVPN_ConfigData_Base64"]).decode("utf-8", "ignore")
            proto = "udp" if "proto udp" in text else "tcp"
            remote = next(l.split() for l in text.splitlines() if l.startswith("remote "))
            out.append(dict(ip=row["IP"], cc=row["CountryShort"].upper(), score=int(row["Score"]),
                            speed=int(row["Speed"]) if str(row.get("Speed", "")).isdigit() else 0,
                            ping=int(row["Ping"]) if row["Ping"].isdigit() else 9999,
                            uptime=int(row["Uptime"]) if str(row.get("Uptime", "")).isdigit() else 0,
                            sessions=int(row["NumVpnSessions"]) if str(row.get("NumVpnSessions", "")).isdigit() else 0,
                            users=int(row["TotalUsers"]) if str(row.get("TotalUsers", "")).isdigit() else 0,
                            text=text, proto=proto, host=remote[1], port=int(remote[2])))
        except Exception:
            continue
    return out


async def tcp_alive(c):
    if c["proto"] != "tcp":
        return True
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(c["host"], c["port"]), 4)
        w.close()
        return True
    except Exception:
        return False



# ---------------------------------------------------------------- 住宅 IP 扫描
def ipapi_batch(ips):
    """ip-api 批量接口：每次最多 100 个，免费额度 15 次/分钟。"""
    fields = "status,query,country,countryCode,regionName,city,isp,org,hosting,proxy,mobile"
    body = json.dumps([{"query": ip, "fields": fields, "lang": "zh-CN"} for ip in ips]).encode()
    req = urllib.request.Request("http://ip-api.com/batch", data=body,
                                 headers={"Content-Type": "application/json", "User-Agent": "resi-agent/1.1"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


async def tcp_rtt(host, port, n=3):
    """真实 TCP 握手耗时（取中位数），从本 VPS 的默认出口测量，不经隧道。"""
    vals = []
    for _ in range(n):
        t = time.perf_counter()
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), 3)
            vals.append((time.perf_counter() - t) * 1000)
            w.close()
        except Exception:
            pass
    return int(sorted(vals)[len(vals) // 2]) if vals else None


async def icmp_rtt(host):
    try:
        p = await asyncio.create_subprocess_exec("ping", "-n", "-c", "3", "-W", "2", host,
                                                 stdout=asyncio.subprocess.PIPE,
                                                 stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(p.communicate(), 10)
    except Exception:
        return None
    m = re.search(rb"= [\d.]+/([\d.]+)/", out)
    return int(float(m.group(1))) if m else None


async def measure(c):
    """TCP 节点测握手；UDP 节点用 ICMP；都不通则退回 VPNGate 自报值并标注来源。"""
    if c["proto"] == "tcp":
        ms = await tcp_rtt(c["host"], c["port"])
        if ms is not None:
            return ms, "tcp"
    ms = await icmp_rtt(c["host"])
    if ms is not None:
        return ms, "icmp"
    if c["ping"] < 9999:
        return c["ping"], "vpngate"
    return None, "none"


async def scan_once(auto=False):
    loop = asyncio.get_running_loop()
    SCAN["state"] = "scanning"
    t0 = time.time()
    try:
        cands = await loop.run_in_executor(None, fetch_vpngate)
        uniq = {c["ip"]: c for c in cands if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", c["ip"])}
        ips = list(uniq)
        log(f"开始扫描 {len(ips)} 个 VPNGate 节点（IP 类型 + 实测延迟）")

        info = {}
        for i in range(0, len(ips), 100):
            for attempt in range(2):
                try:
                    for r in await loop.run_in_executor(None, ipapi_batch, ips[i:i + 100]):
                        if r.get("status") == "success":
                            info[r["query"]] = r
                    break
                except Exception as e:
                    log(f"ip-api 批量查询失败: {e}")
                    await asyncio.sleep(30 if attempt == 0 else 0)
            await asyncio.sleep(4.5)

        sem = asyncio.Semaphore(30)

        async def one(ip):
            c, r = uniq[ip], info[ip]
            async with sem:
                ms, method = await measure(c)
            hosting, mobile = bool(r.get("hosting")), bool(r.get("mobile"))
            return dict(ip=ip, host=c["host"], port=c["port"], proto=c["proto"], cc=c["cc"],
                        country=r.get("country", ""), region=r.get("regionName", ""), city=r.get("city", ""),
                        isp=r.get("isp", ""), org=r.get("org", ""), hosting=hosting,
                        proxy=bool(r.get("proxy")), mobile=mobile,
                        residential=not hosting and not mobile,
                        latency=ms, method=method, score=c["score"], speed=c["speed"],
                        sessions=c.get("sessions", 0), users=c.get("users", 0), uptime=c.get("uptime", 0))

        items = [x for x in await asyncio.gather(*(one(ip) for ip in ips if ip in info))]
        SCAN["res"] = {x["ip"]: (x["latency"] if x["latency"] is not None else 9999)
                       for x in items if x["residential"]}
        SCAN["bad"] = {x["ip"] for x in items if x["hosting"]}

        scan_id = int(time.time() * 1000)
        chunks = [items[i:i + 80] for i in range(0, len(items), 80)] or [[]]
        for n, chunk in enumerate(chunks):
            await loop.run_in_executor(None, hub_post, "/api/agent/scan", dict(
                node_id=NODE_ID, scan_id=scan_id, items=chunk, last=n == len(chunks) - 1))
        SCAN["ts"] = int(time.time() * 1000)
        if auto:
            consider_best(list(uniq.values()))
        ok = sum(1 for x in items if x["residential"] and x["latency"] is not None)
        log(f"扫描完成：{len(items)} 条，可达住宅 IP {ok} 条，用时 {int(time.time() - t0)}s")
    finally:
        SCAN["state"] = "idle"


def consider_best(cands):
    """定时择优：扫描完成后，若当前隧道不是最优，就切到最优 IP（固定 IP / 关闭自动择优 / 隧道未就绪时不动）。"""
    if not S["auto_best"] or S["pin"] or S["status"] != "up" or not S["cur"]:
        return
    want = S["country"]
    pool = [c for c in cands
            if (want == "ANY" or c["cc"] == want) and c["cc"] not in S["exclude"]
            and c["ip"] not in SCAN["bad"] and SCAN["res"].get(c["ip"], 9999) < 9999]
    if not pool:
        return
    best, cur = min(pool, key=route_key), S["cur"]
    if best["ip"] != cur["ip"] and route_key(best) < route_key(cur):
        S["want_ip"] = best["ip"]
        log(f"定时择优：{best['ip']} ({best['cc']}) 优于当前 {cur['ip']} ({cur['cc']})，切换")
        rotate_ev.set()
    else:
        log(f"定时择优：当前 {cur['ip']} 仍是最优，不切换")


async def scan_loop():
    await asyncio.sleep(5)
    auto = False
    while True:
        scan_ev.clear()
        t0 = time.time()
        try:
            await scan_once(auto)
        except Exception as e:
            log(f"扫描失败: {e}")
        try:  # 以「开始时间」起算，保证约每 SCAN_INTERVAL 秒一轮
            await asyncio.wait_for(scan_ev.wait(), max(30, SCAN_INTERVAL - (time.time() - t0)))
            auto = False  # 面板手动触发：只刷新数据，不自动换线
        except asyncio.TimeoutError:
            auto = True


async def sh(*cmd):
    p = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.DEVNULL,
                                             stderr=asyncio.subprocess.DEVNULL)
    return await p.wait()


async def cleanup_routes():
    for _ in range(3):
        await sh("ip", "rule", "del", "oif", DEV, "lookup", TABLE)
    await sh("ip", "route", "flush", "table", TABLE)


async def start_vpn(c):
    keep = [l for l in c["text"].splitlines()
            if not l.startswith(("dev ", "dev-type", "script-security", "up ", "down ", "redirect-gateway"))]
    keep += [f"dev {DEV}", "dev-type tun", "route-nopull", "nobind",
             "data-ciphers AES-256-GCM:AES-128-GCM:AES-128-CBC", "data-ciphers-fallback AES-128-CBC", "verb 3"]
    path = os.path.join(WORKDIR, "current.ovpn")
    with open(path, "w") as f:
        f.write("\n".join(keep) + "\n")
    proc = await asyncio.create_subprocess_exec("openvpn", "--config", path,
                                                stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.STDOUT)

    async def wait_ready():
        while True:
            line = await proc.stdout.readline()
            if not line:
                return False
            if b"Initialization Sequence Completed" in line:
                return True

    try:
        ok = await asyncio.wait_for(wait_ready(), 30)
    except asyncio.TimeoutError:
        ok = False

    async def drain():
        while await proc.stdout.readline():
            pass

    if ok:
        asyncio.create_task(drain())
    return proc, ok


async def stop_vpn(proc):
    if proc and proc.returncode is None:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), 5)
        except asyncio.TimeoutError:
            proc.kill()
    await cleanup_routes()
    S.update(exit_ip="", cc="", isp="", hosting=False, latency=0)


async def verify(c):
    """路由 + 出口质检；通过才算可用。"""
    await cleanup_routes()
    await sh("ip", "route", "replace", "default", "dev", DEV, "table", TABLE)
    await sh("ip", "rule", "add", "oif", DEV, "lookup", TABLE, "priority", "100")
    loop = asyncio.get_running_loop()
    try:
        info = await loop.run_in_executor(None, ident)
    except Exception as e:
        log(f"出口检测失败: {e}")
        return False
    if info.get("status") != "success":
        log("出口检测无结果")
        return False
    if S["pin"]:
        if info.get("hosting"):
            log(f"提示：固定的出口 {info['query']} 被判定为机房 IP")
    elif info.get("countryCode") in S["exclude"]:
        log(f"出口国家 {info['countryCode']} 在排除列表中，跳过")
        return False
    elif S["country"] != "ANY" and info["countryCode"] != S["country"]:
        log(f"出口国家 {info['countryCode']} 与目标 {S['country']} 不符")
        return False
    if info.get("hosting") and not ALLOW_HOSTING and not S["pin"]:
        log(f"出口 {info['query']} 被判定为机房 IP，跳过")
        return False
    S.update(exit_ip=info["query"], cc=info["countryCode"], isp=info.get("isp", ""),
             hosting=bool(info.get("hosting")), latency=await loop.run_in_executor(None, probe) or 0)
    return True


async def monitor(proc):
    loop = asyncio.get_running_loop()
    fails, tick = 0, 0
    while True:
        try:
            await asyncio.wait_for(rotate_ev.wait(), 5)
            return "换 IP / 策略变更"
        except asyncio.TimeoutError:
            pass
        if proc.returncode is not None:
            return "openvpn 已退出"
        tick += 1
        if tick % 3 == 0:
            ms = await loop.run_in_executor(None, probe)
            if ms is None:
                fails += 1
                if fails >= 2:
                    return "探测连续失败"
            else:
                fails, S["latency"] = 0, ms


def route_key(c):
    """路由排序：已扫描确认的住宅 IP 永远排在前面，再按模式排。
    country = 评分优先（默认）  latency = 实测延迟最低  speed = VPNGate 测速最高"""
    lat = SCAN["res"].get(c["ip"])
    known = lat is not None
    lat_v = lat if known else 99999 + c["ping"]
    if S["mode"] == "speed":
        return (c["cc"] not in S["prefer"], not known, -c["speed"], lat_v, -c["score"])
    if S["mode"] == "latency":
        return (c["cc"] not in S["prefer"], not known, lat_v, -c["speed"], -c["score"])
    return (c["cc"] not in S["prefer"], not known, -c["score"], lat_v, c["ping"])


async def tunnel_loop():
    black, cache, cache_t = set(), [], 0
    while True:
        S["status"] = "connecting"
        want = S["country"]
        try:
            if not cache or time.time() - cache_t > 600:
                cache = await asyncio.get_running_loop().run_in_executor(None, fetch_vpngate)
                cache_t = time.time()
                log(f"VPNGate 节点列表 {len(cache)} 条")
        except Exception as e:
            log(f"拉取 VPNGate 失败: {e}")
            await asyncio.sleep(30)
            continue
        pin = S["pin"]
        if S["want_ip"]:  # 定时择优：最优 IP 与上一条线路都放回候选
            black.discard(S["want_ip"])
            black.discard(S["last_ip"])
        if not pin:
            log(f"路由模式: {ROUTE_NAMES[S['mode']]}，目标 {'全球' if want == 'ANY' else want}"
                + (f"，优先 {','.join(sorted(S['prefer']))}" if S["prefer"] else "")
                + (f"，排除 {','.join(sorted(S['exclude']))}" if S["exclude"] else ""))
        if pin:
            cands = [c for c in cache if c["ip"] == pin]
            if not cands and time.time() - cache_t > 60:
                cache_t = 0  # 列表可能过期，刷新一次再判断
                continue
        else:
            cands = [c for c in cache if (want == "ANY" or c["cc"] == want) and c["ip"] not in black
                     and c["cc"] not in S["exclude"]]
        if not pin and not ALLOW_HOSTING:
            cands = [c for c in cands if c["ip"] not in SCAN["bad"]]  # 扫描已确认是机房 IP，不浪费建链时间
        cands.sort(key=route_key)
        if S["want_ip"] and not pin:
            first = [c for c in cands if c["ip"] == S["want_ip"]]
            if first:
                cands = first + [c for c in cands if c["ip"] != S["want_ip"]]
        S["want_ip"] = ""
        if pin and not cands:
            log(f"固定的 {pin} 已不在 VPNGate 列表，恢复自动选择")
            S["pin_fail"], S["pin"] = pin, ""
            continue
        alive = await asyncio.gather(*(tcp_alive(c) for c in cands[:40]))
        cands = [c for c, ok in zip(cands[:40], alive) if ok]
        if pin and not cands:
            log(f"固定的 {pin} 无法连通，恢复自动选择")
            S["pin_fail"], S["pin"] = pin, ""
            continue
        if not cands:
            log(f"{want} 暂无可用候选，30 秒后重试")
            black.clear()
            cache_t = 0
            await asyncio.sleep(30)
            continue
        connected = False
        for c in cands:
            if S["country"] != want or S["pin"] != pin:
                break
            log(f"尝试 {c['ip']} ({c['cc']}, {c['proto']}/{c['port']})")
            proc = None
            try:
                proc, ok = await start_vpn(c)
                if ok and await verify(c):
                    S["status"] = "up"
                    S["cur"], S["last_ip"] = c, c["ip"]
                    connected = True
                    log(f"隧道就绪: 出口 {S['exit_ip']} {S['cc']} {S['isp']} {S['latency']}ms")
                    reason = await monitor(proc)
                    log(f"隧道结束: {reason}")
                    rotate_ev.clear()
            finally:
                await stop_vpn(proc)
                S["cur"] = None
            black.add(c["ip"])
            S["status"] = "connecting"
            if pin and S["pin"] == pin and not connected:
                log(f"固定的 {pin} 连接 / 质检失败，恢复自动选择")
                S["pin_fail"], S["pin"] = pin, ""
                break



# ---------------------------------------------------------------- 系统诊断
def _run(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr)
    except Exception as e:
        return -1, str(e)


def _timed(fn):
    t = time.time()
    try:
        return True, fn(), int((time.time() - t) * 1000)
    except Exception as e:
        return False, str(e), int((time.time() - t) * 1000)


def diag_local():
    out = []

    def add(i, name, st, detail="", ms=None):
        out.append(dict(id=i, name=name, status=st, detail=str(detail)[:200], ms=ms))

    root = hasattr(os, "geteuid") and os.geteuid() == 0
    add("root", "运行身份", "ok" if root else "fail", "root" if root else "需要 root（SO_BINDTODEVICE / ip rule）")
    tun = os.path.exists("/dev/net/tun") and os.access("/dev/net/tun", os.R_OK | os.W_OK)
    add("tun", "TUN/TAP 设备", "ok" if tun else "fail", "/dev/net/tun 可用" if tun else "缺少 /dev/net/tun，请在 VPS 控制台开启 TUN/TAP")
    py = sys.version_info
    add("python", "Python 版本", "ok" if py >= (3, 9) else "fail", f"{py.major}.{py.minor}.{py.micro}")
    for tool in ("openvpn", "ip", "ping"):
        path = shutil.which(tool)
        add("bin_" + tool, f"命令 {tool}", "ok" if path else ("warn" if tool == "ping" else "fail"),
            path or ("未安装" + ("，UDP 节点将无法实测延迟" if tool == "ping" else "")))
    if shutil.which("openvpn"):
        rc, o = _run(["openvpn", "--version"])
        m = re.search(r"OpenVPN (\d+)\.(\d+)", o)
        if m:
            ok = (int(m.group(1)), int(m.group(2))) >= (2, 5)
            add("ovpn_ver", "OpenVPN 版本", "ok" if ok else "fail", f"{m.group(1)}.{m.group(2)}" + ("" if ok else "，需要 >= 2.5"))
    try:
        load = os.getloadavg()[0]
        cpus = os.cpu_count() or 1
        add("load", "系统负载", "ok" if load < cpus * 1.5 else "warn", f"1 分钟负载 {load:.2f}（{cpus} 核）")
    except Exception:
        pass
    try:
        mem = {k: int(v.split()[0]) for k, v in (l.split(":", 1) for l in open("/proc/meminfo"))}
        avail = mem.get("MemAvailable", 0) // 1024
        add("mem", "可用内存", "ok" if avail > 100 else "warn", f"{avail} MB 可用 / {mem.get('MemTotal', 0) // 1024} MB")
    except Exception:
        pass
    try:
        free = shutil.disk_usage(WORKDIR if os.path.isdir(WORKDIR) else "/").free // (1024 * 1024)
        add("disk", "磁盘空间", "ok" if free > 200 else "warn", f"{free} MB 可用")
    except Exception:
        pass
    skew = abs(S["skew"]) / 1000
    add("clock", "系统时钟", "ok" if skew < 60 else ("warn" if skew < 300 else "fail"),
        f"与面板相差 {skew:.0f} 秒" + ("" if skew < 60 else "（时间偏差会导致证书 / 握手失败，请校时）"))
    add("hub", "面板连通", "ok" if 0 < S["hub_rtt"] < 2000 else "warn", f"心跳往返 {S['hub_rtt']} ms", S["hub_rtt"])
    return out


def diag_net():
    out = []

    def add(i, name, ok, detail, ms, warn=False):
        out.append(dict(id=i, name=name, status="ok" if ok else ("warn" if warn else "fail"), detail=str(detail)[:200], ms=ms))

    ok, v, ms = _timed(lambda: socket.getaddrinfo("www.vpngate.net", 80)[0][4][0])
    add("dns", "系统 DNS 解析", ok, v if ok else "解析 www.vpngate.net 失败：" + v, ms)

    def vg():
        req = urllib.request.Request(VPNGATE_API, headers={"User-Agent": "Mozilla/5.0"})
        d = urllib.request.urlopen(req, timeout=12).read(4096)
        if not d:
            raise OSError("空响应")
        return f"收到 {len(d)}B 起始数据"
    ok, v, ms = _timed(vg)
    add("vpngate", "VPNGate API", ok, v, ms)

    def ia():
        d = json.loads(urllib.request.urlopen("http://ip-api.com/json/?fields=status,query,country", timeout=8).read())
        if d.get("status") != "success":
            raise OSError("返回失败")
        return f"{d.get('query')} {d.get('country', '')}"
    ok, v, ms = _timed(ia)
    add("ipapi", "ip-api 质检接口", ok, v, ms)

    ok, v, ms = _timed(lambda: get_public_ip() or (_ for _ in ()).throw(OSError("无法获取")))
    add("pubip", "VPS 公网 IP", ok, v, ms)
    return out


async def proxy_selftest():
    """用本机凭据走一遍完整 SOCKS5 流程：握手 -> 认证 -> 经隧道访问外网，返回看到的出口 IP。"""
    if not S["user"] or not S["pw"]:
        raise OSError("未配置代理凭据")
    r, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", S["port"]), 5)
    try:
        w.write(b"\x05\x01\x02")
        if await asyncio.wait_for(r.readexactly(2), 5) != b"\x05\x02":
            raise OSError("SOCKS5 握手被拒绝")
        u, pw = S["user"].encode(), S["pw"].encode()
        w.write(b"\x01" + bytes([len(u)]) + u + bytes([len(pw)]) + pw)
        if await asyncio.wait_for(r.readexactly(2), 5) != b"\x01\x00":
            raise OSError("认证失败")
        host = b"api.ipify.org"
        w.write(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", 80))
        rep = await asyncio.wait_for(r.readexactly(10), 15)
        if rep[1] != 0:
            raise OSError(f"隧道连接失败（SOCKS 应答码 {rep[1]}）")
        w.write(b"GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n")
        await w.drain()
        data = await asyncio.wait_for(r.read(4096), 10)
        return data.split(b"\r\n\r\n")[-1].strip().decode("ascii", "ignore")
    finally:
        w.close()


async def diag_once():
    loop = asyncio.get_running_loop()
    DIAG["running"] = True
    log("开始系统诊断")
    try:
        items = await loop.run_in_executor(None, diag_local)
        items += await loop.run_in_executor(None, diag_net)

        def add(i, name, st, detail="", ms=None):
            items.append(dict(id=i, name=name, status=st, detail=str(detail)[:200], ms=ms))

        up = S["status"] == "up"
        add("tunnel", "隧道状态", "ok" if up else ("warn" if S["status"] == "connecting" else "fail"),
            f"{S['exit_ip']} {S['cc']} {S['isp']}".strip() if up else f"当前状态：{S['status']}")
        if up:
            ms = await loop.run_in_executor(None, probe)
            add("tun_probe", "隧道出站 (1.1.1.1:443)", "ok" if ms is not None else "fail",
                "连通" if ms is not None else "经隧道无法出站", ms)
            ok, v, ms2 = await loop.run_in_executor(None, _timed, lambda: tun_resolve("example.com"))
            add("tun_dns", "隧道内 DNS", "ok" if ok else "fail", v, ms2)
            rc, o = await loop.run_in_executor(None, _run, ["ip", "rule", "show"])
            has = DEV in o
            add("route", "策略路由", "ok" if has else "fail", f"ip rule 含 {DEV}" if has else "缺少 oif tun_rp 的策略路由")
        add("route_mode", "路由模式", "ok", f"{ROUTE_NAMES[S['mode']]}，目标 {S['country']}" + (f"，已固定 {S['pin']}" if S["pin"] else ""))
        add("scan", "住宅 IP 扫描", "ok" if SCAN["ts"] else "warn",
            f"{len(SCAN['res'])} 个住宅 IP，{int((time.time() * 1000 - SCAN['ts']) / 60000)} 分钟前" if SCAN["ts"] else "尚未完成首次扫描")

        if not S["proxy_on"]:
            add("proxy", "代理服务", "warn", "已在面板停用")
        else:
            ok, v, ms = await loop.run_in_executor(None, _timed, lambda: socket.create_connection(("127.0.0.1", S["port"]), 3).close())
            add("proxy", "代理监听", "ok" if ok else "fail", f"127.0.0.1:{S['port']} 可连接" if ok else f"本机无法连接 :{S['port']}", ms)
            add("proxy_auth", "代理凭据", "ok" if S["user"] and S["pw"] else "fail",
                "已配置" if S["user"] and S["pw"] else "PROXY_USER / PROXY_PASS 未配置，所有连接都会被拒绝")
            if ok and up:
                t = time.time()
                try:
                    ip = await proxy_selftest()
                    same = ip == S["exit_ip"]
                    add("proxy_e2e", "代理端到端自测", "ok", f"经代理看到出口 {ip}" + ("（与质检一致）" if same else "（与质检出口不同，可能是多出口节点）"),
                        int((time.time() - t) * 1000))
                except Exception as e:
                    add("proxy_e2e", "代理端到端自测", "fail", str(e) or type(e).__name__, int((time.time() - t) * 1000))
        add("conns", "连接数", "warn" if PROXY["active"] >= S["max_conns"] * 0.9 else "ok",
            f"当前 {PROXY['active']} / 上限 {S['max_conns']}，累计 {PROXY['total']}，拒绝 {PROXY['rejected']}")

        DIAG["ts"] = int(time.time() * 1000)
        await loop.run_in_executor(None, hub_post, "/api/agent/diag", dict(node_id=NODE_ID, items=items))
        bad = sum(1 for x in items if x["status"] == "fail")
        warn = sum(1 for x in items if x["status"] == "warn")
        log(f"诊断完成：{len(items)} 项，失败 {bad}，警告 {warn}")
    finally:
        DIAG["running"] = False


async def diag_loop():
    await asyncio.sleep(20)  # 启动后自动跑一次
    while True:
        diag_ev.clear()
        try:
            await diag_once()
        except Exception as e:
            log(f"诊断失败: {e}")
        await diag_ev.wait()


# ---------------------------------------------------------------- proxy server (SOCKS5 + HTTP, 同端口)
def auth_ok(user, pw):
    if not S["user"] or not S["pw"]:
        return False  # 未配置凭据一律拒绝，避免变成开放代理
    a = hmac.compare_digest(user.encode(), S["user"].encode())
    b = hmac.compare_digest(pw.encode(), S["pw"].encode())
    return a and b


async def open_out(host, port):
    if S["status"] != "up":
        raise OSError("tunnel down")
    loop = asyncio.get_running_loop()
    ip = await loop.run_in_executor(None, tun_resolve, host)
    a = ipaddress.ip_address(ip)
    if a.version != 4 or not a.is_global:
        raise OSError("blocked address")
    s = tun_sock()
    s.setblocking(False)
    try:
        await asyncio.wait_for(loop.sock_connect(s, (ip, port)), 15)
    except BaseException:
        s.close()
        raise
    return await asyncio.open_connection(sock=s)


def proxy_stats():
    return dict(on=S["proxy_on"], listening=PROXY["listening"], port=S["port"], active=PROXY["active"],
                total=PROXY["total"], rejected=PROXY["rejected"], up=PROXY["up"], down=PROXY["down"],
                since=PROXY["since"], max=S["max_conns"])


async def pipe(r, w, key=None):
    try:
        while True:
            d = await asyncio.wait_for(r.read(65536), 300)
            if not d:
                break
            if key:
                PROXY[key] += len(d)
            w.write(d)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def relay(cr, cw, rr, rw):
    await asyncio.gather(pipe(cr, rw, "up"), pipe(rr, cw, "down"))


async def socks5(cr, cw):
    n = (await cr.readexactly(1))[0]
    methods = await cr.readexactly(n)
    if 2 not in methods:
        cw.write(b"\x05\xff")
        return
    cw.write(b"\x05\x02")
    await cr.readexactly(1)
    user = await cr.readexactly((await cr.readexactly(1))[0])
    pw = await cr.readexactly((await cr.readexactly(1))[0])
    if not auth_ok(user.decode("utf-8", "ignore"), pw.decode("utf-8", "ignore")):
        cw.write(b"\x01\x01")
        return
    cw.write(b"\x01\x00")
    _ver, cmd, _rsv, atyp = await cr.readexactly(4)
    if cmd != 1:
        cw.write(b"\x05\x07\x00\x01\0\0\0\0\0\0")
        return
    if atyp == 1:
        host = socket.inet_ntoa(await cr.readexactly(4))
    elif atyp == 3:
        host = (await cr.readexactly((await cr.readexactly(1))[0])).decode("utf-8", "ignore")
    else:
        cw.write(b"\x05\x08\x00\x01\0\0\0\0\0\0")
        return
    port = struct.unpack("!H", await cr.readexactly(2))[0]
    try:
        rr, rw = await open_out(host, port)
    except Exception:
        cw.write(b"\x05\x04\x00\x01\0\0\0\0\0\0")
        return
    cw.write(b"\x05\x00\x00\x01\0\0\0\0\0\0")
    await cw.drain()
    await relay(cr, cw, rr, rw)


async def http_proxy(first, cr, cw):
    head = first + await asyncio.wait_for(cr.readuntil(b"\r\n\r\n"), 10)
    lines = head.split(b"\r\n")
    method, target, ver = lines[0].decode("latin1").split(" ", 2)
    hdrs, auth = [], ""
    for l in lines[1:]:
        if not l:
            continue
        k, _, v = l.decode("latin1").partition(":")
        kl = k.strip().lower()
        if kl == "proxy-authorization":
            auth = v.strip()
        elif kl not in ("proxy-connection", "connection"):
            hdrs.append((k.strip(), v.strip()))
    ok = False
    if auth.lower().startswith("basic "):
        try:
            u, _, p = base64.b64decode(auth[6:]).decode("utf-8", "ignore").partition(":")
            ok = auth_ok(u, p)
        except Exception:
            pass
    if not ok:
        cw.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="proxy"\r\n'
                 b"Content-Length: 0\r\nConnection: close\r\n\r\n")
        return
    try:
        if method == "CONNECT":
            host, _, port = target.rpartition(":")
            rr, rw = await open_out(host.strip("[]"), int(port))
            cw.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        else:
            u = urlsplit(target)
            rr, rw = await open_out(u.hostname, u.port or 80)
            path = (u.path or "/") + ("?" + u.query if u.query else "")
            out = f"{method} {path} {ver}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs) + "Connection: close\r\n\r\n"
            rw.write(out.encode("latin1"))
    except Exception:
        cw.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        return
    await relay(cr, cw, rr, rw)


async def handle(cr, cw):
    if PROXY["active"] >= S["max_conns"]:
        PROXY["rejected"] += 1
        try:
            cw.close()
        except Exception:
            pass
        return
    PROXY["active"] += 1
    PROXY["total"] += 1
    try:
        first = await asyncio.wait_for(cr.readexactly(1), 10)
        if first == b"\x05":
            await socks5(cr, cw)
        else:
            await http_proxy(first, cr, cw)
    except Exception:
        pass
    finally:
        PROXY["active"] -= 1
        try:
            cw.close()
        except Exception:
            pass


async def proxy_supervisor():
    while True:
        port_ev.clear()
        PROXY["listening"] = False
        if not S["proxy_on"]:
            await port_ev.wait()
            continue
        port = S["port"]
        try:
            srv = await asyncio.start_server(handle, "0.0.0.0", port)
        except OSError as e:
            log(f"监听 :{port} 失败: {e}")
            await asyncio.sleep(10)
            continue
        PROXY["listening"], PROXY["since"] = True, int(time.time() * 1000)
        log(f"代理监听 :{port}（SOCKS5 / HTTP，需认证）")
        await port_ev.wait()
        srv.close()
        PROXY["listening"] = False


async def main():
    global rotate_ev, port_ev, scan_ev, diag_ev
    rotate_ev, port_ev, scan_ev, diag_ev = asyncio.Event(), asyncio.Event(), asyncio.Event(), asyncio.Event()
    os.makedirs(WORKDIR, exist_ok=True)
    await cleanup_routes()
    asyncio.create_task(heartbeat_loop())
    while not S["ready"]:
        await asyncio.sleep(1)
    await asyncio.gather(proxy_supervisor(), tunnel_loop(), scan_loop(), diag_loop())


if __name__ == "__main__":
    asyncio.run(main())
