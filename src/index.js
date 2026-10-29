import { AGENT_PY, INSTALL_SH, UNINSTALL_SH, PANEL_HTML } from "./assets.js";

const ONLINE_MS = 90_000; // 心跳 30 秒，容忍丢 2 次
const LOG_KEEP_MS = 3 * 24 * 3600 * 1000; // 日志只保留 3 天
const VERSION = "1.3.0";
const MODES = ["country", "latency", "speed"];
const enc = new TextEncoder();

// ---------- helpers ----------
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

const text = (body, status = 200, type = "text/plain; charset=utf-8") =>
  new Response(body, { status, headers: { "content-type": type, "cache-control": "no-store" } });

const parseCCs = (v) => {
  const arr = Array.isArray(v) ? v : String(v ?? "").split(",");
  return [...new Set(arr.map((x) => String(x).trim().toUpperCase()).filter((x) => /^[A-Z]{2}$/.test(x)))].slice(0, 100);
};
const clip = (v, n) => String(v ?? "").slice(0, n);
const toInt = (v, d = 0) => (Number.isFinite(Number(v)) ? Math.trunc(Number(v)) : d);

async function safeEq(a, b) {
  const [x, y] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const u = new Uint8Array(x), v = new Uint8Array(y);
  let d = 0;
  for (let i = 0; i < u.length; i++) d |= u[i] ^ v[i];
  return d === 0;
}

// 面板登录：必须显式配置，没有弱口令默认值
async function webAuth(req, env) {
  if (!env.WEB_USER || !env.WEB_PASS) return "unset";
  const h = req.headers.get("Authorization") || "";
  if (!h.startsWith("Basic ")) return false;
  let dec;
  try { dec = atob(h.slice(6)); } catch { return false; }
  const i = dec.indexOf(":");
  if (i < 0) return false;
  const okU = await safeEq(dec.slice(0, i), env.WEB_USER);
  const okP = await safeEq(dec.slice(i + 1), env.WEB_PASS);
  return okU && okP;
}

async function agentAuth(req, env) {
  if (!env.AGENT_TOKEN) return false;
  const h = req.headers.get("Authorization") || "";
  if (!h.startsWith("Bearer ")) return false;
  return safeEq(h.slice(7), env.AGENT_TOKEN);
}

// ---------- D1 ----------
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
let initP = null;
function init(db) {
  return (initP ??= doInit(db).catch((e) => { initP = null; throw e; }));
}
async function doInit(db) {
  await db.batch([
    db.prepare(
      "CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, status TEXT, exit_ip TEXT, country TEXT, isp TEXT, hosting INTEGER DEFAULT 0, latency INTEGER DEFAULT 0, host TEXT, port INTEGER, rotate_nonce INTEGER DEFAULT 0, last_seen INTEGER)"
    ),
    db.prepare("CREATE TABLE IF NOT EXISTS policy (k TEXT PRIMARY KEY, v TEXT)"),
    db.prepare(
      "CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, node_id TEXT, ts INTEGER, line TEXT)"
    ),
    db.prepare(
      `CREATE TABLE IF NOT EXISTS scan_ips (
        node_id TEXT, ip TEXT, host TEXT, port INTEGER, proto TEXT,
        cc TEXT, country TEXT, region TEXT, city TEXT, isp TEXT, org TEXT,
        hosting INTEGER, proxy INTEGER, mobile INTEGER, residential INTEGER,
        latency INTEGER, method TEXT, score INTEGER, scan_id INTEGER, scanned_at INTEGER,
        PRIMARY KEY (node_id, ip))`
    ),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_scan_cc ON scan_ips (cc, residential)"),
    db.prepare("CREATE TABLE IF NOT EXISTS diag (node_id TEXT PRIMARY KEY, ts INTEGER, items TEXT)"),
  ]);
  // 老版本数据库补列（失败不影响主流程）
  await addCols(db, "nodes", [
    ["scan_nonce", "INTEGER DEFAULT 0"], ["scan_state", "TEXT"], ["scan_at", "INTEGER DEFAULT 0"],
    ["pin_ip", "TEXT"], ["diag_nonce", "INTEGER DEFAULT 0"], ["proxy_stats", "TEXT"], ["alias", "TEXT"],
  ]);
  await addCols(db, "scan_ips", [["speed", "INTEGER DEFAULT 0"], ["sessions", "INTEGER DEFAULT 0"], ["users", "INTEGER DEFAULT 0"], ["uptime", "INTEGER DEFAULT 0"]]);
}
async function addCols(db, table, list) {
  const cols = ((await db.prepare(`PRAGMA table_info(${table})`).all()).results || []).map((c) => c.name);
  for (const [n, t] of list)
    if (!cols.includes(n)) { try { await db.prepare(`ALTER TABLE ${table} ADD COLUMN ${n} ${t}`).run(); } catch {} }
}
async function getPolicy(db) {
  const rows = (await db.prepare("SELECT k, v FROM policy").all()).results || [];
  const p = { country: "US", port: "7920", mode: "country", proxy_enabled: "1", max_conns: "500", exclude: "", prefer: "", auto_best: "1" };
  for (const r of rows) p[r.k] = r.v;
  return {
    country: p.country,
    port: toInt(p.port, 7920),
    mode: MODES.includes(p.mode) ? p.mode : "country",
    proxy_enabled: p.proxy_enabled !== "0",
    max_conns: Math.min(Math.max(toInt(p.max_conns, 500), 1), 5000),
    auto_best: p.auto_best !== "0",
    exclude: parseCCs(p.exclude),
    prefer: parseCCs(p.prefer).filter((c) => !parseCCs(p.exclude).includes(c)),
  };
}

// ---------- handlers ----------
async function heartbeat(req, env) {
  let b;
  try { b = await req.json(); } catch { return json({ error: "bad json" }, 400); }
  const id = clip(b.node_id, 64);
  if (!/^[\w.-]+$/.test(id)) return json({ error: "bad node_id" }, 400);

  const now = Date.now();
  const host = /^\d{1,3}(\.\d{1,3}){3}$/.test(b.public_ip || "")
  ? b.public_ip
  : req.headers.get("CF-Connecting-IP") || "";
  const db = env.DB;

  const base = [
    id, clip(b.status, 20), clip(b.exit_ip, 64), clip(b.country, 8), clip(b.isp, 120),
    b.hosting ? 1 : 0, toInt(b.latency), host, toInt(b.port), now,
  ];
  try {
  await db
    .prepare(
      `INSERT INTO nodes (id,status,exit_ip,country,isp,hosting,latency,host,port,last_seen,scan_state,scan_at)
       VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
       ON CONFLICT(id) DO UPDATE SET status=?2,exit_ip=?3,country=?4,isp=?5,hosting=?6,latency=?7,host=?8,port=?9,last_seen=?10,scan_state=?11,scan_at=?12`
    )
    .bind(
      id, clip(b.status, 20), clip(b.exit_ip, 64), clip(b.country, 8), clip(b.isp, 120),
      b.hosting ? 1 : 0, toInt(b.latency), host, toInt(b.port), now,
      clip(b.scan_state, 12), toInt(b.scan_at)
    )
    .run();
  } catch {
    // 新列不可用时退回旧写法：节点状态和日志必须照常上报
    await db
      .prepare(
        `INSERT INTO nodes (id,status,exit_ip,country,isp,hosting,latency,host,port,last_seen)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
         ON CONFLICT(id) DO UPDATE SET status=?2,exit_ip=?3,country=?4,isp=?5,hosting=?6,latency=?7,host=?8,port=?9,last_seen=?10`
      )
      .bind(...base)
      .run();
  }

  if (b.proxy && typeof b.proxy === "object") {
    try { await db.prepare("UPDATE nodes SET proxy_stats=?2 WHERE id=?1").bind(id, clip(JSON.stringify(b.proxy), 600)).run(); } catch {}
  }

  const lines = Array.isArray(b.logs) ? b.logs.slice(0, 20) : [];
  if (lines.length) {
    await db.batch(
      lines.map((l) =>
        db.prepare("INSERT INTO logs (node_id, ts, line) VALUES (?1,?2,?3)").bind(id, now, clip(l, 300))
      )
    );
    await db.prepare("DELETE FROM logs WHERE ts < ?1").bind(now - LOG_KEEP_MS).run();
  }

  const pinFail = clip(b.pin_fail, 45);
  if (pinFail) {
    try { await db.prepare("UPDATE nodes SET pin_ip=NULL WHERE id=?1 AND pin_ip=?2").bind(id, pinFail).run(); } catch {}
  }
  const node = await db.prepare("SELECT * FROM nodes WHERE id=?1").bind(id).first();
  const policy = await getPolicy(db);
  return json({
    policy: {
      country: policy.mode === "country" ? policy.country : "ANY", // 延迟 / 速度优先不限定国家
      exclude: policy.exclude,
      prefer: policy.prefer,
      auto_best: policy.auto_best,
      port: policy.port,
      mode: policy.mode,
      proxy_enabled: policy.proxy_enabled,
      max_conns: policy.max_conns,
      proxy_user: env.PROXY_USER || "",
      proxy_pass: env.PROXY_PASS || "",
    },
    rotate_nonce: node?.rotate_nonce ?? 0,
    scan_nonce: node?.scan_nonce ?? 0,
    diag_nonce: node?.diag_nonce ?? 0,
    pin_ip: node?.pin_ip || "",
    now,
  });
}

// ---------- 住宅 IP 扫描 ----------
const bool01 = (v) => (v ? 1 : 0);

async function scanIngest(req, env) {
  let b;
  try { b = await req.json(); } catch { return json({ error: "bad json" }, 400); }
  const id = clip(b.node_id, 64);
  if (!/^[\w.-]+$/.test(id)) return json({ error: "bad node_id" }, 400);
  const db = env.DB;
  const now = Date.now();
  const scanId = toInt(b.scan_id);
  const items = Array.isArray(b.items) ? b.items.slice(0, 100) : [];

  const stmts = [];
  for (const x of items) {
    const ip = clip(x?.ip, 45);
    if (!IPV4.test(ip)) continue;
    stmts.push(
      db.prepare(
        `INSERT INTO scan_ips (node_id,ip,host,port,proto,cc,country,region,city,isp,org,hosting,proxy,mobile,residential,latency,method,score,scan_id,scanned_at,speed,sessions,users,uptime)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24)
         ON CONFLICT(node_id,ip) DO UPDATE SET host=excluded.host,port=excluded.port,proto=excluded.proto,cc=excluded.cc,
           country=excluded.country,region=excluded.region,city=excluded.city,isp=excluded.isp,org=excluded.org,
           hosting=excluded.hosting,proxy=excluded.proxy,mobile=excluded.mobile,residential=excluded.residential,
           latency=excluded.latency,method=excluded.method,score=excluded.score,scan_id=excluded.scan_id,scanned_at=excluded.scanned_at,speed=excluded.speed,sessions=excluded.sessions,users=excluded.users,uptime=excluded.uptime`
      ).bind(
        id, ip, clip(x.host, 80), toInt(x.port), clip(x.proto, 4), clip(x.cc, 4).toUpperCase(),
        clip(x.country, 60), clip(x.region, 60), clip(x.city, 60), clip(x.isp, 120), clip(x.org, 120),
        bool01(x.hosting), bool01(x.proxy), bool01(x.mobile), bool01(x.residential),
        x.latency == null ? null : toInt(x.latency), clip(x.method, 10), toInt(x.score), scanId, now, toInt(x.speed), toInt(x.sessions), toInt(x.users), toInt(x.uptime)
      )
    );
  }
  // 最后一批：清掉本节点上一轮留下、这一轮已不在列表里的 IP
  if (b.last && scanId)
    stmts.push(db.prepare("DELETE FROM scan_ips WHERE node_id=?1 AND scan_id != ?2").bind(id, scanId));
  if (stmts.length) await db.batch(stmts);
  return json({ ok: true, accepted: items.length });
}

async function scanList(req, env) {
  const q = new URL(req.url).searchParams;
  const rows = (await env.DB.prepare("SELECT * FROM scan_ips").all()).results || [];
  const type = q.get("type") || "all"; // all | residential | hosting
  const ccs = (q.get("country") || "").toUpperCase().split(",").filter(Boolean);
  const maxLat = toInt(q.get("max_latency"), 0);
  const onlyReach = q.get("reachable") === "1";

  let items = rows.filter((r) => {
    if (type === "residential" && !r.residential) return false;
    if (type === "hosting" && !r.hosting) return false;
    if (ccs.length && !ccs.includes(r.cc)) return false;
    if (onlyReach && r.latency == null) return false;
    if (maxLat && (r.latency == null || r.latency > maxLat)) return false;
    return true;
  });
  // 延迟升序（不可测的排最后），其次评分降序
  items.sort((a, b) => (a.latency ?? 1e9) - (b.latency ?? 1e9) || b.score - a.score);
  const limit = Math.min(Math.max(toInt(q.get("limit"), 500), 1), 2000);
  items = items.slice(0, limit);

  if (q.get("format") === "text")
    return text(items.filter((r) => r.latency != null).map((r) => `${r.host}:${r.port}`).join("\n") + (items.length ? "\n" : ""));

  const byCc = new Map();
  for (const r of rows) {
    const e = byCc.get(r.cc) || { cc: r.cc, country: r.country, total: 0, residential: 0 };
    e.total++;
    if (r.residential) e.residential++;
    byCc.set(r.cc, e);
  }
  return json({
    updated: rows.reduce((m, r) => Math.max(m, r.scanned_at || 0), 0),
    total: rows.length,
    residential: rows.filter((r) => r.residential).length,
    reachable_residential: rows.filter((r) => r.residential && r.latency != null).length,
    countries: [...byCc.values()].sort((a, b) => b.residential - a.residential),
    items: items.map((r) => ({
      ...r, hosting: !!r.hosting, proxy: !!r.proxy, mobile: !!r.mobile, residential: !!r.residential,
    })),
  });
}

// 路由预览：按当前模式 + 国家，从最近一次扫描里挑出“agent 下一次会优先尝试”的前 N 个
async function routePreview(req, env) {
  const q = new URL(req.url).searchParams;
  const pol = await getPolicy(env.DB);
  const nodeId = clip(q.get("node_id"), 64);
  const target = pol.mode === "country" ? pol.country : "ANY";
  const rows = ((await env.DB.prepare("SELECT * FROM scan_ips").all()).results || []).filter(
    (r) => r.residential && r.latency != null && (!nodeId || r.node_id === nodeId) &&
      (target === "ANY" || r.cc === target) && !pol.exclude.includes(r.cc)
  );
  const pf = (r) => (pol.prefer.includes(r.cc) ? 0 : 1); // 优先国家永远排最前
  const by0 = {
    speed: (a, b) => (b.speed || 0) - (a.speed || 0) || a.latency - b.latency,
    latency: (a, b) => a.latency - b.latency || (b.speed || 0) - (a.speed || 0),
    country: (a, b) => b.score - a.score || a.latency - b.latency,
  }[pol.mode];
  const by = (a, b) => pf(a) - pf(b) || by0(a, b);
  rows.sort(by);
  const limit = Math.min(Math.max(toInt(q.get("limit"), 5), 1), 50);
  return json({ mode: pol.mode, country: target, exclude: pol.exclude, prefer: pol.prefer, total: rows.length, items: rows.slice(0, limit) });
}

async function diagIngest(req, env) {
  const b = await readJson(req);
  if (!b) return json({ error: "bad json" }, 400);
  const id = clip(b.node_id, 64);
  if (!/^[\w.-]+$/.test(id)) return json({ error: "bad node_id" }, 400);
  const items = (Array.isArray(b.items) ? b.items : []).slice(0, 60).map((x) => ({
    id: clip(x?.id, 24), name: clip(x?.name, 40), status: ["ok", "warn", "fail"].includes(x?.status) ? x.status : "warn",
    detail: clip(x?.detail, 200), ms: x?.ms == null ? null : toInt(x.ms),
  }));
  await env.DB.prepare("INSERT INTO diag (node_id,ts,items) VALUES (?1,?2,?3) ON CONFLICT(node_id) DO UPDATE SET ts=?2,items=?3")
    .bind(id, Date.now(), JSON.stringify(items)).run();
  return json({ ok: true });
}

async function diagList(env) {
  const rows = (await env.DB.prepare("SELECT * FROM diag").all()).results || [];
  return json({ nodes: rows.map((r) => ({ node_id: r.node_id, ts: r.ts, items: JSON.parse(r.items || "[]") })) });
}

async function diagRun(req, env) {
  const b = (await readJson(req)) || {};
  if (b.node_id) await env.DB.prepare("UPDATE nodes SET diag_nonce = diag_nonce + 1 WHERE id=?1").bind(clip(b.node_id, 64)).run();
  else await env.DB.prepare("UPDATE nodes SET diag_nonce = diag_nonce + 1").run();
  return json({ ok: true });
}

// 从 Cloudflare 边缘测试代理端口是否对公网开放（排查防火墙 / 安全组）
async function portCheck(req, env) {
  const id = clip(new URL(req.url).searchParams.get("node_id"), 64);
  const n = await env.DB.prepare("SELECT host, port FROM nodes WHERE id=?1").bind(id).first();
  if (!n || !n.host || !n.port) return json({ ok: false, error: "节点没有上报地址 / 端口" });
  let connect;
  try { ({ connect } = await import("cloudflare:sockets")); }
  catch { return json({ ok: false, error: "当前运行环境不支持 TCP 探测", host: n.host, port: n.port }); }
  const t = Date.now();
  let timer;
  try {
    const sock = connect({ hostname: n.host, port: n.port });
    await Promise.race([
      sock.opened,
      new Promise((_, rej) => { timer = setTimeout(() => rej(new Error("连接超时（5 秒）")), 5000); }),
    ]);
    clearTimeout(timer);
    try { await sock.close(); } catch {}
    return json({ ok: true, ms: Date.now() - t, host: n.host, port: n.port });
  } catch (e) {
    clearTimeout(timer);
    return json({ ok: false, error: String(e?.message || e), host: n.host, port: n.port });
  }
}

// 切换：让指定节点改用扫描出的某个 IP（ip 为空 = 取消固定，恢复自动选择）
async function switchIp(req, env) {
  const b = await readJson(req);
  if (!b) return json({ error: "bad json" }, 400);
  const id = clip(b.node_id, 64), ip = clip(b.ip, 45);
  const node = await env.DB.prepare("SELECT id FROM nodes WHERE id=?1").bind(id).first();
  if (!node) return json({ error: "节点不存在" }, 404);
  if (ip) {
    if (!IPV4.test(ip)) return json({ error: "ip 格式错误" }, 400);
    const hit = await env.DB.prepare("SELECT 1 AS x FROM scan_ips WHERE node_id=?1 AND ip=?2").bind(id, ip).first();
    if (!hit) return json({ error: "该 IP 不在此节点的扫描结果里，请先重新扫描" }, 404);
  }
  await env.DB.prepare("UPDATE nodes SET pin_ip=?2 WHERE id=?1").bind(id, ip || null).run();
  return json({ ok: true, pin_ip: ip });
}

async function scanNow(req, env) {
  let b = {};
  try { b = await req.json(); } catch {}
  if (b.node_id) await env.DB.prepare("UPDATE nodes SET scan_nonce = scan_nonce + 1 WHERE id=?1").bind(clip(b.node_id, 64)).run();
  else await env.DB.prepare("UPDATE nodes SET scan_nonce = scan_nonce + 1").run();
  return json({ ok: true });
}

async function state(req, env) {
  const db = env.DB;
  const now = Date.now();
  const nodes = ((await db.prepare("SELECT * FROM nodes ORDER BY last_seen DESC").all()).results || []).map(
    (n) => ({ ...n, online: now - n.last_seen < ONLINE_MS })
  );
  const cutoff = now - LOG_KEEP_MS;
  try { await db.prepare("DELETE FROM logs WHERE ts < ?1").bind(cutoff).run(); } catch {}
  // 最新在前，只取 3 天内
  const logs = (await db.prepare("SELECT node_id, ts, line FROM logs WHERE ts >= ?1 ORDER BY ts DESC, id DESC LIMIT 300").bind(cutoff).all()).results || [];
  const origin = new URL(req.url).origin;
  return json({
    now,
    version: VERSION,
    nodes,
    logs,
    policy: await getPolicy(db),
    install_cmd: `curl -fsSL -H "Authorization: Bearer ${env.AGENT_TOKEN}" ${origin}/install.sh | sudo bash`,
    uninstall_cmd: `curl -fsSL -H "Authorization: Bearer ${env.AGENT_TOKEN}" ${origin}/uninstall.sh | sudo bash`,
    proxy_auth_set: Boolean(env.PROXY_USER && env.PROXY_PASS),
  });
}

async function readJson(req) {
  try { return await req.json(); } catch { return null; }
}

async function setPolicy(req, env) {
  const b = await readJson(req);
  if (!b) return json({ error: "bad json" }, 400);
  const cur = await getPolicy(env.DB);
  const mode0 = String(b.mode || cur.mode);
  const c0 = String(b.country || "").toUpperCase();
  const country = mode0 === "country" || /^([A-Z]{2}|ANY)$/.test(c0) ? (c0 || cur.country) : cur.country;
  const port = toInt(b.port, cur.port);
  const mode = String(b.mode || cur.mode);
  const enabled = b.proxy_enabled === undefined ? cur.proxy_enabled : !(b.proxy_enabled === false || b.proxy_enabled === "0" || b.proxy_enabled === 0);
  const maxc = toInt(b.max_conns, cur.max_conns);
  const autoBest = b.auto_best === undefined ? cur.auto_best : !(b.auto_best === false || b.auto_best === "0" || b.auto_best === 0);
  const exclude = b.exclude === undefined ? cur.exclude : parseCCs(b.exclude);
  const prefer = (b.prefer === undefined ? cur.prefer : parseCCs(b.prefer)).filter((c) => !exclude.includes(c));
  // 只有「指定国家」模式需要目标国家；其它模式不校验、沿用已保存的值
  if (mode === "country" && !/^([A-Z]{2}|ANY)$/.test(country)) return json({ error: "country 需为两位国家代码，或 ANY" }, 400);
  if (port < 1024 || port > 65535) return json({ error: "port 需在 1024-65535" }, 400);
  if (!MODES.includes(mode)) return json({ error: "mode 需为 country / latency / speed" }, 400);
  if (maxc < 1 || maxc > 5000) return json({ error: "最大连接数需在 1-5000" }, 400);
  const up = (k, v) => env.DB.prepare("INSERT INTO policy (k,v) VALUES (?1,?2) ON CONFLICT(k) DO UPDATE SET v=?2").bind(k, v);
  await env.DB.batch([
    up("country", country), up("port", String(port)), up("mode", mode),
    up("proxy_enabled", enabled ? "1" : "0"), up("max_conns", String(maxc)),
    up("exclude", exclude.join(",")), up("prefer", prefer.join(",")), up("auto_best", autoBest ? "1" : "0"),
  ]);
  return json({ ok: true });
}

async function rotate(req, env) {
  const { node_id } = (await readJson(req)) || {};
  await env.DB.prepare("UPDATE nodes SET rotate_nonce = rotate_nonce + 1 WHERE id=?1").bind(clip(node_id, 64)).run();
  return json({ ok: true });
}

async function renameNode(req, env) {
  const b = (await readJson(req)) || {};
  const id = clip(b.node_id, 64), alias = clip(b.alias, 40).trim();
  const hit = await env.DB.prepare("SELECT 1 AS x FROM nodes WHERE id=?1").bind(id).first();
  if (!hit) return json({ error: "节点不存在" }, 404);
  await env.DB.prepare("UPDATE nodes SET alias=?2 WHERE id=?1").bind(id, alias || null).run();
  return json({ ok: true, alias });
}

async function removeNode(req, env) {
  const { node_id } = (await readJson(req)) || {};
  const id = clip(node_id, 64);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM nodes WHERE id=?1").bind(id),
    env.DB.prepare("DELETE FROM scan_ips WHERE node_id=?1").bind(id),
  ]);
  return json({ ok: true });
}

async function proxies(req, env) {
  const url = new URL(req.url);
  const scheme = url.searchParams.get("scheme") === "http" ? "http" : "socks5";
  const now = Date.now();
  const rows = (await env.DB.prepare("SELECT * FROM nodes WHERE status='up'").all()).results || [];
  const list = rows
    .filter((n) => now - n.last_seen < ONLINE_MS && n.host && n.port)
    .map((n) => ({
      node: n.id,
      country: n.country,
      exit_ip: n.exit_ip,
      latency: n.latency,
      url: `${scheme}://${encodeURIComponent(env.PROXY_USER || "")}:${encodeURIComponent(env.PROXY_PASS || "")}@${n.host.includes(":") ? `[${n.host}]` : n.host}:${n.port}`,
    }));
  if (url.searchParams.get("format") === "json") return json(list);
  return text(list.map((x) => x.url).join("\n") + (list.length ? "\n" : ""));
}

// ---------- 壁纸同步（Cloudflare KV） ----------
const BG_MAX = 7_000_000; // 压缩后的 data URL 通常 < 1MB
const bgMeta = async (env) => (await env.KV.get("bg:meta", "json")) || { ts: 0, op: 88, has: false };

async function bgGet(req, env) {
  if (!env.KV) return json({ error: "KV 未绑定" }, 501);
  const since = toInt(new URL(req.url).searchParams.get("since"), 0);
  const m = await bgMeta(env);
  const out = { ts: m.ts || 0, op: m.op || 88 };
  // 客户端已是最新时不再读图片，省 KV 读取与流量
  if (out.ts > since) out.img = m.has ? (await env.KV.get("bg:img")) || "" : "";
  return json(out);
}

async function bgSet(req, env) {
  if (!env.KV) return json({ error: "KV 未绑定" }, 501);
  const b = await readJson(req);
  if (!b) return json({ error: "bad json" }, 400);
  const cur = await bgMeta(env);
  let op = cur.op || 88, has = !!cur.has;
  if (b.op !== undefined) op = Math.min(100, Math.max(40, toInt(b.op, 88)));
  if (b.img !== undefined) {
    const img = String(b.img);
    if (img === "") { await env.KV.delete("bg:img"); has = false; }
    else {
      const okData = /^data:image\/(jpeg|png|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(img);
      const okUrl = img.length <= 2000 && /^https:\/\/\S+$/i.test(img);
      if (!okData && !okUrl) return json({ error: "图片格式不支持（仅 jpeg/png/webp/gif 或 https 链接）" }, 400);
      if (img.length > BG_MAX) return json({ error: "图片过大" }, 413);
      await env.KV.put("bg:img", img);
      has = true;
    }
  }
  const ts = Math.max(Date.now(), (cur.ts || 0) + 1);
  await env.KV.put("bg:meta", JSON.stringify({ ts, op, has }));
  return json({ ok: true, ts, op });
}

// ---------- router ----------
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;

    if (!env.DB) return text("D1 未绑定：请在 wrangler.toml 配置 binding = DB", 500);
    await init(env.DB);

    // agent 通道（Bearer AGENT_TOKEN）
    if (["/api/agent/heartbeat", "/api/agent/scan", "/api/agent/diag"].includes(path) && req.method === "POST") {
      if (!(await agentAuth(req, env))) return json({ error: "unauthorized" }, 401);
      if (path === "/api/agent/scan") return scanIngest(req, env);
      if (path === "/api/agent/diag") return diagIngest(req, env);
      return heartbeat(req, env);
    }
    if (path === "/agent.py" || path === "/install.sh" || path === "/uninstall.sh") {
      if (!(await agentAuth(req, env))) return text("unauthorized", 401);
      if (path === "/agent.py") return text(AGENT_PY);
      if (path === "/uninstall.sh") return text(UNINSTALL_SH);
      return text(INSTALL_SH.replaceAll("__HUB__", url.origin).replaceAll("__TOKEN__", env.AGENT_TOKEN));
    }

    // 面板通道（Basic Auth）
    const auth = await webAuth(req, env);
    if (auth === "unset")
      return text("请先用 wrangler secret put 设置 WEB_USER / WEB_PASS（本项目不提供默认口令）", 503);
    if (!auth)
      return new Response("Unauthorized", {
        status: 401,
        headers: { "WWW-Authenticate": 'Basic realm="resi-proxy-hub", charset="UTF-8"' },
      });

    if (req.method === "POST" && !(req.headers.get("content-type") || "").includes("application/json"))
      return json({ error: "content-type must be application/json" }, 415);

    try {
      if (path === "/" && req.method === "GET")
        return new Response(PANEL_HTML, {
          headers: {
            "content-type": "text/html; charset=utf-8",
            "cache-control": "no-store",
            "content-security-policy":
              "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob: https:; connect-src 'self'; base-uri 'none'; form-action 'none'",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
          },
        });
      if (path === "/api/bg" && req.method === "GET") return await bgGet(req, env);
      if (path === "/api/bg" && req.method === "POST") return await bgSet(req, env);
      if (path === "/api/state" && req.method === "GET") return await state(req, env);
      if (path === "/api/proxies" && req.method === "GET") return await proxies(req, env);
      if (path === "/api/scan" && req.method === "GET") return await scanList(req, env);
      if (path === "/api/scan/now" && req.method === "POST") return await scanNow(req, env);
      if (path === "/api/route/preview" && req.method === "GET") return await routePreview(req, env);
      if (path === "/api/diag" && req.method === "GET") return await diagList(env);
      if (path === "/api/diag/run" && req.method === "POST") return await diagRun(req, env);
      if (path === "/api/diag/port" && req.method === "GET") return await portCheck(req, env);
      if (path === "/api/switch" && req.method === "POST") return await switchIp(req, env);
      if (path === "/api/policy" && req.method === "POST") return await setPolicy(req, env);
      if (path === "/api/rotate" && req.method === "POST") return await rotate(req, env);
      if (path === "/api/nodes/delete" && req.method === "POST") return await removeNode(req, env);
      if (path === "/api/nodes/rename" && req.method === "POST") return await renameNode(req, env);
    } catch (e) {
      return json({ error: String(e?.message || e) }, 500);
    }
    return text("Not found", 404);
  },
};
