/// <reference lib="deno.unstable" />

import { Hono } from 'https://deno.land/x/hono@v3.11.7/mod.ts';
import { cors } from 'https://deno.land/x/hono@v3.11.7/middleware.ts';
import { setCookie, getCookie } from 'https://deno.land/x/hono@v3.11.7/helper.ts';

/* ==================== 类型定义 ==================== */
interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}
interface VPSServer {
  id: string;
  ip: string;
  port: number;
  username: string;
  authType: 'password' | 'key';
  password?: string;
  privateKey?: string;
  donatedBy: string;
  donatedByUsername: string;
  donatedAt: number;
  status: 'active' | 'inactive' | 'failed';
  note?: string;
  adminNote?: string;
  country: string;
  traffic: string;
  expiryDate: string;
  specs: string;
  ipLocation?: string;
  verifyStatus: 'pending' | 'verified' | 'failed';
  verifyCode?: string;
  verifyFilePath?: string;
  sshFingerprint?: string;
  lastVerifyAt?: number;
  verifyErrorMsg?: string;
}
interface User {
  linuxDoId: string;
  username: string;
  avatarUrl?: string;
  isAdmin: boolean;
  createdAt: number;
}
interface Session {
  id: string;
  userId: string;
  username: string;
  avatarUrl?: string;
  isAdmin: boolean;
  expiresAt: number;
}

const kv = await Deno.openKv();

/* ==================== 工具函数 ==================== */
const genId = () => crypto.randomUUID();

async function getIPLocation(ip: string): Promise<string> {
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=country,regionName,city`, {
      signal: AbortSignal.timeout(5000)
    });
    if (res.ok) {
      const d = await res.json();
      const parts = [d.country, d.regionName, d.city].filter(Boolean);
      if (parts.length) return parts.join(', ');
    }
  } catch {}
  return '未知地区';
}

const isIPv4 = (ip: string) =>
  /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && ip.split('.').every(p => +p >= 0 && +p <= 255);
const isIPv6 = (ip: string) =>
  /^(([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}|([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}|([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}|([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})|:((:[0-9a-f]{1,4}){1,7}|:)|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/i
    .test(ip.replace(/^\[|\]$/g, ''));
const isValidIP = (ip: string) => isIPv4(ip) || isIPv6(ip);

async function getAllVPS(): Promise<VPSServer[]> {
  const iter = kv.list<VPSServer>({ prefix: ['vps'] });
  const arr: VPSServer[] = [];
  for await (const e of iter) arr.push(e.value);
  return arr.sort((a, b) => b.donatedAt - a.donatedAt);
}

async function ipDup(ip: string, port: number) {
  return (await getAllVPS()).some(v => v.ip === ip && v.port === port);
}

async function portOK(ip: string, port: number) {
  try {
    const c = await Deno.connect({
      hostname: ip.replace(/^\[|\]$/g, ''),
      port,
      transport: 'tcp'
    });
    c.close();
    return true;
  } catch {
    return false;
  }
}

async function addVPS(server: Omit<VPSServer, 'id'>) {
  const v: VPSServer = { id: genId(), ...server };
  await kv.set(['vps', v.id], v);
  const r = await kv.get<string[]>(['user_donations', v.donatedBy]);
  const list = r.value || [];
  list.push(v.id);
  await kv.set(['user_donations', v.donatedBy], list);
  return v;
}

async function delVPS(id: string) {
  const r = await kv.get<VPSServer>(['vps', id]);
  if (!r.value) return false;
  await kv.delete(['vps', id]);
  const u = await kv.get<string[]>(['user_donations', r.value.donatedBy]);
  if (u.value) await kv.set(['user_donations', r.value.donatedBy], u.value.filter(x => x !== id));
  return true;
}

async function updVPSStatus(id: string, s: VPSServer['status']) {
  const r = await kv.get<VPSServer>(['vps', id]);
  if (!r.value) return false;
  r.value.status = s;
  await kv.set(['vps', id], r.value);
  return true;
}

/** 实际验证：仅做连通性检查（和投喂时一致），并更新 verify/status/时间/错误原因 */
async function verifyAndUpdate(v: VPSServer) {
  let ok = false;
  let err = '';
  try {
    ok = await portOK(v.ip, v.port);
    if (!ok) err = '端口不可达或被防火墙阻断';
  } catch (e: any) {
    err = e?.message || '未知错误';
  }
  v.lastVerifyAt = Date.now();
  if (ok) {
    v.verifyStatus = 'verified';
    v.status = 'active';
    v.verifyErrorMsg = '';
  } else {
    v.verifyStatus = 'failed';
    v.status = 'failed';
    v.verifyErrorMsg = err || '连接失败';
  }
  await kv.set(['vps', v.id], v);
  return { ok, err };
}

/* ==================== 配置 & 会话 ==================== */
const getOAuth = async () => (await kv.get<OAuthConfig>(['config', 'oauth'])).value || null;
const setOAuth = async (c: OAuthConfig) => { await kv.set(['config', 'oauth'], c); };
const getAdminPwd = async () => (await kv.get<string>(['config', 'admin_password'])).value || 'admin123';
const setAdminPwd = async (p: string) => { await kv.set(['config', 'admin_password'], p); };

async function getSession(id: string) {
  const r = await kv.get<Session>(['sessions', id]);
  if (!r.value) return null;
  if (r.value.expiresAt < Date.now()) { await kv.delete(['sessions', id]); return null; }
  return r.value;
}
async function createSession(
  userId: string, username: string, avatarUrl: string | undefined, isAdmin: boolean
) {
  const s: Session = {
    id: genId(),
    userId,
    username,
    avatarUrl,
    isAdmin,
    expiresAt: Date.now() + 7 * 24 * 3600 * 1000
  };
  await kv.set(['sessions', s.id], s);
  return s.id;
}
async function getUser(linuxDoId: string) {
  return (await kv.get<User>(['users', linuxDoId])).value || null;
}
async function upsertUser(linuxDoId: string, username: string, avatarUrl?: string) {
  const old = await getUser(linuxDoId);
  const u: User = {
    linuxDoId, username, avatarUrl,
    isAdmin: old?.isAdmin || false,
    createdAt: old?.createdAt || Date.now()
  };
  await kv.set(['users', linuxDoId], u);
  return u;
}

/* ==================== OAuth（Linux.do） ==================== */
async function tokenByCode(code: string, cfg: OAuthConfig) {
  const res = await fetch('https://connect.linux.do/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      code,
      redirect_uri: cfg.redirectUri,
      grant_type: 'authorization_code'
    })
  });
  return res.json();
}
async function linuxDoUser(accessToken: string) {
  const r = await fetch('https://connect.linux.do/api/user', {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  return r.json();
}

/* ==================== 中间件 ==================== */
const requireAuth = async (c: any, next: any) => {
  const sid = getCookie(c, 'session_id');
  if (!sid) return c.json({ success: false, message: '未登录' }, 401);
  const s = await getSession(sid);
  if (!s) return c.json({ success: false, message: '会话已过期' }, 401);
  c.set('session', s);
  await next();
};
const requireAdmin = async (c: any, next: any) => {
  const sid = getCookie(c, 'admin_session_id');
  if (!sid) return c.json({ success: false, message: '未登录' }, 401);
  const s = await getSession(sid);
  if (!s || !s.isAdmin) return c.json({ success: false, message: '需要管理员权限' }, 403);
  c.set('session', s);
  await next();
};

/* ==================== Hono 应用 ==================== */
const app = new Hono();
app.use('*', cors());

app.get('/', c => c.redirect('/donate'));

/* ---- OAuth 登录 ---- */
app.get('/oauth/login', async c => {
  const redirectPath = c.req.query('redirect') || '/donate/vps';
  const cfg = await getOAuth();
  if (!cfg) {
    return c.html('<!doctype html><body><h1>配置错误</h1><p>OAuth 未设置</p><a href="/donate">返回</a></body>');
  }
  const url = new URL('https://connect.linux.do/oauth2/authorize');
  url.searchParams.set('client_id', cfg.clientId);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('redirect_uri', cfg.redirectUri);
  url.searchParams.set('scope', 'openid profile');
  url.searchParams.set('state', typeof redirectPath === 'string' ? redirectPath : '/donate/vps');
  return c.redirect(url.toString());
});

app.get('/oauth/callback', async c => {
  const code = c.req.query('code');
  const error = c.req.query('error');
  const state = c.req.query('state') || '/donate';
  if (error) return c.html(`<!doctype html><body><h1>登录失败</h1><p>${error}</p><a href="/donate">返回</a></body>`);
  if (!code) return c.text('Missing code', 400);
  try {
    const cfg = await getOAuth();
    if (!cfg) return c.html('<!doctype html><body><h1>配置错误</h1><a href="/donate">返回</a></body>');
    const token = await tokenByCode(code, cfg);
    const info = await linuxDoUser(token.access_token);

    let avatar = info.avatar_template as string | undefined;
    if (avatar) {
      avatar = avatar.replace('{size}', '120');
      if (avatar.startsWith('//')) avatar = 'https:' + avatar;
      else if (avatar.startsWith('/')) avatar = 'https://connect.linux.do' + avatar;
    }

    const user = await upsertUser(String(info.id), info.username, avatar);
    const sid = await createSession(user.linuxDoId, user.username, user.avatarUrl, user.isAdmin);
    const isProd = Deno.env.get('DENO_DEPLOYMENT_ID') !== undefined;
    setCookie(c, 'session_id', sid, {
      maxAge: 7 * 24 * 3600, httpOnly: true, secure: isProd, sameSite: 'Lax', path: '/'
    });
    const redirectTo = typeof state === 'string' && state.startsWith('/') ? state : '/donate';
    return c.redirect(redirectTo);
  } catch (e: any) {
    return c.html(`<!doctype html><body><h1>登录失败</h1><p>${e.message || e}</p><a href="/donate">返回</a></body>`);
  }
});

/* ---- 用户 API ---- */
app.get('/api/logout', async c => {
  const sid = getCookie(c, 'session_id');
  if (sid) await kv.delete(['sessions', sid]);
  setCookie(c, 'session_id', '', { maxAge: 0, path: '/' });
  return c.json({ success: true });
});

app.get('/api/user/info', requireAuth, async c => {
  const s = c.get('session');
  const r = await kv.get<string[]>(['user_donations', s.userId]);
  return c.json({
    success: true,
    data: {
      username: s.username,
      avatarUrl: s.avatarUrl,
      isAdmin: s.isAdmin,
      donationCount: (r.value || []).length
    }
  });
});

app.get('/api/user/donations', requireAuth, async c => {
  const s = c.get('session');
  const ids = (await kv.get<string[]>(['user_donations', s.userId])).value || [];
  const arr: VPSServer[] = [];
  for (const id of ids) {
    const r = await kv.get<VPSServer>(['vps', id]);
    if (r.value) arr.push(r.value);
  }
  const safe = arr.sort((a, b) => b.donatedAt - a.donatedAt).map(d => ({
    id: d.id, ip: d.ip, port: d.port, username: d.username, authType: d.authType,
    donatedAt: d.donatedAt, status: d.status, note: d.note,
    country: d.country, traffic: d.traffic, expiryDate: d.expiryDate, specs: d.specs,
    ipLocation: d.ipLocation, verifyStatus: d.verifyStatus, lastVerifyAt: d.lastVerifyAt,
    verifyErrorMsg: d.verifyErrorMsg, donatedByUsername: d.donatedByUsername
  }));
  return c.json({ success: true, data: safe });
});

app.put('/api/user/donations/:id/note', requireAuth, async c => {
  const s = c.get('session');
  const id = c.req.param('id');
  const { note } = await c.req.json();
  const r = await kv.get<VPSServer>(['vps', id]);
  if (!r.value) return c.json({ success: false, message: 'VPS 不存在' }, 404);
  if (r.value.donatedBy !== s.userId) return c.json({ success: false, message: '无权修改' }, 403);
  r.value.note = (note || '').toString();
  await kv.set(['vps', id], r.value);
  return c.json({ success: true, message: '备注已更新' });
});

/* ---- 公共榜单 API ---- */
app.get('/api/leaderboard', async c => {
  try {
    const all = await getAllVPS();
    const map = new Map<string, { username: string; count: number; servers: any[] }>();
    for (const v of all) {
      const rec = map.get(v.donatedBy) || { username: v.donatedByUsername, count: 0, servers: [] };
      rec.count++;
      rec.servers.push({
        ipLocation: v.ipLocation || '未知地区',
        country: v.country || '未填写',
        traffic: v.traffic || '未填写',
        expiryDate: v.expiryDate || '未填写',
        specs: v.specs || '未填写',
        status: v.status,
        donatedAt: v.donatedAt,
        note: v.note || ''
      });
      map.set(v.donatedBy, rec);
    }
    const leaderboard = Array.from(map.values()).sort((a, b) => b.count - a.count);
    return c.json({ success: true, data: leaderboard });
  } catch (err) {
    console.error('Leaderboard error:', err);
    return c.json({ success: false, message: '加载失败' }, 500);
  }
});

/* ---- 投喂 API ---- */
app.post('/api/donate', requireAuth, async c => {
  const s = c.get('session');
  const body = await c.req.json();
  const {
    ip, port, username, authType, password, privateKey,
    country, traffic, expiryDate, specs, note
  } = body;

  if (!ip || !port || !username || !authType)
    return c.json({ success: false, message: 'IP / 端口 / 用户名 / 认证方式 必填' }, 400);
  if (!country || !traffic || !expiryDate || !specs)
    return c.json({ success: false, message: '国家、流量、到期、配置 必填' }, 400);
  if (authType === 'password' && !password)
    return c.json({ success: false, message: '密码认证需要密码' }, 400);
  if (authType === 'key' && !privateKey)
    return c.json({ success: false, message: '密钥认证需要私钥' }, 400);
  if (!isValidIP(ip)) return c.json({ success: false, message: 'IP 格式不正确' }, 400);

  const p = parseInt(String(port), 10);
  if (p < 1 || p > 65535) return c.json({ success: false, message: '端口范围 1 ~ 65535' }, 400);
  if (await ipDup(ip, p)) return c.json({ success: false, message: '该 IP:端口 已被投喂' }, 400);
  if (!(await portOK(ip, p)))
    return c.json({ success: false, message: '无法连接到该服务器，请确认 IP / 端口 是否正确、且对外开放' }, 400);

  const ipLoc = await getIPLocation(ip);
  const v = await addVPS({
    ip, port: p, username, authType,
    password: authType === 'password' ? password : undefined,
    privateKey: authType === 'key' ? privateKey : undefined,
    donatedBy: s.userId, donatedByUsername: s.username,
    donatedAt: Date.now(), status: 'active',
    note: note || '', adminNote: '',
    country, traffic, expiryDate, specs,
    ipLocation: ipLoc, verifyStatus: 'verified', lastVerifyAt: Date.now()
  });

  return c.json({
    success: true,
    message: '✅ 投喂成功，已通过连通性验证，感谢支持！',
    data: { id: v.id, ipLocation: v.ipLocation }
  });
});

/* ---- 管理员 API ---- */
app.get('/api/admin/check-session', async c => {
  try {
    const sid = getCookie(c, 'admin_session_id');
    if (!sid) return c.json({ success: false, isAdmin: false });
    const s = await getSession(sid);
    if (!s) return c.json({ success: false, isAdmin: false });
    return c.json({ success: true, isAdmin: !!s.isAdmin, username: s.username });
  } catch {
    return c.json({ success: false, isAdmin: false });
  }
});

app.post('/api/admin/login', async c => {
  const { password } = await c.req.json();
  const real = await getAdminPwd();
  if (password !== real) return c.json({ success: false, message: '密码错误' }, 401);

  const sid = genId();
  const sess: Session = {
    id: sid, userId: 'admin', username: 'Administrator',
    avatarUrl: undefined, isAdmin: true, expiresAt: Date.now() + 7 * 24 * 3600 * 1000
  };
  await kv.set(['sessions', sid], sess);

  const isProd = Deno.env.get('DENO_DEPLOYMENT_ID') !== undefined;
  setCookie(c, 'admin_session_id', sid, {
    maxAge: 7 * 24 * 3600, httpOnly: true, secure: isProd, sameSite: 'Lax', path: '/'
  });
  return c.json({ success: true, message: '登录成功' });
});

app.get('/api/admin/logout', async c => {
  const sid = getCookie(c, 'admin_session_id');
  if (sid) await kv.delete(['sessions', sid]);
  setCookie(c, 'admin_session_id', '', { maxAge: 0, path: '/' });
  return c.json({ success: true });
});

app.get('/api/admin/vps', requireAdmin, async c => {
  try {
    const data = await getAllVPS();
    return c.json({ success: true, data });
  } catch {
    return c.json({ success: false, message: '加载失败' }, 500);
  }
});

app.delete('/api/admin/vps/:id', requireAdmin, async c => {
  const ok = await delVPS(c.req.param('id'));
  return c.json(ok ? { success: true, message: 'VPS 已删除' } : { success: false, message: '不存在' }, ok ? 200 : 404);
});

app.put('/api/admin/vps/:id/status', requireAdmin, async c => {
  const id = c.req.param('id');
  const { status } = await c.req.json();
  if (!['active', 'inactive', 'failed'].includes(status))
    return c.json({ success: false, message: '无效状态' }, 400);
  const ok = await updVPSStatus(id, status);
  return c.json(ok ? { success: true, message: '状态已更新' } : { success: false, message: '不存在' }, ok ? 200 : 404);
});

app.put('/api/admin/vps/:id/notes', requireAdmin, async c => {
  const id = c.req.param('id');
  const { note, adminNote, country, traffic, expiryDate, specs } = await c.req.json();
  const r = await kv.get<VPSServer>(['vps', id]);
  if (!r.value) return c.json({ success: false, message: '不存在' }, 404);
  if (note !== undefined) r.value.note = String(note);
  if (adminNote !== undefined) r.value.adminNote = String(adminNote);
  if (country !== undefined) r.value.country = String(country);
  if (traffic !== undefined) r.value.traffic = String(traffic);
  if (expiryDate !== undefined) r.value.expiryDate = String(expiryDate);
  if (specs !== undefined) r.value.specs = String(specs);
  await kv.set(['vps', id], r.value);
  return c.json({ success: true, message: '信息已更新' });
});

app.get('/api/admin/config/oauth', requireAdmin, async c => {
  const oauth = await getOAuth();
  return c.json({ success: true, data: oauth || {} });
});
app.put('/api/admin/config/oauth', requireAdmin, async c => {
  const { clientId, clientSecret, redirectUri } = await c.req.json();
  if (!clientId || !clientSecret || !redirectUri)
    return c.json({ success: false, message: '字段必填' }, 400);
  await setOAuth({ clientId, clientSecret, redirectUri });
  return c.json({ success: true, message: 'OAuth 配置已更新' });
});

/** 管理员密码：改为两次输入校验后再保存 */
app.put('/api/admin/config/password', requireAdmin, async c => {
  const { password, confirm } = await c.req.json();
  if (!password || String(password).length < 6)
    return c.json({ success: false, message: '密码至少 6 位' }, 400);
  if (password !== confirm)
    return c.json({ success: false, message: '两次输入的密码不一致' }, 400);
  await setAdminPwd(String(password));
  return c.json({ success: true, message: '管理员密码已更新' });
});

/** 统计（仍然计算全部字段，但前端只展示四项） */
app.get('/api/admin/stats', requireAdmin, async c => {
  try {
    const all = await getAllVPS();
    const today0 = new Date(); today0.setHours(0, 0, 0, 0);
    const userStats = new Map<string, number>();
    for (const v of all) userStats.set(v.donatedByUsername, (userStats.get(v.donatedByUsername) || 0) + 1);
    const top = Array.from(userStats.entries()).map(([username, count]) => ({ username, count }))
      .sort((a, b) => b.count - a.count).slice(0, 10);
    return c.json({
      success: true,
      data: {
        totalVPS: all.length,
        activeVPS: all.filter(v => v.status === 'active').length,
        failedVPS: all.filter(v => v.status === 'failed').length,
        inactiveVPS: all.filter(v => v.status === 'inactive').length,
        pendingVPS: all.filter(v => v.verifyStatus === 'pending').length,
        verifiedVPS: all.filter(v => v.verifyStatus === 'verified').length,
        todayNewVPS: all.filter(v => v.donatedAt >= today0.getTime()).length,
        topDonors: top
      }
    });
  } catch {
    return c.json({ success: false, message: '加载失败' }, 500);
  }
});

/** 单个一键验证 */
app.post('/api/admin/vps/:id/verify', requireAdmin, async c => {
  const id = c.req.param('id');
  const r = await kv.get<VPSServer>(['vps', id]);
  if (!r.value) return c.json({ success: false, message: '不存在' }, 404);
  const { ok, err } = await verifyAndUpdate(r.value);
  return c.json({
    success: true,
    data: { ok, error: ok ? '' : (err || '失败') },
    message: ok ? '验证通过' : `验证失败：${err || '连接失败'}`
  });
});

/** 一键验证全部 */
app.post('/api/admin/verify-all', requireAdmin, async c => {
  const list = await getAllVPS();
  let ok = 0, fail = 0;
  for (const v of list) {
    const res = await verifyAndUpdate(v);
    res.ok ? ok++ : fail++;
  }
  return c.json({
    success: true,
    data: { total: list.length, ok, fail },
    message: `验证完成：通过 ${ok} 台，失败 ${fail} 台`
  });
});

/* ==================== /donate 页与 /donate/vps 页（保持你现有交互） ==================== */
/* —— 省略部分相同段落：与上一版一致 —— */
/* 为保证可直接运行，仍完整提供（已略去与后台需求无关处，功能不变） */

app.get('/donate', c => {
  const head = commonHead('风萧萧公益机场 · VPS 投喂榜');
  const html = `<!doctype html><html lang="zh-CN"><head>${head}</head>
<body class="min-h-screen" data-theme="dark">
<div class="max-w-5xl mx-auto px-4 py-8">
  <header class="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
    <div class="space-y-2">
      <h1 class="grad-title text-2xl md:text-4xl font-bold">风萧萧公益机场 · VPS 投喂榜</h1>
      <p class="mt-1 text-sm sm:text-base muted leading-relaxed">
        这是一个完全非盈利的公益项目，没有运营团队，只有我一个人维护。榜单仅展示「国家 / 区域 + IP 归属地 + 流量 + 到期时间 + 投喂备注」。
      </p>
      <p class="text-xs sm:text-sm text-amber-200 leading-relaxed">
        感谢大家的投喂，🤝 这个机场的发展离不开各位热佬的大力支持！这不是我一个人的功劳，是大家的共同成果！共荣！🚀🤝
      </p>
      <button onclick="gotoDonatePage()" class="mt-3 inline-flex items-center gap-2 rounded-xl bg-cyan-500 px-4 py-2 text-sm font-semibold shadow-lg hover:bg-cyan-400">
        🧡 我要投喂 VPS
      </button>
    </div>
    <div class="flex sm:flex-col items-center sm:items-end gap-2">
      <button id="theme-toggle" class="text-xs" onclick="toggleTheme()">浅色模式</button>
    </div>
  </header>

  <section class="mb-6">
    <h2 class="text-xl font-semibold mb-3 flex items-center gap-2">🏆 捐赠榜单 <span id="leaderboard-count" class="text-sm muted"></span></h2>
    <div id="leaderboard" class="space-y-4"><div class="muted text-sm">正在加载榜单...</div></div>
  </section>

  <footer class="mt-10 border-t border-slate-800 pt-4 text-xs muted">
    <p>说明：本项目仅作公益用途，请勿滥用资源（长时间占满带宽、刷流量、倒卖账号等）。</p>
  </footer>
</div>

<div id="toast-root"></div>
<div id="modal-root"></div>
<script>
updateThemeBtn();

async function gotoDonatePage(){
  try{
    const r = await fetch('/api/user/info',{credentials:'same-origin',cache:'no-store'});
    if(r.ok){
      const j = await r.json();
      if(j.success) location.href='/donate/vps';
      else location.href='/oauth/login?redirect='+encodeURIComponent('/donate/vps');
    }else{
      location.href='/oauth/login?redirect='+encodeURIComponent('/donate/vps');
    }
  }catch{
    location.href='/oauth/login?redirect='+encodeURIComponent('/donate/vps');
  }
}

function statusText(s){ return s==='active'?'运行中':(s==='failed'?'失败':'未启用'); }
function statusCls(s){ return s==='active'?'badge-ok':(s==='failed'?'badge-fail':'badge-idle'); }

async function loadLeaderboard(){
  const box=document.getElementById('leaderboard'), countEl=document.getElementById('leaderboard-count');
  const timeoutPromise=new Promise((_,rej)=>setTimeout(()=>rej(new Error('加载超时')),8000));
  try{
    const res=await Promise.race([fetch('/api/leaderboard',{credentials:'same-origin',cache:'no-store'}),timeoutPromise]);
    if(!res.ok){ box.innerHTML='<div class="text-red-400 text-sm">加载失败</div>'; return; }
    const j=await res.json(); const data=j.data||[];
    countEl.textContent=data.length?(' · 共 '+data.length+' 位投喂者'):'';
    if(!data.length){ box.innerHTML='<div class="muted text-sm">暂时还没有投喂记录</div>'; return; }
    box.innerHTML='';
    data.forEach((it,idx)=>{
      const wrap=document.createElement('div'); wrap.className='card rounded-2xl border p-4 shadow-sm';
      const head=document.createElement('div'); head.className='flex items-center justify-between mb-2 gap-2';
      head.innerHTML='<div class="flex items-center gap-2 flex-1 min-w-0"><span style="font-size:18px">'+medalByRank(idx)+'</span>'+
      '<a class="font-semibold text-sky-300 hover:text-cyan-300 truncate" target="_blank" href="https://linux.do/u/'+encodeURIComponent(it.username)+'">@'+it.username+'</a></div>'+
      '<div class="muted text-xs whitespace-nowrap">共投喂 '+it.count+' 台 VPS</div>';
      wrap.appendChild(head);
      const list=document.createElement('div'); list.className='space-y-2 text-xs';
      (it.servers||[]).forEach(srv=>{
        const d=document.createElement('div'); d.className='rounded-xl border px-3 py-2';
        d.innerHTML='<div class="flex items-center justify-between gap-2">'+
          '<span class="text-slate-100 text-xs truncate">'+(srv.country||'未填写')+(srv.ipLocation?' · '+srv.ipLocation:'')+'</span>'+
          '<span class="'+statusCls(srv.status)+' text-[11px]">'+statusText(srv.status)+'</span></div>'+
          '<div class="flex flex-wrap gap-x-4 gap-y-1 text-[11px] mt-1"><span>流量/带宽：'+(srv.traffic||'未填写')+'</span>'+
          '<span>到期：'+(srv.expiryDate||'未填写')+'</span></div>'+
          (srv.specs?'<div class="text-[11px] muted mt-1 break-words">配置：'+srv.specs+'</div>':'')+
          (srv.note?'<div class="text-[11px] text-amber-300/90 mt-1 break-words">投喂备注：'+srv.note+'</div>':'');
        list.appendChild(d);
      });
      wrap.appendChild(list);
      box.appendChild(wrap);
    });
  }catch(err){ box.innerHTML='<div class="text-red-400 text-sm">'+err.message+'</div>'; }
}
loadLeaderboard();

function medalByRank(i){
  const arr=["👑","🏆","🥇","🥈","🥉","💎","🔥","🌟","✨","⚡","🎖️","🛡️","🎗️","🎯","🚀","🧿","🪙","🧭","🗡️","🦄","🐉","🦅","🦁","🐯","🐺","🐻","🐼","🐧","🐬","🐳","🛰️","🪐","🌙","🌈","🌊","🌋","🏔️","🏰","🧱","⚙️","🔧","🔭","🧪","🧠","🪄","🔮","🎩","🎼","🎷","🎻","🥁","🎹"];
  return arr[i%arr.length];
}
</script>
</body></html>`;
  return c.html(html);
});

/* ==================== /donate/vps 投喂中心（与上一版一致，略） ==================== */
app.get('/donate/vps', c => {
  const head = commonHead('风萧萧公益机场 · VPS 投喂中心');
  const today = new Date();
  const y = today.getFullYear(), m = String(today.getMonth() + 1).padStart(2, '0'), d = String(today.getDate()).padStart(2, '0');
  const minDate = `${y}-${m}-${d}`;
  const nextYear = new Date(today); nextYear.setFullYear(today.getFullYear() + 1);
  const ny = `${nextYear.getFullYear()}-${String(nextYear.getMonth() + 1).padStart(2, '0')}-${String(nextYear.getDate()).padStart(2, '0')}`;

  const html = `<!doctype html><html lang="zh-CN"><head>${head}</head>
<body class="min-h-screen" data-theme="dark">
<div class="max-w-6xl mx-auto px-4 py-8">
  <header class="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
    <div>
      <h1 class="grad-title text-2xl md:text-3xl font-bold">风萧萧公益机场 · VPS 投喂榜</h1>
      <p class="mt-1 text-xs muted">当前：投喂中心（提交新 VPS / 查看我的投喂记录）</p>
    </div>
    <div class="flex items-center gap-3">
      <div id="user-info" class="text-sm"></div>
      <button onclick="logout()" class="text-xs rounded-full border px-3 py-1">退出登录</button>
      <button id="theme-toggle" class="text-xs" onclick="toggleTheme()">浅色模式</button>
    </div>
  </header>

  <main class="grid md:grid-cols-2 gap-6 items-start">
    <!-- 左侧提交表单：与上一版一致，略 -->
    <section class="panel rounded-2xl border p-4 shadow-lg">
      <h2 class="text-lg font-semibold mb-2">🧡 提交新的 VPS 投喂</h2>
      <p class="text-xs muted mb-4 leading-relaxed">请确保服务器是你有控制权的机器，并允许用于公益节点。禁止长时间占满带宽、刷流量、倒卖账号等行为。</p>

      <form id="donate-form" class="space-y-3 text-sm">
        <div class="grid grid-cols-2 gap-3">
          <div><label class="block mb-1 text-xs">服务器 IP（必填）</label>
            <input name="ip" required placeholder="示例：203.0.113.8 或 [2001:db8::1]" class="w-full rounded-lg border px-2 py-1.5 text-xs focus:ring-1 focus:ring-cyan-500" />
            <div class="help">支持 IPv4 / IPv6</div></div>
          <div><label class="block mb-1 text-xs">端口（必填）</label>
            <input name="port" required type="number" min="1" max="65535" placeholder="示例：22 / 443 / 8080" class="w-full rounded-lg border px-2 py-1.5 text-xs focus:ring-1 focus:ring-cyan-500" /></div>
        </div>

        <div class="grid grid-cols-2 gap-3">
          <div><label class="block mb-1 text-xs">系统用户名（必填）</label>
            <input name="username" required placeholder="示例：root / ubuntu" class="w-full rounded-lg border px-2 py-1.5 text-xs focus:ring-1 focus:ring-cyan-500" /></div>
          <div><label class="block mb-1 text-xs">认证方式</label>
            <select name="authType" class="w-full rounded-lg border px-2 py-1.5 text-xs focus:ring-1 focus:ring-cyan-500">
              <option value="password">密码</option><option value="key">SSH 私钥</option>
            </select></div>
        </div>

        <div id="password-field">
          <label class="block mb-1 text-xs">密码（密码登录必填）</label>
          <input name="password" type="password" placeholder="示例：MyStrongP@ssw0rd" class="w-full rounded-lg border px-2 py-1.5 text-xs focus:ring-1 focus:ring-cyan-500" />
        </div>

        <div id="key-field" class="hidden">
          <label class="block mb-1 text-xs">SSH 私钥（密钥登录必填）</label>
          <textarea name="privateKey" rows="4" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" class="w-full rounded-lg border px-2 py-1.5 text-xs focus:ring-1 focus:ring-cyan-500"></textarea>
        </div>

        <div class="grid grid-cols-2 gap-3">
          <div><label class="block mb-1 text-xs">国家 / 区域（必填）</label>
            <input name="country" required placeholder="示例：HK - Hong Kong, Kowloon, Hong Kong" class="w-full rounded-lg border px-2 py-1.5 text-xs focus:ring-1 focus:ring-cyan-500" /></div>
          <div><label class="block mb-1 text-xs">流量 / 带宽（必填）</label>
            <input name="traffic" required placeholder="示例：400G/月 · 上下行 1Gbps" class="w-full rounded-lg border px-2 py-1.5 text-xs focus:ring-1 focus:ring-cyan-500" /></div>
        </div>

        <div class="grid grid-cols-2 gap-3">
          <div><label class="block mb-1 text-xs">到期日期（必填）</label>
            <input name="expiryDate" required type="date" min="${minDate}" value="${ny}" class="w-full rounded-lg border px-2 py-1.5 text-xs focus:ring-1 focus:ring-cyan-500" />
            <div class="help">默认已填为 +1 年（可改）</div></div>
          <div><label class="block mb-1 text-xs">配置描述（必填）</label>
            <input name="specs" required placeholder="示例：1C1G · 10Gbps · 1T 流量" class="w-full rounded-lg border px-2 py-1.5 text-xs focus:ring-1 focus:ring-cyan-500" /></div>
        </div>

        <div>
          <label class="block mb-1 text-xs">投喂备注（可选，**将前台展示**）</label>
          <textarea name="note" rows="2" placeholder="示例：电信到香港方向无法走大陆优选链路，共享带宽，不保证大陆连通性" class="w-full rounded-lg border px-2 py-1.5 text-xs focus:ring-1 focus:ring-cyan-500"></textarea>
        </div>

        <div id="donate-message" class="text-xs mt-1 min-h-[1.5rem]"></div>
        <button id="donate-submit-btn" type="submit" class="mt-1 inline-flex items-center justify-center rounded-xl bg-cyan-500 px-4 py-2 text-xs font-semibold shadow-lg hover:bg-cyan-400">提交投喂</button>
      </form>
    </section>

    <!-- 右侧列表：与上一版一致 -->
    <section class="panel rounded-2xl border p-4 shadow-lg">
      <div class="flex items-center justify-between mb-2">
        <h2 class="text-lg font-semibold">📦 我的投喂记录</h2>
        <button onclick="loadDonations()" class="text-[11px] rounded-full border px-2 py-1">刷新</button>
      </div>
      <div id="donations-list" class="space-y-3 text-xs"><div class="muted text-xs">正在加载...</div></div>
    </section>
  </main>

  <footer class="mt-8 text-[11px] muted border-t pt-3">友情提示：投喂即视为同意将该 VPS 用于公益机场中转节点。请勿提交有敏感业务的生产机器。</footer>
</div>

<div id="toast-root"></div>
<div id="modal-root"></div>
<script>
updateThemeBtn();

async function ensureLogin(){
  try{
    const res=await fetch('/api/user/info',{credentials:'same-origin',cache:'no-store'});
    if(!res.ok){ location.href='/donate'; return; }
    const j=await res.json(); if(!j.success){ location.href='/donate'; return; }
    const u=j.data; const p='https://linux.do/u/'+encodeURIComponent(u.username);
    const infoEl=document.getElementById('user-info');
    if(infoEl) infoEl.innerHTML='投喂者：<a href="'+p+'" target="_blank" class="underline text-sky-300">@'+u.username+'</a> · 已投喂 '+(u.donationCount||0)+' 台';
  }catch{ location.href='/donate'; }
}

async function logout(){ try{await fetch('/api/logout',{credentials:'same-origin'})}catch{} location.href='/donate'; }

function bindAuthType(){
  const sel=document.querySelector('select[name="authType"]');
  const pwd=document.getElementById('password-field'); const key=document.getElementById('key-field');
  if(sel&&pwd&&key){ sel.addEventListener('change',function(){ if(sel.value==='password'){pwd.classList.remove('hidden');key.classList.add('hidden');}else{pwd.classList.add('hidden');key.classList.remove('hidden');} }); }
}

function stxt(s){ return s==='active'?'运行中':(s==='failed'?'失败':'未启用'); }
function scls(s){ return s==='active'?'badge-ok':(s==='failed'?'badge-fail':'badge-idle'); }

async function submitDonate(e){
  e.preventDefault();
  const form=e.target, msg=document.getElementById('donate-message'), btn=document.getElementById('donate-submit-btn');
  msg.textContent=''; msg.className='text-xs mt-1 min-h-[1.5rem]';
  const fd=new FormData(form);
  const payload={
    ip:fd.get('ip')?.toString().trim(), port:Number(fd.get('port')||''), username:fd.get('username')?.toString().trim(),
    authType:fd.get('authType')?.toString(), password:fd.get('password')?.toString(), privateKey:fd.get('privateKey')?.toString(),
    country:fd.get('country')?.toString().trim(), traffic:fd.get('traffic')?.toString().trim(), expiryDate:fd.get('expiryDate')?.toString().trim(),
    specs:fd.get('specs')?.toString().trim(), note:fd.get('note')?.toString().trim()
  };
  btn.disabled=true; const t=btn.textContent; btn.textContent='提交中...';
  try{
    const r=await fetch('/api/donate',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const j=await r.json();
    if(!r.ok||!j.success){ msg.textContent=j.message||'提交失败'; modalNotice('投喂失败：'+(j.message||'请检查填写项')); }
    else{ msg.textContent=j.message||'投喂成功'; modalNotice(j.message||'投喂成功'); form.reset(); loadDonations(); }
  }catch{ msg.textContent='提交异常'; modalNotice('提交异常'); } finally{ btn.disabled=false; btn.textContent=t; }
}

async function loadDonations(){
  const box=document.getElementById('donations-list');
  box.innerHTML='<div class="muted text-xs">正在加载...</div>';
  try{
    const r=await fetch('/api/user/donations',{credentials:'same-origin',cache:'no-store'}); const j=await r.json();
    if(!r.ok||!j.success){ box.innerHTML='<div class="text-red-400 text-xs">加载失败</div>'; return; }
    const data=j.data||[]; if(!data.length){ box.innerHTML='<div class="muted text-xs">还没有投喂记录</div>'; return; }
    box.innerHTML=''; data.forEach(v=>{
      const div=document.createElement('div'); div.className='card rounded-xl border px-3 py-2';
      const dt=v.donatedAt?new Date(v.donatedAt):null, t=dt?dt.toLocaleString():'';
      const uname=v.donatedByUsername||''; const p='https://linux.do/u/'+encodeURIComponent(uname);
      div.innerHTML='<div class="flex items-center justify-between gap-2 mb-1"><div class="text-[11px] break-words">IP：'+v.ip+':'+v.port+
      '</div><div class="'+scls(v.status)+' text-[11px]">'+stxt(v.status)+'</div></div>'+
      '<div class="text-[11px]">投喂者：<a href="'+p+'" target="_blank" class="underline text-sky-300">@'+uname+'</a></div>'+
      '<div class="flex flex-wrap gap-x-4 gap-y-1 text-[11px] mt-1"><span>地区：'+(v.country||'未填写')+(v.ipLocation?' · '+v.ipLocation:'')+
      '</span><span>流量/带宽：'+(v.traffic||'未填写')+'</span><span>到期：'+(v.expiryDate||'未填写')+'</span></div>'+
      '<div class="text-[11px] muted mt-1 break-words">配置：'+(v.specs||'未填写')+'</div>'+
      (v.note?'<div class="text-[11px] text-amber-300/90 mt-1 break-words">我的备注：'+v.note+'</div>':'')+
      (t?'<div class="text-[11px] muted mt-1">投喂时间：'+t+'</div>':''); box.appendChild(div);
    });
  }catch{ box.innerHTML='<div class="text-red-400 text-xs">加载异常</div>'; }
}

ensureLogin(); bindAuthType();
document.getElementById('donate-form').addEventListener('submit', submitDonate);
loadDonations();
</script>
</body></html>`;
  return c.html(html);
});

/* ==================== /admin 管理后台 ==================== */
app.get('/admin', c => {
  const head = commonHead('VPS 管理后台');
  const html = `<!doctype html><html lang="zh-CN"><head>${head}</head>
<body class="min-h-screen" data-theme="dark">
<div class="max-w-7xl mx-auto px-4 py-8" id="app-root">
  <div class="muted text-sm">正在检测管理员登录状态...</div>
</div>
<div id="toast-root"></div>
<div id="modal-root"></div>
<script>
updateThemeBtn();

let allVpsList=[]; let statusFilter='all'; let searchFilter=''; let userFilter='';

function stxt(s){ return s==='active'?'运行中':(s==='failed'?'失败':'未启用'); }
function scls(s){ return s==='active'?'badge-ok':(s==='failed'?'badge-fail':'badge-idle'); }

async function checkAdmin(){
  const root=document.getElementById('app-root');
  const timeoutPromise=new Promise((_,rej)=>setTimeout(()=>rej(new Error('请求超时')),5000));
  try{
    const r=await Promise.race([fetch('/api/admin/check-session',{credentials:'same-origin',cache:'no-store'}),timeoutPromise]);
    if(!r.ok){ renderLogin(root); return; }
    const j=await r.json(); if(!j.success||!j.isAdmin){ renderLogin(root); } else { await renderAdmin(root,j.username); }
  }catch{ renderLogin(root); }
}

function renderLogin(root){
  root.innerHTML='';
  const wrap=document.createElement('div'); wrap.className='panel max-w-sm mx-auto rounded-2xl border p-6 shadow-lg';
  wrap.innerHTML='<h1 class="text-xl font-semibold mb-4">管理员登录</h1>'+
    '<p class="text-xs muted mb-4">请输入管理员密码。</p>'+
    '<form id="admin-login-form" class="space-y-3 text-sm">'+
      '<div><label class="block mb-1 text-xs">密码</label><input type="password" name="password" class="w-full rounded-lg border px-3 py-2 text-xs focus:ring-1 focus:ring-cyan-500"/></div>'+
      '<button type="submit" class="mt-1 inline-flex items-center justify-center rounded-xl bg-cyan-500 px-4 py-2 text-xs font-semibold hover:bg-cyan-400">登录</button>'+
    '</form>';
  root.appendChild(wrap);
  document.getElementById('admin-login-form').addEventListener('submit', async(e)=>{
    e.preventDefault();
    const fd=new FormData(e.target); const pwd=fd.get('password')?.toString()||'';
    try{
      const r=await fetch('/api/admin/login',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pwd})});
      const j=await r.json(); if(!r.ok||!j.success){ modalNotice(j.message||'登录失败'); } else { modalNotice('登录成功'); location.reload(); }
    }catch{ modalNotice('登录异常'); }
  });
}

async function renderAdmin(root,name){
  root.innerHTML='';
  const header=document.createElement('header');
  header.className='mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between';
  header.innerHTML='<div><h1 class="grad-title text-2xl md:text-3xl font-bold">VPS 管理后台</h1><p class="mt-2 text-xs muted">仅管理员可见，可查看全部投喂 VPS 与认证信息。</p></div>'+
    '<div class="flex items-center gap-3"><span class="text-xs">管理员：'+name+'</span><button id="theme-toggle" class="text-[11px] rounded-full border px-2 py-1 mr-1">浅色模式</button><button id="btn-admin-logout" class="text-[11px] rounded-full border px-2 py-1">退出</button></div>';
  root.appendChild(header);
  updateThemeBtn();
  document.getElementById('theme-toggle').addEventListener('click',toggleTheme);
  document.getElementById('btn-admin-logout').addEventListener('click', async()=>{ try{await fetch('/api/admin/logout',{credentials:'same-origin'})}catch{} location.reload(); });

  const stats=document.createElement('section'); stats.id='admin-stats'; root.appendChild(stats);

  const cfg=document.createElement('section'); cfg.id='admin-config'; cfg.className='mt-4';
  cfg.innerHTML=
  '<div class="panel rounded-2xl border p-4 mb-4">'+
    '<div class="flex items-center justify-between"><h2 class="text-sm font-semibold">OAuth 配置</h2>'+
    '<button id="btn-toggle-oauth" class="text-[11px] rounded-full border px-2 py-1">展开</button></div>'+
    '<div id="oauth-body" class="mt-3 hidden">'+
      '<form id="oauth-form" class="grid md:grid-cols-3 gap-3 text-[11px]">'+
        '<div><label class="block mb-1 muted text-xs">Client ID</label><input name="clientId" class="w-full rounded-lg border px-2 py-1 text-xs focus:ring-1 focus:ring-cyan-500"/></div>'+
        '<div><label class="block mb-1 muted text-xs">Client Secret</label><input name="clientSecret" class="w-full rounded-lg border px-2 py-1 text-xs focus:ring-1 focus:ring-cyan-500"/></div>'+
        '<div><label class="block mb-1 muted text-xs">Redirect URI</label><input name="redirectUri" class="w-full rounded-lg border px-2 py-1 text-xs focus:ring-1 focus:ring-cyan-500"/></div>'+
      '</form><div class="mt-2 flex gap-2"><button id="btn-save-oauth" class="text-[11px] rounded-xl bg-cyan-500 px-3 py-1 font-semibold">保存 OAuth</button></div>'+
    '</div></div>'+
    '<div class="panel rounded-2xl border p-4">'+
      '<h2 class="text-sm font-semibold mb-3">管理员密码</h2>'+
      '<p class="text-[11px] muted mb-2">用于 <code>/admin</code> 后台登录，至少 6 位。</p>'+
      '<div class="grid sm:grid-cols-3 gap-3 items-center text-[11px]">'+
        '<input id="admin-pass-input-1" type="password" placeholder="输入新的管理员密码" class="rounded-lg border px-3 py-2 text-xs focus:ring-1 focus:ring-cyan-500"/>'+
        '<input id="admin-pass-input-2" type="password" placeholder="再输入一次" class="rounded-lg border px-3 py-2 text-xs focus:ring-1 focus:ring-cyan-500"/>'+
        '<button id="btn-save-admin-pass" class="rounded-xl bg-emerald-500 px-4 py-2 text-[11px] font-semibold hover:bg-emerald-400">保存密码</button>'+
      '</div>'+
      '<p class="text-[11px] muted mt-2">修改成功后立即生效。</p>'+
    '</div>';
  root.appendChild(cfg);

  document.getElementById('btn-toggle-oauth').addEventListener('click',()=>{
    const b=document.getElementById('oauth-body'); const btn=document.getElementById('btn-toggle-oauth');
    if(b.classList.contains('hidden')){ b.classList.remove('hidden'); btn.textContent='收起'; } else { b.classList.add('hidden'); btn.textContent='展开'; }
  });
  document.getElementById('btn-save-oauth').addEventListener('click', saveOAuth);
  document.getElementById('btn-save-admin-pass').addEventListener('click', saveAdminPassword);

  const listWrap=document.createElement('section'); listWrap.className='mt-6';
  listWrap.innerHTML='<div class="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-2">'+
    '<h2 class="text-lg font-semibold">VPS 列表</h2>'+
    '<div class="flex flex-wrap items-center gap-2 text-[11px]">'+
      '<span>状态筛选：</span>'+
      '<button data-status="all" class="px-2 py-1 rounded-full border">全部</button>'+
      '<button data-status="active" class="px-2 py-1 rounded-full border">运行中</button>'+
      '<button data-status="failed" class="px-2 py-1 rounded-full border">失败</button>'+
      '<span class="ml-2">搜索：</span><input id="filter-input" placeholder="按 IP / 用户名 / 备注 ..." class="rounded-lg border px-2 py-1 text-[11px] focus:ring-1 focus:ring-cyan-500"/>'+
      '<button id="filter-btn" class="px-2 py-1 rounded-full border">搜索</button><button id="filter-clear-btn" class="px-2 py-1 rounded-full border">清除</button>'+
      '<button id="btn-verify-all" class="ml-2 px-3 py-1 rounded-full bg-emerald-500 text-[11px] font-semibold">一键验证全部</button>'+
    '</div></div>'+
    '<div id="vps-list" class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4"></div>';
  root.appendChild(listWrap);

  listWrap.querySelectorAll('button[data-status]').forEach(btn=> btn.addEventListener('click',()=>{ statusFilter=btn.getAttribute('data-status')||'all'; userFilter=''; renderVpsList(); }));
  document.getElementById('filter-btn').addEventListener('click',()=>{ searchFilter=document.getElementById('filter-input').value.trim(); userFilter=''; renderVpsList(); });
  document.getElementById('filter-clear-btn').addEventListener('click',()=>{ searchFilter=''; document.getElementById('filter-input').value=''; userFilter=''; renderVpsList(); });
  document.getElementById('btn-verify-all').addEventListener('click', verifyAll);

  await loadStats(); await loadConfig(); await loadVps();
}

async function loadStats(){
  const wrap=document.getElementById('admin-stats');
  wrap.innerHTML='<div class="muted text-xs mb-3">正在加载统计信息...</div>';
  try{
    const r=await fetch('/api/admin/stats',{credentials:'same-origin',cache:'no-store'});
    if(!r.ok){ wrap.innerHTML='<div class="text-red-400 text-xs">统计信息加载失败</div>'; return; }
    const d=(await r.json()).data||{};
    function card(label,value,key){ return '<button data-gok="'+key+'" class="stat-card stat-'+key+' rounded-2xl border px-3 py-2 text-left"><div class="stat-label text-[11px] muted">'+label+'</div><div class="stat-value mt-1">'+value+'</div></button>'; }
    wrap.innerHTML='<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">'+
      card('总投喂数',d.totalVPS||0,'all')+
      card('运行中',d.activeVPS||0,'active')+
      card('失败',d.failedVPS||0,'failed')+
      card('今日新增',d.todayNewVPS||0,'today')+'</div>';
    wrap.querySelectorAll('button[data-gok]').forEach(b=> b.addEventListener('click',()=>{ statusFilter=b.getAttribute('data-gok'); userFilter=''; renderVpsList(); }));
  }catch{ wrap.innerHTML='<div class="text-red-400 text-xs">统计信息加载异常</div>'; }
}

async function loadConfig(){
  try{
    const res=await fetch('/api/admin/config/oauth',{credentials:'same-origin',cache:'no-store'}); const j=await res.json(); const cfg=j.data||{};
    const f=document.getElementById('oauth-form');
    f.querySelector('input[name="clientId"]').value=cfg.clientId||'';
    f.querySelector('input[name="clientSecret"]').value=cfg.clientSecret||'';
    f.querySelector('input[name="redirectUri"]').value=cfg.redirectUri||'';
  }catch{}
}

async function saveOAuth(){
  const f=document.getElementById('oauth-form');
  const payload={
    clientId:f.querySelector('input[name="clientId"]').value.trim(),
    clientSecret:f.querySelector('input[name="clientSecret"]').value.trim(),
    redirectUri:f.querySelector('input[name="redirectUri"]').value.trim()
  };
  try{
    const r=await fetch('/api/admin/config/oauth',{method:'PUT',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const j=await r.json(); modalNotice(j.message|| (r.ok?'保存成功':'保存失败'));
  }catch{ modalNotice('保存异常'); }
}

async function saveAdminPassword(){
  const p1=(document.getElementById('admin-pass-input-1') as HTMLInputElement).value.trim();
  const p2=(document.getElementById('admin-pass-input-2') as HTMLInputElement).value.trim();
  if(!p1||p1.length<6){ modalNotice('请输入至少 6 位的新密码'); return; }
  if(p1!==p2){ modalNotice('两次输入的密码不一致'); return; }
  try{
    const r=await fetch('/api/admin/config/password',{method:'PUT',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p1,confirm:p2})});
    const j=await r.json(); modalNotice(j.message|| (r.ok?'保存成功':'保存失败'));
    if(r.ok){ (document.getElementById('admin-pass-input-1') as HTMLInputElement).value=''; (document.getElementById('admin-pass-input-2') as HTMLInputElement).value=''; }
  }catch{ modalNotice('保存异常'); }
}

async function loadVps(){
  const list=document.getElementById('vps-list'); list.innerHTML='<div class="muted text-xs col-span-full">正在加载 VPS...</div>';
  try{
    const r=await fetch('/api/admin/vps',{credentials:'same-origin',cache:'no-store'}); const j=await r.json();
    if(!r.ok||!j.success){ list.innerHTML='<div class="text-red-400 text-xs col-span-full">加载失败</div>'; return; }
    allVpsList=j.data||[]; renderVpsList();
  }catch(err){ list.innerHTML='<div class="text-red-400 text-xs col-span-full">加载异常: '+err.message+'</div>'; }
}

function renderVpsList(){
  const list=document.getElementById('vps-list');
  if(!allVpsList.length){ list.innerHTML='<div class="muted text-xs col-span-full">暂无 VPS 记录</div>'; return; }

  const kw=(searchFilter||'').toLowerCase();
  const arr=allVpsList.filter(v=>{
    let ok=true;
    if(statusFilter==='active') ok=v.status==='active';
    else if(statusFilter==='failed') ok=v.status==='failed';
    if(userFilter) ok=ok && v.donatedByUsername===userFilter;
    if(kw){ const hay=[v.ip,String(v.port),v.donatedByUsername,v.country,v.traffic,v.specs,v.note,v.adminNote].join(' ').toLowerCase(); ok=ok && hay.includes(kw); }
    return ok;
  });

  if(!arr.length){ list.innerHTML='<div class="muted text-xs col-span-full">当前筛选下没有 VPS</div>'; return; }
  list.innerHTML='';
  arr.forEach(v=>{
    const card=document.createElement('div'); card.className='card rounded-2xl border p-3 flex flex-col gap-2 text-xs';
    const dt=v.donatedAt?new Date(v.donatedAt):null; const t=dt?dt.toLocaleString():'';
    const uname=v.donatedByUsername||''; const link='https://linux.do/u/'+encodeURIComponent(uname);

    card.innerHTML='<div class="flex items-center justify-between gap-2"><div class="text-[11px] break-words">IP：'+v.ip+':'+v.port+'</div><div class="'+scls(v.status)+' text-[11px]">'+stxt(v.status)+'</div></div>'+
      '<div class="flex flex-wrap items-center gap-2 text-[11px]"><span>投喂者：<a class="underline" href="'+link+'" target="_blank">@'+uname+'</a></span>'+
      '<button class="px-2 py-0.5 rounded-full border" data-act="filter-user" data-user="'+uname+'">筛选此用户</button>'+
      '<span>地区：'+(v.country||'未填写')+(v.ipLocation?' · '+v.ipLocation:'')+'</span></div>'+
      '<div class="flex flex-wrap gap-2 text-[11px]"><span>流量/带宽：'+(v.traffic||'未填写')+'</span><span>到期：'+(v.expiryDate||'未填写')+'</span></div>'+
      '<div class="text-[11px] muted break-words">配置：'+(v.specs||'未填写')+'</div>'+
      (v.note?'<div class="text-[11px] text-amber-300/90 break-words">用户备注：'+v.note+'</div>':'')+
      (v.adminNote?'<div class="text-[11px] text-cyan-300/90 break-words">管理员备注：'+v.adminNote+'</div>':'')+
      (t?'<div class="text-[11px] muted">投喂时间：'+t+'</div>':'')+
      '<div class="flex flex-wrap gap-2 mt-1">'+
        '<button class="px-2 py-1 rounded-full border" data-act="login" data-id="'+v.id+'">查看信息</button>'+
        '<button class="px-2 py-1 rounded-full border" data-act="verify" data-id="'+v.id+'">一键验证</button>'+
        '<button class="px-2 py-1 rounded-full border" data-act="mark" data-id="'+v.id+'">标记通过</button>'+
        '<button class="px-2 py-1 rounded-full border" data-act="failed" data-id="'+v.id+'">设为失败</button>'+
        '<button class="px-2 py-1 rounded-full border" data-act="edit" data-id="'+v.id+'">编辑信息</button>'+
        '<button class="px-2 py-1 rounded-full border" data-act="del" data-id="'+v.id+'">删除</button>'+
      '</div>';

    card.querySelectorAll('button[data-act]').forEach(btn=>{
      const id=btn.getAttribute('data-id'); const act=btn.getAttribute('data-act');
      btn.addEventListener('click', async()=>{
        if(!id) return;
        if(act==='login'){ modalLoginInfo(v); return; }
        if(act==='verify'){
          try{
            const r=await fetch('/api/admin/vps/'+id+'/verify',{method:'POST',credentials:'same-origin'});
            const j=await r.json(); modalNotice(j.message||'已验证'); await loadVps(); await loadStats();
          }catch{ modalNotice('验证失败'); }
          return;
        }
        if(act==='mark'){
          try{ const r=await fetch('/api/admin/vps/'+id+'/status',{method:'PUT',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:'active'})});
            const j=await r.json(); modalNotice(j.message||'已标记'); }catch{ modalNotice('操作失败'); }
        } else if(act==='failed'){
          try{ const r=await fetch('/api/admin/vps/'+id+'/status',{method:'PUT',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:'failed'})});
            const j=await r.json(); modalNotice(j.message||'已更新'); }catch{ modalNotice('更新失败'); }
        } else if(act==='del'){
          try{ const r=await fetch('/api/admin/vps/'+id,{method:'DELETE',credentials:'same-origin'}); const j=await r.json(); modalNotice(j.message|| (r.ok?'已删除':'删除失败')); }catch{ modalNotice('删除失败'); }
        } else if(act==='edit'){
          modalEdit('编辑 VPS 信息（用户备注前台可见）',[
            {key:'country',label:'国家/区域',value:v.country||'',placeholder:'如：HK - Hong Kong, Kowloon, Hong Kong'},
            {key:'traffic',label:'流量/带宽',value:v.traffic||'',placeholder:'如：400G/月 · 1Gbps'},
            {key:'expiryDate',label:'到期时间',value:v.expiryDate||'',placeholder:'YYYY-MM-DD'},
            {key:'specs',label:'配置描述',value:v.specs||'',placeholder:'如：1C1G · 10Gbps · 1T/月'},
            {key:'note',label:'公用备注（前台可见）',value:v.note||'',type:'textarea',placeholder:'如：电信方向无法大陆优选链路…'},
            {key:'adminNote',label:'管理员备注（仅后台）',value:v.adminNote||'',type:'textarea',placeholder:'仅管理员可见的附注'}
          ], async(data,close)=>{
            try{
              const r=await fetch('/api/admin/vps/'+id+'/notes',{method:'PUT',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
              const j=await r.json(); if(!r.ok||!j.success){ modalNotice(j.message||'保存失败'); } else { modalNotice('已保存'); close(); await loadVps(); await loadStats(); }
            }catch{ modalNotice('保存异常'); }
          });
          return;
        }
        await loadVps(); await loadStats();
      });
    });

    const filtBtn = card.querySelector('button[data-act="filter-user"]');
    if(filtBtn){ filtBtn.addEventListener('click',()=>{ userFilter=filtBtn.getAttribute('data-user')||''; renderVpsList(); }); }
    list.appendChild(card);
  });
}

async function verifyAll(){
  modalNotice('正在验证全部 VPS，请稍等…');
  try{
    const r=await fetch('/api/admin/verify-all',{method:'POST',credentials:'same-origin'});
    const j=await r.json();
    if(!r.ok||!j.success){ modalNotice(j.message||'批量验证失败'); }
    else{
      const d=j.data||{total:0,ok:0,fail:0};
      modalNotice('验证完成：<br>总数 '+d.total+' 台<br>通过 '+d.ok+' 台<br>失败 '+d.fail+' 台', true);
      await loadVps(); await loadStats();
    }
  }catch{ modalNotice('批量验证异常'); }
}

checkAdmin();

/* ======= 居中弹窗 / 编辑 / 登录信息 / 复制 ======= */
function modalRoot(){ let m=document.getElementById('modal-root'); if(!m){ m=document.createElement('div'); m.id='modal-root'; document.body.appendChild(m);} return m;}
function modalNotice(msg,html=false){
  const root=modalRoot(); const wrap=document.createElement('div');
  wrap.style.cssText='position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;';
  const card=document.createElement('div'); card.className='panel rounded-2xl border p-4'; card.style.width='min(420px,92vw)';
  card.innerHTML='<div class="text-base font-semibold mb-2">提示</div><div class="text-sm muted mb-4">'+(html?msg:escapeHtml(msg))+'</div><div class="flex justify-end"><button class="px-3 py-1 rounded-full border">关闭</button></div>';
  card.querySelector('button')!.onclick=()=>wrap.remove();
  wrap.appendChild(card); root.appendChild(wrap);
}
function escapeHtml(s){ return s.replace(/[&<>"]/g,m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' }[m] as string)); }

function copyToClipboard(text){
  if(!text){ modalNotice('没有可复制的内容'); return; }
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(()=>modalNotice('已复制到剪贴板')).catch(()=>modalNotice('复制失败'));
  }else{
    const ta=document.createElement('textarea'); ta.value=text; ta.style.position='fixed'; ta.style.left='-9999px'; ta.style.top='-9999px'; document.body.appendChild(ta);
    ta.select(); try{ document.execCommand('copy'); modalNotice('已复制到剪贴板'); }catch{ modalNotice('复制失败'); } document.body.removeChild(ta);
  }
}

function modalEdit(title,fields,onOk){
  const wrap=document.createElement('div'); wrap.style.cssText='position:fixed;inset:0;z-index:9998;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;';
  const card=document.createElement('div'); card.className='panel rounded-2xl border p-4'; card.style.width='min(680px,92vw)';
  const h=document.createElement('div'); h.className='text-lg font-semibold mb-3'; h.textContent=title; card.appendChild(h);
  const form=document.createElement('div'); form.className='grid grid-cols-2 gap-3 text-sm';
  fields.forEach(f=>{ const box=document.createElement('div'); const lab=document.createElement('div'); lab.className='muted text-xs mb-1'; lab.textContent=f.label;
    const inp=f.type==='textarea'?document.createElement('textarea'):document.createElement('input'); if(f.type!=='textarea') inp.type='text'; inp.value=f.value||''; inp.placeholder=f.placeholder||''; if(f.type==='textarea') inp.rows=3;
    inp.className='w-full rounded-lg border px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500'; box.appendChild(lab); box.appendChild(inp); (box as any)._get=()=>inp.value; (box as any)._key=f.key; form.appendChild(box); });
  card.appendChild(form);
  const actions=document.createElement('div'); actions.className='mt-4 flex items-center justify-end gap-2';
  const btn1=document.createElement('button'); btn1.textContent='取消'; btn1.className='px-3 py-1 rounded-full border'; btn1.onclick=()=>wrap.remove();
  const btn2=document.createElement('button'); btn2.textContent='保存'; btn2.className='px-3 py-1 rounded-full bg-cyan-500 text-black font-semibold';
  btn2.onclick=()=>{ const data={}; (form.childNodes as any).forEach((n:any)=>{ data[n._key]=n._get(); }); try{ onOk(data,()=>wrap.remove()); }catch(e){ console.error(e); } };
  actions.append(btn1,btn2); card.appendChild(actions); wrap.appendChild(card); document.body.appendChild(wrap);
}

function modalLoginInfo(v){
  const wrap=document.createElement('div'); wrap.style.cssText='position:fixed;inset:0;z-index:9998;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;';
  const card=document.createElement('div'); card.className='panel rounded-2xl border p-4'; card.style.width='min(480px,92vw)';
  const title=document.createElement('div'); title.className='text-base font-semibold mb-3'; title.textContent='VPS 登录信息（仅管理员可见）'; card.appendChild(title);
  const rows=document.createElement('div'); rows.className='space-y-2 text-xs';
  function addRow(label,value,canCopy=true){ const row=document.createElement('div'); row.className='flex items-center justify-between gap-2';
    const left=document.createElement('div'); left.className='muted flex-1 break-words'; left.textContent=label+'：'+(value||'-'); row.appendChild(left);
    if(canCopy&&value){ const btn=document.createElement('button'); btn.className='px-2 py-1 rounded-full border text-[11px] whitespace-nowrap'; btn.textContent='复制'; btn.onclick=()=>copyToClipboard(value); row.appendChild(btn); }
    rows.appendChild(row);
  }
  addRow('IP / 端口', v.ip+':'+v.port);
  addRow('系统用户名', v.username);
  addRow('认证方式', v.authType==='key'?'密钥':'密码', false);
  if(v.authType==='password'){ addRow('登录密码', v.password||''); } else { addRow('SSH 私钥', v.privateKey||''); }
  const statusText=v.verifyStatus||'unknown'; const extra=v.verifyErrorMsg?('（'+v.verifyErrorMsg+'）'):'';
  addRow('验证状态', statusText+extra, false);
  card.appendChild(rows);
  const footer=document.createElement('div'); footer.className='mt-4 flex justify-end';
  const closeBtn=document.createElement('button'); closeBtn.textContent='关闭'; closeBtn.className='px-3 py-1 rounded-full border'; closeBtn.onclick=()=>wrap.remove();
  footer.appendChild(closeBtn); card.appendChild(footer);
  wrap.appendChild(card); document.body.appendChild(wrap);
}
</script>
</body></html>`;
  return c.html(html);
});

/* ==================== 公共 head（主题 + 全局样式 + 工具） ==================== */
function commonHead(title: string): string {
  return `
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>${title}</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
:root{ color-scheme: dark; }
html,body{ font-family: system-ui,-apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",sans-serif; font-size: 15px; -webkit-font-smoothing: antialiased; overflow-x: hidden; }
body{ background:#020617; color:#e5f0ff; }
body[data-theme="light"]{ color-scheme: light; background:#f6f7fb; color:#0f172a; }

.panel,.card{ background:rgba(15,23,42,.98); border:1px solid rgba(30,64,175,.5); box-shadow:0 14px 40px rgba(15,23,42,.7); }
body[data-theme="light"] .panel, body[data-theme="light"] .card{ background:#ffffff; border-color:#e5e7eb; box-shadow:0 12px 35px rgba(148,163,184,.20); }

.card{ word-break:break-word; }

.muted{ color:#94a3b8; } body[data-theme="light"] .muted{ color:#6b7280; }

.grad-title{
  background-image:linear-gradient(115deg,#22d3ee 0%,#38bdf8 25%,#a855f7 50%,#ec4899 75%,#f97316 100%);
  background-size:320% 100%; -webkit-background-clip:text; background-clip:text; color:transparent; display:inline-block;
  animation:grad-loop 10s ease-in-out infinite alternate;
}
@keyframes grad-loop{ 0%{ background-position:0% 50%; } 100%{ background-position:100% 50%; } }

/* Toast 仍保留（偶尔用），但信息类弹窗统一用居中 modalNotice */
#toast-root{ position:fixed; right:16px; bottom:16px; z-index:9998; display:flex; flex-direction:column; gap:10px; }
.toast{ padding:10px 12px; border-radius:12px; border:1px solid rgba(255,255,255,.08); background:rgba(15,23,42,.97); color:#e5f0ff; box-shadow:0 10px 30px rgba(0,0,0,.5); transform:translateY(10px); opacity:0; transition:all .25s ease; }
.toast.show{ transform:translateY(0); opacity:1; }
.toast.success{ border-color:#10b981; } .toast.error{ border-color:#ef4444; } .toast.warn{ border-color:#f59e0b; }

.help{ font-size:11px; opacity:.8; }

.badge-ok{ color:#34d399; font-weight:600; }
.badge-fail{ color:#f97373; font-weight:600; }
.badge-idle{ color:#cbd5e1; }

#theme-toggle{ border-radius:9999px; padding:0.35rem 0.9rem; border:1px solid rgba(148,163,184,.7); background:rgba(15,23,42,.95); color:#e5e7eb; box-shadow:0 8px 20px rgba(15,23,42,.9); }
body[data-theme="light"] #theme-toggle{ background:#ffffff; color:#374151; border-color:#d1d5db; box-shadow:0 6px 18px rgba(148,163,184,.5); }

/* 统计卡：深色维持蓝黑渐变；浅色模式下每个种类用不同柔和底色 */
.stat-card{ background:linear-gradient(135deg,rgba(15,23,42,1),rgba(30,64,175,.8)); border-color:rgba(56,189,248,.4); }
.stat-card .stat-value{ font-size:1.4rem; font-weight:700; color:#7dd3fc; }
.stat-card.stat-active .stat-value{ color:#22c55e; }
.stat-card.stat-failed .stat-value{ color:#f97373; }
.stat-card.stat-all .stat-value{ color:#38bdf8; }
.stat-card.stat-today .stat-value{ color:#60a5fa; }
body[data-theme="light"] .stat-card{ background:#ffffff; }
body[data-theme="light"] .stat-card.stat-all{ background:linear-gradient(135deg,#eff6ff,#e0f2fe); border-color:#bfdbfe; }
body[data-theme="light"] .stat-card.stat-active{ background:linear-gradient(135deg,#ecfdf5,#dcfce7); border-color:#86efac; }
body[data-theme="light"] .stat-card.stat-failed{ background:linear-gradient(135deg,#fef2f2,#fee2e2); border-color:#fecaca; }
body[data-theme="light"] .stat-card.stat-today{ background:linear-gradient(135deg,#eef2ff,#e0e7ff); border-color:#c7d2fe; }

.text-xs{ font-size:0.8rem; line-height:1.4; } .text-sm{ font-size:0.9rem; line-height:1.45; }

input,textarea,select{ background:#020617; color:#e5f0ff; border:1px solid #1f2937; }
input::placeholder, textarea::placeholder{ color:#64748b; }
body[data-theme="light"] input, body[data-theme="light"] textarea, body[data-theme="light"] select{ background:#f9fafb; color:#111827; border-color:#d1d5db; }
body[data-theme="light"] input::placeholder, body[data-theme="light"] textarea::placeholder{ color:#9ca3af; }

button{ transition:background-color .15s ease, color .15s ease, box-shadow .15s ease, border-color .15s ease, transform .06s ease; }
button:active{ transform:translateY(1px); }

@media (max-width: 640px){
  html,body{ font-size:14px; }
  .grad-title{ font-size:1.6rem; line-height:1.3; }
  .panel,.card{ border-radius:16px; }
}
</style>
<script>
(function(){ const saved=localStorage.getItem('theme')||'dark'; document.documentElement.setAttribute('data-theme',saved); document.addEventListener('DOMContentLoaded',()=>{ document.body.setAttribute('data-theme',saved); }); })();
function toggleTheme(){ const cur=document.body.getAttribute('data-theme')||'dark'; const nxt=cur==='dark'?'light':'dark'; document.body.setAttribute('data-theme',nxt); document.documentElement.setAttribute('data-theme',nxt); localStorage.setItem('theme',nxt); updateThemeBtn&&updateThemeBtn(); }
function updateThemeBtn(){ const b=document.getElementById('theme-toggle'); if(b){ const cur=document.body.getAttribute('data-theme')||'dark'; b.textContent=cur==='dark'?'浅色模式':'深色模式'; } }
function toast(msg,type='info',ms=2600){ let root=document.getElementById('toast-root'); if(!root){ root=document.createElement('div'); root.id='toast-root'; document.body.appendChild(root);} const el=document.createElement('div'); el.className='toast '+(type==='success'?'success':type==='error'?'error':type==='warn'?'warn':''); el.textContent=msg; root.appendChild(el); requestAnimationFrame(()=>el.classList.add('show')); setTimeout(()=>{ el.classList.remove('show'); setTimeout(()=>el.remove(),250); },ms); }
</script>
`;
}

/* ==================== 导出 ==================== */
export default app;
