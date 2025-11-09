/// <reference lib="deno.unstable" />

import { Hono } from 'https://deno.land/x/hono@v3.11.7/mod.ts';
import { cors } from 'https://deno.land/x/hono@v3.11.7/middleware.ts';
import { setCookie, getCookie } from 'https://deno.land/x/hono@v3.11.7/helper.ts';

// ==================== 类型定义 ====================
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

// ==================== 工具函数 ====================
function generateId(): string {
  return crypto.randomUUID();
}
function generateSessionId(): string {
  return crypto.randomUUID();
}

// ==================== IP 归属地 ====================
async function getIPLocation(ip: string): Promise<string> {
  try {
    const res = await fetch(
      `http://ip-api.com/json/${ip}?fields=country,regionName,city`,
    );
    if (res.ok) {
      const data = await res.json();
      if (data.country) {
        const parts = [data.country];
        if (data.regionName) parts.push(data.regionName);
        if (data.city) parts.push(data.city);
        return parts.join(', ');
      }
    }
  } catch (e) {
    console.error('IP location query failed:', e);
  }
  return '未知地区';
}

// ==================== IP 校验 ====================
function isValidIPv4(ip: string): boolean {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(ip)) return false;
  const parts = ip.split('.');
  return parts.every((p) => {
    const num = parseInt(p, 10);
    return num >= 0 && num <= 255;
  });
}
function isValidIPv6(ip: string): boolean {
  const cleanIp = ip.replace(/^\[|\]$/g, '');
  const ipv6Regex =
    /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
  return ipv6Regex.test(cleanIp);
}
function isValidIP(ip: string): boolean {
  return isValidIPv4(ip) || isValidIPv6(ip);
}

// ==================== VPS 工具函数 ====================
async function getAllVPS(): Promise<VPSServer[]> {
  const entries = kv.list<VPSServer>({ prefix: ['vps'] });
  const servers: VPSServer[] = [];
  for await (const entry of entries) servers.push(entry.value);
  return servers.sort((a, b) => b.donatedAt - a.donatedAt);
}

async function checkIPExists(ip: string, port: number): Promise<boolean> {
  const all = await getAllVPS();
  return all.some((v) => v.ip === ip && v.port === port);
}

async function checkPortReachable(ip: string, port: number): Promise<boolean> {
  try {
    const cleanIp = ip.replace(/^\[|\]$/g, '');
    const conn = await Deno.connect({ hostname: cleanIp, port, transport: 'tcp' });
    conn.close();
    return true;
  } catch {
    return false;
  }
}

// 一键验证：现在对所有 VPS 重新检测
async function batchVerifyVPS(): Promise<{ total: number; success: number; failed: number; details: any[] }> {
  const allVPS = await getAllVPS();
  const toCheck = allVPS; // 不再只筛 pending，全量检测

  let successCount = 0;
  let failedCount = 0;
  const details: any[] = [];

  for (const vps of toCheck) {
    try {
      const ok = await checkPortReachable(vps.ip, vps.port);
      if (ok) {
        vps.verifyStatus = 'verified';
        vps.status = 'active';
        vps.lastVerifyAt = Date.now();
        vps.verifyErrorMsg = undefined;
        await kv.set(['vps', vps.id], vps);
        successCount++;
        details.push({ id: vps.id, ip: vps.ip, status: 'success' });
      } else {
        vps.verifyStatus = 'failed';
        vps.status = 'failed';
        vps.lastVerifyAt = Date.now();
        vps.verifyErrorMsg = '端口不可达，无法建立连接';
        await kv.set(['vps', vps.id], vps);
        failedCount++;
        details.push({ id: vps.id, ip: vps.ip, status: 'failed', error: vps.verifyErrorMsg });
      }
    } catch (e: any) {
      vps.verifyStatus = 'failed';
      vps.status = 'failed';
      vps.lastVerifyAt = Date.now();
      vps.verifyErrorMsg = e.message || '验证过程中发生错误';
      await kv.set(['vps', vps.id], vps);
      failedCount++;
      details.push({ id: vps.id, ip: vps.ip, status: 'failed', error: vps.verifyErrorMsg });
    }
  }

  return { total: toCheck.length, success: successCount, failed: failedCount, details };
}

// ==================== 配置 & 用户 & Session ====================
async function getOAuthConfig(): Promise<OAuthConfig | null> {
  const r = await kv.get<OAuthConfig>(['config', 'oauth']);
  return r.value;
}
async function setOAuthConfig(config: OAuthConfig): Promise<void> {
  await kv.set(['config', 'oauth'], config);
}

async function getAdminPassword(): Promise<string> {
  const r = await kv.get<string>(['config', 'admin_password']);
  return r.value || 'admin123';
}
async function setAdminPassword(password: string): Promise<void> {
  await kv.set(['config', 'admin_password'], password);
}

async function getSession(id: string): Promise<Session | null> {
  const r = await kv.get<Session>(['sessions', id]);
  if (!r.value) return null;
  if (r.value.expiresAt < Date.now()) {
    await kv.delete(['sessions', id]);
    return null;
  }
  return r.value;
}

async function createSession(
  userId: string,
  username: string,
  avatarUrl: string | undefined,
  isAdmin: boolean,
): Promise<string> {
  const id = generateSessionId();
  const s: Session = {
    id,
    userId,
    username,
    avatarUrl,
    isAdmin,
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
  };
  await kv.set(['sessions', id], s);
  return id;
}

async function getUser(linuxDoId: string): Promise<User | null> {
  const r = await kv.get<User>(['users', linuxDoId]);
  return r.value;
}

async function createOrUpdateUser(
  linuxDoId: string,
  username: string,
  avatarUrl?: string,
): Promise<User> {
  const existing = await getUser(linuxDoId);
  const user: User = {
    linuxDoId,
    username,
    avatarUrl,
    isAdmin: existing?.isAdmin || false,
    createdAt: existing?.createdAt || Date.now(),
  };
  await kv.set(['users', linuxDoId], user);
  return user;
}

async function addVPSServer(server: Omit<VPSServer, 'id'>): Promise<VPSServer> {
  const id = generateId();
  const vps: VPSServer = { id, ...server };
  await kv.set(['vps', id], vps);

  const r = await kv.get<string[]>(['user_donations', server.donatedBy]);
  const list = r.value || [];
  list.push(id);
  await kv.set(['user_donations', server.donatedBy], list);

  return vps;
}

async function getUserDonations(linuxDoId: string): Promise<VPSServer[]> {
  const r = await kv.get<string[]>(['user_donations', linuxDoId]);
  const ids = r.value || [];
  const res: VPSServer[] = [];
  for (const id of ids) {
    const v = await kv.get<VPSServer>(['vps', id]);
    if (v.value) res.push(v.value);
  }
  return res.sort((a, b) => b.donatedAt - a.donatedAt);
}

async function deleteVPS(id: string): Promise<boolean> {
  const v = await kv.get<VPSServer>(['vps', id]);
  if (!v.value) return false;
  await kv.delete(['vps', id]);

  const ud = await kv.get<string[]>(['user_donations', v.value.donatedBy]);
  if (ud.value) {
    const filtered = ud.value.filter((x) => x !== id);
    await kv.set(['user_donations', v.value.donatedBy], filtered);
  }
  return true;
}

async function updateVPSStatus(
  id: string,
  status: 'active' | 'inactive' | 'failed',
): Promise<boolean> {
  const r = await kv.get<VPSServer>(['vps', id]);
  if (!r.value) return false;
  r.value.status = status;
  await kv.set(['vps', id], r.value);
  return true;
}

// ==================== OAuth ====================
async function exchangeCodeForToken(code: string, cfg: OAuthConfig): Promise<any> {
  const res = await fetch('https://connect.linux.do/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      code,
      redirect_uri: cfg.redirectUri,
      grant_type: 'authorization_code',
    }),
  });
  return await res.json();
}
async function getLinuxDoUserInfo(accessToken: string): Promise<any> {
  const res = await fetch('https://connect.linux.do/api/user', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  return await res.json();
}

// ==================== 中间件 ====================
async function requireAuth(c: any, next: any) {
  const sid = getCookie(c, 'session_id');
  if (!sid) return c.json({ success: false, message: '未登录' }, 401);
  const s = await getSession(sid);
  if (!s) return c.json({ success: false, message: '会话已过期' }, 401);
  c.set('session', s);
  await next();
}
async function requireAdmin(c: any, next: any) {
  const sid = getCookie(c, 'admin_session_id');
  if (!sid) return c.json({ success: false, message: '未登录' }, 401);
  const s = await getSession(sid);
  if (!s || !s.isAdmin) {
    return c.json({ success: false, message: '需要管理员权限' }, 403);
  }
  c.set('session', s);
  await next();
}

// ==================== Hono 应用 ====================
const app = new Hono();
app.use('*', cors());

app.get('/', (c) => c.redirect('/donate'));

// OAuth 登录入口
app.get('/oauth/login', async (c) => {
  const redirectPath = c.req.query('redirect') || '/donate/vps';
  const cfg = await getOAuthConfig();
  if (!cfg) {
    return c.html(
      '<!DOCTYPE html><html><body><h1>配置错误</h1><p>OAuth 配置未设置</p><a href="/donate">返回首页</a></body></html>',
    );
  }
  const state = typeof redirectPath === 'string' ? redirectPath : '/donate/vps';
  const url = new URL('https://connect.linux.do/oauth2/authorize');
  url.searchParams.set('client_id', cfg.clientId);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('redirect_uri', cfg.redirectUri);
  url.searchParams.set('scope', 'openid profile');
  url.searchParams.set('state', state);
  return c.redirect(url.toString());
});

// OAuth 回调
app.get('/oauth/callback', async (c) => {
  const code = c.req.query('code');
  const error = c.req.query('error');
  const state = c.req.query('state') || '/donate';

  if (error) {
    return c.html(
      `<!DOCTYPE html><html><body><h1>登录失败</h1><p>OAuth 认证失败: ${error}</p><a href="/donate">返回首页</a></body></html>`,
    );
  }
  if (!code) return c.text('Missing code', 400);

  try {
    const cfg = await getOAuthConfig();
    if (!cfg) {
      return c.html(
        '<!DOCTYPE html><html><body><h1>配置错误</h1><p>OAuth 配置未设置</p><a href="/donate">返回首页</a></body></html>',
      );
    }
    const tokenData = await exchangeCodeForToken(code, cfg);
    const userInfo = await getLinuxDoUserInfo(tokenData.access_token);

    let avatarUrl = userInfo.avatar_template;
    if (avatarUrl) {
      avatarUrl = avatarUrl.replace('{size}', '120');
      if (avatarUrl.startsWith('//')) avatarUrl = 'https:' + avatarUrl;
      else if (avatarUrl.startsWith('/')) {
        avatarUrl = 'https://connect.linux.do' + avatarUrl;
      }
    }

    const user = await createOrUpdateUser(
      userInfo.id.toString(),
      userInfo.username,
      avatarUrl,
    );
    const sid = await createSession(
      user.linuxDoId,
      user.username,
      user.avatarUrl,
      user.isAdmin,
    );
    const isProd = Deno.env.get('DENO_DEPLOYMENT_ID') !== undefined;
    setCookie(c, 'session_id', sid, {
      maxAge: 7 * 24 * 60 * 60,
      httpOnly: true,
      secure: isProd,
      sameSite: 'Lax',
      path: '/',
    });

    const redirectTo =
      typeof state === 'string' && state.startsWith('/') ? state : '/donate';
    return c.redirect(redirectTo);
  } catch (e: any) {
    return c.html(
      `<!DOCTYPE html><html><body><h1>登录失败</h1><p>${e.message}</p><a href="/donate">返回首页</a></body></html>`,
    );
  }
});

// ==================== 普通用户 API ====================
app.get('/api/logout', async (c) => {
  const sid = getCookie(c, 'session_id');
  if (sid) await kv.delete(['sessions', sid]);
  setCookie(c, 'session_id', '', { maxAge: 0, path: '/' });
  return c.json({ success: true });
});

app.get('/api/user/info', requireAuth, async (c) => {
  const s = c.get('session');
  const donations = await getUserDonations(s.userId);
  return c.json({
    success: true,
    data: {
      username: s.username,
      avatarUrl: s.avatarUrl,
      isAdmin: s.isAdmin,
      donationCount: donations.length,
    },
  });
});

app.get('/api/user/donations', requireAuth, async (c) => {
  const s = c.get('session');
  const donations = await getUserDonations(s.userId);

  const safe = donations.map((d) => ({
    id: d.id,
    ip: d.ip,
    port: d.port,
    username: d.username,
    authType: d.authType,
    donatedAt: d.donatedAt,
    status: d.status,
    note: d.note,
    adminNote: d.adminNote,
    country: d.country,
    traffic: d.traffic,
    expiryDate: d.expiryDate,
    specs: d.specs,
    ipLocation: d.ipLocation,
    verifyStatus: d.verifyStatus,
    lastVerifyAt: d.lastVerifyAt,
    verifyErrorMsg: d.verifyErrorMsg,
  }));
  return c.json({ success: true, data: safe });
});

app.put('/api/user/donations/:id/note', requireAuth, async (c) => {
  const s = c.get('session');
  const id = c.req.param('id');
  const { note } = await c.req.json();
  const r = await kv.get<VPSServer>(['vps', id]);
  if (!r.value) return c.json({ success: false, message: 'VPS 不存在' }, 404);
  if (r.value.donatedBy !== s.userId) {
    return c.json({ success: false, message: '无权修改此VPS' }, 403);
  }
  r.value.note = note || '';
  await kv.set(['vps', id], r.value);
  return c.json({ success: true, message: '备注已更新' });
});

// ==================== 公共榜单 API ====================
app.get('/api/leaderboard', async (c) => {
  const all = await getAllVPS();
  const stats = new Map<string, { username: string; count: number; servers: any[] }>();

  for (const v of all) {
    const s = stats.get(v.donatedBy) || {
      username: v.donatedByUsername,
      count: 0,
      servers: [],
    };
    s.count++;
    s.servers.push({
      ipLocation: v.ipLocation || '未知地区',
      country: v.country || '未填写',
      traffic: v.traffic || '未填写',
      expiryDate: v.expiryDate || '未填写',
      specs: v.specs || '未填写',
      note: v.note,
      adminNote: v.adminNote,
      status: v.status,
      donatedAt: v.donatedAt,
    });
    stats.set(v.donatedBy, s);
  }

  const leaderboard = Array.from(stats.values()).sort((a, b) => b.count - a.count);
  return c.json({ success: true, data: leaderboard });
});

app.get('/api/user/:username/donations', async (c) => {
  const username = c.req.param('username');
  const all = await getAllVPS();
  const userVPS = all.filter((v) => v.donatedByUsername === username);
  const donations = userVPS.map((v) => ({
    ipLocation: v.ipLocation || '未知地区',
    country: v.country || '未填写',
    traffic: v.traffic || '未填写',
    expiryDate: v.expiryDate || '未填写',
    specs: v.specs || '未填写',
    note: v.note,
    adminNote: v.adminNote,
    status: v.status,
    donatedAt: v.donatedAt,
  }));
  return c.json({
    success: true,
    data: { username, count: donations.length, donations },
  });
});

// ==================== 投喂 API ====================
app.post('/api/donate', requireAuth, async (c) => {
  const s = c.get('session');
  const body = await c.req.json();
  const {
    ip,
    port,
    username,
    authType,
    password,
    privateKey,
    note,
    country,
    traffic,
    expiryDate,
    specs,
  } = body;

  if (!ip || !port || !username || !authType) {
    return c.json(
      { success: false, message: 'IP、端口、用户名和认证类型为必填项' },
      400,
    );
  }
  if (!country || !traffic || !expiryDate || !specs) {
    return c.json(
      { success: false, message: '国家、流量、到期时间和配置为必填项' },
      400,
    );
  }
  if (authType === 'password' && !password) {
    return c.json({ success: false, message: '密码认证需要提供密码' }, 400);
  }
  if (authType === 'key' && !privateKey) {
    return c.json({ success: false, message: '密钥认证需要提供私钥' }, 400);
  }
  if (!isValidIP(ip)) {
    return c.json({ success: false, message: 'IP 地址格式不正确' }, 400);
  }
  const portNum = parseInt(String(port), 10);
  if (portNum < 1 || portNum > 65535) {
    return c.json(
      { success: false, message: '端口号必须在 1-65535 之间' },
      400,
    );
  }

  const exists = await checkIPExists(ip, portNum);
  if (exists) {
    return c.json(
      { success: false, message: '该 IP 和端口已经被投喂过了' },
      400,
    );
  }

  const reachable = await checkPortReachable(ip, portNum);
  if (!reachable) {
    return c.json(
      { success: false, message: '无法连接到该服务器' },
      400,
    );
  }

  try {
    const ipLocation = await getIPLocation(ip);
    const vps = await addVPSServer({
      ip,
      port: portNum,
      username,
      authType,
      password: authType === 'password' ? password : undefined,
      privateKey: authType === 'key' ? privateKey : undefined,
      donatedBy: s.userId,
      donatedByUsername: s.username,
      donatedAt: Date.now(),
      status: 'active',
      note: note || '',
      adminNote: '',
      country,
      traffic,
      expiryDate,
      specs,
      ipLocation,
      verifyStatus: 'verified',
      lastVerifyAt: Date.now(),
      verifyCode: undefined,
      verifyFilePath: undefined,
      sshFingerprint: undefined,
      verifyErrorMsg: undefined,
    });

    return c.json({
      success: true,
      message: '✅ 投喂成功！VPS 已自动验证并激活',
      data: { id: vps.id, ipLocation: vps.ipLocation },
    });
  } catch (e: any) {
    return c.json({ success: false, message: '投喂失败: ' + e.message }, 500);
  }
});

// ==================== 管理员 API ====================
app.get('/api/admin/check-session', async (c) => {
  const sid = getCookie(c, 'admin_session_id');
  if (!sid) return c.json({ success: false, isAdmin: false });
  const s = await getSession(sid);
  if (!s || s.expiresAt < Date.now()) {
    return c.json({ success: false, isAdmin: false });
  }
  return c.json({
    success: true,
    isAdmin: s.isAdmin || false,
    username: s.username,
  });
});

app.post('/api/admin/login', async (c) => {
  const { password } = await c.req.json();
  const adminPassword = await getAdminPassword();
  if (password !== adminPassword) {
    return c.json({ success: false, message: '密码错误' }, 401);
  }
  const sid = generateSessionId();
  const sess: Session = {
    id: sid,
    userId: 'admin',
    username: 'Administrator',
    avatarUrl: undefined,
    isAdmin: true,
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
  };
  await kv.set(['sessions', sid], sess);
  const isProd = Deno.env.get('DENO_DEPLOYMENT_ID') !== undefined;
  setCookie(c, 'admin_session_id', sid, {
    maxAge: 7 * 24 * 60 * 60,
    httpOnly: true,
    secure: isProd,
    sameSite: 'Lax',
    path: '/',
  });
  return c.json({ success: true, message: '登录成功' });
});

app.get('/api/admin/logout', async (c) => {
  const sid = getCookie(c, 'admin_session_id');
  if (sid) await kv.delete(['sessions', sid]);
  setCookie(c, 'admin_session_id', '', { maxAge: 0, path: '/' });
  return c.json({ success: true });
});

app.get('/api/admin/vps', requireAdmin, async (c) => {
  const servers = await getAllVPS();
  return c.json({ success: true, data: servers });
});

app.delete('/api/admin/vps/:id', requireAdmin, async (c) => {
  const id = c.req.param('id');
  const ok = await deleteVPS(id);
  if (ok) return c.json({ success: true, message: 'VPS 已删除' });
  return c.json({ success: false, message: 'VPS 不存在' }, 404);
});

app.put('/api/admin/vps/:id/status', requireAdmin, async (c) => {
  const id = c.req.param('id');
  const { status } = await c.req.json();
  if (status !== 'active' && status !== 'inactive' && status !== 'failed') {
    return c.json({ success: false, message: '无效的状态' }, 400);
  }
  const ok = await updateVPSStatus(id, status);
  if (ok) return c.json({ success: true, message: '状态已更新' });
  return c.json({ success: false, message: 'VPS 不存在' }, 404);
});

app.put('/api/admin/vps/:id/notes', requireAdmin, async (c) => {
  const id = c.req.param('id');
  const { note, adminNote, country, traffic, expiryDate, specs } =
    await c.req.json();
  const r = await kv.get<VPSServer>(['vps', id]);
  if (!r.value) return c.json({ success: false, message: 'VPS 不存在' }, 404);
  if (note !== undefined) r.value.note = note;
  if (adminNote !== undefined) r.value.adminNote = adminNote;
  if (country !== undefined) r.value.country = country;
  if (traffic !== undefined) r.value.traffic = traffic;
  if (expiryDate !== undefined) r.value.expiryDate = expiryDate;
  if (specs !== undefined) r.value.specs = specs;
  await kv.set(['vps', id], r.value);
  return c.json({ success: true, message: '信息已更新' });
});

app.get('/api/admin/config/oauth', requireAdmin, async (c) => {
  const cfg = await getOAuthConfig();
  return c.json({ success: true, data: cfg || {} });
});

app.put('/api/admin/config/oauth', requireAdmin, async (c) => {
  const { clientId, clientSecret, redirectUri } = await c.req.json();
  if (!clientId || !clientSecret || !redirectUri) {
    return c.json(
      { success: false, message: '所有字段都是必填的' },
      400,
    );
  }
  await setOAuthConfig({ clientId, clientSecret, redirectUri });
  return c.json({ success: true, message: 'OAuth 配置已更新' });
});

app.put('/api/admin/config/password', requireAdmin, async (c) => {
  const { password } = await c.req.json();
  if (!password || password.length < 6) {
    return c.json(
      { success: false, message: '密码至少需要 6 个字符' },
      400,
    );
  }
  await setAdminPassword(password);
  return c.json({ success: true, message: '管理员密码已更新' });
});

app.get('/api/admin/stats', requireAdmin, async (c) => {
  const all = await getAllVPS();
  const active = all.filter((v) => v.status === 'active');
  const failed = all.filter((v) => v.status === 'failed');
  const pending = all.filter((v) => v.verifyStatus === 'pending');

  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);
  const todayNew = all.filter((v) => v.donatedAt >= todayStart.getTime());

  const userStats = new Map<string, number>();
  for (const v of all) {
    const cnt = userStats.get(v.donatedByUsername) || 0;
    userStats.set(v.donatedByUsername, cnt + 1);
  }
  const topDonors = Array.from(userStats.entries())
    .map(([username, count]) => ({ username, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  return c.json({
    success: true,
    data: {
      totalVPS: all.length,
      activeVPS: active.length,
      failedVPS: failed.length,
      inactiveVPS: all.length - active.length - failed.length,
      pendingVPS: pending.length,
      verifiedVPS: all.filter((v) => v.verifyStatus === 'verified').length,
      todayNewVPS: todayNew.length,
      topDonors,
    },
  });
});

app.post('/api/admin/vps/:id/mark-verified', requireAdmin, async (c) => {
  const id = c.req.param('id');
  const r = await kv.get<VPSServer>(['vps', id]);
  if (!r.value) return c.json({ success: false, message: 'VPS 不存在' }, 404);
  r.value.verifyStatus = 'verified';
  r.value.status = 'active';
  r.value.lastVerifyAt = Date.now();
  await kv.set(['vps', id], r.value);
  return c.json({ success: true, message: 'VPS 已标记为验证通过' });
});

app.post('/api/admin/vps/batch-verify', requireAdmin, async (c) => {
  try {
    const result = await batchVerifyVPS();
    return c.json({
      success: true,
      message: `验证完成！成功: ${result.success}，失败: ${result.failed}`,
      data: result,
    });
  } catch (e: any) {
    return c.json(
      { success: false, message: '批量验证失败: ' + e.message },
      500,
    );
  }
});

// ==================== /donate 页面（榜单 + 我要投喂按钮） ====================
app.get('/donate', (c) => {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<title>风萧萧兮公益机场 · VPS 投喂榜</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<script src="https://cdn.tailwindcss.com"></script>
<style>
:root { color-scheme: dark; }
body[data-theme="light"] { background-color:#f8fafc; color:#020617; color-scheme: light; }
.panel,.card,.stat-card{transition:background-color .2s ease,color .2s ease,border-color .2s ease;}
body[data-theme="light"] .panel,
body[data-theme="light"] .card{
  background-color:#ffffff;
  border-color:#e2e8f0;
  color:#0f172a;
}
body[data-theme="light"] .stat-card{
  background-color:#f1f5f9;
  border-color:#e2e8f0;
  color:#0f172a;
}
</style>
</head>
<body class="min-h-screen bg-slate-950 text-slate-100" data-theme="dark">
<script>
(function(){
  const saved = localStorage.getItem('theme') || 'dark';
  document.body.setAttribute('data-theme', saved);
  document.documentElement.setAttribute('data-theme', saved);
})();
</script>

<div class="max-w-5xl mx-auto px-4 py-10">
  <header class="mb-8 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
    <div>
      <h1 class="text-3xl md:text-4xl font-bold bg-gradient-to-r from-cyan-400 via-sky-400 to-indigo-400 bg-clip-text text-transparent">
        风萧萧兮公益机场 · VPS 投喂榜
      </h1>
      <p class="mt-3 text-sm md:text-base text-slate-300 leading-relaxed">
        这是一个完全非盈利的公益项目，没有运营团队，只有我一个人维护。<br/>
        榜单仅展示「国家 / 区域 + IP 归属地 + 流量 + 到期时间」，不会公开任何 IP 或端口信息。
      </p>
      <button onclick="gotoDonatePage()"
        class="mt-5 inline-flex items-center gap-2 rounded-xl bg-cyan-500 px-4 py-2 text-sm font-semibold shadow-lg shadow-cyan-500/30 hover:bg-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:ring-offset-2 focus:ring-offset-slate-950">
        🧡 我要投喂 VPS
      </button>
    </div>
    <button id="theme-toggle"
      class="text-xs rounded-lg border border-slate-700 px-3 py-1 hover:bg-slate-800 self-start"
      onclick="toggleTheme()">浅色模式</button>
  </header>

  <section class="mb-6">
    <h2 class="text-xl font-semibold mb-3 flex items-center gap-2">
      🏆 捐赠榜单
      <span id="leaderboard-count" class="text-sm font-normal text-slate-400"></span>
    </h2>
    <div id="leaderboard" class="space-y-4">
      <div class="text-slate-400 text-sm">正在加载榜单...</div>
    </div>
  </section>

  <footer class="mt-10 border-t border-slate-800 pt-4 text-xs text-slate-500">
    <p>说明：本项目仅作公益用途，请勿滥用资源（长时间占满带宽、刷流量、倒卖账号等）。</p>
  </footer>
</div>

<script>
function updateThemeToggleText(){
  const btn = document.getElementById('theme-toggle');
  if(!btn) return;
  const theme = document.body.getAttribute('data-theme') || 'dark';
  btn.textContent = theme === 'dark' ? '浅色模式' : '深色模式';
}
function toggleTheme(){
  const cur = document.body.getAttribute('data-theme') || 'dark';
  const next = cur === 'dark' ? 'light' : 'dark';
  document.body.setAttribute('data-theme', next);
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
  updateThemeToggleText();
}
updateThemeToggleText();

async function gotoDonatePage(){
  try{
    const r = await fetch('/api/user/info');
    if(r.ok){
      location.href = '/donate/vps';
    }else{
      location.href = '/oauth/login?redirect=' + encodeURIComponent('/donate/vps');
    }
  }catch(e){
    location.href = '/oauth/login?redirect=' + encodeURIComponent('/donate/vps');
  }
}

async function loadLeaderboard(){
  const box = document.getElementById('leaderboard');
  const countEl = document.getElementById('leaderboard-count');
  try{
    const res = await fetch('/api/leaderboard');
    if(!res.ok){
      box.innerHTML = '<div class="text-red-400 text-sm">加载失败</div>';
      return;
    }
    const json = await res.json();
    if(!json.success){
      box.innerHTML = '<div class="text-red-400 text-sm">'+(json.message||'加载失败')+'</div>';
      return;
    }
    const data = json.data || [];
    countEl.textContent = data.length ? (' · 共 '+data.length+' 位投喂者') : '';
    if(!data.length){
      box.innerHTML = '<div class="text-slate-400 text-sm">暂时还没有投喂记录，成为第一个投喂者吧～</div>';
      return;
    }
    box.innerHTML = '';
    data.forEach((item,idx)=>{
      const uname = item.username || '';
      const profileUrl = 'https://linux.do/u/' + encodeURIComponent(uname);

      const wrap = document.createElement('div');
      wrap.className = 'card rounded-2xl border border-slate-800 bg-slate-900/60 p-4 shadow-sm shadow-slate-900/60';

      const titleRow = document.createElement('div');
      titleRow.className = 'flex items-center justify-between gap-2 mb-2';

      const left = document.createElement('div');
      left.className = 'flex items-center gap-2';
      const medal = idx<3?['🥇','🥈','🥉'][idx]:'🏅';
      left.innerHTML =
        '<span class="text-lg">'+medal+'</span>'+
        '<a href="'+profileUrl+'" target="_blank" class="font-semibold text-sky-300 hover:text-cyan-300">@'+uname+'</a>';

      const right = document.createElement('div');
      right.className = 'text-xs text-slate-400';
      right.textContent = '共投喂 '+item.count+' 台 VPS';

      titleRow.appendChild(left);
      titleRow.appendChild(right);
      wrap.appendChild(titleRow);

      const list = document.createElement('div');
      list.className = 'space-y-2 mt-2 text-xs';
      (item.servers||[]).forEach((srv)=>{
        const d = document.createElement('div');
        d.className = 'rounded-xl bg-slate-950/60 border border-slate-800 px-3 py-2 flex flex-col gap-1';

        const statusColor =
          srv.status==='active' ? 'text-emerald-400' :
          srv.status==='failed' ? 'text-red-400' :
          'text-slate-300';
        const statusText =
          srv.status==='active' ? '已激活' :
          srv.status==='failed' ? '验证失败' :
          '未激活';

        d.innerHTML =
          '<div class="flex items-center justify-between gap-2">'+
            '<span class="font-medium text-slate-100 text-xs">'+
              (srv.country||'未填写') + (srv.ipLocation?' · '+srv.ipLocation:'')+
            '</span>'+
            '<span class="'+statusColor+' text-[11px]">'+statusText+'</span>'+
          '</div>'+
          '<div class="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-slate-300 mt-1">'+
            '<span>流量/带宽：'+(srv.traffic||'未填写')+'</span>'+
            '<span>到期：'+(srv.expiryDate||'未填写')+'</span>'+
          '</div>'+
          (srv.specs?'<div class="text-[11px] text-slate-400 mt-1">配置：'+srv.specs+'</div>':'')+
          (srv.note?'<div class="text-[11px] text-amber-300/80 mt-1">投喂者备注：'+srv.note+'</div>':'');

        list.appendChild(d);
      });

      wrap.appendChild(list);
      box.appendChild(wrap);
    });
  }catch(e){
    box.innerHTML = '<div class="text-red-400 text-sm">加载异常</div>';
  }
}
loadLeaderboard();
</script>
</body>
</html>`;
  return c.html(html);
});

// ==================== /donate/vps 页面 ====================
app.get('/donate/vps', (c) => {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<title>风萧萧兮公益机场 · VPS 投喂中心</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<script src="https://cdn.tailwindcss.com"></script>
<style>
:root { color-scheme: dark; }
body[data-theme="light"]{background-color:#f8fafc;color:#020617;color-scheme:light;}
.panel,.card,.stat-card{transition:background-color .2s ease,color .2s ease,border-color .2s ease;}
body[data-theme="light"] .panel,
body[data-theme="light"] .card{background-color:#ffffff;border-color:#e2e8f0;color:#0f172a;}
</style>
</head>
<body class="min-h-screen bg-slate-950 text-slate-100" data-theme="dark">
<script>
(function(){
  const saved = localStorage.getItem('theme') || 'dark';
  document.body.setAttribute('data-theme', saved);
  document.documentElement.setAttribute('data-theme', saved);
})();
</script>

<div class="max-w-6xl mx-auto px-4 py-8">
  <header class="mb-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
    <div>
      <h1 class="text-2xl md:text-3xl font-bold bg-gradient-to-r from-cyan-400 to-indigo-400 bg-clip-text text-transparent">
        VPS 投喂中心
      </h1>
      <p class="mt-2 text-sm text-slate-300">
        仅已登录用户可见，可以提交新的 VPS 投喂，也可以查看和管理自己的投喂记录。
      </p>
    </div>
    <div class="flex items-center gap-3">
      <div id="user-info" class="text-sm text-slate-300"></div>
      <button onclick="logout()" class="text-xs rounded-lg border border-slate-700 px-3 py-1 hover:bg-slate-800">退出登录</button>
      <button id="theme-toggle" class="text-xs rounded-lg border border-slate-700 px-3 py-1 hover:bg-slate-800" onclick="toggleTheme()">浅色模式</button>
    </div>
  </header>

  <main class="grid md:grid-cols-2 gap-6 items-start">
    <section class="panel rounded-2xl border border-slate-800 bg-slate-900/70 p-4 shadow-lg shadow-slate-900/70">
      <h2 class="text-lg font-semibold mb-2">🧡 提交新的 VPS 投喂</h2>
      <p class="text-xs text-slate-400 mb-4 leading-relaxed">
        请确保服务器是你有控制权的机器，并允许用于公益节点。禁止长时间占满带宽、刷流量、倒卖账号等行为。
      </p>

      <form id="donate-form" class="space-y-3 text-sm">
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="block mb-1 text-xs text-slate-300">服务器 IP</label>
            <input name="ip" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" />
          </div>
          <div>
            <label class="block mb-1 text-xs text-slate-300">端口</label>
            <input name="port" required type="number" min="1" max="65535" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" />
          </div>
        </div>

        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="block mb-1 text-xs text-slate-300">系统用户名</label>
            <input name="username" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" />
          </div>
          <div>
            <label class="block mb-1 text-xs text-slate-300">认证方式</label>
            <select name="authType" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500">
              <option value="password">密码</option>
              <option value="key">SSH 私钥</option>
            </select>
          </div>
        </div>

        <div id="password-field">
          <label class="block mb-1 text-xs text-slate-300">密码</label>
          <input name="password" type="password" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" />
        </div>

        <div id="key-field" class="hidden">
          <label class="block mb-1 text-xs text-slate-300">SSH 私钥</label>
          <textarea name="privateKey" rows="4" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
        </div>

        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="block mb-1 text-xs text-slate-300">国家 / 区域</label>
            <input name="country" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" />
          </div>
          <div>
            <label class="block mb-1 text-xs text-slate-300">流量 / 带宽</label>
            <input name="traffic" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" />
          </div>
        </div>

        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="block mb-1 text-xs text-slate-300">到期日期</label>
            <input name="expiryDate" required type="date" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" />
          </div>
          <div>
            <label class="block mb-1 text-xs text-slate-300">配置描述</label>
            <input name="specs" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" />
          </div>
        </div>

        <div>
          <label class="block mb-1 text-xs text-slate-300">投喂备注（可选）</label>
          <textarea name="note" rows="2" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500"></textarea>
        </div>

        <div id="donate-message" class="text-xs mt-1 h-4"></div>

        <button type="submit"
          class="mt-2 inline-flex items-center justify-center rounded-xl bg-cyan-500 px-4 py-2 text-xs font-semibold shadow-lg shadow-cyan-500/30 hover:bg-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:ring-offset-2 focus:ring-offset-slate-950">
          提交投喂
        </button>
      </form>
    </section>

    <section class="panel rounded-2xl border border-slate-800 bg-slate-900/70 p-4 shadow-lg shadow-slate-900/70">
      <div class="flex items-center justify-between mb-2">
        <h2 class="text-lg font-semibold">📦 我的投喂记录</h2>
        <button onclick="loadDonations()" class="text-[11px] rounded-lg border border-slate-700 px-2 py-1 hover:bg-slate-800">刷新</button>
      </div>
      <div id="donations-list" class="space-y-3 text-xs text-slate-200">
        <div class="text-slate-400 text-xs">正在加载...</div>
      </div>
    </section>
  </main>

  <footer class="mt-8 text-[11px] text-slate-500 border-t border-slate-800 pt-3">
    <p>友情提示：投喂即视为同意将该 VPS 用于公益机场中转节点。请勿提交有敏感业务的生产机器。</p>
  </footer>
</div>

<script>
function updateThemeToggleText(){
  const btn = document.getElementById('theme-toggle');
  if(!btn) return;
  const theme = document.body.getAttribute('data-theme') || 'dark';
  btn.textContent = theme === 'dark' ? '浅色模式' : '深色模式';
}
function toggleTheme(){
  const cur = document.body.getAttribute('data-theme') || 'dark';
  const next = cur === 'dark' ? 'light' : 'dark';
  document.body.setAttribute('data-theme', next);
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
  updateThemeToggleText();
}
updateThemeToggleText();

async function ensureLogin(){
  try{
    const res = await fetch('/api/user/info');
    if(!res.ok){
      location.href = '/donate';
      return;
    }
    const json = await res.json();
    if(!json.success){
      location.href = '/donate';
      return;
    }
    const u = json.data;
    const profileUrl = 'https://linux.do/u/' + encodeURIComponent(u.username);
    const el = document.getElementById('user-info');
    el.innerHTML = '投喂者：<a href="'+profileUrl+'" target="_blank" class="underline text-sky-300 hover:text-cyan-300">@'+u.username+'</a> · 已投喂 '+(u.donationCount||0)+' 台';
  }catch(e){
    location.href = '/donate';
  }
}
async function logout(){
  try{await fetch('/api/logout');}catch(e){}
  location.href = '/donate';
}
function bindAuthTypeSwitch(){
  const sel = document.querySelector('select[name="authType"]');
  const pwd = document.getElementById('password-field');
  const key = document.getElementById('key-field');
  sel.addEventListener('change',()=>{
    if(sel.value === 'password'){
      pwd.classList.remove('hidden');
      key.classList.add('hidden');
    }else{
      pwd.classList.add('hidden');
      key.classList.remove('hidden');
    }
  });
}
async function submitDonateForm(e){
  e.preventDefault();
  const form = e.target;
  const msg = document.getElementById('donate-message');
  msg.textContent = '';
  msg.className = 'text-xs mt-1 h-4';

  const fd = new FormData(form);
  const payload = {
    ip: fd.get('ip')?.toString().trim(),
    port: Number(fd.get('port')?.toString().trim()),
    username: fd.get('username')?.toString().trim(),
    authType: fd.get('authType')?.toString(),
    password: fd.get('password')?.toString(),
    privateKey: fd.get('privateKey')?.toString(),
    country: fd.get('country')?.toString().trim(),
    traffic: fd.get('traffic')?.toString().trim(),
    expiryDate: fd.get('expiryDate')?.toString().trim(),
    specs: fd.get('specs')?.toString().trim(),
    note: fd.get('note')?.toString().trim(),
  };
  try{
    const res = await fetch('/api/donate',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload),
    });
    const json = await res.json();
    if(!res.ok || !json.success){
      msg.textContent = json.message || '提交失败';
      msg.classList.add('text-red-400');
    }else{
      msg.textContent = json.message || '投喂成功';
      msg.classList.add('text-emerald-400');
      form.reset();
      loadDonations();
    }
  }catch(e){
    msg.textContent = '提交异常，请稍后重试';
    msg.classList.add('text-red-400');
  }
}
async function loadDonations(){
  const box = document.getElementById('donations-list');
  box.innerHTML = '<div class="text-slate-400 text-xs">正在加载...</div>';
  try{
    const res = await fetch('/api/user/donations');
    if(!res.ok){
      box.innerHTML = '<div class="text-red-400 text-xs">加载失败</div>';
      return;
    }
    const json = await res.json();
    if(!json.success){
      box.innerHTML = '<div class="text-red-400 text-xs">'+(json.message||'加载失败')+'</div>';
      return;
    }
    const data = json.data || [];
    if(!data.length){
      box.innerHTML = '<div class="text-slate-400 text-xs">还没有投喂记录，先在左侧提交一台吧～</div>';
      return;
    }
    box.innerHTML = '';
    data.forEach((vps)=>{
      const div = document.createElement('div');
      div.className = 'card rounded-xl border border-slate-800 bg-slate-950/60 px-3 py-2';

      const statusColor =
        vps.status === 'active' ? 'text-emerald-400' :
        vps.status === 'failed' ? 'text-red-400' :
        'text-slate-300';
      const statusText =
        vps.status === 'active' ? '已激活' :
        vps.status === 'failed' ? '验证失败' :
        '未激活';

      const dt = vps.donatedAt ? new Date(vps.donatedAt) : null;
      const donatedAtText = dt ? dt.toLocaleString() : '';

      const uname = vps.donatedByUsername || '';
      const profileUrl = 'https://linux.do/u/' + encodeURIComponent(uname);

      div.innerHTML =
        '<div class="flex items-center justify-between gap-2 mb-1">'+
          '<div class="text-[11px] text-slate-200">IP：'+vps.ip+':'+vps.port+'</div>'+
          '<div class="'+statusColor+' text-[11px]">'+statusText+'</div>'+
        '</div>'+
        '<div class="text-[11px] text-slate-300 mb-0.5">投喂者：<a href="'+profileUrl+'" target="_blank" class="underline text-sky-300 hover:text-cyan-300">@'+uname+'</a></div>'+
        '<div class="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-slate-300">'+
          '<span>地区：'+(vps.country||'未填写')+(vps.ipLocation?' · '+vps.ipLocation:'')+'</span>'+
          '<span>流量/带宽：'+(vps.traffic||'未填写')+'</span>'+
          '<span>到期：'+(vps.expiryDate||'未填写')+'</span>'+
        '</div>'+
        '<div class="text-[11px] text-slate-400 mt-1">配置：'+(vps.specs||'未填写')+'</div>'+
        (vps.note?'<div class="text-[11px] text-amber-300/80 mt-1">我的备注：'+vps.note+'</div>':'')+
        (donatedAtText?'<div class="text-[11px] text-slate-500 mt-1">投喂时间：'+donatedAtText+'</div>':'');

      box.appendChild(div);
    });
  }catch(e){
    box.innerHTML = '<div class="text-red-400 text-xs">加载异常</div>';
  }
}
ensureLogin();
bindAuthTypeSwitch();
document.getElementById('donate-form').addEventListener('submit', submitDonateForm);
loadDonations();
</script>
</body>
</html>`;
  return c.html(html);
});

// ==================== 管理后台 /admin 页面 ====================
app.get('/admin', (c) => {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<title>风萧萧兮公益机场 · VPS 管理后台</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<script src="https://cdn.tailwindcss.com"></script>
<style>
:root { color-scheme: dark; }
body[data-theme="light"]{background-color:#f8fafc;color:#020617;color-scheme:light;}
.panel,.card,.stat-card{transition:background-color .2s ease,color .2s ease,border-color .2s ease;}
body[data-theme="light"] .panel,
body[data-theme="light"] .card,
body[data-theme="light"] .stat-card{background-color:#ffffff;border-color:#e2e8f0;color:#0f172a;}
body[data-theme="light"] .stat-card-dark{background-color:#f1f5f9;}
</style>
</head>
<body class="min-h-screen bg-slate-950 text-slate-100" data-theme="dark">
<script>
(function(){
  const saved = localStorage.getItem('theme') || 'dark';
  document.body.setAttribute('data-theme', saved);
  document.documentElement.setAttribute('data-theme', saved);
})();
</script>

<div class="max-w-7xl mx-auto px-4 py-8" id="app-root">
  <div class="text-slate-300 text-sm">正在检测管理员登录状态...</div>
</div>

<script>
let allVpsList = [];
let statusFilter = 'all';
let userFilter = '';

function updateThemeToggleText(){
  const btn = document.getElementById('theme-toggle');
  if(!btn) return;
  const theme = document.body.getAttribute('data-theme') || 'dark';
  btn.textContent = theme === 'dark' ? '浅色模式' : '深色模式';
}
function toggleTheme(){
  const cur = document.body.getAttribute('data-theme') || 'dark';
  const next = cur === 'dark' ? 'light' : 'dark';
  document.body.setAttribute('data-theme', next);
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
  updateThemeToggleText();
}

async function checkAdmin(){
  const root = document.getElementById('app-root');
  try{
    const res = await fetch('/api/admin/check-session');
    const json = await res.json();
    if(!json.success || !json.isAdmin){
      renderLogin(root);
    }else{
      renderAdmin(root, json.username);
      await loadStats();
      await loadVps();
    }
  }catch(e){
    root.innerHTML = '<div class="text-red-400 text-sm">加载失败</div>';
  }
}

function renderLogin(root){
  root.innerHTML = '';
  const wrap = document.createElement('div');
  wrap.className = 'panel max-w-sm mx-auto rounded-2xl border border-slate-800 bg-slate-900/80 p-6 shadow-lg shadow-slate-900/80';
  wrap.innerHTML =
    '<h1 class="text-xl font-semibold mb-4">管理员登录</h1>'+
    '<p class="text-xs text-slate-400 mb-4">请输入在后端配置的管理员密码。</p>'+
    '<form id="admin-login-form" class="space-y-3 text-sm">'+
      '<div>'+
        '<label class="block mb-1 text-xs text-slate-300">密码</label>'+
        '<input type="password" name="password" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" />'+
      '</div>'+
      '<div id="admin-login-msg" class="text-[11px] h-4"></div>'+
      '<button type="submit" class="mt-1 inline-flex items-center justify-center rounded-xl bg-cyan-500 px-4 py-2 text-xs font-semibold hover:bg-cyan-400">登录</button>'+
    '</form>';
  root.appendChild(wrap);

  document.getElementById('admin-login-form').addEventListener('submit', async (e)=>{
    e.preventDefault();
    const msg = document.getElementById('admin-login-msg');
    msg.textContent = '';
    msg.className = 'text-[11px] h-4';
    const fd = new FormData(e.target);
    const password = fd.get('password')?.toString() || '';
    try{
      const res = await fetch('/api/admin/login',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({password}),
      });
      const json = await res.json();
      if(!res.ok || !json.success){
        msg.textContent = json.message || '登录失败';
        msg.classList.add('text-red-400');
      }else{
        location.reload();
      }
    }catch(e){
      msg.textContent = '登录异常';
      msg.classList.add('text-red-400');
    }
  });
}

function renderAdmin(root, adminName){
  root.innerHTML = '';
  const header = document.createElement('header');
  header.className = 'mb-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4';
  header.innerHTML =
    '<div>'+
      '<h1 class="text-2xl md:text-3xl font-bold bg-gradient-to-r from-cyan-400 to-indigo-400 bg-clip-text text-transparent">VPS 管理后台</h1>'+
      '<p class="mt-2 text-xs text-slate-400">仅管理员可见，可查看全部投喂 VPS 与认证信息。</p>'+
    '</div>'+
    '<div class="flex items-center gap-3">'+
      '<span class="text-xs text-slate-300">管理员：'+adminName+'</span>'+
      '<button id="theme-toggle" class="text-[11px] rounded-lg border border-slate-700 px-2 py-1 hover:bg-slate-800 mr-1">浅色模式</button>'+
      '<button id="btn-admin-logout" class="text-[11px] rounded-lg border border-slate-700 px-2 py-1 hover:bg-slate-800">退出</button>'+
    '</div>';
  root.appendChild(header);
  updateThemeToggleText();
  document.getElementById('theme-toggle').addEventListener('click',toggleTheme);
  document.getElementById('btn-admin-logout').addEventListener('click',adminLogout);

  const statsWrap = document.createElement('section');
  statsWrap.id = 'admin-stats';
  root.appendChild(statsWrap);

  const listWrap = document.createElement('section');
  listWrap.className = 'mt-6';
  listWrap.innerHTML =
    '<div class="flex items-center justify-between mb-2">'+
      '<h2 class="text-lg font-semibold">VPS 列表</h2>'+
      '<div class="flex items-center gap-2 text-[11px] text-slate-400">'+
        '<span>状态筛选：</span>'+
        '<button data-status-filter="all" class="px-2 py-1 rounded-lg border border-slate-700 hover:bg-slate-800">全部</button>'+
        '<button data-status-filter="active" class="px-2 py-1 rounded-lg border border-emerald-500/40 text-emerald-300 hover:bg-slate-800">活跃</button>'+
        '<button data-status-filter="failed" class="px-2 py-1 rounded-lg border border-red-500/40 text-red-300 hover:bg-slate-800">失败</button>'+
        '<button data-status-filter="inactive" class="px-2 py-1 rounded-lg border border-slate-500/40 text-slate-200 hover:bg-slate-800">未激活</button>'+
      '</div>'+
    '</div>'+
    '<div id="vps-list" class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4"></div>';
  root.appendChild(listWrap);

  listWrap.querySelectorAll('button[data-status-filter]').forEach((btn)=>{
    btn.addEventListener('click',()=>{
      statusFilter = btn.getAttribute('data-status-filter') || 'all';
      userFilter = '';
      renderVpsList();
    });
  });
}

async function adminLogout(){
  try{await fetch('/api/admin/logout');}catch(e){}
  location.reload();
}

function statCard(label,value,filterKey){
  return (
    '<button data-stat-filter="'+filterKey+'" class="stat-card stat-card-dark rounded-2xl border border-slate-800 bg-slate-900/70 px-3 py-2 text-left hover:bg-slate-900">'+
      '<div class="text-[11px] text-slate-400">'+label+'</div>'+
      '<div class="text-lg font-semibold mt-1">'+value+'</div>'+
    '</button>'
  );
}

async function loadStats(){
  const wrap = document.getElementById('admin-stats');
  wrap.innerHTML = '<div class="text-xs text-slate-400 mb-3">正在加载统计信息...</div>';
  try{
    const res = await fetch('/api/admin/stats');
    const json = await res.json();
    if(!res.ok || !json.success){
      wrap.innerHTML = '<div class="text-red-400 text-xs mb-3">统计信息加载失败</div>';
      return;
    }
    const d = json.data || {};
    wrap.innerHTML =
      '<div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-3">'+
        statCard('总投喂数',d.totalVPS||0,'all')+
        statCard('活跃服务器',d.activeVPS||0,'active')+
        statCard('未激活',d.inactiveVPS||0,'inactive')+
        statCard('验证失败',d.failedVPS||0,'failed')+
        statCard('待验证',d.pendingVPS||0,'pending')+
        statCard('今日新增',d.todayNewVPS||0,'today')+
      '</div>'+
      '<div class="flex justify-end mb-2">'+
        '<button id="btn-batch-verify" class="text-[11px] rounded-lg border border-cyan-500/60 text-cyan-300 px-3 py-1 hover:bg-slate-900">🛠 一键验证 VPS 状态</button>'+
      '</div>';

    wrap.querySelectorAll('button[data-stat-filter]').forEach((btn)=>{
      btn.addEventListener('click',()=>{
        const key = btn.getAttribute('data-stat-filter');
        if(key==='active' || key==='inactive' || key==='failed' || key==='pending'){
          statusFilter = key==='pending' ? 'pending' : key;
        }else{
          statusFilter = 'all';
        }
        userFilter = '';
        renderVpsList();
      });
    });

    const batchBtn = document.getElementById('btn-batch-verify');
    batchBtn.addEventListener('click',async ()=>{
      if(!confirm('确认对所有 VPS 执行一键验证？')) return;
      try{
        const r = await fetch('/api/admin/vps/batch-verify',{method:'POST'});
        const j = await r.json();
        alert(j.message || '批量验证完成');
      }catch(e){
        alert('批量验证失败');
      }
      await loadVps();
      await loadStats();
    });
  }catch(e){
    wrap.innerHTML = '<div class="text-red-400 text-xs mb-3">统计信息加载异常</div>';
  }
}

async function loadVps(){
  const list = document.getElementById('vps-list');
  list.innerHTML = '<div class="text-xs text-slate-400">正在加载 VPS...</div>';
  try{
    const res = await fetch('/api/admin/vps');
    const json = await res.json();
    if(!res.ok || !json.success){
      list.innerHTML = '<div class="text-red-400 text-xs">加载失败</div>';
      return;
    }
    allVpsList = json.data || [];
    renderVpsList();
  }catch(e){
    list.innerHTML = '<div class="text-red-400 text-xs">加载异常</div>';
  }
}

function renderVpsList(){
  const list = document.getElementById('vps-list');
  if(!allVpsList.length){
    list.innerHTML = '<div class="text-xs text-slate-400 col-span-full">暂无 VPS 记录</div>';
    return;
  }
  const filtered = allVpsList.filter((v)=>{
    let ok = true;
    if(statusFilter==='active') ok = v.status==='active';
    else if(statusFilter==='inactive') ok = v.status==='inactive';
    else if(statusFilter==='failed') ok = v.status==='failed';
    else if(statusFilter==='pending') ok = v.verifyStatus==='pending';
    if(userFilter) ok = ok && v.donatedByUsername===userFilter;
    return ok;
  });
  if(!filtered.length){
    list.innerHTML = '<div class="text-xs text-slate-400 col-span-full">当前筛选下没有 VPS</div>';
    return;
  }

  list.innerHTML = '';
  filtered.forEach((v)=>{
    const card = document.createElement('div');
    card.className = 'card rounded-2xl border border-slate-800 bg-slate-900/80 p-3 flex flex-col gap-2 text-xs';

    const statusColor =
      v.status==='active' ? 'text-emerald-400' :
      v.status==='failed' ? 'text-red-400' :
      'text-slate-300';
    const statusText =
      v.status==='active' ? '已激活' :
      v.status==='failed' ? '验证失败' :
      '未激活';

    const dt = v.donatedAt ? new Date(v.donatedAt) : null;
    const donatedAtText = dt ? dt.toLocaleString() : '';

    const uname = v.donatedByUsername || '';
    const profileUrl = 'https://linux.do/u/' + encodeURIComponent(uname);

    card.innerHTML =
      '<div class="flex items-center justify-between gap-2">'+
        '<div class="text-[11px] text-slate-200">IP：'+v.ip+':'+v.port+'</div>'+
        '<div class="'+statusColor+' text-[11px]">'+statusText+'</div>'+
      '</div>'+
      '<div class="flex flex-wrap gap-2 text-[11px] text-slate-300">'+
        '<span>投喂者：<a href="'+profileUrl+'" target="_blank" class="underline hover:text-cyan-400">@'+uname+'</a></span>'+
        '<span>地区：'+(v.country||'未填写')+(v.ipLocation?' · '+v.ipLocation:'')+'</span>'+
      '</div>'+
      '<div class="flex flex-wrap gap-2 text-[11px] text-slate-300">'+
        '<span>流量/带宽：'+(v.traffic||'未填写')+'</span>'+
        '<span>到期：'+(v.expiryDate||'未填写')+'</span>'+
      '</div>'+
      '<div class="text-[11px] text-slate-400">配置：'+(v.specs||'未填写')+'</div>'+
      (v.note?'<div class="text-[11px] text-amber-300/80">用户备注：'+v.note+'</div>':'')+
      (v.adminNote?'<div class="text-[11px] text-cyan-300/80">管理员备注：'+v.adminNote+'</div>':'')+
      (donatedAtText?'<div class="text-[11px] text-slate-500">投喂时间：'+donatedAtText+'</div>':'')+
      '<details class="mt-1">'+
        '<summary class="cursor-pointer text-[11px] text-cyan-300">查看详情</summary>'+
        '<div class="mt-1 space-y-1 text-[11px] text-slate-300">'+
          '<div>SSH 用户：'+v.username+'</div>'+
          '<div>认证方式：'+v.authType+'</div>'+
          (v.authType==='password' && v.password ? '<div>密码：'+v.password+'</div>' : '')+
          (v.authType==='key' && v.privateKey ? '<div class="break-all whitespace-pre-wrap">私钥：<br>'+v.privateKey+'</div>' : '')+
          '<div>验证状态：'+(v.verifyStatus||'unknown')+(v.verifyErrorMsg?' · '+v.verifyErrorMsg:'')+'</div>'+
          '<div class="flex flex-wrap gap-2 mt-1">'+
            '<button class="px-2 py-1 rounded-lg border border-emerald-500/40 text-emerald-300 hover:bg-slate-800" data-action="mark" data-id="'+v.id+'">标记通过</button>'+
            '<button class="px-2 py-1 rounded-lg border border-slate-500/40 text-slate-200 hover:bg-slate-800" data-action="inactive" data-id="'+v.id+'">设为未激活</button>'+
            '<button class="px-2 py-1 rounded-lg border border-red-500/40 text-red-300 hover:bg-slate-800" data-action="failed" data-id="'+v.id+'">设为失败</button>'+
            '<button class="px-2 py-1 rounded-lg border border-amber-500/40 text-amber-300 hover:bg-slate-800" data-action="edit-notes" data-id="'+v.id+'" data-note="'+(v.note||'').replace(/"/g,'&quot;')+'" data-adminnote="'+(v.adminNote||'').replace(/"/g,'&quot;')+'">编辑备注</button>'+
            '<button class="px-2 py-1 rounded-lg border border-red-500/40 text-red-300 hover:bg-slate-900" data-action="delete" data-id="'+v.id+'">删除</button>'+
          '</div>'+
        '</div>'+
      '</details>';

    const userBtn = card.querySelector('a[href^="https://linux.do/u/"]');
    if(userBtn){
      userBtn.addEventListener('click',(e)=>{ e.stopPropagation(); });
    }
    card.querySelectorAll('button[data-action]').forEach((btn)=>{
      const id = btn.getAttribute('data-id');
      const action = btn.getAttribute('data-action');
      btn.addEventListener('click',async ()=>{
        if(!id) return;
        if(action==='mark'){
          if(!confirm('确定将此 VPS 标记为验证通过并激活？')) return;
          await fetch('/api/admin/vps/'+id+'/mark-verified',{method:'POST'});
        }else if(action==='inactive' || action==='failed'){
          if(!confirm('确定修改状态为 '+action+' ?')) return;
          await fetch('/api/admin/vps/'+id+'/status',{
            method:'PUT',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({status:action}),
          });
        }else if(action==='delete'){
          if(!confirm('确定删除此 VPS 记录？')) return;
          await fetch('/api/admin/vps/'+id,{method:'DELETE'});
        }else if(action==='edit-notes'){
          const curNote = btn.getAttribute('data-note') || '';
          const curAdmin = btn.getAttribute('data-adminnote') || '';
          const newNote = prompt('用户备注（可以修改）：',curNote);
          if(newNote===null) return;
          const newAdmin = prompt('管理员备注（可以修改）：',curAdmin);
          if(newAdmin===null) return;
          await fetch('/api/admin/vps/'+id+'/notes',{
            method:'PUT',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({note:newNote,adminNote:newAdmin}),
          });
        }
        await loadVps();
        await loadStats();
      });
    });

    const filterBtn = card.querySelector('span a.underline');
    if(filterBtn){
      filterBtn.addEventListener('click',(e)=>{
        e.preventDefault();
        userFilter = v.donatedByUsername;
        renderVpsList();
        window.open(filterBtn.getAttribute('href'),'_blank');
      });
    }

    list.appendChild(card);
  });
}

checkAdmin();
</script>
</body>
</html>`;
  return c.html(html);
});

// ==================== 导出 ====================
export default app;
