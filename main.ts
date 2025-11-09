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

// ==================== Deno KV 初始化 ====================
const kv = await Deno.openKv();

// ==================== 工具函数 ====================
function generateId(): string {
  return crypto.randomUUID();
}

function generateSessionId(): string {
  return crypto.randomUUID();
}

async function getIPLocation(ip: string): Promise<string> {
  try {
    const response = await fetch(`http://ip-api.com/json/${ip}?fields=country,regionName,city`);
    if (response.ok) {
      const data = await response.json();
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

function isValidIPv4(ip: string): boolean {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(ip)) return false;
  const parts = ip.split('.');
  return parts.every(part => {
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255;
  });
}

function isValidIPv6(ip: string): boolean {
  const cleanIp = ip.replace(/^\[|\]$/g, '');
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
  return ipv6Regex.test(cleanIp);
}

function isValidIP(ip: string): boolean {
  return isValidIPv4(ip) || isValidIPv6(ip);
}

async function checkIPExists(ip: string, port: number): Promise<boolean> {
  const allVPS = await getAllVPS();
  return allVPS.some(vps => vps.ip === ip && vps.port === port);
}

async function checkPortReachable(ip: string, port: number): Promise<boolean> {
  try {
    const cleanIp = ip.replace(/^\[|\]$/g, '');
    const conn = await Deno.connect({
      hostname: cleanIp,
      port,
      transport: 'tcp'
    });
    conn.close();
    return true;
  } catch {
    return false;
  }
}

async function batchVerifyVPS(): Promise<{ total: number; success: number; failed: number; details: any[] }> {
  const allVPS = await getAllVPS();
  const pendingVPS = allVPS.filter(v => v.verifyStatus === 'pending');

  let successCount = 0;
  let failedCount = 0;
  const details = [];

  for (const vps of pendingVPS) {
    try {
      const portReachable = await checkPortReachable(vps.ip, vps.port);
      if (portReachable) {
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
    } catch (error: any) {
      vps.verifyStatus = 'failed';
      vps.status = 'failed';
      vps.lastVerifyAt = Date.now();
      vps.verifyErrorMsg = error.message || '验证过程中发生错误';
      await kv.set(['vps', vps.id], vps);
      failedCount++;
      details.push({ id: vps.id, ip: vps.ip, status: 'failed', error: vps.verifyErrorMsg });
    }
  }

  return { total: pendingVPS.length, success: successCount, failed: failedCount, details };
}

// ==================== KV 数据操作 ====================
async function getOAuthConfig(): Promise<OAuthConfig | null> {
  const result = await kv.get<OAuthConfig>(['config', 'oauth']);
  return result.value;
}

async function setOAuthConfig(config: OAuthConfig): Promise<void> {
  await kv.set(['config', 'oauth'], config);
}

async function getAdminPassword(): Promise<string> {
  const result = await kv.get<string>(['config', 'admin_password']);
  return result.value || 'admin123';
}

async function setAdminPassword(password: string): Promise<void> {
  await kv.set(['config', 'admin_password'], password);
}

async function getSession(sessionId: string): Promise<Session | null> {
  const result = await kv.get<Session>(['sessions', sessionId]);
  if (!result.value) return null;
  if (result.value.expiresAt < Date.now()) {
    await kv.delete(['sessions', sessionId]);
    return null;
  }
  return result.value;
}

async function createSession(userId: string, username: string, avatarUrl: string | undefined, isAdmin: boolean): Promise<string> {
  const sessionId = generateSessionId();
  const session: Session = {
    id: sessionId,
    userId,
    username,
    avatarUrl,
    isAdmin,
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
  };
  await kv.set(['sessions', sessionId], session);
  return sessionId;
}

async function getUser(linuxDoId: string): Promise<User | null> {
  const result = await kv.get<User>(['users', linuxDoId]);
  return result.value;
}

async function createOrUpdateUser(linuxDoId: string, username: string, avatarUrl?: string): Promise<User> {
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
  const userDonations = await kv.get<string[]>(['user_donations', server.donatedBy]);
  const donations = userDonations.value || [];
  donations.push(id);
  await kv.set(['user_donations', server.donatedBy], donations);
  return vps;
}

async function getAllVPS(): Promise<VPSServer[]> {
  const entries = kv.list<VPSServer>({ prefix: ['vps'] });
  const servers: VPSServer[] = [];
  for await (const entry of entries) {
    servers.push(entry.value);
  }
  return servers.sort((a, b) => b.donatedAt - a.donatedAt);
}

async function getUserDonations(linuxDoId: string): Promise<VPSServer[]> {
  const userDonations = await kv.get<string[]>(['user_donations', linuxDoId]);
  const donationIds = userDonations.value || [];
  const servers: VPSServer[] = [];
  for (const id of donationIds) {
    const result = await kv.get<VPSServer>(['vps', id]);
    if (result.value) {
      servers.push(result.value);
    }
  }
  return servers.sort((a, b) => b.donatedAt - a.donatedAt);
}

async function deleteVPS(id: string): Promise<boolean> {
  const vps = await kv.get<VPSServer>(['vps', id]);
  if (!vps.value) return false;
  await kv.delete(['vps', id]);
  const userDonations = await kv.get<string[]>(['user_donations', vps.value.donatedBy]);
  if (userDonations.value) {
    const filtered = userDonations.value.filter(vid => vid !== id);
    await kv.set(['user_donations', vps.value.donatedBy], filtered);
  }
  return true;
}

async function updateVPSStatus(id: string, status: 'active' | 'inactive' | 'failed'): Promise<boolean> {
  const result = await kv.get<VPSServer>(['vps', id]);
  if (!result.value) return false;
  result.value.status = status;
  await kv.set(['vps', id], result.value);
  return true;
}

// ==================== OAuth 函数 ====================
async function exchangeCodeForToken(code: string, config: OAuthConfig): Promise<any> {
  const response = await fetch('https://connect.linux.do/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code: code,
      redirect_uri: config.redirectUri,
      grant_type: 'authorization_code',
    }),
  });
  return await response.json();
}

async function getLinuxDoUserInfo(accessToken: string): Promise<any> {
  const response = await fetch('https://connect.linux.do/api/user', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  return await response.json();
}

// ==================== 中间件 ====================
async function requireAuth(c: any, next: any) {
  const sessionId = getCookie(c, 'session_id');
  if (!sessionId) {
    return c.json({ success: false, message: '未登录' }, 401);
  }
  const session = await getSession(sessionId);
  if (!session) {
    return c.json({ success: false, message: '会话已过期' }, 401);
  }
  c.set('session', session);
  await next();
}

async function requireAdmin(c: any, next: any) {
  const sessionId = getCookie(c, 'admin_session_id');
  if (!sessionId) {
    return c.json({ success: false, message: '未登录' }, 401);
  }
  const session = await getSession(sessionId);
  if (!session || !session.isAdmin) {
    return c.json({ success: false, message: '需要管理员权限' }, 403);
  }
  c.set('session', session);
  await next();
}

// ==================== 创建应用 ====================
const app = new Hono();
app.use('*', cors());

// ==================== API 路由 ====================

app.get('/oauth/callback', async (c) => {
  const code = c.req.query('code');
  const error = c.req.query('error');

  if (error) {
    return c.html(`<!DOCTYPE html><html><body><h1>登录失败</h1><p>OAuth 认证失败: ${error}</p><a href="/">返回首页</a></body></html>`);
  }

  if (!code) {
    return c.text('Missing code', 400);
  }

  try {
    const config = await getOAuthConfig();
    if (!config) {
      return c.html(`<!DOCTYPE html><html><body><h1>配置错误</h1><p>OAuth 配置未设置，请联系管理员</p><a href="/">返回首页</a></body></html>`);
    }

    const tokenData = await exchangeCodeForToken(code, config);
    const userInfo = await getLinuxDoUserInfo(tokenData.access_token);

    let avatarUrl = userInfo.avatar_template;
    if (avatarUrl) {
      avatarUrl = avatarUrl.replace('{size}', '120');
      if (avatarUrl.startsWith('//')) {
        avatarUrl = 'https:' + avatarUrl;
      } else if (avatarUrl.startsWith('/')) {
        avatarUrl = 'https://connect.linux.do' + avatarUrl;
      }
    }

    const user = await createOrUpdateUser(userInfo.id.toString(), userInfo.username, avatarUrl);
    const sessionId = await createSession(user.linuxDoId, user.username, user.avatarUrl, user.isAdmin);
    const isProduction = Deno.env.get('DENO_DEPLOYMENT_ID') !== undefined;

    setCookie(c, 'session_id', sessionId, {
      maxAge: 7 * 24 * 60 * 60,
      httpOnly: true,
      secure: isProduction,
      sameSite: 'Lax',
      path: '/',
    });

    return c.redirect('/');
  } catch (e: any) {
    console.error('OAuth callback failed:', e);
    return c.html(`<!DOCTYPE html><html><body><h1>登录失败</h1><p>错误详情: ${e.message}</p><a href="/">返回首页</a></body></html>`);
  }
});

app.get('/api/logout', async (c) => {
  const sessionId = getCookie(c, 'session_id');
  if (sessionId) {
    await kv.delete(['sessions', sessionId]);
  }
  setCookie(c, 'session_id', '', { maxAge: 0, path: '/' });
  return c.json({ success: true });
});

app.get('/api/user/info', requireAuth, async (c) => {
  const session = c.get('session');
  const donations = await getUserDonations(session.userId);
  return c.json({
    success: true,
    data: {
      username: session.username,
      avatarUrl: session.avatarUrl,
      isAdmin: session.isAdmin,
      donationCount: donations.length,
    },
  });
});

app.get('/api/user/donations', requireAuth, async (c) => {
  const session = c.get('session');
  const donations = await getUserDonations(session.userId);
  const safeDonations = donations.map(d => ({
    id: d.id,
    ipLocation: d.ipLocation,
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
    verifyStatus: d.verifyStatus,
    lastVerifyAt: d.lastVerifyAt,
    verifyErrorMsg: d.verifyErrorMsg,
  }));
  return c.json({ success: true, data: safeDonations });
});

app.put('/api/user/donations/:id/note', requireAuth, async (c) => {
  const session = c.get('session');
  const id = c.req.param('id');
  const { note } = await c.req.json();
  const result = await kv.get<VPSServer>(['vps', id]);
  if (!result.value) {
    return c.json({ success: false, message: 'VPS 不存在' }, 404);
  }
  if (result.value.donatedBy !== session.userId) {
    return c.json({ success: false, message: '无权修改此VPS' }, 403);
  }
  result.value.note = note || '';
  await kv.set(['vps', id], result.value);
  return c.json({ success: true, message: '备注已更新' });
});

app.get('/api/leaderboard', async (c) => {
  const allVPS = await getAllVPS();
  const userStats = new Map<string, {
    username: string;
    count: number;
    servers: Array<{
      ipLocation: string;
      port: number;
      country: string;
      traffic: string;
      expiryDate: string;
      specs: string;
      note?: string;
      adminNote?: string;
      status: string;
      donatedAt: number;
    }>;
  }>();

  for (const vps of allVPS) {
    const stats = userStats.get(vps.donatedBy) || {
      username: vps.donatedByUsername,
      count: 0,
      servers: []
    };
    stats.count++;
    stats.servers.push({
      ipLocation: vps.ipLocation || '未知地区',
      port: vps.port,
      country: vps.country || '未填写',
      traffic: vps.traffic || '未填写',
      expiryDate: vps.expiryDate || '未填写',
      specs: vps.specs || '未填写',
      note: vps.note,
      adminNote: vps.adminNote,
      status: vps.status,
      donatedAt: vps.donatedAt
    });
    userStats.set(vps.donatedBy, stats);
  }

  const leaderboard = Array.from(userStats.values()).sort((a, b) => b.count - a.count);
  return c.json({ success: true, data: leaderboard });
});

app.get('/api/user/:username/donations', async (c) => {
  const username = c.req.param('username');
  const allVPS = await getAllVPS();
  const userVPS = allVPS.filter(vps => vps.donatedByUsername === username);
  const donations = userVPS.map(vps => ({
    ipLocation: vps.ipLocation || '未知地区',
    port: vps.port,
    country: vps.country || '未填写',
    traffic: vps.traffic || '未填写',
    expiryDate: vps.expiryDate || '未填写',
    specs: vps.specs || '未填写',
    note: vps.note,
    adminNote: vps.adminNote,
    status: vps.status,
    donatedAt: vps.donatedAt,
  }));
  return c.json({
    success: true,
    data: { username, count: donations.length, donations }
  });
});

app.post('/api/donate', requireAuth, async (c) => {
  const session = c.get('session');
  const body = await c.req.json();
  const { ip, port, username, authType, password, privateKey, note, country, traffic, expiryDate, specs } = body;

  if (!ip || !port || !username || !authType) {
    return c.json({ success: false, message: 'IP、端口、用户名和认证类型为必填项' }, 400);
  }

  if (!country || !traffic || !expiryDate || !specs) {
    return c.json({ success: false, message: '国家、流量、到期时间和配置为必填项' }, 400);
  }

  if (authType === 'password' && !password) {
    return c.json({ success: false, message: '密码认证需要提供密码' }, 400);
  }

  if (authType === 'key' && !privateKey) {
    return c.json({ success: false, message: '密钥认证需要提供私钥' }, 400);
  }

  if (!isValidIP(ip)) {
    return c.json({ success: false, message: 'IP 地址格式不正确（支持 IPv4 和 IPv6）' }, 400);
  }

  if (port < 1 || port > 65535) {
    return c.json({ success: false, message: '端口号必须在 1-65535 之间' }, 400);
  }

  const ipExists = await checkIPExists(ip, parseInt(port));
  if (ipExists) {
    return c.json({ success: false, message: '该 IP 和端口已经被投喂过了' }, 400);
  }

  const portReachable = await checkPortReachable(ip, parseInt(port));
  if (!portReachable) {
    return c.json({ success: false, message: '无法连接到该服务器，请检查 IP 和端口是否正确' }, 400);
  }

  try {
    const ipLocation = await getIPLocation(ip);
    const vps = await addVPSServer({
      ip,
      port: parseInt(port),
      username,
      authType,
      password: authType === 'password' ? password : undefined,
      privateKey: authType === 'key' ? privateKey : undefined,
      donatedBy: session.userId,
      donatedByUsername: session.username,
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
    });

    return c.json({
      success: true,
      message: '✅ 投喂成功！VPS 已自动验证并激活',
      data: { id: vps.id, ipLocation: vps.ipLocation },
    });
  } catch (e: any) {
    console.error('[Donate] ❌ 投喂失败:', e);
    return c.json({ success: false, message: '投喂失败: ' + e.message }, 500);
  }
});

// ==================== 管理员 API ====================

app.get('/api/admin/check-session', async (c) => {
  const sessionId = getCookie(c, 'admin_session_id');
  if (!sessionId) {
    return c.json({ success: false, isAdmin: false });
  }
  const session = await getSession(sessionId);
  if (!session || session.expiresAt < Date.now()) {
    return c.json({ success: false, isAdmin: false });
  }
  return c.json({
    success: true,
    isAdmin: session.isAdmin || false,
    username: session.username
  });
});

app.post('/api/admin/login', async (c) => {
  const { password } = await c.req.json();
  const adminPassword = await getAdminPassword();
  if (password !== adminPassword) {
    return c.json({ success: false, message: '密码错误' }, 401);
  }
  const sessionId = generateSessionId();
  const adminSession: Session = {
    id: sessionId,
    userId: 'admin',
    username: 'Administrator',
    avatarUrl: undefined,
    isAdmin: true,
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
  };
  await kv.set(['sessions', sessionId], adminSession);
  const isProduction = Deno.env.get('DENO_DEPLOYMENT_ID') !== undefined;
  setCookie(c, 'admin_session_id', sessionId, {
    maxAge: 7 * 24 * 60 * 60,
    httpOnly: true,
    secure: isProduction,
    sameSite: 'Lax',
    path: '/',
  });
  return c.json({ success: true, message: '登录成功' });
});

app.get('/api/admin/logout', async (c) => {
  const sessionId = getCookie(c, 'admin_session_id');
  if (sessionId) {
    await kv.delete(['sessions', sessionId]);
  }
  setCookie(c, 'admin_session_id', '', { maxAge: 0, path: '/' });
  return c.json({ success: true });
});

app.get('/api/admin/vps', requireAdmin, async (c) => {
  const servers = await getAllVPS();
  return c.json({ success: true, data: servers });
});

app.delete('/api/admin/vps/:id', requireAdmin, async (c) => {
  const id = c.req.param('id');
  const success = await deleteVPS(id);
  if (success) {
    return c.json({ success: true, message: 'VPS 已删除' });
  } else {
    return c.json({ success: false, message: 'VPS 不存在' }, 404);
  }
});

app.put('/api/admin/vps/:id/status', requireAdmin, async (c) => {
  const id = c.req.param('id');
  const { status } = await c.req.json();
  if (status !== 'active' && status !== 'inactive' && status !== 'failed') {
    return c.json({ success: false, message: '无效的状态' }, 400);
  }
  const success = await updateVPSStatus(id, status);
  if (success) {
    return c.json({ success: true, message: '状态已更新' });
  } else {
    return c.json({ success: false, message: 'VPS 不存在' }, 404);
  }
});

app.put('/api/admin/vps/:id/notes', requireAdmin, async (c) => {
  const id = c.req.param('id');
  const { note, adminNote, country, traffic, expiryDate, specs } = await c.req.json();
  const result = await kv.get<VPSServer>(['vps', id]);
  if (!result.value) {
    return c.json({ success: false, message: 'VPS 不存在' }, 404);
  }
  if (note !== undefined) result.value.note = note;
  if (adminNote !== undefined) result.value.adminNote = adminNote;
  if (country !== undefined) result.value.country = country;
  if (traffic !== undefined) result.value.traffic = traffic;
  if (expiryDate !== undefined) result.value.expiryDate = expiryDate;
  if (specs !== undefined) result.value.specs = specs;
  await kv.set(['vps', id], result.value);
  return c.json({ success: true, message: '信息已更新' });
});

app.get('/api/admin/config/oauth', requireAdmin, async (c) => {
  const config = await getOAuthConfig();
  return c.json({ success: true, data: config || {} });
});

app.put('/api/admin/config/oauth', requireAdmin, async (c) => {
  const { clientId, clientSecret, redirectUri } = await c.req.json();
  if (!clientId || !clientSecret || !redirectUri) {
    return c.json({ success: false, message: '所有字段都是必填的' }, 400);
  }
  await setOAuthConfig({ clientId, clientSecret, redirectUri });
  return c.json({ success: true, message: 'OAuth 配置已更新' });
});

app.put('/api/admin/config/password', requireAdmin, async (c) => {
  const { password } = await c.req.json();
  if (!password || password.length < 6) {
    return c.json({ success: false, message: '密码至少需要 6 个字符' }, 400);
  }
  await setAdminPassword(password);
  return c.json({ success: true, message: '管理员密码已更新' });
});

app.get('/api/admin/stats', requireAdmin, async (c) => {
  const allVPS = await getAllVPS();
  const activeVPS = allVPS.filter(v => v.status === 'active');
  const failedVPS = allVPS.filter(v => v.status === 'failed');
  const pendingVPS = allVPS.filter(v => v.verifyStatus === 'pending');
  const verifiedVPS = allVPS.filter(v => v.verifyStatus === 'verified');
  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);
  const todayNewVPS = allVPS.filter(v => v.donatedAt >= todayStart.getTime());
  const userStats = new Map<string, number>();
  for (const vps of allVPS) {
    const count = userStats.get(vps.donatedByUsername) || 0;
    userStats.set(vps.donatedByUsername, count + 1);
  }
  const topDonors = Array.from(userStats.entries())
    .map(([username, count]) => ({ username, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
  return c.json({
    success: true,
    data: {
      totalVPS: allVPS.length,
      activeVPS: activeVPS.length,
      failedVPS: failedVPS.length,
      inactiveVPS: allVPS.length - activeVPS.length - failedVPS.length,
      pendingVPS: pendingVPS.length,
      verifiedVPS: verifiedVPS.length,
      todayNewVPS: todayNewVPS.length,
      topDonors,
    },
  });
});

app.post('/api/admin/vps/:id/mark-verified', requireAdmin, async (c) => {
  const id = c.req.param('id');
  const result = await kv.get<VPSServer>(['vps', id]);
  if (!result.value) {
    return c.json({ success: false, message: 'VPS 不存在' }, 404);
  }
  const vps = result.value;
  vps.verifyStatus = 'verified';
  vps.status = 'active';
  vps.lastVerifyAt = Date.now();
  await kv.set(['vps', id], vps);
  return c.json({ success: true, message: 'VPS 已标记为验证通过' });
});

app.post('/api/admin/vps/batch-verify', requireAdmin, async (c) => {
  try {
    const result = await batchVerifyVPS();
    return c.json({
      success: true,
      message: `验证完成！成功: ${result.success}，失败: ${result.failed}`,
      data: result
    });
  } catch (error: any) {
    return c.json({ success: false, message: '批量验证失败: ' + error.message }, 500);
  }
});

// ==================== 页面路由 ====================

app.get('/', async (c) => {
  const config = await getOAuthConfig();
  const html = generateHomeHTML(config?.clientId || '');
  return c.html(html);
});

app.get('/donate', async (c) => {
  const config = await getOAuthConfig();
  const html = generateDonateHTML(config?.clientId || '');
  return c.html(html);
});

app.get('/admin', async (c) => {
  const html = generateAdminHTML();
  return c.html(html);
});

// ==================== HTML 生成函数 ====================

function generateHomeHTML(clientId: string): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>风萧萧公益-闲置小鸡投喂站</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    .animate-in { animation: fadeIn 0.5s ease-out; }
    .card-hover { transition: all 0.3s ease; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    .card-hover:hover { transform: translateY(-4px); box-shadow: 0 8px 20px rgba(0,0,0,0.15); }
    .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000; opacity: 0; pointer-events: none; transition: opacity 0.3s; }
    .modal-overlay.show { opacity: 1; pointer-events: auto; }
    .modal-content { background: white; border-radius: 16px; max-width: 800px; width: 90%; max-height: 80vh; overflow-y: auto; transform: scale(0.9); transition: transform 0.3s; }
    .modal-overlay.show .modal-content { transform: scale(1); }
  </style>
</head>
<body class="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
  <nav class="bg-white shadow-md fixed top-0 left-0 right-0 z-50">
    <div class="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
      <h1 class="text-2xl font-bold text-gray-900">🎁 风萧萧公益-闲置小鸡投喂站</h1>
      <div class="flex gap-4">
        <a href="/donate" class="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-2 rounded-lg font-semibold transition">💝 我要投喂</a>
        <button id="loginBtn" onclick="login()" class="bg-gray-800 hover:bg-black text-white px-6 py-2 rounded-lg font-semibold transition">LinuxDo 登录</button>
      </div>
    </div>
  </nav>
  <div class="max-w-7xl mx-auto px-6 pt-24 pb-12">
    <div class="text-center mb-12 animate-in">
      <h2 class="text-4xl font-bold text-gray-900 mb-4">🏆 捐赠榜单</h2>
      <p class="text-xl text-gray-600">感谢各位佬友的慷慨分享！</p>
    </div>
    <div id="leaderboardList" class="space-y-6">
      <div class="text-center py-12 text-gray-400">加载中...</div>
    </div>
  </div>
  <div id="userModal" class="modal-overlay" onclick="closeUserModal(event)">
    <div class="modal-content" onclick="event.stopPropagation()">
      <div class="p-6 border-b">
        <div class="flex justify-between items-center">
          <h3 id="modalUsername" class="text-2xl font-bold"></h3>
          <button onclick="closeUserModal()" class="text-gray-400 hover:text-gray-600">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
          </button>
        </div>
        <p id="modalCount" class="text-gray-600 mt-2"></p>
      </div>
      <div id="modalDonations" class="p-6 space-y-4"></div>
    </div>
  </div>
  <script>
    const CLIENT_ID = '${clientId}';
    const AUTH_URL = 'https://connect.linux.do/oauth2/authorize';
    const REDIRECT_URI = window.location.origin + '/oauth/callback';
    function login() {
      if (!CLIENT_ID) { alert('OAuth 配置未设置，请联系管理员'); return; }
      const url = \`\${AUTH_URL}?client_id=\${CLIENT_ID}&redirect_uri=\${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=read\`;
      window.location.href = url;
    }
    async function loadLeaderboard() {
      try {
        const res = await fetch('/api/leaderboard');
        const data = await res.json();
        if (data.success && data.data.length > 0) {
          const html = data.data.map((user, index) => {
            const medals = ['🥇', '🥈', '🥉'];
            const medal = index < 3 ? \`<span class="text-5xl">\${medals[index]}</span>\` : \`<span class="text-2xl text-gray-400">#\${index + 1}</span>\`;
            return \`
              <div class="bg-white rounded-2xl p-6 card-hover">
                <div class="flex items-start gap-6">
                  <div class="flex-shrink-0 w-20 text-center">\${medal}</div>
                  <div class="flex-1">
                    <div class="flex items-center justify-between mb-4">
                      <h3 class="text-2xl font-bold text-gray-900 cursor-pointer hover:text-indigo-600" onclick="showUserModal('\${user.username}')">@\${user.username}</h3>
                      <span class="bg-indigo-100 text-indigo-800 px-4 py-2 rounded-full font-bold text-lg">\${user.count} 台</span>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                      \${user.servers.slice(0, 6).map(s => \`
                        <div class="bg-gray-50 p-4 rounded-lg border border-gray-200 hover:border-indigo-300 transition">
                          <div class="flex items-center justify-between mb-2">
                            <span class="text-lg">📍 \${s.ipLocation}</span>
                            <span class="px-2 py-1 rounded text-xs font-bold \${s.status === 'active' ? 'bg-green-100 text-green-700' : s.status === 'failed' ? 'bg-red-100 text-red-700' : 'bg-gray-200 text-gray-600'}">\${s.status === 'active' ? '✓' : s.status === 'failed' ? '✕' : '○'}</span>
                          </div>
                          <div class="text-sm text-gray-600 space-y-1">
                            <p>🌍 \${s.country}</p>
                            <p>💻 \${s.specs}</p>
                            <p>📊 \${s.traffic}</p>
                            <p>⏰ 到期:\${s.expiryDate}</p>
                            \${s.note ? \`<p class="text-blue-600">💬 \${s.note}</p>\` : ''}
                            \${s.adminNote ? \`<p class="text-purple-600">🔖 \${s.adminNote}</p>\` : ''}
                          </div>
                        </div>
                      \`).join('')}
                    </div>
                    \${user.servers.length > 6 ? \`<button onclick="showUserModal('\${user.username}')" class="mt-4 text-indigo-600 hover:text-indigo-800 font-semibold">查看全部 \${user.servers.length} 台服务器 →</button>\` : ''}
                  </div>
                </div>
              </div>
            \`;
          }).join('');
          document.getElementById('leaderboardList').innerHTML = html;
        } else {
          document.getElementById('leaderboardList').innerHTML = '<div class="text-center py-12 text-gray-400">暂无捐赠记录</div>';
        }
      } catch (e) {
        console.error('加载榜单失败', e);
        document.getElementById('leaderboardList').innerHTML = '<div class="text-center py-12 text-red-400">加载失败</div>';
      }
    }
    async function showUserModal(username) {
      try {
        const res = await fetch(\`/api/user/\${username}/donations\`);
        const data = await res.json();
        if (data.success) {
          document.getElementById('modalUsername').textContent = '@' + data.data.username;
          document.getElementById('modalCount').textContent = \`已投喂 \${data.data.count} 台服务器\`;
          const html = data.data.donations.map(d => \`
            <div class="bg-gray-50 p-4 rounded-lg border border-gray-200">
              <div class="flex items-center justify-between mb-2">
                <span class="text-lg font-semibold">📍 \${d.ipLocation}</span>
                <span class="px-2 py-1 rounded text-xs font-bold \${d.status === 'active' ? 'bg-green-100 text-green-700' : d.status === 'failed' ? 'bg-red-100 text-red-700' : 'bg-gray-200 text-gray-600'}">\${d.status === 'active' ? '✓ 活跃' : d.status === 'failed' ? '✕ 失败' : '○ 停用'}</span>
              </div>
              <div class="text-sm text-gray-600 space-y-1">
                <p>🌍 国家/地区: \${d.country}</p>
                <p>💻 配置: \${d.specs}</p>
                <p>📊 流量: \${d.traffic}</p>
                <p>⏰ 到期时间: \${d.expiryDate}</p>
                \${d.note ? \`<p class="text-blue-600">💬 用户备注: \${d.note}</p>\` : ''}
                \${d.adminNote ? \`<p class="text-purple-600">🔖 管理员备注: \${d.adminNote}</p>\` : ''}
                <p class="text-gray-400 text-xs pt-2">投喂时间: \${new Date(d.donatedAt).toLocaleString('zh-CN')}</p>
              </div>
            </div>
          \`).join('');
          document.getElementById('modalDonations').innerHTML = html;
          document.getElementById('userModal').classList.add('show');
        }
      } catch (e) { console.error('加载用户详情失败', e); }
    }
    function closeUserModal(event) { document.getElementById('userModal').classList.remove('show'); }
    loadLeaderboard();
  </script>
</body>
</html>`;
}

function generateDonateHTML(clientId: string): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>投喂VPS - 风萧萧公益</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    .animate-in { animation: fadeIn 0.5s ease-out; }
  </style>
</head>
<body class="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
  <nav class="bg-white shadow-md fixed top-0 left-0 right-0 z-50">
    <div class="max-w-4xl mx-auto px-6 py-4 flex justify-between items-center">
      <h1 class="text-2xl font-bold text-gray-900">💝 投喂闲置小鸡</h1>
      <div class="flex gap-4">
        <a href="/" class="text-gray-600 hover:text-gray-900 font-semibold">返回首页</a>
        <button id="loginBtn" onclick="login()" class="bg-gray-800 hover:bg-black text-white px-6 py-2 rounded-lg font-semibold transition">LinuxDo 登录</button>
      </div>
    </div>
  </nav>
  <div class="max-w-4xl mx-auto px-6 pt-24 pb-12">
    <div id="loginPrompt" class="bg-white rounded-2xl p-12 text-center shadow-lg animate-in">
      <div class="text-6xl mb-4">🔐</div>
      <h2 class="text-3xl font-bold mb-4">请先登录</h2>
      <p class="text-gray-600 mb-6 text-lg">使用 LinuxDo 账号登录后即可投喂 VPS</p>
      <button onclick="login()" class="bg-indigo-600 hover:bg-indigo-700 text-white px-8 py-3 rounded-lg font-semibold text-lg transition">LinuxDo 登录</button>
    </div>
    <div id="donateForm" class="hidden bg-white rounded-2xl p-8 shadow-lg animate-in">
      <h2 class="text-3xl font-bold mb-6">投喂你的闲置小鸡</h2>
      <div class="space-y-5">
        <div class="bg-blue-50 p-4 rounded-lg">
          <h3 class="font-bold text-lg mb-3">服务器连接信息</h3>
          <div class="grid grid-cols-3 gap-4">
            <div><label class="block text-sm font-semibold text-gray-700 mb-2">服务器 IP *</label><input id="ipInput" type="text" placeholder="192.168.1.1" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"></div>
            <div><label class="block text-sm font-semibold text-gray-700 mb-2">SSH 端口 *</label><input id="portInput" type="number" placeholder="22" value="22" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"></div>
            <div><label class="block text-sm font-semibold text-gray-700 mb-2">登录用户名 *</label><input id="usernameInput" type="text" placeholder="root" value="root" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"></div>
          </div>
        </div>
        <div class="bg-green-50 p-4 rounded-lg">
          <h3 class="font-bold text-lg mb-3">VPS 详细信息</h3>
          <div class="grid grid-cols-2 gap-4">
            <div><label class="block text-sm font-semibold text-gray-700 mb-2">国家/地区 *</label><input id="countryInput" type="text" placeholder="如: 美国、香港、日本" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"></div>
            <div><label class="block text-sm font-semibold text-gray-700 mb-2">配置信息 *</label><input id="specsInput" type="text" placeholder="如: 2C4G8M 或 2核4G 8Mbps" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"></div>
            <div><label class="block text-sm font-semibold text-gray-700 mb-2">流量信息 *</label><input id="trafficInput" type="text" placeholder="如: 500GB/月 或 不限流量" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"></div>
            <div><label class="block text-sm font-semibold text-gray-700 mb-2">到期时间 *</label><input id="expiryDateInput" type="date" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"></div>
          </div>
        </div>
        <div><label class="block text-sm font-semibold text-gray-700 mb-2">认证方式 *</label><select id="authTypeSelect" onchange="toggleAuthFields()" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"><option value="password">密码认证</option><option value="key">密钥认证</option></select></div>
        <div id="passwordField"><label class="block text-sm font-semibold text-gray-700 mb-2">SSH 密码 *</label><input id="passwordInput" type="password" placeholder="请输入 SSH 密码" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"></div>
        <div id="keyField" class="hidden"><label class="block text-sm font-semibold text-gray-700 mb-2">SSH 私钥 *</label><textarea id="keyInput" placeholder="请粘贴完整的 SSH 私钥内容" rows="5" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent font-mono text-sm"></textarea></div>
        <div><label class="block text-sm font-semibold text-gray-700 mb-2">备注（可选）</label><input id="noteInput" type="text" placeholder="例如: 阿里云香港 适合建站" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"></div>
        <button onclick="submitDonation()" class="w-full bg-indigo-600 hover:bg-indigo-700 text-white py-4 rounded-lg font-bold text-lg transition mt-6">🚀 提交投喂</button>
      </div>
    </div>
  </div>
  <script>
    const CLIENT_ID = '${clientId}';
    const AUTH_URL = 'https://connect.linux.do/oauth2/authorize';
    const REDIRECT_URI = window.location.origin + '/oauth/callback';
    async function checkAuth() {
      try {
        const res = await fetch('/api/user/info', { credentials: 'same-origin' });
        const data = await res.json();
        if (data.success) {
          document.getElementById('loginPrompt').classList.add('hidden');
          document.getElementById('donateForm').classList.remove('hidden');
          document.getElementById('loginBtn').classList.add('hidden');
        }
      } catch (e) { console.log('未登录'); }
    }
    function login() {
      if (!CLIENT_ID) { alert('OAuth 配置未设置，请联系管理员'); return; }
      const url = \`\${AUTH_URL}?client_id=\${CLIENT_ID}&redirect_uri=\${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=read\`;
      window.location.href = url;
    }
    function toggleAuthFields() {
      const authType = document.getElementById('authTypeSelect').value;
      const passwordField = document.getElementById('passwordField');
      const keyField = document.getElementById('keyField');
      if (authType === 'password') { passwordField.classList.remove('hidden'); keyField.classList.add('hidden'); }
      else { passwordField.classList.add('hidden'); keyField.classList.remove('hidden'); }
    }
    async function submitDonation() {
      const ip = document.getElementById('ipInput').value.trim();
      const port = document.getElementById('portInput').value.trim();
      const username = document.getElementById('usernameInput').value.trim();
      const authType = document.getElementById('authTypeSelect').value;
      const password = document.getElementById('passwordInput').value;
      const privateKey = document.getElementById('keyInput').value;
      const note = document.getElementById('noteInput').value.trim();
      const country = document.getElementById('countryInput').value.trim();
      const specs = document.getElementById('specsInput').value.trim();
      const traffic = document.getElementById('trafficInput').value.trim();
      const expiryDate = document.getElementById('expiryDateInput').value;
      if (!ip || !port || !username || !authType) { alert('请填写服务器连接信息'); return; }
      if (!country || !specs || !traffic || !expiryDate) { alert('请填写完整的 VPS 详细信息'); return; }
      if (authType === 'password' && !password) { alert('请填写 SSH 密码'); return; }
      if (authType === 'key' && !privateKey) { alert('请填写 SSH 私钥'); return; }
      const submitBtn = event.target;
      const originalText = submitBtn.textContent;
      submitBtn.disabled = true;
      submitBtn.textContent = '⏳ 提交中...';
      submitBtn.classList.add('opacity-50');
      try {
        const res = await fetch('/api/donate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip, port, username, authType, password, privateKey, note, country, specs, traffic, expiryDate }),
          credentials: 'same-origin',
        });
        const data = await res.json();
        if (data.success) {
          alert('✅ ' + data.message);
          document.getElementById('ipInput').value = '';
          document.getElementById('portInput').value = '22';
          document.getElementById('usernameInput').value = 'root';
          document.getElementById('passwordInput').value = '';
          document.getElementById('keyInput').value = '';
          document.getElementById('noteInput').value = '';
          document.getElementById('countryInput').value = '';
          document.getElementById('specsInput').value = '';
          document.getElementById('trafficInput').value = '';
          document.getElementById('expiryDateInput').value = '';
          setTimeout(() => { window.location.href = '/'; }, 2000);
        } else { alert('❌ ' + data.message); }
      } catch (e) { alert('提交失败: ' + e.message); }
      finally { submitBtn.disabled = false; submitBtn.textContent = originalText; submitBtn.classList.remove('opacity-50'); }
    }
    checkAuth();
  </script>
</body>
</html>`;
}

function generateAdminHTML(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>管理员后台</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    .animate-in { animation: fadeIn 0.5s ease-out; }
    .card-hover { transition: all 0.2s ease; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
    .card-hover:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.12); }
    .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000; opacity: 0; pointer-events: none; transition: opacity 0.3s; }
    .modal-overlay.show { opacity: 1; pointer-events: auto; }
    .modal-content { background: white; border-radius: 16px; max-width: 600px; width: 90%; max-height: 80vh; overflow: hidden; transform: scale(0.9); transition: transform 0.3s; }
    .modal-overlay.show .modal-content { transform: scale(1); }
  </style>
</head>
<body class="min-h-screen bg-gray-50">
  <nav class="bg-white shadow-md">
    <div class="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
      <h1 class="text-2xl font-bold">🔧 管理员后台</h1>
      <div class="flex gap-4">
        <a href="/" class="text-gray-600 hover:text-gray-900">返回首页</a>
        <button onclick="logout()" class="text-red-600 hover:text-red-800">登出</button>
      </div>
    </div>
  </nav>
  <div class="max-w-7xl mx-auto p-6">
    <div id="loginForm" class="max-w-md mx-auto bg-white rounded-xl p-8 shadow-lg animate-in">
      <h2 class="text-2xl font-bold mb-6 text-center">🔐 管理员登录</h2>
      <div class="space-y-4">
        <div><label class="block text-sm font-semibold mb-2">管理员密码</label><input id="adminPassword" type="password" placeholder="请输入管理员密码" class="w-full px-4 py-3 border rounded-lg" onkeypress="if(event.key==='Enter') adminLogin()"></div>
        <button onclick="adminLogin()" class="w-full bg-gray-800 hover:bg-black text-white py-3 rounded-lg font-semibold">登录</button>
        <p class="text-sm text-gray-500 text-center">默认密码: admin123（首次登录后请立即修改）</p>
      </div>
    </div>
    <div id="adminPanel" class="hidden">
      <div class="grid grid-cols-1 md:grid-cols-6 gap-6 mb-6">
        <div class="bg-white rounded-xl p-6 card-hover"><p class="text-sm text-gray-500 mb-1">总投喂数</p><p id="totalVPS" class="text-3xl font-bold">0</p></div>
        <div class="bg-white rounded-xl p-6 card-hover"><p class="text-sm text-gray-500 mb-1">活跃服务器</p><p id="activeVPS" class="text-3xl font-bold text-green-600">0</p></div>
        <div class="bg-white rounded-xl p-6 card-hover"><p class="text-sm text-gray-500 mb-1">验证失败</p><p id="failedVPS" class="text-3xl font-bold text-red-600">0</p></div>
        <div class="bg-white rounded-xl p-6 card-hover"><p class="text-sm text-gray-500 mb-1">待验证</p><p id="pendingVPS" class="text-3xl font-bold text-yellow-600">0</p></div>
        <div class="bg-white rounded-xl p-6 card-hover"><p class="text-sm text-gray-500 mb-1">今日新增</p><p id="todayNewVPS" class="text-3xl font-bold text-blue-600">0</p></div>
        <div class="bg-white rounded-xl p-6 card-hover"><p class="text-sm text-gray-500 mb-1">投喂用户</p><p id="totalUsers" class="text-3xl font-bold">0</p></div>
      </div>
      <div class="bg-white rounded-xl p-6">
        <div class="flex justify-between items-center mb-6 border-b pb-4">
          <div class="flex gap-2">
            <button onclick="showTab('vps')" class="tab-btn px-4 py-2 font-semibold rounded-t-lg bg-gray-800 text-white">VPS 列表</button>
            <button onclick="showTab('config')" class="tab-btn px-4 py-2 font-semibold rounded-t-lg text-gray-600 hover:text-gray-900">系统配置</button>
          </div>
          <button onclick="batchVerifyVPS()" class="bg-gray-800 hover:bg-black text-white px-4 py-2 rounded-lg font-semibold text-sm">一键验证</button>
        </div>
        <div id="vpsTab" class="tab-content"><div id="vpsList" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"></div></div>
        <div id="configTab" class="tab-content hidden">
          <div class="space-y-6">
            <div class="border rounded-lg p-6">
              <h3 class="text-lg font-bold mb-4">LinuxDo OAuth 配置</h3>
              <div class="space-y-4">
                <div><label class="block text-sm font-semibold mb-2">Client ID</label><input id="clientId" type="text" class="w-full px-4 py-2 border rounded-lg"></div>
                <div><label class="block text-sm font-semibold mb-2">Client Secret</label><input id="clientSecret" type="password" class="w-full px-4 py-2 border rounded-lg"></div>
                <div><label class="block text-sm font-semibold mb-2">Redirect URI</label><input id="redirectUri" type="text" class="w-full px-4 py-2 border rounded-lg"></div>
                <button onclick="saveOAuthConfig()" class="bg-gray-800 hover:bg-black text-white px-6 py-2 rounded-lg font-semibold">保存 OAuth 配置</button>
              </div>
            </div>
            <div class="border rounded-lg p-6">
              <h3 class="text-lg font-bold mb-4">修改管理员密码</h3>
              <div class="space-y-4">
                <div><label class="block text-sm font-semibold mb-2">新密码</label><input id="newPassword" type="password" class="w-full px-4 py-2 border rounded-lg"></div>
                <button onclick="changePassword()" class="bg-gray-800 hover:bg-black text-white px-6 py-2 rounded-lg font-semibold">修改密码</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
  <div id="editModal" class="modal-overlay" onclick="closeEditModal(event)">
    <div class="modal-content" onclick="event.stopPropagation()">
      <div class="p-6 border-b flex justify-between items-center">
        <h3 class="text-xl font-bold">✏️ 编辑 VPS 信息</h3>
        <button onclick="closeEditModal()" class="text-gray-400 hover:text-gray-600"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
      </div>
      <div class="p-6 space-y-4 max-h-96 overflow-y-auto">
        <div><label class="block text-sm font-semibold mb-2">用户备注</label><input id="editNote" type="text" class="w-full px-4 py-2 border rounded-lg"></div>
        <div><label class="block text-sm font-semibold mb-2">管理员备注</label><input id="editAdminNote" type="text" class="w-full px-4 py-2 border rounded-lg"></div>
        <div><label class="block text-sm font-semibold mb-2">国家/地区</label><input id="editCountry" type="text" class="w-full px-4 py-2 border rounded-lg"></div>
        <div><label class="block text-sm font-semibold mb-2">配置信息</label><input id="editSpecs" type="text" class="w-full px-4 py-2 border rounded-lg"></div>
        <div><label class="block text-sm font-semibold mb-2">流量信息</label><input id="editTraffic" type="text" class="w-full px-4 py-2 border rounded-lg"></div>
        <div><label class="block text-sm font-semibold mb-2">到期时间</label><input id="editExpiry" type="date" class="w-full px-4 py-2 border rounded-lg"></div>
      </div>
      <div class="p-6 border-t flex justify-end gap-2">
        <button onclick="closeEditModal()" class="px-6 py-2 border rounded-lg">取消</button>
        <button onclick="saveEdit()" class="bg-gray-800 hover:bg-black text-white px-6 py-2 rounded-lg">保存</button>
      </div>
    </div>
  </div>
  <script>
    let editingVPSId = null;
    async function checkAdminSession() {
      try {
        const res = await fetch('/api/admin/check-session');
        const data = await res.json();
        if (data.success && data.isAdmin) {
          document.getElementById('loginForm').classList.add('hidden');
          document.getElementById('adminPanel').classList.remove('hidden');
          loadAdminData();
        }
      } catch (e) { console.log('未登录'); }
    }
    async function adminLogin() {
      const password = document.getElementById('adminPassword').value;
      if (!password) { alert('请输入密码'); return; }
      try {
        const res = await fetch('/api/admin/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }) });
        const data = await res.json();
        if (data.success) {
          document.getElementById('loginForm').classList.add('hidden');
          document.getElementById('adminPanel').classList.remove('hidden');
          loadAdminData();
          alert('登录成功');
        } else { alert(data.message); }
      } catch (e) { alert('登录失败: ' + e.message); }
    }
    async function loadAdminData() { await Promise.all([loadStats(), loadVPSList(), loadOAuthConfig()]); }
    async function loadStats() {
      try {
        const res = await fetch('/api/admin/stats');
        const data = await res.json();
        if (data.success) {
          document.getElementById('totalVPS').textContent = data.data.totalVPS;
          document.getElementById('activeVPS').textContent = data.data.activeVPS;
          document.getElementById('failedVPS').textContent = data.data.failedVPS;
          document.getElementById('pendingVPS').textContent = data.data.pendingVPS;
          document.getElementById('todayNewVPS').textContent = data.data.todayNewVPS;
          document.getElementById('totalUsers').textContent = data.data.topDonors.length;
        }
      } catch (e) { console.error('加载统计失败', e); }
    }
    async function loadVPSList() {
      try {
        const res = await fetch('/api/admin/vps');
        const data = await res.json();
        if (data.success && data.data.length > 0) {
          const html = data.data.map(v => \`
            <div class="bg-white rounded-lg p-4 border hover:shadow-lg transition cursor-pointer" onclick="toggleDetails('\${v.id}')">
              <div class="flex justify-between items-start mb-2">
                <div><p class="font-bold">\${v.donatedByUsername}</p><p class="text-sm text-gray-600">\${v.ipLocation || v.ip}</p></div>
                <span class="px-2 py-1 rounded text-xs font-bold \${v.status === 'active' ? 'bg-green-100 text-green-700' : v.status === 'failed' ? 'bg-red-100 text-red-700' : 'bg-gray-200 text-gray-600'}">\${v.status === 'active' ? '✓' : v.status === 'failed' ? '✕' : '○'}</span>
              </div>
              <p class="text-xs text-gray-500">\${v.country} | \${v.specs}</p>
              <div id="details-\${v.id}" class="hidden mt-3 pt-3 border-t space-y-2">
                <p class="text-xs"><strong>IP:</strong> \${v.ip}:\${v.port}</p>
                <p class="text-xs"><strong>流量:</strong> \${v.traffic}</p>
                <p class="text-xs"><strong>到期:</strong> \${v.expiryDate}</p>
                \${v.note ? \`<p class="text-xs text-blue-600">💬 \${v.note}</p>\` : ''}
                \${v.adminNote ? \`<p class="text-xs text-purple-600">🔖 \${v.adminNote}</p>\` : ''}
                <div class="flex gap-2 mt-3">
                  <button onclick="event.stopPropagation(); editVPS('\${v.id}')" class="px-3 py-1 text-xs bg-blue-500 text-white rounded">编辑</button>
                  <button onclick="event.stopPropagation(); toggleStatus('\${v.id}', '\${v.status}')" class="px-3 py-1 text-xs bg-gray-500 text-white rounded">\${v.status === 'active' ? '停用' : '启用'}</button>
                  <button onclick="event.stopPropagation(); deleteVPS('\${v.id}')" class="px-3 py-1 text-xs bg-red-500 text-white rounded">删除</button>
                </div>
              </div>
            </div>
          \`).join('');
          document.getElementById('vpsList').innerHTML = html;
        } else {
          document.getElementById('vpsList').innerHTML = '<p class="text-center text-gray-500 col-span-full">暂无 VPS 记录</p>';
        }
      } catch (e) { console.error('加载 VPS 列表失败', e); }
    }
    function toggleDetails(id) { document.getElementById('details-' + id).classList.toggle('hidden'); }
    async function editVPS(id) {
      try {
        const res = await fetch('/api/admin/vps');
        const data = await res.json();
        const vps = data.data.find(v => v.id === id);
        if (vps) {
          editingVPSId = id;
          document.getElementById('editNote').value = vps.note || '';
          document.getElementById('editAdminNote').value = vps.adminNote || '';
          document.getElementById('editCountry').value = vps.country || '';
          document.getElementById('editSpecs').value = vps.specs || '';
          document.getElementById('editTraffic').value = vps.traffic || '';
          document.getElementById('editExpiry').value = vps.expiryDate || '';
          document.getElementById('editModal').classList.add('show');
        }
      } catch (e) { alert('加载失败'); }
    }
    function closeEditModal(event) { document.getElementById('editModal').classList.remove('show'); editingVPSId = null; }
    async function saveEdit() {
      if (!editingVPSId) return;
      try {
        const res = await fetch(\`/api/admin/vps/\${editingVPSId}/notes\`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            note: document.getElementById('editNote').value,
            adminNote: document.getElementById('editAdminNote').value,
            country: document.getElementById('editCountry').value,
            specs: document.getElementById('editSpecs').value,
            traffic: document.getElementById('editTraffic').value,
            expiryDate: document.getElementById('editExpiry').value,
          })
        });
        const data = await res.json();
        if (data.success) { alert('保存成功'); closeEditModal(); loadVPSList(); } else { alert(data.message); }
      } catch (e) { alert('保存失败: ' + e.message); }
    }
    async function toggleStatus(id, currentStatus) {
      const newStatus = currentStatus === 'active' ? 'inactive' : 'active';
      try {
        const res = await fetch(\`/api/admin/vps/\${id}/status\`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: newStatus })
        });
        if ((await res.json()).success) { loadVPSList(); loadStats(); }
      } catch (e) { alert('更新失败'); }
    }
    async function deleteVPS(id) {
      if (!confirm('确定要删除吗？')) return;
      try {
        const res = await fetch(\`/api/admin/vps/\${id}\`, { method: 'DELETE' });
        if ((await res.json()).success) { alert('已删除'); loadVPSList(); loadStats(); }
      } catch (e) { alert('删除失败'); }
    }
    async function batchVerifyVPS() {
      if (!confirm('确定要批量验证吗？')) return;
      try {
        const res = await fetch('/api/admin/vps/batch-verify', { method: 'POST' });
        const data = await res.json();
        if (data.success) { alert(data.message); loadVPSList(); loadStats(); }
      } catch (e) { alert('验证失败'); }
    }
    async function loadOAuthConfig() {
      try {
        const res = await fetch('/api/admin/config/oauth');
        const data = await res.json();
        if (data.success && data.data) {
          document.getElementById('clientId').value = data.data.clientId || '';
          document.getElementById('clientSecret').value = data.data.clientSecret || '';
          document.getElementById('redirectUri').value = data.data.redirectUri || '';
        }
      } catch (e) { console.error('加载配置失败', e); }
    }
    async function saveOAuthConfig() {
      const clientId = document.getElementById('clientId').value.trim();
      const clientSecret = document.getElementById('clientSecret').value.trim();
      const redirectUri = document.getElementById('redirectUri').value.trim();
      if (!clientId || !clientSecret || !redirectUri) { alert('所有字段都是必填的'); return; }
      try {
        const res = await fetch('/api/admin/config/oauth', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ clientId, clientSecret, redirectUri })
        });
        if ((await res.json()).success) { alert('配置已保存'); }
      } catch (e) { alert('保存失败'); }
    }
    async function changePassword() {
      const password = document.getElementById('newPassword').value;
      if (!password || password.length < 6) { alert('密码至少需要 6 个字符'); return; }
      try {
        const res = await fetch('/api/admin/config/password', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });
        if ((await res.json()).success) { alert('密码已更新'); document.getElementById('newPassword').value = ''; }
      } catch (e) { alert('更新失败'); }
    }
    function showTab(tab) {
      document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('bg-gray-800', 'text-white');
        btn.classList.add('text-gray-600');
      });
      event.target.classList.add('bg-gray-800', 'text-white');
      event.target.classList.remove('text-gray-600');
      document.querySelectorAll('.tab-content').forEach(content => content.classList.add('hidden'));
      document.getElementById(tab + 'Tab').classList.remove('hidden');
    }
    async function logout() { await fetch('/api/admin/logout'); window.location.reload(); }
    window.addEventListener('DOMContentLoaded', checkAdminSession);
  </script>
</body>
</html>`;
}

// 启动服务器
Deno.serve(app.fetch);
