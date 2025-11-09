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
  traffic: string;      // 流量/带宽描述
  expiryDate: string;   // 到期日期描述（前端以字符串展示）
  specs: string;        // 配置描述
  ipLocation?: string;  // IP 归属地
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

function generateId(): string {
  return crypto.randomUUID();
}

function generateSessionId(): string {
  return crypto.randomUUID();
}

// ==================== IP 归属地查询 ====================
async function getIPLocation(ip: string): Promise<string> {
  try {
    const response = await fetch(
      `http://ip-api.com/json/${ip}?fields=country,regionName,city`,
    );
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

// ==================== IP 校验 ====================
function isValidIPv4(ip: string): boolean {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(ip)) return false;
  const parts = ip.split('.');
  return parts.every((part) => {
    const num = parseInt(part, 10);
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
  for await (const entry of entries) {
    servers.push(entry.value);
  }
  return servers.sort((a, b) => b.donatedAt - a.donatedAt);
}

async function checkIPExists(ip: string, port: number): Promise<boolean> {
  const allVPS = await getAllVPS();
  return allVPS.some((vps) => vps.ip === ip && vps.port === port);
}

async function checkPortReachable(ip: string, port: number): Promise<boolean> {
  try {
    const cleanIp = ip.replace(/^\[|\]$/g, '');
    const conn = await Deno.connect({
      hostname: cleanIp,
      port,
      transport: 'tcp',
    });
    conn.close();
    return true;
  } catch {
    return false;
  }
}

async function batchVerifyVPS(): Promise<{
  total: number;
  success: number;
  failed: number;
  details: any[];
}> {
  const allVPS = await getAllVPS();
  const pendingVPS = allVPS.filter((v) => v.verifyStatus === 'pending');
  let successCount = 0;
  let failedCount = 0;
  const details: any[] = [];

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
        details.push({
          id: vps.id,
          ip: vps.ip,
          status: 'failed',
          error: vps.verifyErrorMsg,
        });
      }
    } catch (error: any) {
      vps.verifyStatus = 'failed';
      vps.status = 'failed';
      vps.lastVerifyAt = Date.now();
      vps.verifyErrorMsg = error.message || '验证过程中发生错误';
      await kv.set(['vps', vps.id], vps);
      failedCount++;
      details.push({
        id: vps.id,
        ip: vps.ip,
        status: 'failed',
        error: vps.verifyErrorMsg,
      });
    }
  }
  return {
    total: pendingVPS.length,
    success: successCount,
    failed: failedCount,
    details,
  };
}

// ==================== 配置 & 用户 & 会话 ====================
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

async function createSession(
  userId: string,
  username: string,
  avatarUrl: string | undefined,
  isAdmin: boolean,
): Promise<string> {
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

async function addVPSServer(
  server: Omit<VPSServer, 'id'>,
): Promise<VPSServer> {
  const id = generateId();
  const vps: VPSServer = { id, ...server };
  await kv.set(['vps', id], vps);

  const userDonations = await kv.get<string[]>(['user_donations', server.donatedBy]);
  const donations = userDonations.value || [];
  donations.push(id);
  await kv.set(['user_donations', server.donatedBy], donations);

  return vps;
}

async function getUserDonations(linuxDoId: string): Promise<VPSServer[]> {
  const userDonations = await kv.get<string[]>(['user_donations', linuxDoId]);
  const donationIds = userDonations.value || [];
  const servers: VPSServer[] = [];
  for (const id of donationIds) {
    const result = await kv.get<VPSServer>(['vps', id]);
    if (result.value) servers.push(result.value);
  }
  return servers.sort((a, b) => b.donatedAt - a.donatedAt);
}

async function deleteVPS(id: string): Promise<boolean> {
  const vps = await kv.get<VPSServer>(['vps', id]);
  if (!vps.value) return false;
  await kv.delete(['vps', id]);

  const userDonations = await kv.get<string[]>(['user_donations', vps.value.donatedBy]);
  if (userDonations.value) {
    const filtered = userDonations.value.filter((vid) => vid !== id);
    await kv.set(['user_donations', vps.value.donatedBy], filtered);
  }
  return true;
}

async function updateVPSStatus(
  id: string,
  status: 'active' | 'inactive' | 'failed',
): Promise<boolean> {
  const result = await kv.get<VPSServer>(['vps', id]);
  if (!result.value) return false;
  result.value.status = status;
  await kv.set(['vps', id], result.value);
  return true;
}

// ==================== OAuth 请求 ====================
async function exchangeCodeForToken(
  code: string,
  config: OAuthConfig,
): Promise<any> {
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
  if (!sessionId) return c.json({ success: false, message: '未登录' }, 401);
  const session = await getSession(sessionId);
  if (!session) return c.json({ success: false, message: '会话已过期' }, 401);
  c.set('session', session);
  await next();
}

async function requireAdmin(c: any, next: any) {
  const sessionId = getCookie(c, 'admin_session_id');
  if (!sessionId) return c.json({ success: false, message: '未登录' }, 401);
  const session = await getSession(sessionId);
  if (!session || !session.isAdmin) {
    return c.json({ success: false, message: '需要管理员权限' }, 403);
  }
  c.set('session', session);
  await next();
}

// ==================== Hono 应用 ====================
const app = new Hono();
app.use('*', cors());

// -------- 根路径：重定向到 /donate --------
app.get('/', (c) => c.redirect('/donate'));

// -------- OAuth 登录入口（重定向到 Linux.do）---------
app.get('/oauth/login', async (c) => {
  const redirectPath = c.req.query('redirect') || '/donate/vps';
  const config = await getOAuthConfig();
  if (!config) {
    return c.html(
      '<!DOCTYPE html><html><body><h1>配置错误</h1><p>OAuth 配置未设置</p><a href="/donate">返回首页</a></body></html>',
    );
  }

  const state = typeof redirectPath === 'string' ? redirectPath : '/donate/vps';
  const authUrl = new URL('https://connect.linux.do/oauth2/authorize');
  authUrl.searchParams.set('client_id', config.clientId);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', config.redirectUri);
  authUrl.searchParams.set('scope', 'openid profile');
  authUrl.searchParams.set('state', state);

  return c.redirect(authUrl.toString());
});

// -------- OAuth 回调 --------
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
    const config = await getOAuthConfig();
    if (!config) {
      return c.html(
        '<!DOCTYPE html><html><body><h1>配置错误</h1><p>OAuth 配置未设置</p><a href="/donate">返回首页</a></body></html>',
      );
    }

    const tokenData = await exchangeCodeForToken(code, config);
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
    const sessionId = await createSession(
      user.linuxDoId,
      user.username,
      user.avatarUrl,
      user.isAdmin,
    );

    const isProduction = Deno.env.get('DENO_DEPLOYMENT_ID') !== undefined;
    setCookie(c, 'session_id', sessionId, {
      maxAge: 7 * 24 * 60 * 60,
      httpOnly: true,
      secure: isProduction,
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

// ==================== 用户相关 API ====================
app.get('/api/logout', async (c) => {
  const sessionId = getCookie(c, 'session_id');
  if (sessionId) await kv.delete(['sessions', sessionId]);
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
  // 登录用户可以看到自己的 IP 和端口
  const safeDonations = donations.map((d) => ({
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

// ==================== 公共榜单 API（不暴露 IP/端口） ====================
app.get('/api/leaderboard', async (c) => {
  const allVPS = await getAllVPS();
  const userStats = new Map<
    string,
    {
      username: string;
      count: number;
      servers: any[];
    }
  >();

  for (const vps of allVPS) {
    const stats = userStats.get(vps.donatedBy) || {
      username: vps.donatedByUsername,
      count: 0,
      servers: [],
    };
    stats.count++;
    stats.servers.push({
      // 不返回 ip 与 port
      ipLocation: vps.ipLocation || '未知地区',
      country: vps.country || '未填写',
      traffic: vps.traffic || '未填写',
      expiryDate: vps.expiryDate || '未填写',
      specs: vps.specs || '未填写',
      note: vps.note,
      adminNote: vps.adminNote,
      status: vps.status,
      donatedAt: vps.donatedAt,
    });
    userStats.set(vps.donatedBy, stats);
  }

  const leaderboard = Array.from(userStats.values()).sort(
    (a, b) => b.count - a.count,
  );
  return c.json({ success: true, data: leaderboard });
});

// 公共用户详情接口（同样不暴露 IP，仅展示归属地等信息，可以保留/按需使用）
app.get('/api/user/:username/donations', async (c) => {
  const username = c.req.param('username');
  const allVPS = await getAllVPS();
  const userVPS = allVPS.filter((vps) => vps.donatedByUsername === username);
  const donations = userVPS.map((vps) => ({
    // 不返回 ip/port
    ipLocation: vps.ipLocation || '未知地区',
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
    data: { username, count: donations.length, donations },
  });
});

// ==================== 投喂 API ====================
app.post('/api/donate', requireAuth, async (c) => {
  const session = c.get('session');
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
    return c.json(
      { success: false, message: '密码认证需要提供密码' },
      400,
    );
  }
  if (authType === 'key' && !privateKey) {
    return c.json(
      { success: false, message: '密钥认证需要提供私钥' },
      400,
    );
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

  const ipExists = await checkIPExists(ip, portNum);
  if (ipExists) {
    return c.json(
      { success: false, message: '该 IP 和端口已经被投喂过了' },
      400,
    );
  }

  const portReachable = await checkPortReachable(ip, portNum);
  if (!portReachable) {
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
    return c.json(
      { success: false, message: '投喂失败: ' + e.message },
      500,
    );
  }
});

// ==================== 管理员 API ====================
app.get('/api/admin/check-session', async (c) => {
  const sessionId = getCookie(c, 'admin_session_id');
  if (!sessionId) return c.json({ success: false, isAdmin: false });
  const session = await getSession(sessionId);
  if (!session || session.expiresAt < Date.now()) {
    return c.json({ success: false, isAdmin: false });
  }
  return c.json({
    success: true,
    isAdmin: session.isAdmin || false,
    username: session.username,
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
  if (sessionId) await kv.delete(['sessions', sessionId]);
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
  if (success) return c.json({ success: true, message: 'VPS 已删除' });
  return c.json({ success: false, message: 'VPS 不存在' }, 404);
});

app.put('/api/admin/vps/:id/status', requireAdmin, async (c) => {
  const id = c.req.param('id');
  const { status } = await c.req.json();
  if (status !== 'active' && status !== 'inactive' && status !== 'failed') {
    return c.json({ success: false, message: '无效的状态' }, 400);
  }
  const success = await updateVPSStatus(id, status);
  if (success) return c.json({ success: true, message: '状态已更新' });
  return c.json({ success: false, message: 'VPS 不存在' }, 404);
});

app.put('/api/admin/vps/:id/notes', requireAdmin, async (c) => {
  const id = c.req.param('id');
  const { note, adminNote, country, traffic, expiryDate, specs } =
    await c.req.json();
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
  const allVPS = await getAllVPS();
  const activeVPS = allVPS.filter((v) => v.status === 'active');
  const failedVPS = allVPS.filter((v) => v.status === 'failed');
  const pendingVPS = allVPS.filter((v) => v.verifyStatus === 'pending');

  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);
  const todayNewVPS = allVPS.filter(
    (v) => v.donatedAt >= todayStart.getTime(),
  );

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
      inactiveVPS:
        allVPS.length - activeVPS.length - failedVPS.length,
      pendingVPS: pendingVPS.length,
      verifiedVPS: allVPS.filter((v) => v.verifyStatus === 'verified')
        .length,
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
      data: result,
    });
  } catch (error: any) {
    return c.json(
      { success: false, message: '批量验证失败: ' + error.message },
      500,
    );
  }
});

// ==================== 前端页面：/donate ====================
app.get('/donate', (c) => {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>风萧萧兮公益 VPS 投喂 · 捐赠榜单</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-slate-950 text-slate-100">
  <div class="max-w-5xl mx-auto px-4 py-10">
    <header class="mb-8">
      <h1 class="text-3xl md:text-4xl font-bold bg-gradient-to-r from-cyan-400 via-sky-400 to-indigo-400 bg-clip-text text-transparent">
        风萧萧兮公益机场 · VPS 投喂榜
      </h1>
      <p class="mt-3 text-sm md:text-base text-slate-300 leading-relaxed">
        这是一个完全非盈利的公益项目，没有运营团队，只有我一个人维护。<br/>
        感谢所有愿意投喂 VPS 的朋友，你们让更多人可以免费、安全地使用网络。<br/>
        榜单中仅展示国家 / 区域、IP 归属地、流量与到期时间，不会公开任何 IP 或端口信息。
      </p>

      <button
        onclick="gotoDonatePage()"
        class="mt-5 inline-flex items-center gap-2 rounded-xl bg-cyan-500 px-4 py-2 text-sm font-semibold shadow-lg shadow-cyan-500/30 hover:bg-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:ring-offset-2 focus:ring-offset-slate-950"
      >
        🧡 我要投喂 VPS
      </button>
    </header>

    <section class="mb-6">
      <h2 class="text-xl font-semibold mb-3 flex items-center gap-2">
        🏆 捐赠榜单
        <span id="leaderboard-count" class="text-sm font-normal text-slate-400"></span>
      </h2>
      <div id="leaderboard" class="space-y-4">
        <div class="text-slate-400 text-sm">
          正在加载榜单...
        </div>
      </div>
    </section>

    <footer class="mt-10 border-t border-slate-800 pt-4 text-xs text-slate-500">
      <p>说明：本项目仅作公益用途，请勿滥用资源（长时间占满带宽、刷流量、倒卖账号等）。</p>
    </footer>
  </div>

<script>
async function gotoDonatePage() {
  try {
    const res = await fetch('/api/user/info');
    if (res.ok) {
      window.location.href = '/donate/vps';
    } else {
      window.location.href = '/oauth/login?redirect=' + encodeURIComponent('/donate/vps');
    }
  } catch (e) {
    window.location.href = '/oauth/login?redirect=' + encodeURIComponent('/donate/vps');
  }
}

async function loadLeaderboard() {
  const container = document.getElementById('leaderboard');
  const countEl = document.getElementById('leaderboard-count');
  try {
    const res = await fetch('/api/leaderboard');
    if (!res.ok) {
      container.innerHTML = '<div class="text-red-400 text-sm">加载失败，请稍后重试。</div>';
      return;
    }
    const json = await res.json();
    if (!json.success) {
      container.innerHTML = '<div class="text-red-400 text-sm">' + (json.message || '加载失败') + '</div>';
      return;
    }
    const data = json.data || [];
    countEl.textContent = data.length ? (' · 共 ' + data.length + ' 位投喂者') : '';

    if (!data.length) {
      container.innerHTML = '<div class="text-slate-400 text-sm">暂时还没有投喂记录，成为第一个投喂者吧～</div>';
      return;
    }

    container.innerHTML = '';
    data.forEach((item, idx) => {
      const wrapper = document.createElement('div');
      wrapper.className = 'rounded-2xl border border-slate-800 bg-slate-900/60 p-4 shadow-sm shadow-slate-900/60';

      const titleRow = document.createElement('div');
      titleRow.className = 'flex items-center justify-between gap-2 mb-2';

      const left = document.createElement('div');
      left.className = 'flex items-center gap-2';
      left.innerHTML = '<span class="text-lg">' + (idx < 3 ? ['🥇','🥈','🥉'][idx] : '🏅') + '</span>' +
                       '<span class="font-semibold">@' + item.username + '</span>';

      const right = document.createElement('div');
      right.className = 'text-xs text-slate-400';
      right.textContent = '共投喂 ' + item.count + ' 台 VPS';

      titleRow.appendChild(left);
      titleRow.appendChild(right);
      wrapper.appendChild(titleRow);

      const list = document.createElement('div');
      list.className = 'space-y-2 mt-2 text-xs';

      (item.servers || []).forEach((srv) => {
        const div = document.createElement('div');
        div.className = 'rounded-xl bg-slate-950/60 border border-slate-800 px-3 py-2 flex flex-col gap-1';

        const statusColor =
          srv.status === 'active' ? 'text-emerald-400' :
          srv.status === 'failed' ? 'text-red-400' :
          'text-slate-300';

        const statusText =
          srv.status === 'active' ? '已激活' :
          srv.status === 'failed' ? '验证失败' :
          '未激活';

        div.innerHTML =
          '<div class="flex items-center justify-between gap-2">' +
            '<span class="font-medium text-slate-100 text-xs">' +
              (srv.country || '未填写') +
              (srv.ipLocation ? ' · ' + srv.ipLocation : '') +
            '</span>' +
            '<span class="' + statusColor + ' text-[11px]">' + statusText + '</span>' +
          '</div>' +
          '<div class="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-slate-300 mt-1">' +
            '<span>流量/带宽：' + (srv.traffic || '未填写') + '</span>' +
            '<span>到期：' + (srv.expiryDate || '未填写') + '</span>' +
          '</div>' +
          (srv.specs ? '<div class="text-[11px] text-slate-400 mt-1">配置：' + srv.specs + '</div>' : '') +
          (srv.note ? '<div class="text-[11px] text-amber-300/80 mt-1">投喂者备注：' + srv.note + '</div>' : '');

        list.appendChild(div);
      });

      wrapper.appendChild(list);
      container.appendChild(wrapper);
    });
  } catch (e) {
    console.error(e);
    container.innerHTML = '<div class="text-red-400 text-sm">加载异常，请稍后重试。</div>';
  }
}

loadLeaderboard();
</script>
</body>
</html>`;
  return c.html(html);
});

// ==================== 前端页面：/donate/vps（投喂表单 + 我的投喂） ====================
app.get('/donate/vps', (c) => {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>风萧萧兮公益 VPS 投喂面板</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-slate-950 text-slate-100">
  <div class="max-w-6xl mx-auto px-4 py-8">
    <header class="mb-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
      <div>
        <h1 class="text-2xl md:text-3xl font-bold bg-gradient-to-r from-cyan-400 to-indigo-400 bg-clip-text text-transparent">
          VPS 投喂中心
        </h1>
        <p class="mt-2 text-sm text-slate-300">
          这里是已登录用户的投喂面板，可以提交新的 VPS，也可以查看和管理自己的投喂记录。
        </p>
      </div>
      <div class="flex items-center gap-3">
        <div id="user-info" class="text-sm text-slate-300"></div>
        <button
          onclick="logout()"
          class="text-xs rounded-lg border border-slate-700 px-3 py-1 hover:bg-slate-800"
        >
          退出登录
        </button>
      </div>
    </header>

    <main class="grid md:grid-cols-2 gap-6 items-start">
      <!-- 投喂表单 -->
      <section class="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 shadow-lg shadow-slate-900/70">
        <h2 class="text-lg font-semibold mb-2">🧡 提交新的 VPS 投喂</h2>
        <p class="text-xs text-slate-400 mb-4 leading-relaxed">
          请确保是你有控制权的服务器，且允许我们用于公益节点。禁止恶意占用宽带、长时间跑满或刷流量、分享/售卖账号等行为。
        </p>

        <form id="donate-form" class="space-y-3 text-sm">
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block mb-1 text-xs text-slate-300">服务器 IP</label>
              <input name="ip" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" placeholder="例如 1.2.3.4" />
            </div>
            <div>
              <label class="block mb-1 text-xs text-slate-300">端口</label>
              <input name="port" required type="number" min="1" max="65535" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" placeholder="1-65535" />
            </div>
          </div>

          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block mb-1 text-xs text-slate-300">系统用户名</label>
              <input name="username" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" placeholder="root / ubuntu / ..." />
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
              <input name="country" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" placeholder="例如：日本、香港、美国" />
            </div>
            <div>
              <label class="block mb-1 text-xs text-slate-300">流量 / 带宽</label>
              <input name="traffic" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" placeholder="例：1T/月 · 100M 带宽" />
            </div>
          </div>

          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block mb-1 text-xs text-slate-300">到期日期</label>
              <input name="expiryDate" required type="date" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" />
            </div>
            <div>
              <label class="block mb-1 text-xs text-slate-300">配置描述</label>
              <input name="specs" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" placeholder="例：2C4G · 40G SSD" />
            </div>
          </div>

          <div>
            <label class="block mb-1 text-xs text-slate-300">投喂备注（可选）</label>
            <textarea name="note" rows="2" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" placeholder="写点想对项目说的话吧～"></textarea>
          </div>

          <div id="donate-message" class="text-xs mt-1 h-4"></div>

          <button
            type="submit"
            class="mt-2 inline-flex items-center justify-center rounded-xl bg-cyan-500 px-4 py-2 text-xs font-semibold shadow-lg shadow-cyan-500/30 hover:bg-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:ring-offset-2 focus:ring-offset-slate-950"
          >
            提交投喂
          </button>
        </form>
      </section>

      <!-- 我的投喂记录 -->
      <section class="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 shadow-lg shadow-slate-900/70">
        <div class="flex items-center justify-between mb-2">
          <h2 class="text-lg font-semibold">📦 我的投喂记录</h2>
          <button
            onclick="loadDonations()"
            class="text-[11px] rounded-lg border border-slate-700 px-2 py-1 hover:bg-slate-800"
          >
            刷新
          </button>
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
async function ensureLogin() {
  try {
    const res = await fetch('/api/user/info');
    if (!res.ok) {
      window.location.href = '/donate';
      return;
    }
    const json = await res.json();
    if (!json.success) {
      window.location.href = '/donate';
      return;
    }
    const u = json.data;
    const el = document.getElementById('user-info');
    el.textContent = '@' + u.username + ' · 已投喂 ' + (u.donationCount || 0) + ' 台';
  } catch (e) {
    window.location.href = '/donate';
  }
}

async function logout() {
  try {
    await fetch('/api/logout');
  } catch (e) {}
  window.location.href = '/donate';
}

function bindAuthTypeSwitch() {
  const select = document.querySelector('select[name="authType"]');
  const pwdField = document.getElementById('password-field');
  const keyField = document.getElementById('key-field');
  select.addEventListener('change', () => {
    if (select.value === 'password') {
      pwdField.classList.remove('hidden');
      keyField.classList.add('hidden');
    } else {
      pwdField.classList.add('hidden');
      keyField.classList.remove('hidden');
    }
  });
}

async function submitDonateForm(e) {
  e.preventDefault();
  const form = e.target;
  const msgEl = document.getElementById('donate-message');
  msgEl.textContent = '';
  msgEl.className = 'text-xs mt-1 h-4';

  const formData = new FormData(form);
  const payload = {
    ip: formData.get('ip')?.toString().trim(),
    port: Number(formData.get('port')?.toString().trim()),
    username: formData.get('username')?.toString().trim(),
    authType: formData.get('authType')?.toString(),
    password: formData.get('password')?.toString(),
    privateKey: formData.get('privateKey')?.toString(),
    country: formData.get('country')?.toString().trim(),
    traffic: formData.get('traffic')?.toString().trim(),
    expiryDate: formData.get('expiryDate')?.toString().trim(),
    specs: formData.get('specs')?.toString().trim(),
    note: formData.get('note')?.toString().trim(),
  };

  try {
    const res = await fetch('/api/donate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const json = await res.json();
    if (!res.ok || !json.success) {
      msgEl.textContent = json.message || '提交失败';
      msgEl.classList.add('text-red-400');
    } else {
      msgEl.textContent = json.message || '投喂成功';
      msgEl.classList.add('text-emerald-400');
      form.reset();
      loadDonations();
    }
  } catch (e) {
    msgEl.textContent = '提交异常，请稍后重试';
    msgEl.classList.add('text-red-400');
  }
}

async function loadDonations() {
  const container = document.getElementById('donations-list');
  container.innerHTML = '<div class="text-slate-400 text-xs">正在加载...</div>';
  try {
    const res = await fetch('/api/user/donations');
    if (!res.ok) {
      container.innerHTML = '<div class="text-red-400 text-xs">加载失败</div>';
      return;
    }
    const json = await res.json();
    if (!json.success) {
      container.innerHTML = '<div class="text-red-400 text-xs">' + (json.message || '加载失败') + '</div>';
      return;
    }
    const data = json.data || [];
    if (!data.length) {
      container.innerHTML = '<div class="text-slate-400 text-xs">还没有投喂记录，先在左侧提交一台吧～</div>';
      return;
    }
    container.innerHTML = '';
    data.forEach((vps) => {
      const div = document.createElement('div');
      div.className = 'rounded-xl border border-slate-800 bg-slate-950/60 px-3 py-2';

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

      div.innerHTML =
        '<div class="flex items-center justify-between gap-2 mb-1">' +
          '<div class="text-[11px] text-slate-200">IP：' + vps.ip + ':' + vps.port + '</div>' +
          '<div class="' + statusColor + ' text-[11px]">' + statusText + '</div>' +
        '</div>' +
        '<div class="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-slate-300">' +
          '<span>地区：' + (vps.country || '未填写') + (vps.ipLocation ? ' · ' + vps.ipLocation : '') + '</span>' +
          '<span>流量/带宽：' + (vps.traffic || '未填写') + '</span>' +
          '<span>到期：' + (vps.expiryDate || '未填写') + '</span>' +
        '</div>' +
        '<div class="text-[11px] text-slate-400 mt-1">配置：' + (vps.specs || '未填写') + '</div>' +
        (vps.note ? '<div class="text-[11px] text-amber-300/80 mt-1">我的备注：' + vps.note + '</div>' : '') +
        (donatedAtText ? '<div class="text-[11px] text-slate-500 mt-1">投喂时间：' + donatedAtText + '</div>' : '');

      container.appendChild(div);
    });
  } catch (e) {
    container.innerHTML = '<div class="text-red-400 text-xs">加载异常</div>';
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

// ==================== 管理后台页面：/admin （卡片 + 筛选） ====================
app.get('/admin', (c) => {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>风萧萧兮公益 VPS 管理后台</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-slate-950 text-slate-100">
  <div class="max-w-7xl mx-auto px-4 py-8" id="app-root">
    <div class="text-slate-300 text-sm">正在检测管理员登录状态...</div>
  </div>

<script>
let allVpsList = [];
let statusFilter = 'all';
let userFilter = '';

async function checkAdmin() {
  const root = document.getElementById('app-root');
  try {
    const res = await fetch('/api/admin/check-session');
    const json = await res.json();
    if (!json.success || !json.isAdmin) {
      renderLogin(root);
    } else {
      renderAdmin(root, json.username);
      await loadStats();
      await loadVps();
    }
  } catch (e) {
    root.innerHTML = '<div class="text-red-400 text-sm">加载失败</div>';
  }
}

function renderLogin(root) {
  root.innerHTML = '';
  const wrap = document.createElement('div');
  wrap.className = 'max-w-sm mx-auto rounded-2xl border border-slate-800 bg-slate-900/80 p-6 shadow-lg shadow-slate-900/80';

  wrap.innerHTML =
    '<h1 class="text-xl font-semibold mb-4">管理员登录</h1>' +
    '<p class="text-xs text-slate-400 mb-4">请输入在后端配置的管理员密码。</p>' +
    '<form id="admin-login-form" class="space-y-3 text-sm">' +
      '<div>' +
        '<label class="block mb-1 text-xs text-slate-300">密码</label>' +
        '<input type="password" name="password" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500" />' +
      '</div>' +
      '<div id="admin-login-msg" class="text-[11px] h-4"></div>' +
      '<button type="submit" class="mt-1 inline-flex items-center justify-center rounded-xl bg-cyan-500 px-4 py-2 text-xs font-semibold hover:bg-cyan-400">登录</button>' +
    '</form>';

  root.appendChild(wrap);

  document.getElementById('admin-login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = document.getElementById('admin-login-msg');
    msg.textContent = '';
    msg.className = 'text-[11px] h-4';
    const fd = new FormData(e.target);
    const password = fd.get('password')?.toString() || '';
    try {
      const res = await fetch('/api/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      const json = await res.json();
      if (!res.ok || !json.success) {
        msg.textContent = json.message || '登录失败';
        msg.classList.add('text-red-400');
      } else {
        location.reload();
      }
    } catch (err) {
      msg.textContent = '登录异常';
      msg.classList.add('text-red-400');
    }
  });
}

function renderAdmin(root, adminName) {
  root.innerHTML = '';
  const header = document.createElement('header');
  header.className = 'mb-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4';
  header.innerHTML =
    '<div>' +
      '<h1 class="text-2xl md:text-3xl font-bold bg-gradient-to-r from-cyan-400 to-indigo-400 bg-clip-text text-transparent">VPS 管理后台</h1>' +
      '<p class="mt-2 text-xs text-slate-400">仅管理员可见 · 可查看全部投喂 VPS 与认证信息。</p>' +
    '</div>' +
    '<div class="flex items-center gap-3">' +
      '<span class="text-xs text-slate-300">管理员：' + adminName + '</span>' +
      '<button onclick="adminLogout()" class="text-[11px] rounded-lg border border-slate-700 px-2 py-1 hover:bg-slate-800">退出</button>' +
    '</div>';
  root.appendChild(header);

  const statsWrap = document.createElement('section');
  statsWrap.id = 'admin-stats';
  root.appendChild(statsWrap);

  const listWrap = document.createElement('section');
  listWrap.className = 'mt-6';
  listWrap.innerHTML =
    '<div class="flex items-center justify-between mb-2">' +
      '<h2 class="text-lg font-semibold">VPS 列表</h2>' +
      '<div class="flex items-center gap-2 text-[11px] text-slate-400">' +
        '<span>筛选：</span>' +
        '<button onclick="setStatusFilter(\\'all\\')" class="px-2 py-1 rounded-lg border border-slate-700 hover:bg-slate-800" data-status="all">全部</button>' +
        '<button onclick="setStatusFilter(\\'active\\')" class="px-2 py-1 rounded-lg border border-emerald-500/40 text-emerald-300 hover:bg-slate-800" data-status="active">活跃</button>' +
        '<button onclick="setStatusFilter(\\'failed\\')" class="px-2 py-1 rounded-lg border border-red-500/40 text-red-300 hover:bg-slate-800" data-status="failed">失败</button>' +
        '<button onclick="setStatusFilter(\\'inactive\\')" class="px-2 py-1 rounded-lg border border-slate-500/40 text-slate-200 hover:bg-slate-800" data-status="inactive">未激活</button>' +
      '</div>' +
    '</div>' +
    '<div id="vps-list" class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4"></div>';
  root.appendChild(listWrap);
}

async function adminLogout() {
  try {
    await fetch('/api/admin/logout');
  } catch (e) {}
  location.reload();
}

async function loadStats() {
  const wrap = document.getElementById('admin-stats');
  wrap.innerHTML = '<div class="text-xs text-slate-400 mb-3">正在加载统计信息...</div>';
  try {
    const res = await fetch('/api/admin/stats');
    const json = await res.json();
    if (!res.ok || !json.success) {
      wrap.innerHTML = '<div class="text-red-400 text-xs mb-3">统计信息加载失败</div>';
      return;
    }
    const d = json.data || {};
    wrap.innerHTML =
      '<div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-4">' +
        statCard('total', '总投喂数', d.totalVPS || 0, 'all') +
        statCard('active', '活跃服务器', d.activeVPS || 0, 'active') +
        statCard('inactive', '未激活', d.inactiveVPS || 0, 'inactive') +
        statCard('failed', '验证失败', d.failedVPS || 0, 'failed') +
        statCard('pending', '待验证', d.pendingVPS || 0, 'pending') +
        statCard('today', '今日新增', d.todayNewVPS || 0, 'today') +
      '</div>';
  } catch (e) {
    wrap.innerHTML = '<div class="text-red-400 text-xs mb-3">统计信息加载异常</div>';
  }
}

function statCard(id, label, value, filterKey) {
  return (
    '<button onclick="clickStatFilter(\\'' + filterKey + '\\')" class="rounded-2xl border border-slate-800 bg-slate-900/70 px-3 py-2 text-left hover:bg-slate-900">' +
      '<div class="text-[11px] text-slate-400">' + label + '</div>' +
      '<div class="text-lg font-semibold mt-1">' + value + '</div>' +
    '</button>'
  );
}

function clickStatFilter(key) {
  if (key === 'all' || key === 'today') {
    statusFilter = 'all';
  } else if (key === 'active' || key === 'inactive' || key === 'failed') {
    statusFilter = key;
  } else if (key === 'pending') {
    statusFilter = 'pending';
  }
  userFilter = '';
  renderVpsList();
}

function setStatusFilter(status) {
  statusFilter = status;
  userFilter = '';
  renderVpsList();
}

async function loadVps() {
  const listEl = document.getElementById('vps-list');
  listEl.innerHTML = '<div class="text-xs text-slate-400">正在加载 VPS...</div>';
  try {
    const res = await fetch('/api/admin/vps');
    const json = await res.json();
    if (!res.ok || !json.success) {
      listEl.innerHTML = '<div class="text-red-400 text-xs">加载失败</div>';
      return;
    }
    allVpsList = json.data || [];
    renderVpsList();
  } catch (e) {
    listEl.innerHTML = '<div class="text-red-400 text-xs">加载异常</div>';
  }
}

function renderVpsList() {
  const listEl = document.getElementById('vps-list');
  if (!allVpsList.length) {
    listEl.innerHTML = '<div class="text-xs text-slate-400 col-span-full">暂无 VPS 记录</div>';
    return;
  }
  const filtered = allVpsList.filter((v) => {
    let ok = true;
    if (statusFilter === 'active') ok = v.status === 'active';
    else if (statusFilter === 'inactive') ok = v.status === 'inactive';
    else if (statusFilter === 'failed') ok = v.status === 'failed';
    else if (statusFilter === 'pending') ok = v.verifyStatus === 'pending';
    if (userFilter) ok = ok && v.donatedByUsername === userFilter;
    return ok;
  });

  if (!filtered.length) {
    listEl.innerHTML = '<div class="text-xs text-slate-400 col-span-full">当前筛选下没有 VPS</div>';
    return;
  }

  listEl.innerHTML = '';
  filtered.forEach((v) => {
    const card = document.createElement('div');
    card.className = 'rounded-2xl border border-slate-800 bg-slate-900/80 p-3 flex flex-col gap-2 text-xs';

    const statusColor =
      v.status === 'active' ? 'text-emerald-400' :
      v.status === 'failed' ? 'text-red-400' :
      'text-slate-300';

    const statusText =
      v.status === 'active' ? '已激活' :
      v.status === 'failed' ? '验证失败' :
      '未激活';

    const dt = v.donatedAt ? new Date(v.donatedAt) : null;
    const donatedAtText = dt ? dt.toLocaleString() : '';

    card.innerHTML =
      '<div class="flex items-center justify-between gap-2">' +
        '<div class="text-[11px] text-slate-200">IP：' + v.ip + ':' + v.port + '</div>' +
        '<div class="' + statusColor + ' text-[11px]">' + statusText + '</div>' +
      '</div>' +
      '<div class="flex flex-wrap gap-2 text-[11px] text-slate-300">' +
        '<span>投喂者：<button class="underline hover:text-cyan-400" onclick="filterByUser(\\'' + v.donatedByUsername + '\\')">@' + v.donatedByUsername + '</button></span>' +
        '<span>地区：' + (v.country || '未填写') + (v.ipLocation ? ' · ' + v.ipLocation : '') + '</span>' +
      '</div>' +
      '<div class="flex flex-wrap gap-2 text-[11px] text-slate-300">' +
        '<span>流量/带宽：' + (v.traffic || '未填写') + '</span>' +
        '<span>到期：' + (v.expiryDate || '未填写') + '</span>' +
      '</div>' +
      '<div class="text-[11px] text-slate-400">配置：' + (v.specs || '未填写') + '</div>' +
      (v.note ? '<div class="text-[11px] text-amber-300/80">用户备注：' + v.note + '</div>' : '') +
      (v.adminNote ? '<div class="text-[11px] text-cyan-300/80">管理员备注：' + v.adminNote + '</div>' : '') +
      (donatedAtText ? '<div class="text-[11px] text-slate-500">投喂时间：' + donatedAtText + '</div>' : '') +
      '<details class="mt-1">' +
        '<summary class="cursor-pointer text-[11px] text-cyan-300">查看详情</summary>' +
        '<div class="mt-1 space-y-1 text-[11px] text-slate-300">' +
          '<div>SSH 用户：' + v.username + '</div>' +
          '<div>认证方式：' + v.authType + '</div>' +
          '<div>验证状态：' + (v.verifyStatus || 'unknown') + (v.verifyErrorMsg ? ' · ' + v.verifyErrorMsg : '') + '</div>' +
          '<div class="flex flex-wrap gap-2 mt-1">' +
            '<button onclick="markVerified(\\'' + v.id + '\\')" class="px-2 py-1 rounded-lg border border-emerald-500/40 text-emerald-300 hover:bg-slate-800">标记通过</button>' +
            '<button onclick="setStatus(\\'' + v.id + '\\', \\'inactive\\')" class="px-2 py-1 rounded-lg border border-slate-500/40 text-slate-200 hover:bg-slate-800">设为未激活</button>' +
            '<button onclick="setStatus(\\'' + v.id + '\\', \\'failed\\')" class="px-2 py-1 rounded-lg border border-red-500/40 text-red-300 hover:bg-slate-800">设为失败</button>' +
            '<button onclick="deleteVps(\\'' + v.id + '\\')" class="px-2 py-1 rounded-lg border border-red-500/40 text-red-300 hover:bg-slate-900">删除</button>' +
          '</div>' +
        '</div>' +
      '</details>';

    listEl.appendChild(card);
  });
}

function filterByUser(u) {
  userFilter = u;
  renderVpsList();
}

async function markVerified(id) {
  if (!confirm('确定将此 VPS 标记为验证通过并激活？')) return;
  await fetch('/api/admin/vps/' + id + '/mark-verified', { method: 'POST' });
  await loadVps();
  await loadStats();
}

async function setStatus(id, status) {
  if (!confirm('确定修改状态为 ' + status + ' ？')) return;
  await fetch('/api/admin/vps/' + id + '/status', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  });
  await loadVps();
  await loadStats();
}

async function deleteVps(id) {
  if (!confirm('确定删除此 VPS 记录？')) return;
  await fetch('/api/admin/vps/' + id, { method: 'DELETE' });
  await loadVps();
  await loadStats();
}

checkAdmin();
</script>
</body>
</html>`;
  return c.html(html);
});

// ==================== 导出 ====================
export default app;
