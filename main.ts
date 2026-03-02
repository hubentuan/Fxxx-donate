/// <reference lib="deno.unstable" />

import { Hono, Context, Next } from 'https://deno.land/x/hono@v3.11.7/mod.ts';
import { cors } from 'https://deno.land/x/hono@v3.11.7/middleware.ts';
import { setCookie, getCookie } from 'https://deno.land/x/hono@v3.11.7/helper.ts';

declare const Deno: any;

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
  region?: string;
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
const ICONS = {
  crown: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="m2 4 3 12h14l3-12-6 7-4-7-4 7-6-7zm3 16h14"/></svg>',
  trophy: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M6 9H4.5a2.5 2.5 0 0 1 0-5H18"/><path d="M18 9h1.5a2.5 2.5 0 0 0 0-5H18"/><path d="M4 22h16"/><path d="M10 14.66V17c0 .55-.47.98-.97 1.21C7.85 18.75 7 20.24 7 22"/><path d="M14 14.66V17c0 .55.47.98.97 1.21C16.15 18.75 17 20.24 17 22"/><path d="M18 2H6v7a6 6 0 0 0 12 0V2Z"/></svg>',
  medal: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><circle cx="12" cy="8" r="7"/><polyline points="8.21 13.89 7 23 12 20 17 23 15.79 13.88"/></svg>',
  star: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>',
  server: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/></svg>',
  globe: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><circle cx="12" cy="12" r="10"/><line x1="2" x2="22" y1="12" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
  chart: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M3 3v18h18"/><path d="M18 17V9"/><path d="M13 17V5"/><path d="M8 17v-3"/></svg>',
  calendar: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><rect width="18" height="18" x="3" y="4" rx="2" ry="2"/><line x1="16" x2="16" y1="2" y2="6"/><line x1="8" x2="8" y1="2" y2="6"/><line x1="3" x2="21" y1="10" y2="10"/></svg>',
  cpu: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/></svg>',
  message: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>',
  chevronDown: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="m6 9 6 6 6-6"/></svg>',
  check: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><polyline points="20 6 9 17 4 12"/></svg>',
  x: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>',
  info: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>',
  user: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
  clock: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
  search: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><circle cx="11" cy="11" r="8"/><line x1="21" x2="16.65" y1="21" y2="16.65"/></svg>',
  edit: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>',
  trash: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
  settings: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
  note: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" x2="8" y1="13" y2="13"/><line x1="16" x2="8" y1="17" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>',
  alert: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg>',
  key: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>',
  lock: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  save: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>',
  plug: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M12 22v-5"/><path d="M9 8V2"/><path d="M15 8V2"/><path d="M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z"/></svg>',
  bulb: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M15 14c.2-1 .7-1.7 1.5-2.5 1-1 1.5-2.4 1.5-3.8 0-3.3-2.7-6-6-6 0 0-6 .7-6 6 0 1.4.5 2.8 1.5 3.8.8.8 1.3 1.5 1.5 2.5"/><path d="M9 18h6"/><path d="M10 22h4"/></svg>',
  heart: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="w-full h-full"><path d="m12 21.35-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35Z"/></svg>',
  rocket: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"/><path d="m12 15-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"/><path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"/><path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"/></svg>',
  upload: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" x2="12" y1="3" y2="15"/></svg>',
  checkCircle: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
  warning: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" x2="12" y1="9" y2="13"/><line x1="12" x2="12.01" y1="17" y2="17"/></svg>'
};

const genId = () => crypto.randomUUID();

/**
 * 清理 IP 输入：去除所有不可见字符、零宽空格、BOM、全角字符等
 * 这是修复 "IP 格式不正确" bug 的关键函数
 */
function cleanIPInput(raw: string): string {
  let s = String(raw);
  // 1. 全角数字/冒号/点 → 半角
  s = s.replace(/[\uff10-\uff19]/g, c => String.fromCharCode(c.charCodeAt(0) - 0xfee0));
  s = s.replace(/\uff1a/g, ':');  // 全角冒号
  s = s.replace(/\uff0e/g, '.');  // 全角句号
  s = s.replace(/\u3002/g, '.');  // 中文句号「。」
  // 2. 剥离所有不可见/控制字符、零宽字符、BOM 等
  s = s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, '');
  s = s.replace(/[\u200b-\u200f\u2028-\u202f\u2060\ufeff\ufff0-\uffff]/g, '');
  // 3. 去首尾空白（含 \r \n \t 等）
  s = s.trim();
  // 4. 去掉可能的 http:// 前缀或尾部 / 路径
  s = s.replace(/^https?:\/\//i, '');
  s = s.replace(/\/.*$/, '');
  return s;
}

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
  } catch (_) { }
  return '未知地区';
}

const isIPv4 = (ip: string) => {
  const trimmed = cleanIPInput(ip);
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) return false;
  return trimmed.split('.').every(p => {
    const num = parseInt(p, 10);
    return num >= 0 && num <= 255;
  });
};

const isIPv6 = (ip: string) => {
  const trimmed = cleanIPInput(ip).replace(/^\[|\]$/g, '');
  // 简化的IPv6验证，支持完整格式和压缩格式
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/;
  return ipv6Regex.test(trimmed);
};
const isValidIP = (ip: string) => isIPv4(ip) || isIPv6(ip);

async function getAllVPS(): Promise<VPSServer[]> {
  const iter = kv.list({ prefix: ['vps'] });
  const arr: VPSServer[] = [];
  for await (const e of iter) arr.push(e.value);
  return arr.sort((a, b) => b.donatedAt - a.donatedAt);
}

async function ipDup(ip: string, port: number) {
  return (await getAllVPS()).some(v => v.ip === ip && v.port === port);
}

async function portOK(ip: string, port: number) {
  try {
    const conn = await Deno.connect({
      hostname: ip.replace(/^\[|\]$/g, ''),
      port,
      transport: 'tcp'
    });
    conn.close();
    return true;
  } catch {
    return false;
  }
}

async function addVPS(server: Omit<VPSServer, 'id'>) {
  const v: VPSServer = { id: genId(), ...server };
  await kv.set(['vps', v.id], v);
  const r = await kv.get(['user_donations', v.donatedBy]);
  const list = r.value || [];
  list.push(v.id);
  await kv.set(['user_donations', v.donatedBy], list);
  return v;
}

async function delVPS(id: string) {
  const r = await kv.get(['vps', id]);
  if (!r.value) return false;
  await kv.delete(['vps', id]);
  const u = await kv.get(['user_donations', r.value.donatedBy]);
  if (u.value) {
    await kv.set(['user_donations', r.value.donatedBy], u.value.filter(x => x !== id));
  }
  return true;
}

async function updVPSStatus(id: string, s: VPSServer['status']) {
  const r = await kv.get(['vps', id]);
  if (!r.value) return false;
  r.value.status = s;
  await kv.set(['vps', id], r.value);
  return true;
}

/* ==================== 配置 & 会话 ==================== */
const getOAuth = async () =>
  (await kv.get(['config', 'oauth'])).value || null;
const setOAuth = async (c: OAuthConfig) => {
  await kv.set(['config', 'oauth'], c);
};
const getAdminPwd = async () =>
  (await kv.get(['config', 'admin_password'])).value || 'admin123';
const setAdminPwd = async (p: string) => {
  await kv.set(['config', 'admin_password'], p);
};

async function getSession(id: string) {
  const r = await kv.get(['sessions', id]);
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
  isAdmin: boolean
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
  return (await kv.get(['users', linuxDoId])).value || null;
}

async function upsertUser(linuxDoId: string, username: string, avatarUrl?: string) {
  const old = await getUser(linuxDoId);
  const u: User = {
    linuxDoId,
    username,
    avatarUrl,
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
const requireAuth = async (c: Context, next: Next) => {
  const sid = getCookie(c, 'session_id');
  if (!sid) return c.json({ success: false, message: '未登录' }, 401);
  const s = await getSession(sid);
  if (!s) return c.json({ success: false, message: '会话已过期' }, 401);
  c.set('session', s);
  await next();
};

const requireAdmin = async (c: Context, next: Next) => {
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

app.get('/', (c: Context) => c.redirect('/donate'));

/* ---- Favicon 路由（防止 404 错误）---- */
app.get('/favicon.ico', (c: Context) => {
  // 返回一个简单的橙色心形 SVG favicon
  const svg = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='0.9em' font-size='90'>🧡</text></svg>`;
  return c.body(svg, 200, {
    'Content-Type': 'image/svg+xml',
    'Cache-Control': 'public, max-age=86400' // 缓存1天
  });
});

/* ---- OAuth 登录 ---- */
app.get('/oauth/login', async (c: Context) => {
  const redirectPath = c.req.query('redirect') || '/donate/vps';
  const cfg = await getOAuth();
  if (!cfg) {
    return c.html(
      '<!doctype html><body><h1>配置错误</h1><p>OAuth 未设置</p><a href="/donate">返回</a></body>',
    );
  }
  const url = new URL('https://connect.linux.do/oauth2/authorize');
  url.searchParams.set('client_id', cfg.clientId);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('redirect_uri', cfg.redirectUri);
  url.searchParams.set('scope', 'openid profile');
  url.searchParams.set(
    'state',
    typeof redirectPath === 'string' ? redirectPath : '/donate/vps',
  );
  return c.redirect(url.toString());
});

app.get('/oauth/callback', async (c: Context) => {
  const code = c.req.query('code');
  const error = c.req.query('error');
  const state = c.req.query('state') || '/donate';

  if (error) {
    return c.html(
      `<!doctype html><body><h1>登录失败</h1><p>${error}</p><a href="/donate">返回</a></body>`,
    );
  }
  if (!code) return c.text('Missing code', 400);

  try {
    const cfg = await getOAuth();
    if (!cfg) {
      return c.html('<!doctype html><body><h1>配置错误</h1><a href="/donate">返回</a></body>');
    }

    const token = await tokenByCode(code, cfg);
    const info = await linuxDoUser(token.access_token);

    let avatar = info.avatar_template as string | undefined;
    if (avatar) {
      avatar = avatar.replace('{size}', '120');
      if (avatar.startsWith('//')) avatar = 'https:' + avatar;
      else if (avatar.startsWith('/')) avatar = 'https://connect.linux.do' + avatar;
    }

    const user = await upsertUser(String(info.id), info.username, avatar);
    const sid = await createSession(
      user.linuxDoId,
      user.username,
      user.avatarUrl,
      user.isAdmin
    );
    const isProd = Deno.env.get('DENO_DEPLOYMENT_ID') !== undefined;

    setCookie(c, 'session_id', sid, {
      maxAge: 7 * 24 * 3600,
      httpOnly: true,
      secure: isProd,
      sameSite: 'Lax',
      path: '/'
    });

    const redirectTo =
      typeof state === 'string' && state.startsWith('/') ? state : '/donate';
    return c.redirect(redirectTo);
  } catch (e: any) {
    return c.html(
      `<!doctype html><body><h1>登录失败</h1><p>${e.message || e}</p><a href="/donate">返回</a></body>`,
    );
  }
});

/* ---- 用户 API ---- */
app.get('/api/logout', async (c: Context) => {
  const sid = getCookie(c, 'session_id');
  if (sid) await kv.delete(['sessions', sid]);
  setCookie(c, 'session_id', '', { maxAge: 0, path: '/' });
  return c.json({ success: true });
});

app.get('/api/user/info', requireAuth, async (c: Context) => {
  const s = c.get('session');
  const r = await kv.get(['user_donations', s.userId]);
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

app.get('/api/user/donations', requireAuth, async (c: Context) => {
  const s = c.get('session');
  const ids = (await kv.get(['user_donations', s.userId])).value || [];
  const arr: VPSServer[] = [];

  for (const id of ids) {
    const r = await kv.get(['vps', id]);
    if (r.value) arr.push(r.value);
  }

  const safe = arr
    .sort((a, b) => b.donatedAt - a.donatedAt)
    .map(d => ({
      id: d.id,
      ip: d.ip,
      port: d.port,
      username: d.username,
      authType: d.authType,
      donatedAt: d.donatedAt,
      status: d.status,
      note: d.note,
      country: d.country,
      region: d.region,
      traffic: d.traffic,
      expiryDate: d.expiryDate,
      specs: d.specs,
      ipLocation: d.ipLocation,
      verifyStatus: d.verifyStatus,
      lastVerifyAt: d.lastVerifyAt,
      verifyErrorMsg: d.verifyErrorMsg,
      donatedByUsername: d.donatedByUsername
    }));

  return c.json({ success: true, data: safe });
});

app.put('/api/user/donations/:id/note', requireAuth, async (c: Context) => {
  const s = c.get('session');
  const id = c.req.param('id');
  const { note } = await c.req.json();

  const r = await kv.get(['vps', id]);
  if (!r.value) return c.json({ success: false, message: 'VPS 不存在' }, 404);
  if (r.value.donatedBy !== s.userId)
    return c.json({ success: false, message: '无权修改' }, 403);

  r.value.note = (note || '').toString();
  await kv.set(['vps', id], r.value);
  return c.json({ success: true, message: '备注已更新' });
});

/* ---- 公共榜单 API ---- */
app.get('/api/leaderboard', async (c: Context) => {
  try {
    const all = await getAllVPS();
    const map = new Map<string, { username: string; count: number; servers: any[] }>();

    for (const v of all) {
      const rec =
        map.get(v.donatedBy) ||
        {
          username: v.donatedByUsername,
          count: 0,
          servers: []
        };
      rec.count++;
      rec.servers.push({
        ipLocation: v.ipLocation || '未知地区',
        country: v.country || '未填写',
        region: v.region || '',
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
app.post('/api/donate', requireAuth, async (c: Context) => {
  const s = c.get('session');
  const body = await c.req.json();
  const {
    ip,
    port,
    username,
    authType,
    password,
    privateKey,
    country,
    region,
    traffic,
    expiryDate,
    specs,
    note
  } = body;

  if (!ip || !port || !username || !authType) {
    return c.json({ success: false, message: 'IP / 端口 / 用户名 / 认证方式 必填' }, 400);
  }
  if (!country || !traffic || !expiryDate || !specs) {
    return c.json(
      { success: false, message: '国家、流量、到期、配置 必填' },
      400,
    );
  }
  if (authType === 'password' && !password) {
    return c.json({ success: false, message: '密码认证需要密码' }, 400);
  }
  if (authType === 'key' && !privateKey) {
    return c.json({ success: false, message: '密钥认证需要私钥' }, 400);
  }

  // 使用 cleanIPInput 深度清理 IP，去除不可见字符、全角字符等
  const ipClean = cleanIPInput(ip);
  if (!isValidIP(ipClean)) {
    return c.json({ success: false, message: 'IP 格式不正确' }, 400);
  }

  const p = parseInt(String(port), 10);
  if (p < 1 || p > 65535) {
    return c.json({ success: false, message: '端口范围 1 ~ 65535' }, 400);
  }
  if (await ipDup(ipClean, p)) {
    return c.json({ success: false, message: '该 IP:端口 已被投喂' }, 400);
  }
  if (!(await portOK(ipClean, p))) {
    return c.json({
      success: false,
      message: '无法连接到该服务器，请确认 IP / 端口 是否正确、且对外开放',
    }, 400);
  }

  const ipLoc = await getIPLocation(ipClean);
  const now = Date.now();

  const v = await addVPS({
    ip: ipClean,     // ✅ 这里也换成 ipClean
    port: p,
    username,
    authType,
    password,
    privateKey,
    country,
    region: region ? String(region).trim() : undefined,
    traffic,
    expiryDate,
    specs,
    note,
    donatedBy: s.userId,
    donatedByUsername: s.username,
    donatedAt: now,
    status: 'active',
    ipLocation: ipLoc,
    verifyStatus: 'verified',
    lastVerifyAt: now,
    verifyErrorMsg: ''
  });

  return c.json({
    success: true,
    message: '投喂成功，已通过连通性验证，感谢支持！',
    data: { id: v.id, ipLocation: v.ipLocation }
  });
});

/* ---- 管理员 API ---- */
app.get('/api/admin/check-session', async (c: Context) => {
  try {
    const sid = getCookie(c, 'admin_session_id');
    if (!sid) return c.json({ success: false, isAdmin: false });

    const s = await getSession(sid);
    if (!s) return c.json({ success: false, isAdmin: false });

    return c.json({
      success: true,
      isAdmin: !!s.isAdmin,
      username: s.username
    });
  } catch (err) {
    console.error('Admin check error:', err);
    return c.json({ success: false, isAdmin: false });
  }
});

app.post('/api/admin/login', async (c: Context) => {
  const { password } = await c.req.json();
  const real = await getAdminPwd();

  if (password !== real)
    return c.json({ success: false, message: '密码错误' }, 401);

  const sid = genId();
  const sess: Session = {
    id: sid,
    userId: 'admin',
    username: 'Administrator',
    avatarUrl: undefined,
    isAdmin: true,
    expiresAt: Date.now() + 7 * 24 * 3600 * 1000
  };
  await kv.set(['sessions', sid], sess);

  const isProd = Deno.env.get('DENO_DEPLOYMENT_ID') !== undefined;
  setCookie(c, 'admin_session_id', sid, {
    maxAge: 7 * 24 * 3600,
    httpOnly: true,
    secure: isProd,
    sameSite: 'Lax',
    path: '/'
  });

  return c.json({ success: true, message: '登录成功' });
});

app.get('/api/admin/logout', async (c: Context) => {
  const sid = getCookie(c, 'admin_session_id');
  if (sid) await kv.delete(['sessions', sid]);
  setCookie(c, 'admin_session_id', '', { maxAge: 0, path: '/' });
  return c.json({ success: true });
});

app.get('/api/admin/vps', requireAdmin, async c => {
  try {
    const data = await getAllVPS();
    return c.json({ success: true, data });
  } catch (err) {
    console.error('Admin VPS list error:', err);
    return c.json({ success: false, message: '加载失败' }, 500);
  }
});

app.delete('/api/admin/vps/:id', requireAdmin, async (c: Context) => {
  const ok = await delVPS(c.req.param('id'));
  return c.json(
    ok ? { success: true, message: 'VPS 已删除' } : { success: false, message: '不存在' },
    ok ? 200 : 404,
  );
});

app.put('/api/admin/vps/:id/status', requireAdmin, async (c: Context) => {
  const id = c.req.param('id');
  const { status } = await c.req.json();

  if (!['active', 'inactive', 'failed'].includes(status)) {
    return c.json({ success: false, message: '无效状态' }, 400);
  }

  const ok = await updVPSStatus(id, status as VPSServer['status']);
  return c.json(
    ok ? { success: true, message: '状态已更新' } : { success: false, message: '不存在' },
    ok ? 200 : 404,
  );
});

app.put('/api/admin/vps/:id/notes', requireAdmin, async (c: Context) => {
  const id = c.req.param('id');
  const { note, adminNote, country, region, traffic, expiryDate, specs } = await c.req.json();

  const r = await kv.get(['vps', id]);
  if (!r.value) return c.json({ success: false, message: '不存在' }, 404);

  if (note !== undefined) r.value.note = String(note);
  if (adminNote !== undefined) r.value.adminNote = String(adminNote);
  if (country !== undefined) r.value.country = String(country);
  if (region !== undefined) r.value.region = String(region);
  if (traffic !== undefined) r.value.traffic = String(traffic);
  if (expiryDate !== undefined) r.value.expiryDate = String(expiryDate);
  if (specs !== undefined) r.value.specs = String(specs);

  await kv.set(['vps', id], r.value);
  return c.json({ success: true, message: '信息已更新' });
});

app.get('/api/admin/config/oauth', requireAdmin, async (c: Context) => {
  const oauth = await getOAuth();
  return c.json({ success: true, data: oauth || {} });
});

app.put('/api/admin/config/oauth', requireAdmin, async (c: Context) => {
  const { clientId, clientSecret, redirectUri } = await c.req.json();

  if (!clientId || !clientSecret || !redirectUri) {
    return c.json({ success: false, message: '字段必填' }, 400);
  }

  await setOAuth({ clientId, clientSecret, redirectUri });
  return c.json({ success: true, message: 'OAuth 配置已更新' });
});

app.put('/api/admin/config/password', requireAdmin, async (c: Context) => {
  const { password } = await c.req.json();

  if (!password || String(password).length < 6) {
    return c.json({ success: false, message: '密码至少 6 位' }, 400);
  }

  await setAdminPwd(String(password));
  return c.json({ success: true, message: '管理员密码已更新' });
});

/* VPS 配置编辑 */
app.put('/api/admin/vps/:id/config', requireAdmin, async (c: Context) => {
  const id = c.req.param('id');
  const { ip, port, username, authType, password, privateKey } = await c.req.json();

  // 验证必填字段
  if (!ip || !port || !username || !authType) {
    return c.json({ success: false, message: 'IP / 端口 / 用户名 / 认证方式 必填' }, 400);
  }

  // 验证认证凭据
  if (authType === 'password' && !password) {
    return c.json({ success: false, message: '密码认证需要密码' }, 400);
  }
  if (authType === 'key' && !privateKey) {
    return c.json({ success: false, message: '密钥认证需要私钥' }, 400);
  }

  // 清理并验证IP
  const ipClean = cleanIPInput(ip);
  if (!isValidIP(ipClean)) {
    return c.json({ success: false, message: 'IP 格式不正确' }, 400);
  }

  // 验证端口范围
  const p = parseInt(String(port), 10);
  if (p < 1 || p > 65535) {
    return c.json({ success: false, message: '端口范围 1 ~ 65535' }, 400);
  }

  // 获取现有VPS记录
  const r = await kv.get(['vps', id]);
  if (!r.value) {
    return c.json({ success: false, message: 'VPS 不存在' }, 404);
  }

  // 更新配置字段
  r.value.ip = ipClean;
  r.value.port = p;
  r.value.username = String(username).trim();
  r.value.authType = authType as 'password' | 'key';

  if (authType === 'password') {
    r.value.password = String(password);
    r.value.privateKey = undefined;
  } else {
    r.value.privateKey = String(privateKey);
    r.value.password = undefined;
  }

  // 测试连通性
  const isConnectable = await portOK(ipClean, p);
  r.value.lastVerifyAt = Date.now();

  if (isConnectable) {
    r.value.status = 'active';
    r.value.verifyStatus = 'verified';
    r.value.verifyErrorMsg = '';
  } else {
    r.value.verifyStatus = 'failed';
    r.value.verifyErrorMsg = '无法连接到该服务器，请检查配置是否正确';
  }

  // 保存更新
  await kv.set(['vps', id], r.value);

  return c.json({
    success: true,
    message: isConnectable
      ? '配置更新成功，连通性验证通过'
      : '配置已保存，但无法连接到服务器，请检查配置',
    data: {
      id: r.value.id,
      status: r.value.status,
      verifyStatus: r.value.verifyStatus,
      lastVerifyAt: r.value.lastVerifyAt,
      verifyErrorMsg: r.value.verifyErrorMsg
    }
  });
});

/* 后端统计：今日新增按固定东八区日期判断 */
app.get('/api/admin/stats', requireAdmin, async (c: Context) => {
  try {
    const all = await getAllVPS();

    // 用东八区（中国时间）来定义“今天”
    const tzOffsetMinutes = 8 * 60; // UTC+8
    const now = new Date();
    const nowUtcMs = now.getTime() + now.getTimezoneOffset() * 60000;
    const cnNow = new Date(nowUtcMs + tzOffsetMinutes * 60000);
    const cy = cnNow.getFullYear();
    const cm = cnNow.getMonth();
    const cd = cnNow.getDate();

    const isTodayCN = (ts: number | undefined) => {
      if (!ts) return false;
      const d = new Date(ts);
      const utcMs = d.getTime() + d.getTimezoneOffset() * 60000;
      const cn = new Date(utcMs + tzOffsetMinutes * 60000);
      return (
        cn.getFullYear() === cy &&
        cn.getMonth() === cm &&
        cn.getDate() === cd
      );
    };

    const userStats = new Map<string, number>();
    for (const v of all) {
      userStats.set(
        v.donatedByUsername,
        (userStats.get(v.donatedByUsername) || 0) + 1,
      );
    }

    const top = Array.from(userStats.entries())
      .map(([username, count]) => ({ username, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    return c.json({
      success: true,
      data: {
        totalVPS: all.length,
        activeVPS: all.filter(v => v.status === 'active').length,
        failedVPS: all.filter(v => v.status === 'failed').length,
        inactiveVPS: all.filter(v => v.status === 'inactive').length,
        pendingVPS: all.filter(v => v.verifyStatus === 'pending').length,
        verifiedVPS: all.filter(v => v.verifyStatus === 'verified').length,
        todayNewVPS: all.filter(v => isTodayCN(v.donatedAt)).length,
        topDonors: top
      }
    });
  } catch (err) {
    console.error('Admin stats error:', err);
    return c.json({ success: false, message: '加载失败' }, 500);
  }
});

app.post('/api/admin/vps/:id/mark-verified', requireAdmin, async (c: Context) => {
  const id = c.req.param('id');
  const r = await kv.get(['vps', id]);

  if (!r.value) return c.json({ success: false, message: '不存在' }, 404);

  r.value.verifyStatus = 'verified';
  r.value.status = 'active';
  r.value.lastVerifyAt = Date.now();
  r.value.verifyErrorMsg = '';

  await kv.set(['vps', id], r.value);
  return c.json({ success: true, message: '已标记为验证通过' });
});

/* 单个一键验证接口 */
app.post('/api/admin/vps/:id/verify', requireAdmin, async (c: Context) => {
  const id = c.req.param('id');
  const r = await kv.get(['vps', id]);
  if (!r.value) return c.json({ success: false, message: '不存在' }, 404);

  const v = r.value;
  const ok = await portOK(v.ip, v.port);
  v.lastVerifyAt = Date.now();

  if (ok) {
    v.status = 'active';
    v.verifyStatus = 'verified';
    v.verifyErrorMsg = '';
    await kv.set(['vps', id], v);
    return c.json({
      success: true,
      message: '验证成功，VPS 连通正常',
      data: {
        status: v.status,
        verifyStatus: v.verifyStatus,
        verifyErrorMsg: v.verifyErrorMsg,
        lastVerifyAt: v.lastVerifyAt
      }
    });
  } else {
    v.status = 'failed';
    v.verifyStatus = 'failed';
    v.verifyErrorMsg = '无法连接 VPS，请检查服务器是否在线、防火墙/安全组端口放行';
    await kv.set(['vps', id], v);
    return c.json({
      success: false,
      message: '❌ 验证失败：无法连接 VPS',
      data: {
        status: v.status,
        verifyStatus: v.verifyStatus,
        verifyErrorMsg: v.verifyErrorMsg,
        lastVerifyAt: v.lastVerifyAt
      }
    });
  }
});

/* 一键验证全部 VPS */
app.post('/api/admin/verify-all', requireAdmin, async (c: Context) => {
  const all = await getAllVPS();
  let total = 0;
  let success = 0;
  let failed = 0;

  for (const v of all) {
    total++;
    const ok = await portOK(v.ip, v.port);
    const r = await kv.get(['vps', v.id]);
    if (!r.value) continue;
    const cur = r.value;
    cur.lastVerifyAt = Date.now();
    if (ok) {
      cur.status = 'active';
      cur.verifyStatus = 'verified';
      cur.verifyErrorMsg = '';
      success++;
    } else {
      cur.status = 'failed';
      cur.verifyStatus = 'failed';
      cur.verifyErrorMsg = '无法连接 VPS，请检查服务器是否在线、防火墙/安全组端口放行';
      failed++;
    }
    await kv.set(['vps', cur.id], cur);
  }

  return c.json({
    success: true,
    message: `批量验证完成：成功 ${success} 台，失败 ${failed} 台`,
    data: { total, success, failed }
  });
});

/* ==================== /donate 榜单页 ==================== */
app.get('/donate', (c: Context) => {
  const head = commonHead('风萧萧公益机场 · VPS 投喂榜');
  const html = `<!doctype html><html lang="zh-CN"><head>${head}
<script src="https://unpkg.com/globe.gl"></script>
<style>
  #globe-container {
    width: 100%;
    height: 500px;
    border-radius: 16px;
    overflow: hidden;
    background: #000;
    transition: height 0.5s cubic-bezier(0.4, 0, 0.2, 1);
    box-shadow: inset 0 0 40px rgba(0,0,0,0.5);
  }
  
  #globe-container.minimized {
    height: 240px;
  }
  
  /* 访问者位置标记动画 */
  @keyframes pulse-glow {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.6; transform: scale(1.2); }
  }
  
  .legend-line {
    width: 24px;
    height: 3px;
    border-radius: 2px;
  }
  
  .legend-visitor { background: linear-gradient(90deg, #06b6d4, #f59e0b); }
  .legend-nearby { background: linear-gradient(90deg, rgba(34, 197, 94, 0.6), rgba(74, 222, 128, 0.8)); }
  .legend-medium { background: linear-gradient(90deg, rgba(59, 130, 246, 0.6), rgba(96, 165, 250, 0.8)); }
  .legend-long { background: linear-gradient(90deg, rgba(168, 85, 247, 0.7), rgba(192, 132, 252, 0.9)); }
  .legend-ultra-long { background: linear-gradient(90deg, rgba(236, 72, 153, 0.8), rgba(244, 114, 182, 1.0)); }

  @media (max-width: 768px) {
    #globe-container { height: 350px; }
    #globe-container.minimized { height: 180px; }
  }
</style>
</head>
<body class="min-h-screen" data-theme="dark">
<div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 md:py-12 relative z-10">

  <header class="mb-12 animate-in">
    <div class="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-8">
      <div class="flex-1 space-y-6">
        <div>
          <h1 class="grad-title-animated text-5xl md:text-6xl font-bold leading-tight tracking-tight mb-2">
            VPS 投喂榜
          </h1>
          <p class="text-lg opacity-80 font-medium">风萧萧公益机场 · 全球节点实时监控</p>
        </div>

        <div class="panel p-6 md:p-8 space-y-5 backdrop-blur-xl bg-white/50 dark:bg-black/40 border border-white/20 dark:border-white/10">
          <p class="text-base leading-relaxed">
            <span class="opacity-70">这是一个完全非盈利的公益项目，目前由我独自维护。</span><br>
            <span class="block mt-2">特别感谢以下几位佬的日常协助：
            <a href="https://linux.do/u/shklrt" target="_blank" class="font-semibold text-indigo-500 hover:text-indigo-400 transition-colors">@shklrt</a>、
            <a href="https://linux.do/u/sar60677" target="_blank" class="font-semibold text-indigo-500 hover:text-indigo-400 transition-colors">@sar60677</a>、
            <a href="https://linux.do/u/carrydelahaye" target="_blank" class="font-semibold text-indigo-500 hover:text-indigo-400 transition-colors">@Carry&nbsp;Delahaye</a>、
            <a href="https://linux.do/u/kkkyyx" target="_blank" class="font-semibold text-indigo-500 hover:text-indigo-400 transition-colors">@kkkyyx</a>。
            </span>
          </p>

          <div class="bg-amber-500/10 border border-amber-500/20 text-amber-700 dark:text-amber-400 text-sm leading-relaxed rounded-xl px-5 py-4 flex items-start gap-3">
            <span class="text-xl mt-0.5">💝</span>
            <div>
              <span class="font-bold">榜单按投喂 VPS 数量排序。</span>
              无论名次高低，您的每一次支持，对我和这个项目来说都弥足珍贵，衷心感谢！
            </div>
          </div>
          
          <div class="flex items-center gap-2 text-sm opacity-80">
             <span class="text-lg">🤝</span>
             <span>感谢大家的投喂，这个机场的发展离不开各位热佬的大力支持！共荣！🚀</span>
          </div>
        </div>

        <div class="flex flex-wrap items-center gap-4">
          <button onclick="gotoDonatePage()" class="btn-primary flex items-center gap-2 px-6 py-3 text-base shadow-lg shadow-indigo-500/20">
            <span class="text-xl">🧡</span> 我要投喂 VPS
          </button>
          <button id="theme-toggle" onclick="toggleTheme()" class="btn-secondary px-5 py-3">
            浅色模式
          </button>
        </div>
      </div>
    </div>
  </header>

  <!-- 3D地球可视化区域 -->
  <section id="globe-section" class="mb-12 animate-in" style="animation-delay: 0.1s">
    <div class="panel p-1 overflow-hidden border border-white/20 dark:border-white/10 shadow-2xl shadow-indigo-500/10">
      <div class="relative bg-black rounded-xl overflow-hidden">
        <div class="absolute top-4 left-4 z-10 flex items-center gap-3 bg-black/60 backdrop-blur-md px-4 py-2 rounded-full border border-white/10">
          <span class="text-2xl">🌍</span>
          <div>
            <h2 class="text-sm font-bold text-white leading-none">全球分布</h2>
            <p class="text-[10px] text-gray-400 mt-0.5">实时节点监控</p>
          </div>
        </div>
        
        <div class="absolute top-4 right-4 z-10 flex gap-2">
          <button id="toggle-size" class="bg-black/60 hover:bg-black/80 text-white text-xs px-3 py-1.5 rounded-lg border border-white/10 backdrop-blur-md transition-colors">最小化</button>
          <button id="toggle-rotate" class="bg-black/60 hover:bg-black/80 text-white text-xs px-3 py-1.5 rounded-lg border border-white/10 backdrop-blur-md transition-colors">暂停旋转</button>
        </div>

        <!-- 地球容器 -->
        <div id="globe-container"></div>
        
        <!-- 底部统计条 -->
        <div class="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/90 to-transparent pt-12 pb-4 px-6 flex flex-wrap items-end justify-between gap-4 pointer-events-none">
          <div id="globe-stats" class="flex gap-6 text-xs md:text-sm font-medium text-white pointer-events-auto">
            <div class="flex items-center gap-2 bg-white/10 px-3 py-1.5 rounded-full backdrop-blur-md border border-white/5">
              <span class="opacity-70">📍 位置:</span>
              <span id="visitor-location" class="text-cyan-400">检测中...</span>
            </div>
            <div class="flex items-center gap-2 bg-white/10 px-3 py-1.5 rounded-full backdrop-blur-md border border-white/5">
              <span class="opacity-70">🖥️ 总数:</span>
              <span id="total-servers">0</span>
            </div>
            <div class="flex items-center gap-2 bg-white/10 px-3 py-1.5 rounded-full backdrop-blur-md border border-white/5">
              <span class="opacity-70">✅ 活跃:</span>
              <span id="active-servers" class="text-emerald-400">0</span>
            </div>
            <div class="flex items-center gap-2 bg-white/10 px-3 py-1.5 rounded-full backdrop-blur-md border border-white/5">
              <span class="opacity-70">🔗 连接:</span>
              <span id="total-connections" class="text-blue-400">0</span>
            </div>
          </div>
          
          <div class="connection-legend flex gap-3 text-[10px] text-gray-400 pointer-events-auto bg-black/40 px-3 py-1.5 rounded-lg backdrop-blur-sm border border-white/5">
            <div class="flex items-center gap-1.5"><div class="w-3 h-0.5 rounded-full bg-gradient-to-r from-cyan-500 to-amber-400"></div><span>主线</span></div>
            <div class="flex items-center gap-1.5"><div class="w-3 h-0.5 rounded-full bg-gradient-to-r from-green-500/50 to-green-400/80"></div><span>近距</span></div>
            <div class="flex items-center gap-1.5"><div class="w-3 h-0.5 rounded-full bg-gradient-to-r from-blue-500/50 to-blue-400/80"></div><span>跨区</span></div>
            <div class="flex items-center gap-1.5"><div class="w-3 h-0.5 rounded-full bg-gradient-to-r from-purple-500/60 to-purple-400/80"></div><span>跨洲</span></div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <section class="mb-12 animate-in" style="animation-delay: 0.2s">
    <div class="flex items-center justify-between mb-8">
      <div class="flex items-center gap-4">
        <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-amber-400 to-orange-600 flex items-center justify-center text-2xl shadow-lg shadow-orange-500/20">🏆</div>
        <div>
          <h2 class="text-3xl font-bold leading-tight">捐赠榜单</h2>
          <p id="leaderboard-count" class="text-sm opacity-60 mt-1 font-medium"></p>
        </div>
      </div>
    </div>
    
    <div id="leaderboard" class="space-y-6">
      <div class="flex items-center justify-center py-20">
        <div class="flex flex-col items-center gap-4">
          <div class="loading-spinner w-8 h-8 border-4 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin"></div>
          <div class="opacity-60 text-sm font-medium">正在加载榜单数据...</div>
        </div>
      </div>
    </div>
  </section>

  <footer class="mt-20 pt-10 pb-10 text-center border-t border-gray-200 dark:border-white/5">
    <div class="inline-block panel px-6 py-4 rounded-full border bg-white/50 dark:bg-white/5 backdrop-blur-md">
      <p class="flex items-center justify-center gap-2 text-sm opacity-60 font-medium">
        <span class="text-lg">ℹ️</span>
        <span>说明：本项目仅作公益用途，请勿滥用资源。</span>
      </p>
    </div>
  </footer>

</div>

<div id="toast-root"></div>
<script>
updateThemeBtn();

let allLeaderboardData = [];

async function gotoDonatePage(){
  try{
    const r = await fetch('/api/user/info',{credentials:'same-origin',cache:'no-store'});
    if(r.ok){
      const j = await r.json();
      if(j.success) {
        location.href='/donate/vps';
      } else {
        location.href='/oauth/login?redirect='+encodeURIComponent('/donate/vps');
      }
    } else {
      location.href='/oauth/login?redirect='+encodeURIComponent('/donate/vps');
    }
  }catch(err){
    console.error('Check login error:', err);
    location.href='/oauth/login?redirect='+encodeURIComponent('/donate/vps');
  }
}

function statusText(s){ return s==='active'?'运行中':(s==='failed'?'失败':'未启用'); }
function statusCls(s){ return s==='active'?'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20':(s==='failed'?'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20':'bg-gray-500/10 text-gray-500 border-gray-500/20'); }

function renderLeaderboard(){
  const box = document.getElementById('leaderboard');
  const countEl = document.getElementById('leaderboard-count');

  countEl.textContent = allLeaderboardData.length ? ('共 '+allLeaderboardData.length+' 位投喂者') : '';

  if(!allLeaderboardData.length){
    box.innerHTML='<div class="opacity-60 text-sm py-12 text-center">暂时还没有投喂记录</div>';
    return;
  }

  const expandedStates = {};
  for(let i = 0; i < allLeaderboardData.length; i++){
    expandedStates['card-'+i] = localStorage.getItem('card-'+i) !== 'collapsed';
  }

  const fragment = document.createDocumentFragment();
  const animationLimit = 20;

  allLeaderboardData.forEach((it,idx)=>{
    const cardId = 'card-'+idx;
    const isExpanded = expandedStates[cardId];

    let gradientClass = 'bg-white/60 dark:bg-white/5'; // Default glass
    let borderClass = 'border-white/40 dark:border-white/10';
    let rankBadge = '';
    
    if(idx === 0) {
      gradientClass = 'bg-gradient-to-r from-amber-500/10 to-transparent dark:from-amber-500/20';
      borderClass = 'border-amber-500/30';
      rankBadge = '<div class="absolute -top-3 -left-3 w-8 h-8 bg-amber-500 rounded-full flex items-center justify-center text-white font-bold shadow-lg shadow-amber-500/40 z-10">1</div>';
    }
    else if(idx === 1) {
      gradientClass = 'bg-gradient-to-r from-slate-400/10 to-transparent dark:from-slate-400/20';
      borderClass = 'border-slate-400/30';
      rankBadge = '<div class="absolute -top-3 -left-3 w-8 h-8 bg-slate-400 rounded-full flex items-center justify-center text-white font-bold shadow-lg shadow-slate-400/40 z-10">2</div>';
    }
    else if(idx === 2) {
      gradientClass = 'bg-gradient-to-r from-orange-700/10 to-transparent dark:from-orange-700/20';
      borderClass = 'border-orange-700/30';
      rankBadge = '<div class="absolute -top-3 -left-3 w-8 h-8 bg-orange-700 rounded-full flex items-center justify-center text-white font-bold shadow-lg shadow-orange-700/40 z-10">3</div>';
    }

    const badge=getBadge(it.count);

    let serversHTML = '';
    (it.servers||[]).forEach(srv=>{
      serversHTML += '<div class="panel border border-white/20 dark:border-white/5 rounded-xl p-4 transition-all hover:bg-white/40 dark:hover:bg-white/10 group">'+
        '<div class="flex items-start justify-between gap-3 mb-3">'+
          '<div class="flex items-center gap-3 flex-1 min-w-0">'+
            '<div class="w-10 h-10 rounded-lg bg-indigo-500/10 flex items-center justify-center text-indigo-500 group-hover:scale-110 transition-transform"><div class="w-6 h-6">'+ICONS.globe+'</div></div>'+
            '<div class="flex flex-col gap-0.5 min-w-0">'+
              '<span class="font-semibold text-sm truncate">'+(srv.country||'未填写')+(srv.region?' · '+srv.region:'')+'</span>'+
              (srv.ipLocation?'<span class="text-xs opacity-60 truncate">'+srv.ipLocation+'</span>':'')+
            '</div>'+
          '</div>'+
          '<span class="'+statusCls(srv.status)+' text-[10px] px-2.5 py-1 rounded-full font-bold uppercase tracking-wider border flex-shrink-0">'+statusText(srv.status)+'</span>'+
        '</div>'+
        '<div class="grid grid-cols-2 gap-3 text-xs">'+
          '<div class="flex items-center gap-2 bg-black/5 dark:bg-white/5 rounded-lg px-3 py-2">'+
            '<div class="w-4 h-4 opacity-50">'+ICONS.chart+'</div>'+
            '<span class="truncate font-medium opacity-80">'+(srv.traffic||'未填写')+'</span>'+
          '</div>'+
          '<div class="flex items-center gap-2 bg-black/5 dark:bg-white/5 rounded-lg px-3 py-2">'+
            '<div class="w-4 h-4 opacity-50">'+ICONS.calendar+'</div>'+
            '<span class="truncate font-medium opacity-80">'+(srv.expiryDate||'未填写')+'</span>'+
          '</div>'+
        '</div>'+
        (srv.specs?'<div class="text-xs mt-3 bg-black/5 dark:bg-white/5 rounded-lg px-3 py-2.5 flex items-start gap-2"><div class="w-4 h-4 opacity-50 flex-shrink-0">'+ICONS.cpu+'</div><span class="flex-1 opacity-80">'+srv.specs+'</span></div>':'')+
        (srv.note?'<div class="text-xs mt-3 bg-amber-500/10 border border-amber-500/20 text-amber-700 dark:text-amber-400 rounded-lg px-3 py-2.5 flex items-start gap-2"><div class="w-4 h-4 opacity-60 flex-shrink-0">'+ICONS.message+'</div><span class="flex-1">'+srv.note+'</span></div>':'');
      serversHTML += '</div>';
    });

    const wrap=document.createElement('div');
    wrap.className='card border transition-all relative ' + borderClass + (idx < animationLimit ? ' animate-slide-in' : '');
    if(idx < animationLimit) wrap.style.animationDelay = (idx * 0.05 + 0.3) + 's';
    wrap.dataset.cardId = cardId;

    wrap.innerHTML =
      rankBadge +
      '<div class="flex items-center justify-between p-5 md:p-6 border-b border-white/10 gap-4 '+gradientClass+'">'+
        '<div class="flex items-center gap-5 flex-1 min-w-0">'+
          '<div class="flex-shrink-0 w-14 h-14 rounded-2xl bg-white/80 dark:bg-white/10 flex items-center justify-center text-3xl shadow-sm border border-white/20">'+medalByRank(idx)+'</div>'+
          '<div class="flex flex-col gap-1.5 min-w-0">'+
            '<a class="font-bold text-xl hover:text-indigo-400 truncate transition-colors flex items-center gap-2" target="_blank" href="https://linux.do/u/'+encodeURIComponent(it.username)+'">'+
              '@'+it.username+
              '<span class="text-xs opacity-40 font-normal px-2 py-0.5 rounded-full border border-white/10">Linux.do</span>'+
            '</a>'+
            '<div class="flex items-center gap-2 flex-wrap">'+
              renderBadge(badge)+
              '<span class="text-xs opacity-60 font-medium">已投喂 '+it.count+' 台</span>'+
            '</div>'+
          '</div>'+
        '</div>'+
        '<div class="flex items-center gap-4">'+
          '<div class="hidden sm:flex flex-col items-end">'+
             '<div class="text-2xl font-bold leading-none">'+it.count+'</div>'+
             '<div class="text-[10px] uppercase tracking-wider opacity-50 font-bold mt-1">Servers</div>'+
          '</div>'+
          '<button class="toggle-expand flex-shrink-0 w-10 h-10 flex items-center justify-center rounded-xl bg-white/50 dark:bg-white/5 hover:bg-indigo-500/10 hover:text-indigo-500 border border-white/10 transition-all cursor-pointer" data-card="'+cardId+'" title="'+(isExpanded ? '收起列表' : '展开列表')+'">'+
            '<div class="w-5 h-5 transition-transform duration-300 '+(isExpanded ? 'rotate-180' : 'rotate-0')+'">'+ICONS.chevronDown+'</div>'+
          '</button>'+
        '</div>'+
      '</div>'+
      '<div class="server-list-wrapper grid transition-[grid-template-rows] duration-300 ease-out" style="grid-template-rows: '+(isExpanded ? '1fr' : '0fr')+'">'+
        '<div class="overflow-hidden">'+
          '<div class="server-list px-5 md:px-6 pb-6 pt-5 space-y-4 bg-white/30 dark:bg-black/20">'+
            serversHTML+
          '</div>'+
        '</div>'+
      '</div>';

    fragment.appendChild(wrap);
  });

  box.innerHTML = '';
  box.appendChild(fragment);

  box.addEventListener('click', (e) => {
    const toggleBtn = e.target.closest('.toggle-expand');
    if(!toggleBtn) return;

    const cardId = toggleBtn.dataset.card;
    const wrap = toggleBtn.closest('[data-card-id]');
    const wrapper = wrap.querySelector('.server-list-wrapper');
    const toggleIcon = toggleBtn.querySelector('div');
    const isCurrentlyExpanded = wrapper.style.gridTemplateRows === '1fr';

    if(isCurrentlyExpanded){
      wrapper.style.gridTemplateRows = '0fr';
      toggleIcon.classList.remove('rotate-180');
      toggleIcon.classList.add('rotate-0');
      toggleBtn.setAttribute('title', '展开列表');
      localStorage.setItem(cardId, 'collapsed');
    } else {
      wrapper.style.gridTemplateRows = '1fr';
      toggleIcon.classList.remove('rotate-0');
      toggleIcon.classList.add('rotate-180');
      toggleBtn.setAttribute('title', '收起列表');
      localStorage.removeItem(cardId);
    }
  });
}

async function loadLeaderboard(){
  const box = document.getElementById('leaderboard'), countEl=document.getElementById('leaderboard-count');
  
  // 骨架屏优化
  box.innerHTML='<div class="space-y-6">'+
    Array(3).fill(0).map(()=>
    '<div class="card p-6 flex items-center gap-4 animate-pulse">'+
    '<div class="w-14 h-14 rounded-2xl bg-gray-200 dark:bg-white/5"></div>'+
    '<div class="flex-1 space-y-3">'+
    '<div class="h-5 w-1/3 bg-gray-200 dark:bg-white/5 rounded"></div>'+
    '<div class="h-4 w-1/4 bg-gray-200 dark:bg-white/5 rounded"></div>'+
    '</div>'+
    '</div>').join('')+
    '</div>';

  const timeoutPromise = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('加载超时')), 8000)
  );

  try{
    const fetchPromise = fetch('/api/leaderboard',{
      credentials:'same-origin',
      cache:'no-store'
    });

    const res = await Promise.race([fetchPromise, timeoutPromise]);

    if(!res.ok) {
      box.innerHTML='<div class="text-red-400 text-sm text-center py-8">加载失败: HTTP '+res.status+'<br><button onclick="loadLeaderboard()" class="mt-4 btn-secondary">重试</button></div>';
      return;
    }

    const j = await res.json();
    if(!j.success){
      box.innerHTML='<div class="text-red-400 text-sm text-center py-8">加载失败: '+(j.message||'未知错误')+'<br><button onclick="loadLeaderboard()" class="btn-secondary mt-4">重试</button></div>';
      return;
    }

    allLeaderboardData = j.data||[];
    
    if(!allLeaderboardData.length){
      box.innerHTML='<div class="opacity-60 text-sm py-12 text-center">暂时还没有投喂记录，成为第一个投喂者吧～</div>';
      countEl.textContent = '';
      return;
    }
    
    renderLeaderboard();
  }catch(err){
    console.error('Leaderboard load error:', err);
    box.innerHTML='<div class="text-red-400 text-sm text-center py-8">'+err.message+'<br><button onclick="loadLeaderboard()" class="btn-secondary mt-4">重试</button></div>';
  }
}

loadLeaderboard();

// ==================== Globe.gl 初始化和渲染 ====================


let globeInstance = null;
let serversData = [];
let connectionsData = [];
let updateInterval = null;
let visitorLocation = null; // 访问者位置

/**
 * 地理编码函数：将位置字符串转换为经纬度坐标
 * 扩展版 - 包含更多国家和城市
 */
function geocode(location) {
  const LOCATION_DB = {
    // 亚洲 - 东亚
    'China': { lat: 35.8617, lng: 104.1954 },
    '中国': { lat: 35.8617, lng: 104.1954 },
    '中国大陆': { lat: 35.8617, lng: 104.1954 },
    'Beijing': { lat: 39.9042, lng: 116.4074 },
    '北京': { lat: 39.9042, lng: 116.4074 },
    'Shanghai': { lat: 31.2304, lng: 121.4737 },
    '上海': { lat: 31.2304, lng: 121.4737 },
    'Guangzhou': { lat: 23.1291, lng: 113.2644 },
    '广州': { lat: 23.1291, lng: 113.2644 },
    'Shenzhen': { lat: 22.5431, lng: 114.0579 },
    '深圳': { lat: 22.5431, lng: 114.0579 },
    'Chengdu': { lat: 30.5728, lng: 104.0668 },
    '成都': { lat: 30.5728, lng: 104.0668 },
    'Hangzhou': { lat: 30.2741, lng: 120.1551 },
    '杭州': { lat: 30.2741, lng: 120.1551 },
    'Chongqing': { lat: 29.4316, lng: 106.9123 },
    '重庆': { lat: 29.4316, lng: 106.9123 },
    'Wuhan': { lat: 30.5928, lng: 114.3055 },
    '武汉': { lat: 30.5928, lng: 114.3055 },
    'Xi\\'an': { lat: 34.3416, lng: 108.9398 },
    'Xian': { lat: 34.3416, lng: 108.9398 },
    '西安': { lat: 34.3416, lng: 108.9398 },
    'Nanjing': { lat: 32.0603, lng: 118.7969 },
    '南京': { lat: 32.0603, lng: 118.7969 },
    'Tianjin': { lat: 39.3434, lng: 117.3616 },
    '天津': { lat: 39.3434, lng: 117.3616 },
    'Suzhou': { lat: 31.2989, lng: 120.5853 },
    '苏州': { lat: 31.2989, lng: 120.5853 },
    'Qingdao': { lat: 36.0671, lng: 120.3826 },
    '青岛': { lat: 36.0671, lng: 120.3826 },
    'Dalian': { lat: 38.9140, lng: 121.6147 },
    '大连': { lat: 38.9140, lng: 121.6147 },
    'Xiamen': { lat: 24.4798, lng: 118.0894 },
    '厦门': { lat: 24.4798, lng: 118.0894 },
    'Changsha': { lat: 28.2282, lng: 112.9388 },
    '长沙': { lat: 28.2282, lng: 112.9388 },
    'Zhengzhou': { lat: 34.7466, lng: 113.6253 },
    '郑州': { lat: 34.7466, lng: 113.6253 },
    'Shenyang': { lat: 41.8057, lng: 123.4328 },
    '沈阳': { lat: 41.8057, lng: 123.4328 },
    'Harbin': { lat: 45.8038, lng: 126.5340 },
    '哈尔滨': { lat: 45.8038, lng: 126.5340 },
    'Kunming': { lat: 25.0406, lng: 102.7129 },
    '昆明': { lat: 25.0406, lng: 102.7129 },
    'Guiyang': { lat: 26.6470, lng: 106.6302 },
    '贵阳': { lat: 26.6470, lng: 106.6302 },
    'Nanning': { lat: 22.8170, lng: 108.3665 },
    '南宁': { lat: 22.8170, lng: 108.3665 },
    'Fuzhou': { lat: 26.0745, lng: 119.2965 },
    '福州': { lat: 26.0745, lng: 119.2965 },
    'Jinan': { lat: 36.6512, lng: 117.1209 },
    '济南': { lat: 36.6512, lng: 117.1209 },
    'Taiyuan': { lat: 37.8706, lng: 112.5489 },
    '太原': { lat: 37.8706, lng: 112.5489 },
    'Shijiazhuang': { lat: 38.0428, lng: 114.5149 },
    '石家庄': { lat: 38.0428, lng: 114.5149 },
    'Urumqi': { lat: 43.8256, lng: 87.6168 },
    '乌鲁木齐': { lat: 43.8256, lng: 87.6168 },
    'Lanzhou': { lat: 36.0611, lng: 103.8343 },
    '兰州': { lat: 36.0611, lng: 103.8343 },
    'Hohhot': { lat: 40.8414, lng: 111.7519 },
    '呼和浩特': { lat: 40.8414, lng: 111.7519 },
    'Yinchuan': { lat: 38.4681, lng: 106.2731 },
    '银川': { lat: 38.4681, lng: 106.2731 },
    'Xining': { lat: 36.6171, lng: 101.7782 },
    '西宁': { lat: 36.6171, lng: 101.7782 },
    'Lhasa': { lat: 29.6520, lng: 91.1721 },
    '拉萨': { lat: 29.6520, lng: 91.1721 },
    'Haikou': { lat: 20.0444, lng: 110.1999 },
    '海口': { lat: 20.0444, lng: 110.1999 },
    'Sanya': { lat: 18.2528, lng: 109.5117 },
    '三亚': { lat: 18.2528, lng: 109.5117 },
    'Hong Kong': { lat: 22.3193, lng: 114.1694 },
    '香港': { lat: 22.3193, lng: 114.1694 },
    '中国香港': { lat: 22.3193, lng: 114.1694 },
    'Macau': { lat: 22.1987, lng: 113.5439 },
    '澳门': { lat: 22.1987, lng: 113.5439 },
    '中国澳门': { lat: 22.1987, lng: 113.5439 },
    'Taiwan': { lat: 23.6978, lng: 120.9605 },
    '台湾': { lat: 23.6978, lng: 120.9605 },
    '中国台湾': { lat: 23.6978, lng: 120.9605 },
    'Taipei': { lat: 25.0330, lng: 121.5654 },
    '台北': { lat: 25.0330, lng: 121.5654 },
    'Kaohsiung': { lat: 22.6273, lng: 120.3014 },
    '高雄': { lat: 22.6273, lng: 120.3014 },
    'Taichung': { lat: 24.1477, lng: 120.6736 },
    '台中': { lat: 24.1477, lng: 120.6736 },
    
    'Japan': { lat: 36.2048, lng: 138.2529 },
    '日本': { lat: 36.2048, lng: 138.2529 },
    'Tokyo': { lat: 35.6762, lng: 139.6503 },
    '东京': { lat: 35.6762, lng: 139.6503 },
    'Osaka': { lat: 34.6937, lng: 135.5023 },
    '大阪': { lat: 34.6937, lng: 135.5023 },
    'Nagoya': { lat: 35.1815, lng: 136.9066 },
    '名古屋': { lat: 35.1815, lng: 136.9066 },
    'Kyoto': { lat: 35.0116, lng: 135.7681 },
    '京都': { lat: 35.0116, lng: 135.7681 },
    'Fukuoka': { lat: 33.5904, lng: 130.4017 },
    '福冈': { lat: 33.5904, lng: 130.4017 },
    'Sapporo': { lat: 43.0642, lng: 141.3469 },
    '札幌': { lat: 43.0642, lng: 141.3469 },
    'Yokohama': { lat: 35.4437, lng: 139.6380 },
    '横滨': { lat: 35.4437, lng: 139.6380 },
    
    'South Korea': { lat: 35.9078, lng: 127.7669 },
    'Korea': { lat: 35.9078, lng: 127.7669 },
    '韩国': { lat: 35.9078, lng: 127.7669 },
    'Seoul': { lat: 37.5665, lng: 126.9780 },
    '首尔': { lat: 37.5665, lng: 126.9780 },
    'Busan': { lat: 35.1796, lng: 129.0756 },
    '釜山': { lat: 35.1796, lng: 129.0756 },
    'Incheon': { lat: 37.4563, lng: 126.7052 },
    '仁川': { lat: 37.4563, lng: 126.7052 },
    'Daegu': { lat: 35.8714, lng: 128.6014 },
    '大邱': { lat: 35.8714, lng: 128.6014 },
    
    // 亚洲 - 东南亚
    'Singapore': { lat: 1.3521, lng: 103.8198 },
    '新加坡': { lat: 1.3521, lng: 103.8198 },
    
    'Thailand': { lat: 15.8700, lng: 100.9925 },
    '泰国': { lat: 15.8700, lng: 100.9925 },
    'Bangkok': { lat: 13.7563, lng: 100.5018 },
    '曼谷': { lat: 13.7563, lng: 100.5018 },
    'Phuket': { lat: 7.8804, lng: 98.3923 },
    '普吉': { lat: 7.8804, lng: 98.3923 },
    
    'Vietnam': { lat: 14.0583, lng: 108.2772 },
    '越南': { lat: 14.0583, lng: 108.2772 },
    'Hanoi': { lat: 21.0285, lng: 105.8542 },
    '河内': { lat: 21.0285, lng: 105.8542 },
    'Ho Chi Minh': { lat: 10.8231, lng: 106.6297 },
    '胡志明市': { lat: 10.8231, lng: 106.6297 },
    'Saigon': { lat: 10.8231, lng: 106.6297 },
    '西贡': { lat: 10.8231, lng: 106.6297 },
    
    'Malaysia': { lat: 4.2105, lng: 101.9758 },
    '马来西亚': { lat: 4.2105, lng: 101.9758 },
    'Kuala Lumpur': { lat: 3.1390, lng: 101.6869 },
    '吉隆坡': { lat: 3.1390, lng: 101.6869 },
    'Penang': { lat: 5.4164, lng: 100.3327 },
    '槟城': { lat: 5.4164, lng: 100.3327 },
    
    'Indonesia': { lat: -0.7893, lng: 113.9213 },
    '印度尼西亚': { lat: -0.7893, lng: 113.9213 },
    'Jakarta': { lat: -6.2088, lng: 106.8456 },
    '雅加达': { lat: -6.2088, lng: 106.8456 },
    'Bali': { lat: -8.3405, lng: 115.0920 },
    '巴厘岛': { lat: -8.3405, lng: 115.0920 },
    'Surabaya': { lat: -7.2575, lng: 112.7521 },
    '泗水': { lat: -7.2575, lng: 112.7521 },
    
    'Philippines': { lat: 12.8797, lng: 121.7740 },
    '菲律宾': { lat: 12.8797, lng: 121.7740 },
    'Manila': { lat: 14.5995, lng: 120.9842 },
    '马尼拉': { lat: 14.5995, lng: 120.9842 },
    'Cebu': { lat: 10.3157, lng: 123.8854 },
    '宿务': { lat: 10.3157, lng: 123.8854 },
    
    'Myanmar': { lat: 21.9162, lng: 95.9560 },
    '缅甸': { lat: 21.9162, lng: 95.9560 },
    'Yangon': { lat: 16.8661, lng: 96.1951 },
    '仰光': { lat: 16.8661, lng: 96.1951 },
    
    'Cambodia': { lat: 12.5657, lng: 104.9910 },
    '柬埔寨': { lat: 12.5657, lng: 104.9910 },
    'Phnom Penh': { lat: 11.5564, lng: 104.9282 },
    '金边': { lat: 11.5564, lng: 104.9282 },
    
    'Laos': { lat: 19.8563, lng: 102.4955 },
    '老挝': { lat: 19.8563, lng: 102.4955 },
    'Vientiane': { lat: 17.9757, lng: 102.6331 },
    '万象': { lat: 17.9757, lng: 102.6331 },
    
    // 亚洲 - 南亚（印度重点优化 - 添加更多别名）
    'India': { lat: 20.5937, lng: 78.9629 },
    '印度': { lat: 20.5937, lng: 78.9629 },
    'IN': { lat: 20.5937, lng: 78.9629 },
    'IND': { lat: 20.5937, lng: 78.9629 },
    'Mumbai': { lat: 19.0760, lng: 72.8777 },
    '孟买': { lat: 19.0760, lng: 72.8777 },
    'Bombay': { lat: 19.0760, lng: 72.8777 },
    'Delhi': { lat: 28.7041, lng: 77.1025 },
    '德里': { lat: 28.7041, lng: 77.1025 },
    'New Delhi': { lat: 28.6139, lng: 77.2090 },
    '新德里': { lat: 28.6139, lng: 77.2090 },
    'Bangalore': { lat: 12.9716, lng: 77.5946 },
    '班加罗尔': { lat: 12.9716, lng: 77.5946 },
    'Bengaluru': { lat: 12.9716, lng: 77.5946 },
    'Hyderabad': { lat: 17.3850, lng: 78.4867 },
    '海得拉巴': { lat: 17.3850, lng: 78.4867 },
    'Chennai': { lat: 13.0827, lng: 80.2707 },
    '金奈': { lat: 13.0827, lng: 80.2707 },
    'Madras': { lat: 13.0827, lng: 80.2707 },
    'Kolkata': { lat: 22.5726, lng: 88.3639 },
    '加尔各答': { lat: 22.5726, lng: 88.3639 },
    'Calcutta': { lat: 22.5726, lng: 88.3639 },
    'Pune': { lat: 18.5204, lng: 73.8567 },
    '浦那': { lat: 18.5204, lng: 73.8567 },
    'Ahmedabad': { lat: 23.0225, lng: 72.5714 },
    '艾哈迈达巴德': { lat: 23.0225, lng: 72.5714 },
    'Jaipur': { lat: 26.9124, lng: 75.7873 },
    '斋浦尔': { lat: 26.9124, lng: 75.7873 },
    'Surat': { lat: 21.1702, lng: 72.8311 },
    'Lucknow': { lat: 26.8467, lng: 80.9462 },
    'Kanpur': { lat: 26.4499, lng: 80.3319 },
    'Nagpur': { lat: 21.1458, lng: 79.0882 },
    'Indore': { lat: 22.7196, lng: 75.8577 },
    'Thane': { lat: 19.2183, lng: 72.9781 },
    'Bhopal': { lat: 23.2599, lng: 77.4126 },
    'Visakhapatnam': { lat: 17.6868, lng: 83.2185 },
    'Patna': { lat: 25.5941, lng: 85.1376 },
    'Vadodara': { lat: 22.3072, lng: 73.1812 },
    'Ghaziabad': { lat: 28.6692, lng: 77.4538 },
    'Ludhiana': { lat: 30.9010, lng: 75.8573 },
    'Agra': { lat: 27.1767, lng: 78.0081 },
    'Nashik': { lat: 19.9975, lng: 73.7898 },
    'Faridabad': { lat: 28.4089, lng: 77.3178 },
    'Meerut': { lat: 28.9845, lng: 77.7064 },
    'Rajkot': { lat: 22.3039, lng: 70.8022 },
    'Varanasi': { lat: 25.3176, lng: 82.9739 },
    'Srinagar': { lat: 34.0837, lng: 74.7973 },
    'Aurangabad': { lat: 19.8762, lng: 75.3433 },
    'Dhanbad': { lat: 23.7957, lng: 86.4304 },
    'Amritsar': { lat: 31.6340, lng: 74.8723 },
    'Navi Mumbai': { lat: 19.0330, lng: 73.0297 },
    'Allahabad': { lat: 25.4358, lng: 81.8463 },
    'Prayagraj': { lat: 25.4358, lng: 81.8463 },
    'Ranchi': { lat: 23.3441, lng: 85.3096 },
    'Howrah': { lat: 22.5958, lng: 88.2636 },
    'Coimbatore': { lat: 11.0168, lng: 76.9558 },
    'Jabalpur': { lat: 23.1815, lng: 79.9864 },
    'Gwalior': { lat: 26.2183, lng: 78.1828 },
    'Vijayawada': { lat: 16.5062, lng: 80.6480 },
    'Jodhpur': { lat: 26.2389, lng: 73.0243 },
    'Madurai': { lat: 9.9252, lng: 78.1198 },
    'Raipur': { lat: 21.2514, lng: 81.6296 },
    'Kota': { lat: 25.2138, lng: 75.8648 },
    'Chandigarh': { lat: 30.7333, lng: 76.7794 },
    'Guwahati': { lat: 26.1445, lng: 91.7362 },
    'Solapur': { lat: 17.6599, lng: 75.9064 },
    'Mysore': { lat: 12.2958, lng: 76.6394 },
    'Mysuru': { lat: 12.2958, lng: 76.6394 },
    'Bareilly': { lat: 28.3670, lng: 79.4304 },
    'Aligarh': { lat: 27.8974, lng: 78.0880 },
    'Tiruppur': { lat: 11.1085, lng: 77.3411 },
    'Moradabad': { lat: 28.8389, lng: 78.7378 },
    'Jalandhar': { lat: 31.3260, lng: 75.5762 },
    'Bhubaneswar': { lat: 20.2961, lng: 85.8245 },
    'Salem': { lat: 11.6643, lng: 78.1460 },
    'Warangal': { lat: 17.9689, lng: 79.5941 },
    'Guntur': { lat: 16.3067, lng: 80.4365 },
    'Bhiwandi': { lat: 19.3009, lng: 73.0643 },
    'Saharanpur': { lat: 29.9680, lng: 77.5460 },
    'Gorakhpur': { lat: 26.7606, lng: 83.3732 },
    'Bikaner': { lat: 28.0229, lng: 73.3119 },
    'Amravati': { lat: 20.9374, lng: 77.7796 },
    'Noida': { lat: 28.5355, lng: 77.3910 },
    'Jamshedpur': { lat: 22.8046, lng: 86.2029 },
    'Bhilai': { lat: 21.2095, lng: 81.3784 },
    'Cuttack': { lat: 20.4625, lng: 85.8830 },
    'Kochi': { lat: 9.9312, lng: 76.2673 },
    'Cochin': { lat: 9.9312, lng: 76.2673 },
    'Bhavnagar': { lat: 21.7645, lng: 72.1519 },
    'Dehradun': { lat: 30.3165, lng: 78.0322 },
    'Durgapur': { lat: 23.5204, lng: 87.3119 },
    'Asansol': { lat: 23.6739, lng: 86.9524 },
    'Nanded': { lat: 19.1383, lng: 77.3210 },
    'Kolhapur': { lat: 16.7050, lng: 74.2433 },
    'Ajmer': { lat: 26.4499, lng: 74.6399 },
    'Akola': { lat: 20.7002, lng: 77.0082 },
    'Gulbarga': { lat: 17.3297, lng: 76.8343 },
    'Jamnagar': { lat: 22.4707, lng: 70.0577 },
    'Ujjain': { lat: 23.1765, lng: 75.7885 },
    'Siliguri': { lat: 26.7271, lng: 88.3953 },
    'Jhansi': { lat: 25.4484, lng: 78.5685 },
    'Jammu': { lat: 32.7266, lng: 74.8570 },
    'Mangalore': { lat: 12.9141, lng: 74.8560 },
    'Erode': { lat: 11.3410, lng: 77.7172 },
    'Belgaum': { lat: 15.8497, lng: 74.4977 },
    'Tirunelveli': { lat: 8.7139, lng: 77.7567 },
    'Malegaon': { lat: 20.5579, lng: 74.5287 },
    'Gaya': { lat: 24.7955, lng: 85.0002 },
    'Jalgaon': { lat: 21.0077, lng: 75.5626 },
    'Udaipur': { lat: 24.5854, lng: 73.7125 },
    'Pakistan': { lat: 30.3753, lng: 69.3451 },
    '巴基斯坦': { lat: 30.3753, lng: 69.3451 },
    'Karachi': { lat: 24.8607, lng: 67.0011 },
    '卡拉奇': { lat: 24.8607, lng: 67.0011 },
    'Islamabad': { lat: 33.6844, lng: 73.0479 },
    '伊斯兰堡': { lat: 33.6844, lng: 73.0479 },
    'Bangladesh': { lat: 23.6850, lng: 90.3563 },
    '孟加拉国': { lat: 23.6850, lng: 90.3563 },
    'Dhaka': { lat: 23.8103, lng: 90.4125 },
    '达卡': { lat: 23.8103, lng: 90.4125 },
    'Sri Lanka': { lat: 7.8731, lng: 80.7718 },
    '斯里兰卡': { lat: 7.8731, lng: 80.7718 },
    'Colombo': { lat: 6.9271, lng: 79.8612 },
    '科伦坡': { lat: 6.9271, lng: 79.8612 },
    
    // 欧洲 - 西欧
    'United Kingdom': { lat: 55.3781, lng: -3.4360 },
    'UK': { lat: 55.3781, lng: -3.4360 },
    '英国': { lat: 55.3781, lng: -3.4360 },
    'London': { lat: 51.5074, lng: -0.1278 },
    '伦敦': { lat: 51.5074, lng: -0.1278 },
    'Manchester': { lat: 53.4808, lng: -2.2426 },
    '曼彻斯特': { lat: 53.4808, lng: -2.2426 },
    
    'France': { lat: 46.2276, lng: 2.2137 },
    '法国': { lat: 46.2276, lng: 2.2137 },
    'Paris': { lat: 48.8566, lng: 2.3522 },
    '巴黎': { lat: 48.8566, lng: 2.3522 },
    'Marseille': { lat: 43.2965, lng: 5.3698 },
    '马赛': { lat: 43.2965, lng: 5.3698 },
    'Lyon': { lat: 45.7640, lng: 4.8357 },
    '里昂': { lat: 45.7640, lng: 4.8357 },
    
    'Germany': { lat: 51.1657, lng: 10.4515 },
    '德国': { lat: 51.1657, lng: 10.4515 },
    'Berlin': { lat: 52.5200, lng: 13.4050 },
    '柏林': { lat: 52.5200, lng: 13.4050 },
    'Frankfurt': { lat: 50.1109, lng: 8.6821 },
    '法兰克福': { lat: 50.1109, lng: 8.6821 },
    'Munich': { lat: 48.1351, lng: 11.5820 },
    '慕尼黑': { lat: 48.1351, lng: 11.5820 },
    'Hamburg': { lat: 53.5511, lng: 9.9937 },
    '汉堡': { lat: 53.5511, lng: 9.9937 },
    'Cologne': { lat: 50.9375, lng: 6.9603 },
    '科隆': { lat: 50.9375, lng: 6.9603 },
    'Netherlands': { lat: 52.1326, lng: 5.2913 },
    '荷兰': { lat: 52.1326, lng: 5.2913 },
    'Amsterdam': { lat: 52.3676, lng: 4.9041 },
    '阿姆斯特丹': { lat: 52.3676, lng: 4.9041 },
    'Rotterdam': { lat: 51.9225, lng: 4.4792 },
    '鹿特丹': { lat: 51.9225, lng: 4.4792 },
    
    'Belgium': { lat: 50.5039, lng: 4.4699 },
    '比利时': { lat: 50.5039, lng: 4.4699 },
    'Brussels': { lat: 50.8503, lng: 4.3517 },
    '布鲁塞尔': { lat: 50.8503, lng: 4.3517 },
    
    'Switzerland': { lat: 46.8182, lng: 8.2275 },
    '瑞士': { lat: 46.8182, lng: 8.2275 },
    'Zurich': { lat: 47.3769, lng: 8.5417 },
    '苏黎世': { lat: 47.3769, lng: 8.5417 },
    'Geneva': { lat: 46.2044, lng: 6.1432 },
    '日内瓦': { lat: 46.2044, lng: 6.1432 },
    
    'Austria': { lat: 47.5162, lng: 14.5501 },
    '奥地利': { lat: 47.5162, lng: 14.5501 },
    'Vienna': { lat: 48.2082, lng: 16.3738 },
    '维也纳': { lat: 48.2082, lng: 16.3738 },
    
    // 欧洲 - 北欧
    'Sweden': { lat: 60.1282, lng: 18.6435 },
    '瑞典': { lat: 60.1282, lng: 18.6435 },
    'Stockholm': { lat: 59.3293, lng: 18.0686 },
    '斯德哥尔摩': { lat: 59.3293, lng: 18.0686 },
    
    'Norway': { lat: 60.4720, lng: 8.4689 },
    '挪威': { lat: 60.4720, lng: 8.4689 },
    'Oslo': { lat: 59.9139, lng: 10.7522 },
    '奥斯陆': { lat: 59.9139, lng: 10.7522 },
    
    'Finland': { lat: 61.9241, lng: 25.7482 },
    '芬兰': { lat: 61.9241, lng: 25.7482 },
    'Helsinki': { lat: 60.1699, lng: 24.9384 },
    '赫尔辛基': { lat: 60.1699, lng: 24.9384 },
    
    'Denmark': { lat: 56.2639, lng: 9.5018 },
    '丹麦': { lat: 56.2639, lng: 9.5018 },
    'Copenhagen': { lat: 55.6761, lng: 12.5683 },
    '哥本哈根': { lat: 55.6761, lng: 12.5683 },
    
    'Ireland': { lat: 53.4129, lng: -8.2439 },
    '爱尔兰': { lat: 53.4129, lng: -8.2439 },
    'Dublin': { lat: 53.3498, lng: -6.2603 },
    '都柏林': { lat: 53.3498, lng: -6.2603 },
    
    // 欧洲 - 南欧
    'Italy': { lat: 41.8719, lng: 12.5674 },
    '意大利': { lat: 41.8719, lng: 12.5674 },
    'Rome': { lat: 41.9028, lng: 12.4964 },
    '罗马': { lat: 41.9028, lng: 12.4964 },
    'Milan': { lat: 45.4642, lng: 9.1900 },
    '米兰': { lat: 45.4642, lng: 9.1900 },
    'Venice': { lat: 45.4408, lng: 12.3155 },
    '威尼斯': { lat: 45.4408, lng: 12.3155 },
    'Florence': { lat: 43.7696, lng: 11.2558 },
    '佛罗伦萨': { lat: 43.7696, lng: 11.2558 },
    
    'Spain': { lat: 40.4637, lng: -3.7492 },
    '西班牙': { lat: 40.4637, lng: -3.7492 },
    'Madrid': { lat: 40.4168, lng: -3.7038 },
    '马德里': { lat: 40.4168, lng: -3.7038 },
    'Barcelona': { lat: 41.3851, lng: 2.1734 },
    '巴塞罗那': { lat: 41.3851, lng: 2.1734 },
    
    'Portugal': { lat: 39.3999, lng: -8.2245 },
    '葡萄牙': { lat: 39.3999, lng: -8.2245 },
    'Lisbon': { lat: 38.7223, lng: -9.1393 },
    '里斯本': { lat: 38.7223, lng: -9.1393 },
    
    'Greece': { lat: 39.0742, lng: 21.8243 },
    '希腊': { lat: 39.0742, lng: 21.8243 },
    'Athens': { lat: 37.9838, lng: 23.7275 },
    '雅典': { lat: 37.9838, lng: 23.7275 },
    
    // 欧洲 - 东欧
    'Poland': { lat: 51.9194, lng: 19.1451 },
    '波兰': { lat: 51.9194, lng: 19.1451 },
    'Warsaw': { lat: 52.2297, lng: 21.0122 },
    '华沙': { lat: 52.2297, lng: 21.0122 },
    'Krakow': { lat: 50.0647, lng: 19.9450 },
    '克拉科夫': { lat: 50.0647, lng: 19.9450 },
    
    'Czech Republic': { lat: 49.8175, lng: 15.4730 },
    'Czechia': { lat: 49.8175, lng: 15.4730 },
    '捷克': { lat: 49.8175, lng: 15.4730 },
    'Prague': { lat: 50.0755, lng: 14.4378 },
    '布拉格': { lat: 50.0755, lng: 14.4378 },
    
    'Romania': { lat: 45.9432, lng: 24.9668 },
    '罗马尼亚': { lat: 45.9432, lng: 24.9668 },
    'Bucharest': { lat: 44.4268, lng: 26.1025 },
    '布加勒斯特': { lat: 44.4268, lng: 26.1025 },
    
    'Hungary': { lat: 47.1625, lng: 19.5033 },
    '匈牙利': { lat: 47.1625, lng: 19.5033 },
    'Budapest': { lat: 47.4979, lng: 19.0402 },
    '布达佩斯': { lat: 47.4979, lng: 19.0402 },
    
    'Ukraine': { lat: 48.3794, lng: 31.1656 },
    '乌克兰': { lat: 48.3794, lng: 31.1656 },
    'Kyiv': { lat: 50.4501, lng: 30.5234 },
    '基辅': { lat: 50.4501, lng: 30.5234 },
    
    'Russia': { lat: 61.5240, lng: 105.3188 },
    '俄罗斯': { lat: 61.5240, lng: 105.3188 },
    'Moscow': { lat: 55.7558, lng: 37.6173 },
    '莫斯科': { lat: 55.7558, lng: 37.6173 },
    'Saint Petersburg': { lat: 59.9343, lng: 30.3351 },
    '圣彼得堡': { lat: 59.9343, lng: 30.3351 },
    
    'Moldova': { lat: 47.4116, lng: 28.3699 },
    '摩尔多瓦': { lat: 47.4116, lng: 28.3699 },
    'Chisinau': { lat: 47.0105, lng: 28.8638 },
    '基希讷乌': { lat: 47.0105, lng: 28.8638 },
    
    // 北美
    'United States': { lat: 37.0902, lng: -95.7129 },
    'USA': { lat: 37.0902, lng: -95.7129 },
    'US': { lat: 37.0902, lng: -95.7129 },
    '美国': { lat: 37.0902, lng: -95.7129 },
    'New York': { lat: 40.7128, lng: -74.0060 },
    '纽约': { lat: 40.7128, lng: -74.0060 },
    'Los Angeles': { lat: 34.0522, lng: -118.2437 },
    '洛杉矶': { lat: 34.0522, lng: -118.2437 },
    'Chicago': { lat: 41.8781, lng: -87.6298 },
    '芝加哥': { lat: 41.8781, lng: -87.6298 },
    'San Francisco': { lat: 37.7749, lng: -122.4194 },
    '旧金山': { lat: 37.7749, lng: -122.4194 },
    'Seattle': { lat: 47.6062, lng: -122.3321 },
    '西雅图': { lat: 47.6062, lng: -122.3321 },
    'Miami': { lat: 25.7617, lng: -80.1918 },
    '迈阿密': { lat: 25.7617, lng: -80.1918 },
    'Dallas': { lat: 32.7767, lng: -96.7970 },
    '达拉斯': { lat: 32.7767, lng: -96.7970 },
    'Boston': { lat: 42.3601, lng: -71.0589 },
    '波士顿': { lat: 42.3601, lng: -71.0589 },
    'Washington': { lat: 38.9072, lng: -77.0369 },
    '华盛顿': { lat: 38.9072, lng: -77.0369 },
    'Atlanta': { lat: 33.7490, lng: -84.3880 },
    '亚特兰大': { lat: 33.7490, lng: -84.3880 },
    'Houston': { lat: 29.7604, lng: -95.3698 },
    '休斯顿': { lat: 29.7604, lng: -95.3698 },
    'Phoenix': { lat: 33.4484, lng: -112.0740 },
    '凤凰城': { lat: 33.4484, lng: -112.0740 },
    'Philadelphia': { lat: 39.9526, lng: -75.1652 },
    '费城': { lat: 39.9526, lng: -75.1652 },
    'San Diego': { lat: 32.7157, lng: -117.1611 },
    '圣地亚哥': { lat: 32.7157, lng: -117.1611 },
    'Denver': { lat: 39.7392, lng: -104.9903 },
    '丹佛': { lat: 39.7392, lng: -104.9903 },
    'Las Vegas': { lat: 36.1699, lng: -115.1398 },
    '拉斯维加斯': { lat: 36.1699, lng: -115.1398 },
    'Portland': { lat: 45.5152, lng: -122.6784 },
    '波特兰': { lat: 45.5152, lng: -122.6784 },
    'Austin': { lat: 30.2672, lng: -97.7431 },
    '奥斯汀': { lat: 30.2672, lng: -97.7431 },
    'Canada': { lat: 56.1304, lng: -106.3468 },
    '加拿大': { lat: 56.1304, lng: -106.3468 },
    'Toronto': { lat: 43.6532, lng: -79.3832 },
    '多伦多': { lat: 43.6532, lng: -79.3832 },
    'Vancouver': { lat: 49.2827, lng: -123.1207 },
    '温哥华': { lat: 49.2827, lng: -123.1207 },
    'Montreal': { lat: 45.5017, lng: -73.5673 },
    '蒙特利尔': { lat: 45.5017, lng: -73.5673 },
    'Calgary': { lat: 51.0447, lng: -114.0719 },
    '卡尔加里': { lat: 51.0447, lng: -114.0719 },
    'Ottawa': { lat: 45.4215, lng: -75.6972 },
    '渥太华': { lat: 45.4215, lng: -75.6972 },
    'Mexico': { lat: 23.6345, lng: -102.5528 },
    '墨西哥': { lat: 23.6345, lng: -102.5528 },
    
    // 南美
    'Brazil': { lat: -14.2350, lng: -51.9253 },
    '巴西': { lat: -14.2350, lng: -51.9253 },
    'Sao Paulo': { lat: -23.5505, lng: -46.6333 },
    '圣保罗': { lat: -23.5505, lng: -46.6333 },
    'Rio de Janeiro': { lat: -22.9068, lng: -43.1729 },
    '里约热内卢': { lat: -22.9068, lng: -43.1729 },
    'Brasilia': { lat: -15.8267, lng: -47.9218 },
    '巴西利亚': { lat: -15.8267, lng: -47.9218 },
    
    'Argentina': { lat: -38.4161, lng: -63.6167 },
    '阿根廷': { lat: -38.4161, lng: -63.6167 },
    'Buenos Aires': { lat: -34.6037, lng: -58.3816 },
    '布宜诺斯艾利斯': { lat: -34.6037, lng: -58.3816 },
    
    'Chile': { lat: -35.6751, lng: -71.5430 },
    '智利': { lat: -35.6751, lng: -71.5430 },
    'Santiago': { lat: -33.4489, lng: -70.6693 },
    '圣地亚哥': { lat: -33.4489, lng: -70.6693 },
    
    'Colombia': { lat: 4.5709, lng: -74.2973 },
    '哥伦比亚': { lat: 4.5709, lng: -74.2973 },
    'Bogota': { lat: 4.7110, lng: -74.0721 },
    '波哥大': { lat: 4.7110, lng: -74.0721 },
    
    'Peru': { lat: -9.1900, lng: -75.0152 },
    '秘鲁': { lat: -9.1900, lng: -75.0152 },
    'Lima': { lat: -12.0464, lng: -77.0428 },
    '利马': { lat: -12.0464, lng: -77.0428 },
    
    // 大洋洲
    'Australia': { lat: -25.2744, lng: 133.7751 },
    '澳大利亚': { lat: -25.2744, lng: 133.7751 },
    '澳洲': { lat: -25.2744, lng: 133.7751 },
    'Sydney': { lat: -33.8688, lng: 151.2093 },
    '悉尼': { lat: -33.8688, lng: 151.2093 },
    'Melbourne': { lat: -37.8136, lng: 144.9631 },
    '墨尔本': { lat: -37.8136, lng: 144.9631 },
    'Brisbane': { lat: -27.4698, lng: 153.0251 },
    '布里斯班': { lat: -27.4698, lng: 153.0251 },
    'Perth': { lat: -31.9505, lng: 115.8605 },
    '珀斯': { lat: -31.9505, lng: 115.8605 },
    'Adelaide': { lat: -34.9285, lng: 138.6007 },
    '阿德莱德': { lat: -34.9285, lng: 138.6007 },
    'Canberra': { lat: -35.2809, lng: 149.1300 },
    '堪培拉': { lat: -35.2809, lng: 149.1300 },
    
    'New Zealand': { lat: -40.9006, lng: 174.8860 },
    '新西兰': { lat: -40.9006, lng: 174.8860 },
    'Auckland': { lat: -36.8485, lng: 174.7633 },
    '奥克兰': { lat: -36.8485, lng: 174.7633 },
    'Wellington': { lat: -41.2865, lng: 174.7762 },
    '惠灵顿': { lat: -41.2865, lng: 174.7762 },
    
    // 中东
    'Turkey': { lat: 38.9637, lng: 35.2433 },
    '土耳其': { lat: 38.9637, lng: 35.2433 },
    'Istanbul': { lat: 41.0082, lng: 28.9784 },
    '伊斯坦布尔': { lat: 41.0082, lng: 28.9784 },
    'Ankara': { lat: 39.9334, lng: 32.8597 },
    '安卡拉': { lat: 39.9334, lng: 32.8597 },
    
    'Israel': { lat: 31.0461, lng: 34.8516 },
    '以色列': { lat: 31.0461, lng: 34.8516 },
    'Tel Aviv': { lat: 32.0853, lng: 34.7818 },
    '特拉维夫': { lat: 32.0853, lng: 34.7818 },
    'Jerusalem': { lat: 31.7683, lng: 35.2137 },
    '耶路撒冷': { lat: 31.7683, lng: 35.2137 },
    
    'United Arab Emirates': { lat: 23.4241, lng: 53.8478 },
    'UAE': { lat: 23.4241, lng: 53.8478 },
    '阿联酋': { lat: 23.4241, lng: 53.8478 },
    'Dubai': { lat: 25.2048, lng: 55.2708 },
    '迪拜': { lat: 25.2048, lng: 55.2708 },
    'Abu Dhabi': { lat: 24.4539, lng: 54.3773 },
    '阿布扎比': { lat: 24.4539, lng: 54.3773 },
    
    'Saudi Arabia': { lat: 23.8859, lng: 45.0792 },
    '沙特阿拉伯': { lat: 23.8859, lng: 45.0792 },
    'Riyadh': { lat: 24.7136, lng: 46.6753 },
    '利雅得': { lat: 24.7136, lng: 46.6753 },
    'Jeddah': { lat: 21.5433, lng: 39.1728 },
    '吉达': { lat: 21.5433, lng: 39.1728 },
    
    'Iran': { lat: 32.4279, lng: 53.6880 },
    '伊朗': { lat: 32.4279, lng: 53.6880 },
    'Tehran': { lat: 35.6892, lng: 51.3890 },
    '德黑兰': { lat: 35.6892, lng: 51.3890 },
    
    // 非洲
    'South Africa': { lat: -30.5595, lng: 22.9375 },
    '南非': { lat: -30.5595, lng: 22.9375 },
    'Johannesburg': { lat: -26.2041, lng: 28.0473 },
    '约翰内斯堡': { lat: -26.2041, lng: 28.0473 },
    'Cape Town': { lat: -33.9249, lng: 18.4241 },
    '开普敦': { lat: -33.9249, lng: 18.4241 },
    
    'Egypt': { lat: 26.8206, lng: 30.8025 },
    '埃及': { lat: 26.8206, lng: 30.8025 },
    'Cairo': { lat: 30.0444, lng: 31.2357 },
    '开罗': { lat: 30.0444, lng: 31.2357 },
    
    'Nigeria': { lat: 9.0820, lng: 8.6753 },
    '尼日利亚': { lat: 9.0820, lng: 8.6753 },
    'Lagos': { lat: 6.5244, lng: 3.3792 },
    '拉各斯': { lat: 6.5244, lng: 3.3792 },
    
    'Kenya': { lat: -0.0236, lng: 37.9062 },
    '肯尼亚': { lat: -0.0236, lng: 37.9062 },
    'Nairobi': { lat: -1.2864, lng: 36.8172 },
    '内罗毕': { lat: -1.2864, lng: 36.8172 },
    
    'Morocco': { lat: 31.7917, lng: -7.0926 },
    '摩洛哥': { lat: 31.7917, lng: -7.0926 },
    'Casablanca': { lat: 33.5731, lng: -7.5898 },
    '卡萨布兰卡': { lat: 33.5731, lng: -7.5898 }
  };

  if (!location || typeof location !== 'string') {
    return null;
  }

  const cleanLocation = location.trim();
  if (!cleanLocation) {
    return null;
  }

  // 1. 精确匹配
  if (LOCATION_DB[cleanLocation]) {
    return LOCATION_DB[cleanLocation];
  }

  // 2. 分割并逐部分匹配（从后往前，因为通常国家在后面）
  const parts = cleanLocation.split(',').map(s => s.trim()).filter(Boolean);
  for (let i = parts.length - 1; i >= 0; i--) {
    const part = parts[i];
    if (LOCATION_DB[part]) {
      return LOCATION_DB[part];
    }
  }

  // 3. 移除emoji后再次尝试精确匹配
  const cleanNoEmoji = cleanLocation.replace(/[\u{1F1E6}-\u{1F1FF}]/gu, '').trim();
  if (cleanNoEmoji !== cleanLocation && LOCATION_DB[cleanNoEmoji]) {
    return LOCATION_DB[cleanNoEmoji];
  }

  // 4. 模糊匹配（不区分大小写）
  const cleanLower = cleanLocation.toLowerCase();
  for (const [key, coords] of Object.entries(LOCATION_DB)) {
    const keyLower = key.toLowerCase();
    if (cleanLower.includes(keyLower) || keyLower.includes(cleanLower)) {
      return coords;
    }
  }

  // 5. 分部分模糊匹配
  for (let i = parts.length - 1; i >= 0; i--) {
    const partLower = parts[i].toLowerCase();
    for (const [key, coords] of Object.entries(LOCATION_DB)) {
      const keyLower = key.toLowerCase();
      if (keyLower.includes(partLower) || partLower.includes(keyLower)) {
        return coords;
      }
    }
  }
  
  // 6. 特殊处理：尝试移除所有非字母数字字符后匹配
  const cleanAlphaNum = cleanLocation.replace(/[^a-zA-Z0-9\u4e00-\u9fa5]/g, '').toLowerCase();
  if (cleanAlphaNum.length >= 2) {
    for (const [key, coords] of Object.entries(LOCATION_DB)) {
      const keyAlphaNum = key.replace(/[^a-zA-Z0-9\u4e00-\u9fa5]/g, '').toLowerCase();
      if (cleanAlphaNum === keyAlphaNum || 
          (cleanAlphaNum.length >= 3 && keyAlphaNum.includes(cleanAlphaNum)) ||
          (keyAlphaNum.length >= 3 && cleanAlphaNum.includes(keyAlphaNum))) {
        return coords;
      }
    }
  }

  // 7. 无法匹配
  return null;
}

function addJitter(coords, index) {
  if (!coords) return null;
  
  const jitterAmount = 0.5;
  const seed = index || 0;
  const pseudoRandom1 = (Math.sin(seed * 12.9898) * 43758.5453) % 1;
  const pseudoRandom2 = (Math.cos(seed * 78.233) * 43758.5453) % 1;
  
  return {
    lat: coords.lat + (pseudoRandom1 - 0.5) * jitterAmount,
    lng: coords.lng + (pseudoRandom2 - 0.5) * jitterAmount
  };
}

function getCountryFlag(countryString) {
  if (!countryString || typeof countryString !== 'string') {
    return '🌍';
  }
  
  const chars = Array.from(countryString);
  
  for (let i = 0; i < chars.length - 1; i++) {
    const cp1 = chars[i].codePointAt(0);
    const cp2 = chars[i + 1].codePointAt(0);
    if (!cp1 || !cp2) continue;
    
    if (
      cp1 >= 0x1f1e6 && cp1 <= 0x1f1ff &&
      cp2 >= 0x1f1e6 && cp2 <= 0x1f1ff
    ) {
      return chars[i] + chars[i + 1];
    }
  }
  
  return '🌍';
}

function haversineDistance(coords1, coords2) {
  const R = 6371;
  const toRadians = (degrees) => degrees * Math.PI / 180;
  const dLat = toRadians(coords2.lat - coords1.lat);
  const dLng = toRadians(coords2.lng - coords1.lng);
  const lat1Rad = toRadians(coords1.lat);
  const lat2Rad = toRadians(coords2.lat);
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(lat1Rad) * Math.cos(lat2Rad) *
            Math.sin(dLng / 2) * Math.sin(dLng / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

/**
 * 获取访问者的地理位置（多API备份策略）
 */
async function getVisitorLocation() {
  // API列表（按优先级排序）
  const apis = [
    // API 1: ipapi.co（免费，无需密钥，精确度高）
    async () => {
      const res = await fetch('https://ipapi.co/json/', { 
        signal: AbortSignal.timeout(3000) 
      });
      if (res.ok) {
        const data = await res.json();
        if (data.latitude && data.longitude) {
          return {
            lat: data.latitude,
            lng: data.longitude,
            city: data.city || '未知',
            country: data.country_name || '未知'
          };
        }
      }
      return null;
    },
    
    // API 2: ip-api.com（免费，无需密钥，速度快）
    async () => {
      const res = await fetch('http://ip-api.com/json/?fields=status,country,city,lat,lon', { 
        signal: AbortSignal.timeout(3000) 
      });
      if (res.ok) {
        const data = await res.json();
        if (data.status === 'success' && data.lat && data.lon) {
          return {
            lat: data.lat,
            lng: data.lon,
            city: data.city || '未知',
            country: data.country || '未知'
          };
        }
      }
      return null;
    },
    
    // API 3: ipinfo.io（免费，无需密钥）
    async () => {
      const res = await fetch('https://ipinfo.io/json', { 
        signal: AbortSignal.timeout(3000) 
      });
      if (res.ok) {
        const data = await res.json();
        if (data.loc) {
          const [lat, lng] = data.loc.split(',').map(Number);
          if (lat && lng) {
            return {
              lat: lat,
              lng: lng,
              city: data.city || '未知',
              country: data.country || '未知'
            };
          }
        }
      }
      return null;
    },
    
    // API 4: ipwhois.app（免费，无需密钥）
    async () => {
      const res = await fetch('https://ipwhois.app/json/', { 
        signal: AbortSignal.timeout(3000) 
      });
      if (res.ok) {
        const data = await res.json();
        if (data.latitude && data.longitude) {
          return {
            lat: data.latitude,
            lng: data.longitude,
            city: data.city || '未知',
            country: data.country || '未知'
          };
        }
      }
      return null;
    }
  ];
  
  // 依次尝试每个API
  for (const api of apis) {
    try {
      const result = await api();
      if (result) {
        return result;
      }
    } catch (e) {
      continue;
    }
  }
  
  // 所有API都失败，使用默认位置（中国北京）
  return {
    lat: 39.9042,
    lng: 116.4074,
    city: 'Beijing',
    country: 'China'
  };
}

/**
 * 提取国家/地区标识
 */
function getRegionKey(server) {
  // 从国家字符串中提取主要标识（去除 emoji）
  const country = server.country || '';
  const region = server.ipLocation || '';
  
  // 提取国家名称（去除 emoji）
  const countryName = country.replace(/[\u{1F1E6}-\u{1F1FF}]/gu, '').trim();
  
  // 如果有详细位置信息，使用第一部分作为区域标识
  if (region) {
    const parts = region.split(',').map(s => s.trim());
    return parts[0] || countryName;
  }
  
  return countryName;
}

/**
 * 计算连接线 - 优化算法V2：确保每个服务器都有连接
 * 策略：
 * 1. 访问者到所有服务器的星联主线（100%覆盖）
 * 2. 每个服务器至少连接2-3个其他服务器（智能选择）
 * 3. 性能优化：使用高效算法，避免卡顿
 */
function calculateConnections(servers, visitor) {
  const connections = [];
  
  const validServers = servers.filter(s => 
    s.coords && 
    s.coords.lat !== null && 
    s.coords.lng !== null && 
    !(s.coords.lat === 0 && s.coords.lng === 0)
  );
  
  if (validServers.length === 0) return [];
  
  const visitorCoords = visitor || { lat: 39.9042, lng: 116.4074 };
  
  // ========== 第一层：访问者到所有服务器的星联主线（100%覆盖）==========
  validServers.forEach((server) => {
    const distance = haversineDistance(visitorCoords, server.coords);
    connections.push({
      startLat: visitorCoords.lat,
      startLng: visitorCoords.lng,
      endLat: server.coords.lat,
      endLng: server.coords.lng,
      type: 'visitor-primary',
      distance: distance,
      serverStatus: server.status
    });
  });
  
  // ========== 第二层：服务器之间的智能互联（确保每个都有连接）==========
  
  // 按地区分组（用于智能连接）
  const regionGroups = new Map();
  validServers.forEach(server => {
    const regionKey = getRegionKey(server);
    if (!regionGroups.has(regionKey)) {
      regionGroups.set(regionKey, []);
    }
    regionGroups.get(regionKey).push(server);
  });
  
  // 为每个服务器建立连接（确保100%覆盖）
  validServers.forEach((server, index) => {
    const serverRegion = getRegionKey(server);
    
    // 计算到所有其他服务器的距离（一次性计算，缓存结果）
    const distances = validServers
      .filter(s => s.id !== server.id)
      .map(s => ({
        server: s,
        distance: haversineDistance(server.coords, s.coords),
        sameRegion: getRegionKey(s) === serverRegion
      }))
      .sort((a, b) => a.distance - b.distance); // 按距离排序
    
    if (distances.length === 0) return;
    
    // 策略：每个服务器连接2-3个其他服务器（性能优化）
    const connectionsToMake = [];
    
    // 1. 连接最近的不同地区服务器（优先跨区域）
    const nearestDifferentRegion = distances.find(d => !d.sameRegion);
    if (nearestDifferentRegion) {
      connectionsToMake.push({
        target: nearestDifferentRegion,
        type: nearestDifferentRegion.distance < 3000 ? 'mesh-nearby' : 
              nearestDifferentRegion.distance < 5000 ? 'mesh-medium' :
              nearestDifferentRegion.distance < 8000 ? 'mesh-long' : 'mesh-ultra-long'
      });
    }
    
    // 2. 如果同地区有服务器，连接最近的一个（避免孤立）
    const nearestSameRegion = distances.find(d => d.sameRegion);
    if (nearestSameRegion && distances.filter(d => d.sameRegion).length <= 3) {
      connectionsToMake.push({
        target: nearestSameRegion,
        type: 'mesh-nearby'
      });
    }
    
    // 3. 连接一个中远距离服务器（增加网络密度）
    const mediumDistance = distances.find(d => 
      !d.sameRegion && 
      d.distance >= 3000 && 
      d.distance < 8000 &&
      !connectionsToMake.some(c => c.target.server.id === d.server.id)
    );
    if (mediumDistance) {
      connectionsToMake.push({
        target: mediumDistance,
        type: mediumDistance.distance < 5000 ? 'mesh-medium' : 'mesh-long'
      });
    }
    
    // 4. 对于孤立地区，额外连接一个超远距离服务器
    const serversInRegion = regionGroups.get(serverRegion)?.length || 0;
    if (serversInRegion <= 2) {
      const ultraLong = distances.find(d => 
        d.distance >= 8000 &&
        !connectionsToMake.some(c => c.target.server.id === d.server.id)
      );
      if (ultraLong) {
        connectionsToMake.push({
          target: ultraLong,
          type: 'mesh-ultra-long'
        });
      }
    }
    
    // 添加连接
    connectionsToMake.forEach(({ target, type }) => {
      connections.push({
        startLat: server.coords.lat,
        startLng: server.coords.lng,
        endLat: target.server.coords.lat,
        endLng: target.server.coords.lng,
        type: type,
        distance: target.distance
      });
    });
  });
  
  // 去重（双向连接只保留一条）
  const seen = new Set();
  const uniqueConnections = connections.filter(conn => {
    const key = [
      conn.startLat.toFixed(4),
      conn.startLng.toFixed(4),
      conn.endLat.toFixed(4),
      conn.endLng.toFixed(4)
    ].sort().join(',');
    
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  
  return uniqueConnections;
}

function isWebGLAvailable() {
  try {
    const canvas = document.createElement('canvas');
    return !!(canvas.getContext('webgl') || canvas.getContext('experimental-webgl'));
  } catch(e) {
    return false;
  }
}

async function fetchServersFromLeaderboard() {
  try {
    const res = await fetch('/api/leaderboard', {
      credentials: 'same-origin',
      cache: 'no-store'
    });
    
    if (!res.ok) {
      return serversData;
    }
    
    const data = await res.json();
    if (!data.success || !data.data) {
      return serversData;
    }
    
    const allServers = [];
    let serverIndex = 0;
    
    data.data.forEach(donor => {
      if (!donor.servers || !Array.isArray(donor.servers)) {
        return;
      }
      
      donor.servers.forEach(server => {
        const serverId = donor.username + '_' + serverIndex;
        serverIndex++;
        
        // 优先使用 ipLocation，其次 country
        const location = server.ipLocation || server.country || '未知地区';
        let coords = geocode(location);
        
        // 备用方案：如果无法匹配，尝试移除emoji后再匹配
        if (!coords && server.country) {
          const cleanCountry = server.country.replace(/[\u{1F1E6}-\u{1F1FF}]/gu, '').trim();
          coords = geocode(cleanCountry);
        }
        
        if (coords) {
          coords = addJitter(coords, serverIndex);
        }
        
        allServers.push({
          id: serverId,
          coords: coords,
          country: server.country || '未填写',
          ipLocation: server.ipLocation || '未知地区',
          status: server.status || 'active',
          donatedByUsername: donor.username,
          traffic: server.traffic,
          expiryDate: server.expiryDate,
          specs: server.specs,
          note: server.note,
          donatedAt: server.donatedAt
        });
      });
    });
    
    return allServers;
    
  } catch (error) {
    return serversData;
  }
}

function updateStats(servers, connections) {
  const total = servers.length;
  const active = servers.filter(s => s.status === 'active').length;
  
  const totalEl = document.getElementById('total-servers');
  const activeEl = document.getElementById('active-servers');
  const connectionsEl = document.getElementById('total-connections');
  const visitorEl = document.getElementById('visitor-location');
  
  if (totalEl) totalEl.textContent = total;
  if (activeEl) activeEl.textContent = active;
  if (connectionsEl) connectionsEl.textContent = connections.length;
  
  // 更新访问者位置显示
  if (visitorEl && visitorLocation) {
    visitorEl.textContent = \`\${visitorLocation.city}, \${visitorLocation.country}\`;
  }
}

function initGlobe() {
  if (typeof Globe === 'undefined') {
    const container = document.getElementById('globe-container');
    if (container) {
      container.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #fff; text-align: center; padding: 20px;"><div><div style="font-size: 48px; margin-bottom: 16px;">⚠️</div><div style="font-size: 18px; margin-bottom: 8px;">3D地球库加载失败</div><div style="font-size: 14px; opacity: 0.7;">请刷新页面重试</div></div></div>';
    }
    return;
  }
  
  if (!isWebGLAvailable()) {
    const container = document.getElementById('globe-container');
    if (container) {
      container.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #fff; text-align: center; padding: 20px;"><div><div style="font-size: 48px; margin-bottom: 16px;">⚠️</div><div style="font-size: 18px; margin-bottom: 8px;">您的浏览器不支持WebGL</div><div style="font-size: 14px; opacity: 0.7;">请使用现代浏览器访问</div></div></div>';
    }
    return;
  }
  
  const validServers = serversData.filter(s => s.coords && s.coords.lat !== null && s.coords.lng !== null);
  
  try {
    globeInstance = Globe()
      (document.getElementById('globe-container'))
    
    .globeImageUrl('//unpkg.com/three-globe/example/img/earth-blue-marble.jpg')
    .bumpImageUrl('//unpkg.com/three-globe/example/img/earth-topology.png')
    .backgroundColor('#000000')
    
    .pointsData(validServers)
    .pointLat(d => d.coords.lat)
    .pointLng(d => d.coords.lng)
    .pointColor(d => {
      // 活跃服务器：鲜艳的翠绿色（带发光效果）
      if (d.status === 'active') return '#10b981';
      // 失败服务器：鲜红色
      if (d.status === 'failed') return '#ef4444';
      // 未启用：灰色
      return '#94a3b8';
    })
    .pointAltitude(0.018) // 稍微提高，更突出
    .pointRadius(0.40) // 更大一点，更醒目
    .pointResolution(16) // 更高分辨率，更圆滑
    
    .pointLabel(d => {
      const flag = getCountryFlag(d.country);
      const statusEmoji = d.status === 'active' ? '✅' : '❌';
      const statusText = d.status === 'active' ? '运行中' : '离线';
      
      return \`
        <div style="
          background: rgba(0,0,0,0.9);
          padding: 12px 16px;
          border-radius: 8px;
          color: white;
          font-family: system-ui, -apple-system, sans-serif;
          box-shadow: 0 4px 12px rgba(0,0,0,0.3);
          backdrop-filter: blur(8px);
          border: 1px solid rgba(255,255,255,0.1);
        ">
          <div style="font-size: 18px; margin-bottom: 8px; font-weight: 600;">
            \${flag} @\${d.donatedByUsername}
          </div>
          <div style="font-size: 14px; opacity: 0.9; margin-bottom: 4px;">
            📍 \${d.country}
          </div>
          <div style="font-size: 13px; opacity: 0.8; margin-bottom: 8px;">
            \${d.ipLocation || '未知位置'}
          </div>
          <div style="font-size: 14px; font-weight: 500;">
            状态: \${statusEmoji} \${statusText}
          </div>
        </div>
      \`;
    })
    
    .htmlElementsData([])
    
    .arcsData(connectionsData)
    .arcStartLat(d => d.startLat)
    .arcStartLng(d => d.startLng)
    .arcEndLat(d => d.endLat)
    .arcEndLng(d => d.endLng)
    .arcColor(d => {
      // 访问者主连接 - 优雅的流光渐变（青色→金色）
      if (d.type === 'visitor-primary') {
        if (d.serverStatus === 'active') {
          // 活跃服务器：青色到金色的流光效果（更柔和）
          return ['rgba(6, 182, 212, 0.85)', 'rgba(251, 191, 36, 0.95)'];
        } else {
          // 离线服务器：灰色
          return ['rgba(100, 116, 139, 0.4)', 'rgba(148, 163, 184, 0.5)'];
        }
      }
      // 网状互联 - 近距离（翠绿色渐变）
      else if (d.type === 'mesh-nearby') {
        return ['rgba(34, 197, 94, 0.4)', 'rgba(74, 222, 128, 0.5)'];
      }
      // 网状互联 - 中距离（天蓝色渐变）
      else if (d.type === 'mesh-medium') {
        return ['rgba(59, 130, 246, 0.5)', 'rgba(96, 165, 250, 0.6)'];
      }
      // 网状互联 - 长距离（紫罗兰渐变）
      else if (d.type === 'mesh-long') {
        return ['rgba(168, 85, 247, 0.6)', 'rgba(192, 132, 252, 0.7)'];
      }
      // 网状互联 - 超长距离（玫瑰粉渐变）
      else if (d.type === 'mesh-ultra-long') {
        return ['rgba(236, 72, 153, 0.7)', 'rgba(244, 114, 182, 0.8)'];
      }
      // 默认（金色）
      return ['rgba(255, 215, 0, 0.4)', 'rgba(255, 190, 0, 0.5)'];
    })
    .arcStroke(d => {
      // 访问者主连接 - 细腻优雅（不要太粗）
      if (d.type === 'visitor-primary') return 0.6;
      // 超长距离 - 中等粗细
      if (d.type === 'mesh-ultra-long') return 0.5;
      // 长距离
      if (d.type === 'mesh-long') return 0.45;
      // 中距离
      if (d.type === 'mesh-medium') return 0.4;
      // 近距离
      if (d.type === 'mesh-nearby') return 0.35;
      return 0.35;
    })
    .arcAltitude(d => {
      // 访问者主连接 - 优雅的弧线高度
      if (d.type === 'visitor-primary') {
        // 根据距离调整高度，形成优美的弧线
        const baseAlt = 0.15;
        const distanceFactor = Math.min(d.distance / 10000, 1);
        return baseAlt + distanceFactor * 0.15; // 最高可达0.30
      }
      // 超长距离连接 - 高弧线
      if (d.type === 'mesh-ultra-long') return 0.25;
      // 长距离连接 - 中高弧线
      if (d.type === 'mesh-long') return 0.16;
      // 中距离连接 - 中等弧线
      if (d.type === 'mesh-medium') return 0.09;
      // 近距离连接 - 低弧线
      return 0.05;
    })
    .arcDashLength(d => {
      // 访问者主连接 - 流畅的虚线段
      if (d.type === 'visitor-primary') return 0.75;
      // 超长距离 - 长虚线
      if (d.type === 'mesh-ultra-long') return 0.65;
      // 长距离
      if (d.type === 'mesh-long') return 0.6;
      // 中距离
      if (d.type === 'mesh-medium') return 0.55;
      return 0.5;
    })
    .arcDashGap(d => {
      // 访问者主连接 - 适中的间隙（流光效果）
      if (d.type === 'visitor-primary') return 0.25;
      // 超长距离 - 较小间隙
      if (d.type === 'mesh-ultra-long') return 0.35;
      // 长距离
      if (d.type === 'mesh-long') return 0.4;
      return 0.45;
    })
    .arcDashAnimateTime(d => {
      // 访问者主连接 - 流畅的动画速度
      if (d.type === 'visitor-primary') return 2200;
      // 超长距离 - 慢速（强调距离感）
      if (d.type === 'mesh-ultra-long') return 5500;
      // 长距离 - 较慢
      if (d.type === 'mesh-long') return 4800;
      // 中距离 - 中等
      if (d.type === 'mesh-medium') return 4000;
      // 近距离 - 较快
      return 3200;
    })
    .arcDashInitialGap(() => Math.random())
    
    .enablePointerInteraction(true);
  
  if (globeInstance && globeInstance.controls) {
    const controls = globeInstance.controls();
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.3; // 稍微加快旋转速度，更流畅
    controls.enableRotate = true;
    controls.enableZoom = true;
    controls.minDistance = 101;
    controls.maxDistance = 500;
    controls.enablePan = false;
    controls.enableDamping = true;
    controls.dampingFactor = 0.1; // 优化阻尼，更流畅
  }
  
  // 性能优化：设置渲染器参数
  if (globeInstance && globeInstance.renderer) {
    const renderer = globeInstance.renderer();
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2)); // 限制像素比，提升性能
  }
  
    const container = document.getElementById('globe-container');
    if (container && globeInstance) {
      globeInstance.width(container.clientWidth);
      globeInstance.height(container.clientHeight);
    }
  } catch (error) {
    const container = document.getElementById('globe-container');
    if (container) {
      const errorMsg = error && error.message ? error.message : '未知错误';
      container.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #fff; text-align: center; padding: 20px;"><div><div style="font-size: 48px; margin-bottom: 16px;">⚠️</div><div style="font-size: 18px; margin-bottom: 8px;">3D地球初始化失败</div><div style="font-size: 14px; opacity: 0.7;">错误: ' + errorMsg + '</div></div></div>';
    }
  }
}

function updateGlobeData() {
  if (!globeInstance) return;
  
  const validServers = serversData.filter(s => s.coords && s.coords.lat !== null && s.coords.lng !== null);
  
  globeInstance.pointsData(validServers);
  globeInstance.htmlElementsData([]);
  globeInstance.arcsData(connectionsData);
  
  updateStats(serversData, connectionsData);
}

let lastConnectionsUpdate = 0;
const CONNECTIONS_UPDATE_INTERVAL = 180000; // 增加到3分钟，减少重新计算频率

async function updateData() {
  const newServersData = await fetchServersFromLeaderboard();
  
  const serverCountChanged = newServersData.length !== serversData.length;
  const now = Date.now();
  const shouldUpdateConnections = serverCountChanged || (now - lastConnectionsUpdate > CONNECTIONS_UPDATE_INTERVAL);
  
  serversData = newServersData;
  
  if (shouldUpdateConnections) {
    // 使用访问者位置计算连接
    connectionsData = calculateConnections(serversData, visitorLocation);
    lastConnectionsUpdate = now;
  }
  
  if (globeInstance) {
    updateGlobeData();
  }
  
  updateStats(serversData, connectionsData);
}

function toggleSize() {
  const container = document.getElementById('globe-container');
  const button = document.getElementById('toggle-size');
  
  if (!container || !button) return;
  
  if (container.classList.contains('minimized')) {
    container.classList.remove('minimized');
    button.textContent = '最小化';
  } else {
    container.classList.add('minimized');
    button.textContent = '最大化';
  }
  
  if (globeInstance) {
    setTimeout(() => {
      globeInstance.width(container.clientWidth);
      globeInstance.height(container.clientHeight);
    }, 300);
  }
}

function toggleRotate() {
  const button = document.getElementById('toggle-rotate');
  
  if (!globeInstance || !globeInstance.controls || !button) return;
  
  const controls = globeInstance.controls();
  controls.autoRotate = !controls.autoRotate;
  
  button.textContent = controls.autoRotate ? '暂停旋转' : '继续旋转';
}

function handleResize() {
  if (!globeInstance) return;
  
  const container = document.getElementById('globe-container');
  if (container) {
    globeInstance.width(container.clientWidth);
    globeInstance.height(container.clientHeight);
  }
}

function handleVisibilityChange() {
  if (document.hidden) {
    if (globeInstance && globeInstance.controls) {
      globeInstance.controls().autoRotate = false;
    }
    if (updateInterval) {
      clearInterval(updateInterval);
      updateInterval = null;
    }
  } else {
    if (globeInstance && globeInstance.controls) {
      const button = document.getElementById('toggle-rotate');
      const shouldRotate = !button || button.textContent === '暂停旋转';
      globeInstance.controls().autoRotate = shouldRotate;
    }
    if (!updateInterval) {
      updateInterval = setInterval(updateData, 30000);
    }
  }
}

function waitForGlobe() {
  return new Promise((resolve) => {
    if (typeof Globe !== 'undefined') {
      resolve();
    } else {
      const checkInterval = setInterval(() => {
        if (typeof Globe !== 'undefined') {
          clearInterval(checkInterval);
          resolve();
        }
      }, 100);
      
      setTimeout(() => {
        clearInterval(checkInterval);
        resolve();
      }, 10000);
    }
  });
}

(async function() {
  await waitForGlobe();
  
  // 首先获取访问者位置
  visitorLocation = await getVisitorLocation();
  
  // 然后加载数据并初始化地球
  await updateData();
  initGlobe();
  
  // 如果有访问者位置，添加一个特殊的标记点（超炫动画效果）
  if (visitorLocation && globeInstance) {
    const visitorPoint = [{
      lat: visitorLocation.lat,
      lng: visitorLocation.lng,
      label: '您的位置',
      city: visitorLocation.city,
      country: visitorLocation.country
    }];
    
    // 添加访问者位置的标记（使用 htmlElements，带脉冲动画）
    globeInstance.htmlElementsData(visitorPoint)
      .htmlLat(d => d.lat)
      .htmlLng(d => d.lng)
      .htmlAltitude(0.025)
      .htmlElement(d => {
        const el = document.createElement('div');
        el.style.cssText = \`
          position: relative;
          width: 32px;
          height: 32px;
          display: flex;
          align-items: center;
          justify-content: center;
          cursor: pointer;
        \`;
        
        // 创建脉冲动画背景
        const pulse = document.createElement('div');
        pulse.style.cssText = \`
          position: absolute;
          width: 100%;
          height: 100%;
          background: radial-gradient(circle, rgba(6, 182, 212, 0.6), transparent);
          border-radius: 50%;
          animation: pulse-glow 2s ease-in-out infinite;
        \`;
        
        // 创建图标
        const icon = document.createElement('div');
        icon.innerHTML = '📍';
        icon.style.cssText = \`
          font-size: 28px;
          position: relative;
          z-index: 1;
          filter: drop-shadow(0 0 8px rgba(6, 182, 212, 0.8));
        \`;
        
        el.appendChild(pulse);
        el.appendChild(icon);
        el.title = \`您的位置：\${d.city}, \${d.country}\`;
        
        return el;
      });
  }
  
  const toggleSizeBtn = document.getElementById('toggle-size');
  const toggleRotateBtn = document.getElementById('toggle-rotate');
  
  if (toggleSizeBtn) {
    toggleSizeBtn.addEventListener('click', toggleSize);
  }
  
  if (toggleRotateBtn) {
    toggleRotateBtn.addEventListener('click', toggleRotate);
  }
  
  // 使用防抖处理窗口大小调整
  let resizeTimer = null;
  window.addEventListener('resize', () => {
    if(resizeTimer) clearTimeout(resizeTimer);
    resizeTimer = setTimeout(handleResize, 300);
  });
  
  document.addEventListener('visibilitychange', handleVisibilityChange);
  
  // 优化更新间隔到90秒，减少性能消耗
  updateInterval = setInterval(updateData, 90000);
})();
</script>
</body></html>`;
  return c.html(html);
});


/* ==================== /donate/vps 投喂中心 ==================== */
app.get('/donate/vps', c => {
  const head = commonHead('风萧萧公益机场 · VPS 投喂中心');
  const today = new Date();
  const y = today.getFullYear(),
    m = String(today.getMonth() + 1).padStart(2, '0'),
    d = String(today.getDate()).padStart(2, '0');
  const minDate = `${y}-${m}-${d}`;
  const nextYear = new Date(today);
  nextYear.setFullYear(today.getFullYear() + 1);
  const ny = `${nextYear.getFullYear()}-${String(nextYear.getMonth() + 1).padStart(
    2,
    '0',
  )}-${String(nextYear.getDate()).padStart(2, '0')}`;

  const html = `<!doctype html><html lang="zh-CN"><head>${head}</head>
<body class="min-h-screen bg-[#0B0C15] text-slate-200 font-sans selection:bg-indigo-500/30">
<!-- Background Effects -->
<div class="fixed inset-0 -z-10 overflow-hidden pointer-events-none">
  <div class="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-indigo-600/10 rounded-full blur-[120px]"></div>
  <div class="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-purple-600/10 rounded-full blur-[120px]"></div>
  <div class="absolute top-[20%] right-[20%] w-[30%] h-[30%] bg-blue-600/5 rounded-full blur-[100px]"></div>
</div>

<div class="max-w-[1600px] mx-auto px-6 py-8 md:py-12">
  <!-- Header -->
  <header class="mb-12 animate-fade-in flex flex-col md:flex-row md:items-center justify-between gap-6">
    <div>
      <h1 class="text-4xl md:text-5xl font-bold text-white mb-3 tracking-tight flex items-center gap-4">
        VPS 投喂中心
      </h1>
      <p class="text-slate-400 flex items-center gap-2 text-lg">
        <span class="w-5 h-5 text-pink-500 animate-pulse">${ICONS.heart || '🧡'}</span>
        <span>共建公益节点网络，感谢您的无私奉献</span>
      </p>
    </div>
    <div class="flex items-center gap-4">
       <div id="user-info" class="hidden md:block px-5 py-2.5 rounded-full text-sm border border-white/5 bg-white/5 text-slate-300 backdrop-blur-md"></div>
       <a href="/donate" class="btn-secondary rounded-full px-6 py-2.5 bg-white/5 hover:bg-white/10 border border-white/10 text-white transition-all">首页</a>
       <button onclick="logout()" class="btn-secondary rounded-full px-6 py-2.5 bg-white/5 hover:bg-red-500/20 border border-white/10 text-white hover:text-red-300 transition-all">退出</button>
    </div>
  </header>

  <div class="grid lg:grid-cols-12 gap-8 items-start">
    <!-- Left: Submission Form -->
    <section class="lg:col-span-7 space-y-6 animate-slide-up" style="animation-delay: 0.1s">
       <div class="relative group">
         <div class="absolute -inset-0.5 bg-gradient-to-r from-indigo-500 to-purple-600 rounded-[2.1rem] opacity-30 blur group-hover:opacity-50 transition duration-1000"></div>
         <div class="relative bg-[#13141F] rounded-[2rem] p-8 border border-white/5 shadow-2xl">
            
            <div class="flex items-center gap-5 mb-8">
              <div class="w-14 h-14 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-white shadow-lg shadow-indigo-500/20">
                <div class="w-7 h-7">${ICONS.server}</div>
              </div>
              <div>
                <h2 class="text-2xl font-bold text-white">提交新节点</h2>
                <p class="text-slate-400 mt-1">请填写服务器连接信息</p>
              </div>
            </div>
            
            <div class="bg-indigo-500/5 border border-indigo-500/10 rounded-2xl p-5 mb-8 flex gap-4">
              <div class="w-6 h-6 flex-shrink-0 text-indigo-400 mt-0.5">${ICONS.info}</div>
              <div class="text-indigo-200/80 text-sm leading-relaxed">请确保服务器是你有控制权的机器。禁止提交被黑/扫描到的机器。</div>
            </div>

            <form id="donate-form" class="space-y-8">
              <!-- IP & Port -->
              <div class="grid md:grid-cols-2 gap-6">
                <div class="group">
                  <label class="block mb-2.5 text-sm font-medium text-slate-400 group-focus-within:text-indigo-400 transition-colors">
                    服务器 IP <span class="text-red-400">*</span>
                  </label>
                  <div class="relative">
                    <div class="absolute left-5 top-4 w-6 h-6 text-slate-500 group-focus-within:text-indigo-400 transition-colors">${ICONS.globe}</div>
                    <input name="ip" required placeholder="1.2.3.4"
                           class="w-full bg-[#1A1B26] border border-white/5 rounded-xl py-4 pl-14 pr-5 text-white placeholder-slate-600 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all outline-none text-lg" />
                  </div>
                  <div class="text-xs text-slate-600 mt-2 pl-1">支持 IPv4 / IPv6</div>
                </div>
                <div class="group">
                  <label class="block mb-2.5 text-sm font-medium text-slate-400 group-focus-within:text-indigo-400 transition-colors">
                    端口 <span class="text-red-400">*</span>
                  </label>
                  <div class="relative">
                    <div class="absolute left-5 top-4 w-6 h-6 text-slate-500 group-focus-within:text-indigo-400 transition-colors">${ICONS.plug}</div>
                    <input name="port" required type="number" min="1" max="65535" placeholder="22"
                           class="w-full bg-[#1A1B26] border border-white/5 rounded-xl py-4 pl-14 pr-5 text-white placeholder-slate-600 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all outline-none text-lg" />
                  </div>
                </div>
              </div>

              <!-- User & Auth -->
              <div class="grid md:grid-cols-2 gap-6">
                <div class="group">
                  <label class="block mb-2.5 text-sm font-medium text-slate-400 group-focus-within:text-indigo-400 transition-colors">
                    用户名 <span class="text-red-400">*</span>
                  </label>
                  <div class="relative">
                    <div class="absolute left-5 top-4 w-6 h-6 text-slate-500 group-focus-within:text-indigo-400 transition-colors">${ICONS.user}</div>
                    <input name="username" required placeholder="root"
                           class="w-full bg-[#1A1B26] border border-white/5 rounded-xl py-4 pl-14 pr-5 text-white placeholder-slate-600 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all outline-none text-lg" />
                  </div>
                </div>
                <div class="group">
                  <label class="block mb-2.5 text-sm font-medium text-slate-400 group-focus-within:text-indigo-400 transition-colors">
                    认证方式 <span class="text-red-400">*</span>
                  </label>
                  <div class="relative">
                    <div class="absolute left-5 top-4 w-6 h-6 text-slate-500 z-10">${ICONS.lock}</div>
                    <select name="authType" class="w-full bg-[#1A1B26] border border-white/5 rounded-xl py-4 pl-14 pr-5 text-white focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all outline-none appearance-none text-lg cursor-pointer">
                      <option value="password">密码认证</option>
                      <option value="key">SSH 密钥</option>
                    </select>
                    <div class="absolute right-5 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500 pointer-events-none">
                      ${ICONS.chevronDown}
                    </div>
                  </div>
                </div>
              </div>
              <!-- Auth Fields -->
              <div id="password-field" class="group">
                <label class="block mb-2.5 text-sm font-medium text-slate-400 group-focus-within:text-indigo-400 transition-colors">
                  密码 <span class="text-red-400">*</span>
                </label>
                <div class="relative">
                  <div class="absolute left-5 top-4 w-6 h-6 text-slate-500 group-focus-within:text-indigo-400 transition-colors">${ICONS.key}</div>
                  <input name="password" type="password" placeholder="••••••••••••"
                         class="w-full bg-white text-slate-900 border-0 rounded-xl py-4 pl-14 pr-5 placeholder-slate-400 focus:ring-4 focus:ring-indigo-500/30 transition-all outline-none text-lg font-medium shadow-[0_0_20px_rgba(255,255,255,0.1)]" />
                </div>
              </div>
              
              <div id="private-key-field" class="hidden group">
                <label class="block mb-2.5 text-sm font-medium text-slate-400 group-focus-within:text-indigo-400 transition-colors">
                  SSH 私钥 <span class="text-red-400">*</span>
                </label>
                <div class="relative">
                  <div class="absolute left-5 top-4 w-6 h-6 text-slate-500 group-focus-within:text-indigo-400 transition-colors">${ICONS.key}</div>
                  <textarea name="privateKey" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----..." rows="5"
                            class="w-full bg-[#1A1B26] border border-white/5 rounded-xl py-4 pl-14 pr-5 text-white placeholder-slate-600 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all outline-none font-mono text-sm leading-relaxed"></textarea>
                </div>
              </div>

              <!-- Location -->
              <div class="grid md:grid-cols-2 gap-6">
                <div class="group">
                  <label class="block mb-2.5 text-sm font-medium text-slate-400 group-focus-within:text-indigo-400 transition-colors">
                    国家/地区 <span class="text-red-400">*</span>
                  </label>
                  <div class="relative">
                    <div class="absolute left-5 top-4 w-6 h-6 text-slate-500 z-10">${ICONS.globe}</div>
                     <select id="country-select" name="country" class="w-full bg-[#1A1B26] border border-white/5 rounded-xl py-4 pl-14 pr-5 text-white focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all outline-none appearance-none text-lg cursor-pointer">
                      <option value="" disabled selected>请选择国家/区域</option>
                      <optgroup label="热门区域">
                        <option value="HK">🇭🇰 香港 (Hong Kong)</option>
                        <option value="JP">🇯🇵 日本 (Japan)</option>
                        <option value="US">🇺🇸 美国 (United States)</option>
                        <option value="SG">🇸🇬 新加坡 (Singapore)</option>
                        <option value="KR">🇰🇷 韩国 (South Korea)</option>
                        <option value="TW">🇹🇼 台湾 (Taiwan)</option>
                      </optgroup>
                      <optgroup label="其他区域">
                        <option value="CN">🇨🇳 中国 (China)</option>
                        <option value="GB">🇬🇧 英国 (United Kingdom)</option>
                        <option value="DE">🇩🇪 德国 (Germany)</option>
                        <option value="FR">🇫🇷 法国 (France)</option>
                        <option value="RU">🇷🇺 俄罗斯 (Russia)</option>
                        <option value="CA">🇨🇦 加拿大 (Canada)</option>
                        <option value="AU">🇦🇺 澳大利亚 (Australia)</option>
                      </optgroup>
                    </select>
                    <div class="absolute right-5 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500 pointer-events-none">
                      ${ICONS.chevronDown}
                    </div>
                  </div>
                </div>
                <div class="group">
                  <label class="block mb-2.5 text-sm font-medium text-slate-400 group-focus-within:text-indigo-400 transition-colors">
                    具体位置 <span class="text-slate-600 text-xs font-normal">(可选)</span>
                  </label>
                  <div class="relative">
                    <div class="absolute left-5 top-4 w-6 h-6 text-slate-500 group-focus-within:text-indigo-400 transition-colors">${ICONS.search}</div>
                    <input name="region" placeholder="例如：东京、洛杉矶"
                           class="w-full bg-[#1A1B26] border border-white/5 rounded-xl py-4 pl-14 pr-5 text-white placeholder-slate-600 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all outline-none text-lg" />
                  </div>
                </div>
              </div>

              <!-- Traffic & Expiry -->
              <div class="grid md:grid-cols-2 gap-6">
                <div class="group">
                  <label class="block mb-2.5 text-sm font-medium text-slate-400 group-focus-within:text-indigo-400 transition-colors">
                    流量/带宽 <span class="text-red-400">*</span>
                  </label>
                  <div class="relative">
                    <div class="absolute left-5 top-4 w-6 h-6 text-slate-500 group-focus-within:text-indigo-400 transition-colors">${ICONS.chart}</div>
                    <input name="traffic" required placeholder="1T/月 · 1Gbps"
                           class="w-full bg-[#1A1B26] border border-white/5 rounded-xl py-4 pl-14 pr-5 text-white placeholder-slate-600 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all outline-none text-lg" />
                  </div>
                </div>
                <div class="group">
                  <label class="block mb-2.5 text-sm font-medium text-slate-400 group-focus-within:text-indigo-400 transition-colors">
                    到期时间 <span class="text-red-400">*</span>
                  </label>
                  <div class="relative">
                    <div class="absolute left-5 top-4 w-6 h-6 text-slate-500 group-focus-within:text-indigo-400 transition-colors">${ICONS.calendar}</div>
                    <input name="expiryDate" required type="date" min="${minDate}" value="${ny}"
                           class="w-full bg-[#1A1B26] border border-white/5 rounded-xl py-4 pl-14 pr-5 text-white placeholder-slate-600 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all outline-none text-lg" />
                  </div>
                </div>
              </div>

              <!-- Specs -->
              <div class="group">
                <label class="block mb-2.5 text-sm font-medium text-slate-400 group-focus-within:text-indigo-400 transition-colors">
                  配置描述 <span class="text-red-400">*</span>
                </label>
                <div class="relative">
                  <div class="absolute left-5 top-4 w-6 h-6 text-slate-500 group-focus-within:text-indigo-400 transition-colors">${ICONS.cpu}</div>
                  <input name="specs" required placeholder="1C1G · 20G SSD"
                         class="w-full bg-[#1A1B26] border border-white/5 rounded-xl py-4 pl-14 pr-5 text-white placeholder-slate-600 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all outline-none text-lg" />
                </div>
              </div>

              <!-- Note -->
              <div class="group">
                <label class="block mb-2.5 text-sm font-medium text-slate-400 group-focus-within:text-indigo-400 transition-colors">
                  备注 <span class="text-slate-600 text-xs font-normal">(可选)</span>
                </label>
                <div class="relative">
                  <div class="absolute left-5 top-4 w-6 h-6 text-slate-500 group-focus-within:text-indigo-400 transition-colors">${ICONS.message}</div>
                  <textarea name="note" rows="3" placeholder="例如：三网回程优化，解锁流媒体..."
                            class="w-full bg-[#1A1B26] border border-white/5 rounded-xl py-4 pl-14 pr-5 text-white placeholder-slate-600 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all outline-none text-lg"></textarea>
                </div>
              </div>

              <div id="donate-message" class="text-sm min-h-[1.5rem] font-medium text-center"></div>

              <button id="donate-submit-btn" type="submit" class="w-full btn-primary py-5 rounded-xl text-xl font-bold shadow-lg shadow-indigo-500/20 hover:shadow-indigo-500/40 transition-all transform hover:-translate-y-0.5 active:translate-y-0 bg-gradient-to-r from-indigo-600 to-purple-600 border-0 flex items-center justify-center gap-3">
                <span class="w-6 h-6">${ICONS.rocket}</span>
                <span>提交投喂</span>
              </button>
            </form>
         </div>
       </div>
    </section>

    <!-- Right: My Donations -->
    <section class="lg:col-span-5 space-y-6 animate-slide-up" style="animation-delay: 0.2s">
       <div class="relative bg-[#13141F] rounded-[2rem] p-8 border border-white/5 shadow-2xl min-h-[800px]">
          <div class="flex items-center justify-between mb-8">
            <div class="flex items-center gap-4">
              <div class="w-12 h-12 rounded-2xl bg-white/5 flex items-center justify-center text-purple-400 border border-white/5">
                <div class="w-6 h-6">${ICONS.star}</div>
              </div>
              <h2 class="text-xl font-bold text-white">我的投喂</h2>
            </div>
            <div class="flex gap-2">
              <button onclick="exportDonations()" class="p-3 rounded-xl bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition-all border border-white/5" title="导出">
                <div class="w-5 h-5">${ICONS.save}</div>
              </button>
              <button onclick="loadDonations()" class="p-3 rounded-xl bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition-all border border-white/5" title="刷新">
                <div class="w-5 h-5">${ICONS.clock}</div>
              </button>
            </div>
          </div>
          
          <div id="donations-list" class="space-y-4">
            <!-- List content will be injected by JS -->
          </div>
       </div>
    </section>
  </div>

  <footer class="mt-20 pb-12 text-center animate-fade-in">
    <div class="inline-flex items-center gap-3 px-8 py-4 rounded-full bg-white/5 border border-white/5 text-slate-400 backdrop-blur-sm">
      <span class="w-5 h-5 text-indigo-400">${ICONS.info}</span>
      <span class="text-sm font-medium">感谢您为公益事业做出的贡献</span>
    </div>
  </footer>
</div>


<div id="toast-root"></div>
<script>
updateThemeBtn();





async function ensureLogin(){
  try{
    const res = await fetch('/api/user/info',{credentials:'same-origin',cache:'no-store'});
    if(!res.ok){ location.href='/donate'; return; }
    const j=await res.json();
    if(!j.success){ location.href='/donate'; return; }
    const u=j.data;
    const p='https://linux.do/u/'+encodeURIComponent(u.username);
    const infoEl = document.getElementById('user-info');
    if(infoEl) {
      infoEl.innerHTML='投喂者：<a href="'+p+'" target="_blank" class="underline text-sky-300">@'+u.username+'</a> · 已投喂 '+(u.donationCount||0)+' 台';
    }
  }catch(err){
    console.error('Login check error:', err);
    location.href='/donate';
  }
}

async function logout(){
  try{ await fetch('/api/logout',{credentials:'same-origin'});}catch{}
  location.href='/donate';
}

async function exportDonations(){
  try{
    const r=await fetch('/api/user/donations',{credentials:'same-origin',cache:'no-store'});
    const j=await r.json();
    if(!r.ok||!j.success){
      toast('导出失败','error');
      return;
    }
    const data=j.data||[];
    if(!data.length){
      toast('暂无投喂记录可导出','warn');
      return;
    }
    
    const exportData = {
      exportTime: new Date().toISOString(),
      totalCount: data.length,
      donations: data.map(v => ({
        ip: v.ip,
        port: v.port,
        username: v.username,
        country: v.country,
        ipLocation: v.ipLocation,
        traffic: v.traffic,
        expiryDate: v.expiryDate,
        specs: v.specs,
        status: v.status,
        donatedAt: new Date(v.donatedAt).toISOString(),
        note: v.note || ''
      }))
    };
    
    const blob = new Blob([JSON.stringify(exportData, null, 2)], {type: 'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'my-vps-donations-'+Date.now()+'.json';
    a.click();
    URL.revokeObjectURL(url);
    toast('导出成功','success');
  }catch(err){
    console.error('Export error:', err);
    toast('导出异常','error');
  }
}

function bindAuthType(){
  const sel=document.querySelector('select[name="authType"]');
  const pwd=document.getElementById('password-field');
  const key=document.getElementById('private-key-field');
  if(sel && pwd && key) {
    sel.addEventListener('change',function(){
      if(sel.value==='password'){
        pwd.classList.remove('hidden');
        key.classList.add('hidden');
      }else{
        pwd.classList.add('hidden');
        key.classList.remove('hidden');
      }
    });
  }
}

function stxt(s){ return s==='active'?'运行中':(s==='failed'?'失败':'未启用'); }
function scls(s){ return s==='active'?'badge-ok':(s==='failed'?'badge-fail':'badge-idle'); }

function clientCleanIP(raw){
  let s = String(raw||'');
  s = s.replace(/[\uff10-\uff19]/g, c => String.fromCharCode(c.charCodeAt(0) - 0xfee0));
  s = s.replace(/\uff1a/g, ':').replace(/\uff0e/g, '.').replace(/\u3002/g, '.');
  s = s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, '');
  s = s.replace(/[\u200b-\u200f\u2028-\u202f\u2060\ufeff]/g, '');
  s = s.trim();
  s = s.replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
  return s;
}

async function submitDonate(e){
  e.preventDefault();
  const form=e.target, msg=document.getElementById('donate-message'), btn=document.getElementById('donate-submit-btn');
  msg.textContent=''; msg.className='text-xs mt-1 min-h-[1.5rem]';
  const fd=new FormData(form);
  const cleanedIP = clientCleanIP(fd.get('ip'));
  const payload={
    ip:cleanedIP,
    port:Number(fd.get('port')||''),
    username:fd.get('username')?.toString().trim(),
    authType:fd.get('authType')?.toString(),
    password:fd.get('password')?.toString(),
    privateKey:fd.get('privateKey')?.toString(),
    country:fd.get('country')?.toString().trim(),
    region:fd.get('region')?.toString().trim(),
    traffic:fd.get('traffic')?.toString().trim(),
    expiryDate:fd.get('expiryDate')?.toString().trim(),
    specs:fd.get('specs')?.toString().trim(),
    note:fd.get('note')?.toString().trim()
  };
  
  btn.disabled=true;
  btn.classList.add('loading');
  const originalHTML=btn.innerHTML;
  btn.innerHTML='<span>提交中...</span>';
  
  try{
    const r=await fetch('/api/donate',{
      method:'POST',
      credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)
    });
    const j=await r.json();
    
    btn.classList.remove('loading');
    
    if(!r.ok||!j.success){
      btn.classList.add('error');
      msg.textContent=j.message||'提交失败';
      msg.className='text-sm mt-1 min-h-[1.5rem] text-red-400';
      toast('投喂失败：'+(j.message||'请检查填写项'), 'error');
      setTimeout(()=>btn.classList.remove('error'), 400);
    } else{
      btn.classList.add('success');
      btn.innerHTML='<span>✓ 提交成功</span>';
      msg.textContent=j.message||'投喂成功';
      msg.className='text-sm mt-1 min-h-[1.5rem] text-green-500';
      toast(j.message||'投喂成功','success');
      
      setTimeout(()=>{
        btn.classList.remove('success');
        btn.innerHTML=originalHTML;
        form.reset();
        loadDonations();
      }, 2000);
    }
  }catch(e){
    console.error('Donate error:', e);
    btn.classList.remove('loading');
    btn.classList.add('error');
    msg.textContent='提交异常';
    msg.className='text-sm mt-1 min-h-[1.5rem] text-red-400';
    toast('提交异常','error');
    setTimeout(()=>btn.classList.remove('error'), 400);
  } finally{
    setTimeout(()=>{
      btn.disabled=false;
      if(!btn.classList.contains('success')){
        btn.innerHTML=originalHTML;
      }
    }, 500);
  }
}

async function loadDonations(){
  const box=document.getElementById('donations-list');
  
  // 显示骨架屏
  box.innerHTML=\`<div class="space-y-4">
    <div class="skeleton-card"><div class="skeleton-header">
    <div class="skeleton skeleton-avatar"></div>
    <div class="flex-1"><div class="skeleton skeleton-title"></div></div>
    </div>
    <div class="skeleton skeleton-text"></div>
    <div class="skeleton skeleton-text medium"></div>
    <div class="skeleton skeleton-text short"></div>
    </div>
    <div class="skeleton-card"><div class="skeleton-header">
    <div class="skeleton skeleton-avatar"></div>
    <div class="flex-1"><div class="skeleton skeleton-title"></div></div>
    </div>
    <div class="skeleton skeleton-text"></div>
    <div class="skeleton skeleton-text medium"></div>
    </div>
    </div>\`;
  
  try{
    const r=await fetch('/api/user/donations',{credentials:'same-origin',cache:'no-store'});
    const j=await r.json();
    if(!r.ok||!j.success){
      box.innerHTML='<div class="text-red-400 text-sm">加载失败</div>';
      return;
    }
    const data=j.data||[];
    if(!data.length){
      box.innerHTML=\`<div class="muted text-sm py-8 text-center flex flex-col items-center gap-3"><div class="w-12 h-12 opacity-20">\${ICONS.server}</div><p>还没有投喂记录，先在左侧提交一台吧～</p></div>\`;
      return;
    }
    box.innerHTML='';
    data.forEach(v=>{
      const div=document.createElement('div');
      div.className='card border p-4 transition-all hover:border-indigo-500/30 group bg-[#1A1B26]/50 border-white/5 rounded-xl';
      const dt=v.donatedAt?new Date(v.donatedAt):null, t=dt?dt.toLocaleString():'';
      const uname=v.donatedByUsername||'';
      const p='https://linux.do/u/'+encodeURIComponent(uname);
      
      div.innerHTML=\`
        <div class="flex items-center justify-between gap-2 mb-3 pb-3 border-b border-white/5">
          <div class="text-sm font-medium flex items-center gap-2">
            <div class="w-4 h-4 text-indigo-400">\${ICONS.server}</div>
            <span class="break-words font-mono">\${v.ip}:\${v.port}</span>
          </div>
          <div class="\${scls(v.status)} text-xs px-2.5 py-1 rounded-full font-semibold">\${stxt(v.status)}</div>
        </div>
        <div class="text-sm mb-3 flex items-center gap-2">
          <div class="w-4 h-4 opacity-50">\${ICONS.user}</div>
          <span>投喂者：<a href="\${p}" target="_blank" class="underline hover:text-cyan-300 transition-colors">@\${uname}</a></span>
        </div>
        <div class="grid grid-cols-2 gap-3 text-sm mt-3">
          <div class="flex items-center gap-2">
            <div class="w-4 h-4 opacity-50">\${ICONS.globe}</div>
            <span class="truncate">\${(v.country||'未填写')}\${(v.region?' · '+v.region:'')}\${(v.ipLocation?' · '+v.ipLocation:'')}</span>
          </div>
          <div class="flex items-center gap-2">
            <div class="w-4 h-4 opacity-50">\${ICONS.chart}</div>
            <span class="truncate">\${(v.traffic||'未填写')}</span>
          </div>
          <div class="flex items-center gap-2">
            <div class="w-4 h-4 opacity-50">\${ICONS.calendar}</div>
            <span class="truncate">\${(v.expiryDate||'未填写')}</span>
          </div>
        </div>
        <div class="text-sm muted mt-3 panel border border-white/5 rounded-lg px-3 py-2 break-words flex items-start gap-2 bg-white/5">
          <div class="w-4 h-4 opacity-50 mt-0.5">\${ICONS.cpu}</div>
          <span>\${(v.specs||'未填写')}</span>
        </div>
        \${v.note ? \`<div class="text-sm mt-3 bg-amber-500/5 border border-amber-500/20 rounded-lg px-3 py-2 break-words flex items-start gap-2 text-amber-200/80">
          <div class="w-4 h-4 opacity-50 mt-0.5">\${ICONS.message}</div>
          <span>\${v.note}</span>
        </div>\` : ''}
        \${t ? \`<div class="text-xs muted mt-3 flex items-center gap-2">
          <div class="w-4 h-4 opacity-50">\${ICONS.clock}</div>
          <span>\${t}</span>
        </div>\` : ''}
      \`;
      box.appendChild(div);
    });
  }catch(err){
    console.error('Load donations error:', err);
    box.innerHTML='<div class="text-red-400 text-sm">加载异常</div>';
  }
}

ensureLogin();
bindAuthType();
document.getElementById('donate-form').addEventListener('submit', submitDonate);
loadDonations();

// 实时IP格式验证（与后端完全一致）
const ipInput = document.querySelector('input[name="ip"]');

if(ipInput){
  // IPv4 验证（与后端一致）
  const isIPv4 = (ip) => {
    const trimmed = ip.trim();
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) return false;
    return trimmed.split('.').every(p => {
      const num = parseInt(p, 10);
      return num >= 0 && num <= 255;
    });
  };

  // IPv6 验证（与后端一致）
  const isIPv6 = (ip) => {
    const trimmed = ip.trim().replace(/^\[|\]$/g, '');
    const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/;
    return ipv6Regex.test(trimmed);
  };

  // 获得焦点时清除错误状态
  ipInput.addEventListener('focus', function(){
    this.classList.remove('error');
    this.classList.remove('success');
  });

  // 输入时实时验证（防抖）
  let ipValidateTimer = null;
  ipInput.addEventListener('input', function(){
    const ip = this.value.trim();
    
    // 清除之前的定时器
    if(ipValidateTimer) clearTimeout(ipValidateTimer);
    
    // 如果为空，清除所有状态
    if(!ip) {
      this.classList.remove('error');
      this.classList.remove('success');
      return;
    }
    
    // 防抖：500ms 后验证
    ipValidateTimer = setTimeout(() => {
      if(isIPv4(ip) || isIPv6(ip)){
        this.classList.remove('error');
        this.classList.add('success');
      } else {
        this.classList.remove('success');
        this.classList.add('error');
      }
    }, 500);
  });

  // 失去焦点时最终验证
  ipInput.addEventListener('blur', function(){
    const ip = this.value.trim();
    if(!ip) {
      this.classList.remove('error');
      this.classList.remove('success');
      return;
    }

    if(isIPv4(ip) || isIPv6(ip)){
      this.classList.remove('error');
      this.classList.add('success');
    } else {
      this.classList.add('error');
      toast('IP 格式不正确，请检查输入','error');
    }
  });
}

// 端口范围验证
const portInput = document.querySelector('input[name="port"]');

if(portInput){
  // 获得焦点时清除错误状态
  portInput.addEventListener('focus', function(){
    this.classList.remove('error');
    this.classList.remove('success');
  });

  // 失去焦点时验证
  portInput.addEventListener('blur', function(){
    const port = parseInt(this.value);
    if(!port) return;

    if(port < 1 || port > 65535){
      this.classList.add('error');
      toast('端口范围应在 1-65535 之间','error');
    } else {
      this.classList.remove('error');
      this.classList.add('success');
      setTimeout(()=>this.classList.remove('success'), 2000);
    }
  });
}
</script>
</body></html>`;
  return c.html(html);
});

/* ==================== /admin 管理后台 ==================== */
app.get('/admin', (c: Context) => {
  const head = commonHead('VPS 管理后台');
  const html = `<!doctype html><html lang="zh-CN"><head>${head}</head>
<body class="min-h-screen">
<div class="max-w-7xl mx-auto px-4 py-8" id="app-root">
  <div class="flex items-center justify-center min-h-[60vh]">
    <div class="text-center space-y-3">
      <div class="loading-spinner mx-auto"></div>
      <div class="text-sm text-slate-600">正在检测管理员登录状态...</div>
    </div>
  </div>
</div>
<div id="toast-root"></div>
<script>
updateThemeBtn();

let allVpsList=[]; let statusFilter='all'; let searchFilter=''; let userFilter='';

function stxt(s){ return s==='active'?'运行中':(s==='failed'?'失败':'未启用'); }
function scls(s){ return s==='active'?'badge-ok':(s==='failed'?'badge-fail':'badge-idle'); }
function isTodayLocal(ts){
  if(!ts) return false;
  const d=new Date(ts);
  const now=new Date();
  return d.getFullYear()===now.getFullYear() &&
         d.getMonth()===now.getMonth() &&
         d.getDate()===now.getDate();
}

async function checkAdmin(){
  const root=document.getElementById('app-root');

  const timeoutPromise = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('请求超时')), 5000)
  );

  try{
    const fetchPromise = fetch('/api/admin/check-session',{
      credentials:'same-origin',
      cache:'no-store'
    });

    const r = await Promise.race([fetchPromise, timeoutPromise]);

    if(!r.ok) {
      console.error('Check session failed with status:', r.status);
      renderLogin(root);
      return;
    }

    const j = await r.json();
    if(!j.success || !j.isAdmin){
      renderLogin(root);
    } else {
      await renderAdmin(root, j.username);
    }
  }catch(err){
    console.error('Admin check error:', err);
    renderLogin(root);
  }
}

function renderLogin(root){
  root.innerHTML='';
  const wrap=document.createElement('div');
  wrap.className='panel max-w-md mx-auto border p-8 animate-in';
  wrap.innerHTML='<div class="text-center mb-6">'+
    '<div class="inline-flex items-center justify-center w-16 h-16 rounded-full mb-4" style="background:#007AFF">'+
      '<span class="text-3xl">🔐</span>'+
    '</div>'+
    '<h1 class="text-2xl font-bold mb-2">管理员登录</h1>'+
    '<p class="text-sm muted">请输入管理员密码以继续</p>'+
  '</div>'+
    '<form id="admin-login-form" class="space-y-4">'+
      '<div>'+
        '<label class="block mb-2 text-sm font-medium flex items-center gap-2">'+
          '<span>🔑</span> 密码'+
        '</label>'+
        '<input type="password" name="password" placeholder="请输入管理员密码" '+
               'class="w-full rounded-lg border px-4 py-3 text-sm focus:ring-2 focus:ring-cyan-500"/>'+
      '</div>'+
      '<div id="admin-login-msg" class="text-sm min-h-[1.5rem] font-medium"></div>'+
      '<button type="submit" class="w-full btn-primary">'+
        '<span class="text-lg">🚀</span> 登录'+
      '</button>'+
    '</form>';
  root.appendChild(wrap);
  document.getElementById('admin-login-form').addEventListener('submit', async(e)=>{
    e.preventDefault();
    const fd=new FormData(e.target);
    const pwd=fd.get('password')?.toString()||'';
    try{
      const r=await fetch('/api/admin/login',{

        method:'POST',
        credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({password:pwd})
      });
      const j=await r.json();
      if(!r.ok||!j.success){
        toast(j.message||'登录失败','error');
      } else {
        toast('登录成功','success');
        location.reload();
      }
    }catch(err){
      console.error('Login error:', err);
      toast('登录异常','error');
    }
  });
}

async function renderAdmin(root, name){
  root.innerHTML='';
  const header=document.createElement('header');
  header.className='mb-8 animate-in';
  header.innerHTML='<div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">'+
    '<div class="space-y-3">'+
      '<div class="flex items-center gap-3">'+
        '<div class="inline-flex items-center justify-center w-12 h-12 rounded-xl" style="background:#007AFF">'+
          '<span class="text-2xl">⚙️</span>'+
        '</div>'+
        '<h1 class="grad-title-animated text-3xl md:text-4xl font-bold">VPS 管理后台</h1>'+
      '</div>'+
      '<p class="text-sm muted flex items-center gap-2 ml-15">'+
        '<span class="text-base">🔒</span>'+
        '<span>仅管理员可见，可查看全部投喂 VPS 与认证信息</span>'+
      '</p>'+
    '</div>'+
    '<div class="flex flex-wrap items-center gap-3">'+
      '<div class="panel px-5 py-2.5 border">'+
        '<span class="text-sm">👤</span>'+
        '<span class="text-sm font-medium">'+name+'</span>'+
      '</div>'+
      '<button id="theme-toggle" class="btn-secondary">浅色模式</button>'+
      '<button id="btn-admin-logout" class="btn-danger">'+
        '退出登录'+
      '</button>'+
    '</div>'+
  '</div>';
  root.appendChild(header);

  const themeBtn = document.getElementById('theme-toggle');
  if(themeBtn){
    updateThemeBtn();
    themeBtn.addEventListener('click', toggleTheme);
  }
  document.getElementById('btn-admin-logout').addEventListener('click', async()=>{
    try{await fetch('/api/admin/logout',{credentials:'same-origin'})}catch{}
    location.reload();
  });

  const stats=document.createElement('section');
  stats.id='admin-stats';
  root.appendChild(stats);

  const cfg=document.createElement('section');
  cfg.id='admin-config';
  cfg.className='mt-6 space-y-4';
  cfg.innerHTML=
  '<div class="panel border p-6">'+
    '<div class="flex items-center justify-between mb-4">'+
      '<div class="flex items-center gap-3">'+
        '<span class="text-xl">🔗</span>'+
        '<h2 class="text-lg font-bold">OAuth 配置</h2>'+
      '</div>'+
      '<button id="btn-toggle-oauth" class="btn-secondary text-xs">展开</button>'+
    '</div>'+
    '<div id="oauth-body" class="hidden">'+
      '<form id="oauth-form" class="grid md:grid-cols-3 gap-4">'+
        '<div>'+
          '<label class="block mb-2 text-sm font-medium flex items-center gap-1.5">'+
            '<span>🆔</span> Client ID'+
          '</label>'+
          '<input name="clientId" placeholder="输入 Client ID" class="w-full rounded-lg border px-3 py-2 text-sm"/>'+
        '</div>'+
        '<div>'+
          '<label class="block mb-2 text-sm font-medium flex items-center gap-1.5">'+
            '<span>🔐</span> Client Secret'+
          '</label>'+
          '<input name="clientSecret" placeholder="输入 Client Secret" class="w-full rounded-lg border px-3 py-2 text-sm"/>'+
        '</div>'+
        '<div>'+
          '<label class="block mb-2 text-sm font-medium flex items-center gap-1.5">'+
            '<span>🔗</span> Redirect URI'+
          '</label>'+
          '<input name="redirectUri" placeholder="输入 Redirect URI" class="w-full rounded-lg border px-3 py-2 text-sm"/>'+
        '</div>'+
      '</form>'+
      '<div class="mt-4 flex gap-2">'+
        '<button id="btn-save-oauth" class="btn-primary">'+
          '<span>💾</span> 保存 OAuth 配置'+
        '</button>'+
      '</div>'+
    '</div>'+
  '</div>'+
  '<div class="panel border p-6">'+
    '<div class="flex items-center justify-between mb-4">'+
      '<div class="flex items-center gap-3">'+
        '<span class="text-xl">🔑</span>'+
        '<h2 class="text-lg font-bold">管理员密码</h2>'+
      '</div>'+
      '<button id="btn-toggle-password" class="btn-secondary text-xs">展开</button>'+
    '</div>'+
    '<div id="password-body" class="hidden">'+
      '<div class="alert-warning text-sm mb-4 rounded-xl px-3 py-2">'+
        '⚠️ 仅用于 <code>/admin</code> 后台登录，至少 6 位，建议与 Linux.do 账号密码不同'+
      '</div>'+
      '<div class="grid md:grid-cols-2 gap-4 mb-4">'+
        '<div>'+
          '<label class="block mb-2 text-sm font-medium">新密码</label>'+
          '<input id="admin-pass-input" type="password" placeholder="输入新的管理员密码" '+
                 'class="w-full rounded-lg border px-3 py-2.5 text-sm"/>'+
        '</div>'+
        '<div>'+
          '<label class="block mb-2 text-sm font-medium">确认密码</label>'+
          '<input id="admin-pass-input2" type="password" placeholder="再次输入以确认" '+
                 'class="w-full rounded-lg border px-3 py-2.5 text-sm"/>'+
        '</div>'+
      '</div>'+
      '<button id="btn-save-admin-pass" class="btn-primary">'+
        '<span>🔒</span> 保存密码'+
      '</button>'+
      '<p class="text-xs muted mt-3">💡 修改成功后立即生效，下次登录需要使用新密码</p>'+
    '</div>'+
  '</div>';
  root.appendChild(cfg);

  document.getElementById('btn-toggle-oauth').addEventListener('click',()=>{
    const b=document.getElementById('oauth-body');
    const btn=document.getElementById('btn-toggle-oauth');
    if(b.classList.contains('hidden')){
      b.classList.remove('hidden');
      btn.textContent='收起';
    } else {
      b.classList.add('hidden');
      btn.textContent='展开';
    }
  });
  
  document.getElementById('btn-toggle-password').addEventListener('click',()=>{
    const b=document.getElementById('password-body');
    const btn=document.getElementById('btn-toggle-password');
    if(b.classList.contains('hidden')){
      b.classList.remove('hidden');
      btn.textContent='收起';
    } else {
      b.classList.add('hidden');
      btn.textContent='展开';
    }
  });
  
  document.getElementById('btn-save-oauth').addEventListener('click', saveOAuth);
  document.getElementById('btn-save-admin-pass').addEventListener('click', saveAdminPassword);

  const listWrap=document.createElement('section');
  listWrap.className='mt-8';
  listWrap.innerHTML='<div class="panel border p-6 mb-6">'+
    '<div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-6">'+
      '<div class="flex items-center gap-3">'+
        '<span class="text-2xl">📋</span>'+
        '<h2 class="text-2xl font-bold">VPS 列表</h2>'+
      '</div>'+
      '<button id="btn-verify-all" class="btn-primary">'+
        '<span>🔄</span> 一键验证全部'+
      '</button>'+
    '</div>'+
    '<div class="flex flex-col md:flex-row gap-3">'+
      '<div class="flex flex-wrap items-center gap-2">'+
        '<span class="text-sm font-medium">筛选：</span>'+
        '<button data-status="all" class="btn-secondary text-xs">全部</button>'+
        '<button data-status="active" class="btn-secondary text-xs">✅ 运行中</button>'+
        '<button data-status="failed" class="btn-secondary text-xs">❌ 失败</button>'+
      '</div>'+
      '<div class="flex-1 flex gap-2">'+
        '<input id="filter-input" placeholder="🔍 搜索 IP / 用户名 / 备注..." class="flex-1"/>'+
        '<button id="filter-btn" class="btn-secondary">搜索</button>'+
        '<button id="filter-clear-btn" class="btn-secondary">清除</button>'+
      '</div>'+
    '</div>'+
  '</div>'+
  '<div id="vps-list" class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4"></div>';
  root.appendChild(listWrap);

  listWrap.querySelectorAll('button[data-status]').forEach(btn=> btn.addEventListener('click',()=>{
    statusFilter=btn.getAttribute('data-status')||'all';
    userFilter='';
    renderVpsList();
  }));
  document.getElementById('filter-btn').addEventListener('click',()=>{
    searchFilter=document.getElementById('filter-input').value.trim();
    userFilter='';
    renderVpsList();
  });
  document.getElementById('filter-clear-btn').addEventListener('click',()=>{
    searchFilter='';
    document.getElementById('filter-input').value='';
    userFilter='';
    renderVpsList();
  });
  document.getElementById('btn-verify-all').addEventListener('click', verifyAll);

  await loadStats();
  await loadConfig();
  await loadVps();
}

async function loadStats(){
  const wrap=document.getElementById('admin-stats');
  wrap.innerHTML='<div class="flex items-center justify-center py-8">'+
    '<div class="flex flex-col items-center gap-3">'+
      '<div class="loading-spinner"></div>'+
      '<div class="text-sm muted">正在加载统计信息...</div>'+
    '</div>'+
  '</div>';
  try{
    const r=await fetch('/api/admin/stats',{credentials:'same-origin',cache:'no-store'});

    if(!r.ok) {
      wrap.innerHTML='<div class="text-red-400 text-xs">统计信息加载失败: HTTP '+r.status+'</div>';
      return;
    }

    const j=await r.json();
    if(!j.success){
      wrap.innerHTML='<div class="text-red-400 text-xs">统计信息加载失败</div>';
      return;
    }

    const d=j.data||{};
    function card(label,value,key,icon){
      const percent = d.totalVPS > 0 ? Math.round((value / d.totalVPS) * 100) : 0;
      return '<button data-gok="'+key+'" class="stat-card stat-'+key+' border px-4 py-3 text-left">'+
        '<div class="flex items-center justify-between mb-2">'+
          '<div class="stat-label text-xs muted">'+icon+' '+label+'</div>'+
          '<div class="text-xs muted">'+percent+'%</div>'+
        '</div>'+
        '<div class="stat-value mb-2">'+value+'</div>'+
        '<div class="w-full h-1.5 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">'+
          '<div class="h-full rounded-full transition-all duration-500" style="width:'+percent+'%;background:currentColor"></div>'+
        '</div>'+
        '</button>';
    }
    wrap.innerHTML='<div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">'+
      card('总投喂数',d.totalVPS||0,'all','📊')+
      card('运行中',d.activeVPS||0,'active','✅')+
      card('失败',d.failedVPS||0,'failed','❌')+
      card('今日新增',d.todayNewVPS||0,'today','🆕')+'</div>';
    
    // 添加数字计数动画
    setTimeout(()=>{
      wrap.querySelectorAll('.stat-value').forEach(el => {
        const target = parseInt(el.textContent);
        if(!isNaN(target)){
          el.classList.add('count-up');
          animateNumber(el, target);
        }
      });
    }, 100);
    
    wrap.querySelectorAll('button[data-gok]').forEach(b=> b.addEventListener('click',()=>{
      statusFilter=b.getAttribute('data-gok');
      userFilter='';
      renderVpsList();
    }));
  }catch(err){
    console.error('Stats load error:', err);
    wrap.innerHTML='<div class="text-red-400 text-xs">统计信息加载异常</div>';
  }
}

async function loadConfig(){
  try {
    const res=await fetch('/api/admin/config/oauth',{credentials:'same-origin',cache:'no-store'});
    const j=await res.json();
    const cfg=j.data||{};
    const f=document.getElementById('oauth-form');
    f.querySelector('input[name="clientId"]').value=cfg.clientId||'';
    f.querySelector('input[name="clientSecret"]').value=cfg.clientSecret||'';
    f.querySelector('input[name="redirectUri"]').value=cfg.redirectUri||'';
  } catch(err) {
    console.error('Config load error:', err);
  }
}

async function saveOAuth(){
  const f=document.getElementById('oauth-form');
  const payload={
    clientId:f.querySelector('input[name="clientId"]').value.trim(),
    clientSecret:f.querySelector('input[name="clientSecret"]').value.trim(),
    redirectUri:f.querySelector('input[name="redirectUri"]').value.trim()
  };
  try{
    const r=await fetch('/api/admin/config/oauth',{
      method:'PUT',
      credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)
    });
    const j=await r.json();
    if(!r.ok||!j.success){
      toast(j.message||'保存失败','error');
    } else {
      toast('OAuth 已保存','success');
    }
  }catch(err){
    console.error('Save OAuth error:', err);
    toast('保存异常','error');
  }
}

async function saveAdminPassword(){
  const input=document.getElementById('admin-pass-input');
  const input2=document.getElementById('admin-pass-input2');
  const pwd=input.value.trim();
  const pwd2=input2.value.trim();
  if(!pwd || !pwd2){
    toast('请填写两次新密码','warn');
    return;
  }
  if(pwd!==pwd2){
    toast('两次输入的密码不一致','error');
    return;
  }
  try{
    const r=await fetch('/api/admin/config/password',{
      method:'PUT',
      credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:pwd})
    });
    const j=await r.json();
    if(!r.ok||!j.success){
      toast(j.message||'保存失败','error');
    } else {
      toast('管理员密码已更新','success');
      input.value='';
      input2.value='';
    }
  }catch(err){
    console.error('Save admin password error:', err);
    toast('保存异常','error');
  }
}



async function loadVps(){
  const list=document.getElementById('vps-list');
  list.innerHTML='<div class="col-span-full flex items-center justify-center py-12">'+
    '<div class="flex flex-col items-center gap-3">'+
      '<div class="loading-spinner"></div>'+
      '<div class="text-sm muted">正在加载 VPS 列表...</div>'+
    '</div>'+
  '</div>';
  try{
    const r=await fetch('/api/admin/vps',{credentials:'same-origin',cache:'no-store'});

    if(!r.ok) {
      list.innerHTML='<div class="text-red-400 text-xs col-span-full">加载失败: HTTP '+r.status+'</div>';
      return;
    }

    const j=await r.json();
    if(!j.success){
      list.innerHTML='<div class="text-red-400 text-xs col-span-full">加载失败</div>';
      return;
    }
    allVpsList=j.data||[];
    renderVpsList();
  }catch(err){
    console.error('VPS load error:', err);
    list.innerHTML='<div class="text-red-400 text-xs col-span-full">加载异常: '+err.message+'</div>';
  }
}

async function verifyAll(){
  if(!allVpsList.length){
    toast('当前没有 VPS 可以验证','warn');
    return;
  }
  if(!confirm('确定要对全部 VPS 执行连通性检测吗？这可能会持续数十秒。')) return;
  try{
    const r=await fetch('/api/admin/verify-all',{method:'POST',credentials:'same-origin'});
    const j=await r.json();
    if(!r.ok||!j.success){
      toast(j.message||'批量验证失败','error');
    }else{
      const d=j.data||{};
      const msg=j.message||('批量验证完成：成功 '+(d.success||0)+' 台，失败 '+(d.failed||0)+' 台');
      toast(msg,'success',4000);
    }
  }catch(err){
    console.error('Verify all error:',err);
    toast('批量验证异常','error');
  }
  await loadVps();
  await loadStats();
}

function renderVpsList(){
  const list=document.getElementById('vps-list');
  if(!allVpsList.length){
    list.innerHTML='<div class="muted text-xs col-span-full">暂无 VPS 记录</div>';
    return;
  }

  const kw=(searchFilter||'').toLowerCase();

  const arr=allVpsList.filter(v=>{
    let ok=true;
    if(statusFilter==='active') ok=v.status==='active';
    else if(statusFilter==='failed') ok=v.status==='failed';
    else if(statusFilter==='today') ok=v.donatedAt && isTodayLocal(v.donatedAt);
    if(userFilter) ok=ok && v.donatedByUsername===userFilter;
    if(kw){
      const hay=[v.ip,String(v.port),v.donatedByUsername,v.country,v.region,v.traffic,v.specs,v.note,v.adminNote].join(' ').toLowerCase();
      ok=ok && hay.includes(kw);
    }
    return ok;
  });

  if(!arr.length){
    list.innerHTML='<div class="muted text-xs col-span-full">当前筛选下没有 VPS</div>';
    return;
  }

  list.innerHTML='';
  arr.forEach(v=>{
    const card=document.createElement('div');
    card.className='card rounded-2xl border p-4 flex flex-col gap-3 text-sm shadow-lg hover:shadow-xl transition-all';
    const dt=v.donatedAt?new Date(v.donatedAt):null;
    const t=dt?dt.toLocaleString():'';
    const uname=v.donatedByUsername||'';
    const p='https://linux.do/u/'+encodeURIComponent(uname);

    card.innerHTML='<div class="flex items-center justify-between gap-2 pb-3 border-b border-white/10">'+
        '<div class="flex items-center gap-2 text-sm font-medium">'+
          '<div class="w-5 h-5 text-indigo-500">'+ICONS.server+'</div>'+
          '<span class="break-words font-mono">'+v.ip+':'+v.port+'</span>'+
        '</div>'+
        '<span class="'+scls(v.status)+' text-xs px-2 py-1 rounded-full">'+stxt(v.status)+'</span>'+
      '</div>'+
      '<div class="space-y-2 text-xs">'+
        '<div class="flex items-center gap-2">'+
          '<div class="w-4 h-4 opacity-60">'+ICONS.user+'</div>'+
          '<span>投喂者：<a href="'+p+'" target="_blank" class="text-sky-500 hover:text-cyan-400 underline transition-colors">@'+uname+'</a></span>'+
        '</div>'+
        '<div class="flex items-center gap-2">'+
          '<div class="w-4 h-4 opacity-60">'+ICONS.globe+'</div>'+
          '<span>'+(v.country||'未填写')+(v.region?' · '+v.region:'')+(v.ipLocation?' · '+v.ipLocation:'')+'</span>'+
        '</div>'+
        '<div class="grid grid-cols-2 gap-2">'+
          '<div class="flex items-center gap-1.5 panel border border-white/10 rounded-lg px-2 py-1.5"><div class="w-3.5 h-3.5 opacity-60">'+ICONS.chart+'</div><span class="truncate">'+(v.traffic||'未填写')+'</span></div>'+
          '<div class="flex items-center gap-1.5 panel border border-white/10 rounded-lg px-2 py-1.5"><div class="w-3.5 h-3.5 opacity-60">'+ICONS.calendar+'</div><span class="truncate">'+(v.expiryDate||'未填写')+'</span></div>'+
        '</div>'+
        '<div class="panel border border-white/10 rounded-lg px-2 py-1.5 flex items-start gap-1.5">'+
          '<div class="w-3.5 h-3.5 opacity-60 mt-0.5">'+ICONS.cpu+'</div>'+
          '<span class="break-words">'+(v.specs||'未填写')+'</span>'+
        '</div>'+
        (v.note?'<div class="bg-amber-500/5 border border-amber-500/20 rounded-lg px-2 py-1.5 text-amber-600 dark:text-amber-300 flex items-start gap-1.5">'+
          '<div class="w-3.5 h-3.5 opacity-60 mt-0.5">'+ICONS.message+'</div>'+
          '<span class="break-words">'+v.note+'</span>'+
        '</div>':'')+
        (v.adminNote?'<div class="bg-cyan-500/5 border border-cyan-500/20 rounded-lg px-2 py-1.5 text-cyan-600 dark:text-cyan-300 flex items-start gap-1.5">'+
          '<div class="w-3.5 h-3.5 opacity-60 mt-0.5">'+ICONS.note+'</div>'+
          '<span class="break-words">'+v.adminNote+'</span>'+
        '</div>':'')+
        (t?'<div class="flex items-center gap-1.5 text-xs muted"><div class="w-3.5 h-3.5 opacity-60">'+ICONS.clock+'</div><span>'+t+'</span></div>':'')+
      '</div>'+
      '<div class="flex flex-wrap gap-2 pt-3 border-t border-white/10">'+
        '<button class="btn-secondary text-xs flex items-center gap-1" data-act="login" data-id="'+v.id+'"><div class="w-3 h-3">'+ICONS.search+'</div> 查看</button>'+
        '<button class="btn-secondary text-xs flex items-center gap-1" data-act="verify" data-id="'+v.id+'"><div class="w-3 h-3">'+ICONS.check+'</div> 验证</button>'+
        '<button class="btn-secondary text-xs flex items-center gap-1" data-act="editConfig" data-id="'+v.id+'"><div class="w-3 h-3">'+ICONS.settings+'</div> 配置</button>'+
        '<button class="btn-secondary text-xs flex items-center gap-1" data-act="edit" data-id="'+v.id+'"><div class="w-3 h-3">'+ICONS.edit+'</div> 信息</button>'+
        '<button class="btn-danger text-xs flex items-center gap-1" data-act="del" data-id="'+v.id+'"><div class="w-3 h-3">'+ICONS.trash+'</div> 删除</button>'+
      '</div>';

    card.querySelectorAll('button[data-act]').forEach(btn=>{
      const id=btn.getAttribute('data-id');
      const act=btn.getAttribute('data-act');
      btn.addEventListener('click', async()=>{
        if(!id) return;

        if(act==='login'){
          modalLoginInfo(v);
          return;
        }

        if(act==='editConfig'){
          openEditModal(id);
          return;
        }

        if(act==='verify'){
          try{
            const r=await fetch('/api/admin/vps/'+id+'/verify',{method:'POST',credentials:'same-origin'});
            const j=await r.json();
            toast(j.message || (j.success ? '验证成功' : '验证失败'), j.success ? 'success' : 'error');

            // 本地就地更新，不再整页重新加载，避免列表抖动
            const target = allVpsList.find(x => x.id === id);
            if (target) {
              const data = j.data || {};
              const now = Date.now();
              target.lastVerifyAt = data.lastVerifyAt || now;
              if (j.success) {
                target.status = data.status || 'active';
                target.verifyStatus = data.verifyStatus || 'verified';
                target.verifyErrorMsg = data.verifyErrorMsg || '';
              } else {
                target.status = data.status || 'failed';
                target.verifyStatus = data.verifyStatus || 'failed';
                target.verifyErrorMsg =
                  data.verifyErrorMsg || '无法连接 VPS，请检查服务器是否在线、防火墙/安全组端口放行';
              }
              renderVpsList();
            }
          }catch{
            toast('验证异常','error');
          }
          // 只刷新顶部统计，不再重新拉取全部 VPS 列表
          await loadStats();
          return;
        }

        if(act==='failed'){
          try{
            const r=await fetch('/api/admin/vps/'+id+'/status',{
              method:'PUT',
              credentials:'same-origin',
              headers:{'Content-Type':'application/json'},
              body:JSON.stringify({status:'failed'})
            });
            const j=await r.json();
            toast(j.message||'已更新','success');
          }catch{
            toast('更新失败','error');
          }
        }
        else if(act==='del'){
          if(!confirm('确定要删除这台 VPS 吗？此操作不可恢复。')) return;
          
          btn.classList.add('loading');
          btn.disabled = true;
          
          try{
            const r=await fetch('/api/admin/vps/'+id,{method:'DELETE',credentials:'same-origin'});
            const j=await r.json();
            if(r.ok){
              card.style.animation = 'slideOut 0.3s ease-out forwards';
              setTimeout(()=>{
                toast(j.message||'已删除', 'success');
              }, 300);
            } else {
              toast(j.message||'删除失败', 'error');
            }
          }catch{
            toast('删除失败','error');
          } finally {
            btn.classList.remove('loading');
            btn.disabled = false;
          }
        }
        else if(act==='edit'){
          modalEdit('编辑 VPS 信息（用户备注前台可见）',[
            {key:'country',label:'国家/区域',value:v.country||'',placeholder:'如：🇭🇰 中国香港'},
            {key:'region',label:'地区/城市',value:v.region||'',placeholder:'如：东京、洛杉矶、法兰克福（可选）'},
            {key:'traffic',label:'流量/带宽',value:v.traffic||'',placeholder:'如：400G/月 · 1Gbps'},
            {key:'expiryDate',label:'到期时间',value:v.expiryDate||'',placeholder:'YYYY-MM-DD'},
            {key:'specs',label:'配置描述',value:v.specs||'',placeholder:'如：1C1G · 10Gbps · 1T/月'},
            {key:'note',label:'公用备注（前台可见）',value:v.note||'',type:'textarea',placeholder:'如：电信方向无法大陆优选链路…'},
            {key:'adminNote',label:'管理员备注（仅后台）',value:v.adminNote||'',type:'textarea',placeholder:'仅管理员可见的附注'}
          ], async(data,close)=>{
            try{
              const r=await fetch('/api/admin/vps/'+id+'/notes',{
                method:'PUT',
                credentials:'same-origin',
                headers:{'Content-Type':'application/json'},
                body:JSON.stringify(data)
              });
              const j=await r.json();
              if(!r.ok||!j.success){
                toast(j.message||'保存失败','error');
              }else{
                toast('已保存','success');
                close();
                await loadVps();
                await loadStats();
              }
            }catch{
              toast('保存异常','error');
            }
          });
          return;
        }

        await loadVps();
        await loadStats();
      });
    });

    const link=card.querySelector('a[href^="https://linux.do/u/"]');
    if(link){
      link.addEventListener('click',e=>{
        e.preventDefault();
        userFilter=v.donatedByUsername;
        renderVpsList();
      });
    }
    list.appendChild(card);
  });
}

/* ==================== 配置编辑模态框相关函数 ==================== */

function openEditModal(vpsId) {
  const vps = allVpsList.find(v => v.id === vpsId);
  if (!vps) {
    toast('VPS不存在', 'error');
    return;
  }
  
  // 创建模态框
  const modal = document.createElement('div');
  modal.id = 'edit-config-modal';
  modal.className = 'fixed inset-0 z-50 flex items-center justify-center p-4';
  modal.style.background = 'rgba(0, 0, 0, 0.5)';
  modal.style.backdropFilter = 'blur(4px)';
  
  modal.innerHTML = \`
    <div class="panel border max-w-2xl w-full max-h-[90vh] overflow-y-auto animate-in">
      <div class="sticky top-0 bg-inherit border-b px-6 py-4 flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div class="w-6 h-6 text-indigo-500">\${ICONS.settings}</div>
          <h3 class="text-xl font-bold">编辑 VPS 配置</h3>
        </div>
        <button onclick="closeEditModal()" class="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-black/5 dark:hover:bg-white/10 transition-colors"><div class="w-5 h-5 opacity-60">\${ICONS.x}</div></button>
      </div>
      
      <form id="edit-config-form" class="p-6 space-y-5">
        <div class="alert-warning text-sm leading-relaxed rounded-xl px-4 py-3">
          <div class="flex items-start gap-2"><div class="w-5 h-5 flex-shrink-0 mt-0.5">\${ICONS.alert}</div><span>修改配置后将自动进行连通性测试。即使测试失败，配置也会被保存。</span></div>
        </div>
        
        <div class="grid md:grid-cols-2 gap-5">
          <div>
            <label class="block mb-2.5 text-sm font-medium flex items-center gap-1.5">
              <div class="w-4 h-4 opacity-60">\${ICONS.globe}</div> 服务器 IP <span class="text-red-400">*</span>
            </label>
            <input name="ip" required value="\${vps.ip}" placeholder="示例：203.0.113.8"
                   class="w-full rounded-lg border px-3 py-2 text-sm" />
          </div>
          <div>
            <label class="block mb-2.5 text-sm font-medium flex items-center gap-1.5">
              <div class="w-4 h-4 opacity-60">\${ICONS.plug}</div> 端口 <span class="text-red-400">*</span>
            </label>
            <input name="port" required type="number" min="1" max="65535" value="\${vps.port}"
                   class="w-full rounded-lg border px-3 py-2 text-sm" />
          </div>
        </div>

        <div class="grid md:grid-cols-2 gap-5">
          <div>
            <label class="block mb-2.5 text-sm font-medium flex items-center gap-1.5">
              <div class="w-4 h-4 opacity-60">\${ICONS.user}</div> 系统用户名 <span class="text-red-400">*</span>
            </label>
            <input name="username" required value="\${vps.username}" placeholder="示例：root"
                   class="w-full rounded-lg border px-3 py-2 text-sm" />
          </div>
          <div>
            <label class="block mb-2.5 text-sm font-medium flex items-center gap-1.5">
              <div class="w-4 h-4 opacity-60">\${ICONS.lock}</div> 认证方式
            </label>
            <div class="relative">
              <select name="authType" class="w-full appearance-none rounded-xl border border-white/10 bg-black/5 dark:bg-white/5 px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/50 transition-all">
                <option value="password" \${vps.authType === 'password' ? 'selected' : ''}>密码认证</option>
                <option value="key" \${vps.authType === 'key' ? 'selected' : ''}>SSH 私钥认证</option>
              </select>
              <div class="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 opacity-40 pointer-events-none">\${ICONS.chevronDown}</div>
            </div>
          </div>
        </div>

        <div id="edit-password-field" class="\${vps.authType === 'password' ? '' : 'hidden'}">
          <label class="block mb-2.5 text-sm font-medium flex items-center gap-1.5">
            <div class="w-4 h-4 opacity-60">\${ICONS.key}</div> 密码
          </label>
          <input name="password" type="password" placeholder="留空则不修改密码"
                 class="w-full rounded-lg border px-3 py-2 text-sm" />
          <div class="help mt-1.5 flex items-center gap-1">
            <div class="w-3.5 h-3.5">\${ICONS.bulb}</div>当前已设置密码，留空则保持不变
          </div>
        </div>

        <div id="edit-key-field" class="\${vps.authType === 'key' ? '' : 'hidden'}">
          <label class="block mb-2.5 text-sm font-medium flex items-center gap-1.5">
            <div class="w-4 h-4 opacity-60">\${ICONS.key}</div> SSH 私钥
          </label>
          <textarea name="privateKey" rows="4" placeholder="留空则不修改私钥"
                    class="w-full rounded-lg border px-3 py-2 text-sm font-mono"></textarea>
          <div class="help mt-1.5 flex items-center gap-1">
            <div class="w-3.5 h-3.5">\${ICONS.bulb}</div>当前已设置私钥，留空则保持不变
          </div>
        </div>

        <div id="edit-message" class="text-sm min-h-[1.5rem] font-medium"></div>

        <div class="flex gap-3 pt-4 border-t">
          <button type="button" onclick="closeEditModal()" class="btn-secondary flex-1">
            取消
          </button>
          <button type="submit" id="edit-submit-btn" class="btn-primary flex-1">
            <div class="w-4 h-4">\${ICONS.save}</div> 保存配置
          </button>
        </div>
      </form>
    </div>
  \`;
  
  document.body.appendChild(modal);
  
  // 设置VPS ID
  const form = document.getElementById('edit-config-form');
  form.dataset.vpsId = vpsId;
  
  // 绑定认证方式切换
  const authTypeSelect = form.querySelector('select[name="authType"]');
  authTypeSelect.addEventListener('change', function() {
    toggleEditAuthFields(this.value);
  });
  
  // 绑定表单提交
  form.addEventListener('submit', submitConfigEdit);
  
  // 点击背景关闭
  modal.addEventListener('click', function(e) {
    if (e.target === modal) {
      closeEditModal();
    }
  });
}

function closeEditModal() {
  const modal = document.getElementById('edit-config-modal');
  if (modal) {
    modal.remove();
  }
}

function toggleEditAuthFields(authType) {
  const passwordField = document.getElementById('edit-password-field');
  const keyField = document.getElementById('edit-key-field');
  
  if (authType === 'password') {
    passwordField.classList.remove('hidden');
    keyField.classList.add('hidden');
  } else {
    passwordField.classList.add('hidden');
    keyField.classList.remove('hidden');
  }
}

async function submitConfigEdit(e) {
  e.preventDefault();
  const form = e.target;
  const vpsId = form.dataset.vpsId;
  const msg = document.getElementById('edit-message');
  const btn = document.getElementById('edit-submit-btn');
  
  msg.textContent = '';
  msg.className = 'text-sm min-h-[1.5rem] font-medium';
  
  // 收集表单数据
  const formData = new FormData(form);
  const vps = allVpsList.find(v => v.id === vpsId);
  
  const payload = {
    ip: formData.get('ip').toString().trim(),
    port: Number(formData.get('port')),
    username: formData.get('username').toString().trim(),
    authType: formData.get('authType').toString(),
    password: formData.get('password').toString() || vps.password,
    privateKey: formData.get('privateKey').toString() || vps.privateKey
  };
  
  // 显示加载状态
  btn.disabled = true;
  const originalHTML = btn.innerHTML;
  btn.innerHTML = '<span>保存中...</span>';
  
  try {
    const res = await fetch(\`/api/admin/vps/\${vpsId}/config\`, {
      method: 'PUT',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    
    const json = await res.json();
    
    if (res.ok && json.success) {
      msg.textContent = json.message || '配置更新成功';
      msg.className = 'text-sm min-h-[1.5rem] font-medium text-green-500';
      toast(json.message || '配置更新成功', 'success');
      
      // 更新本地数据
      if (vps && json.data) {
        vps.ip = payload.ip;
        vps.port = payload.port;
        vps.username = payload.username;
        vps.authType = payload.authType;
        if (payload.authType === 'password') {
          vps.password = payload.password;
          vps.privateKey = undefined;
        } else {
          vps.privateKey = payload.privateKey;
          vps.password = undefined;
        }
        vps.status = json.data.status;
        vps.verifyStatus = json.data.verifyStatus;
        vps.lastVerifyAt = json.data.lastVerifyAt;
        vps.verifyErrorMsg = json.data.verifyErrorMsg || '';
      }
      
      // 延迟关闭模态框并刷新列表
      setTimeout(() => {
        closeEditModal();
        renderVpsList();
        loadStats();
      }, 1500);
    } else {
      msg.textContent = json.message || '配置更新失败';
      msg.className = 'text-sm min-h-[1.5rem] font-medium text-red-400';
      toast(json.message || '配置更新失败', 'error');
    }
  } catch (err) {
    console.error('Config update error:', err);
    msg.textContent = '更新异常';
    msg.className = 'text-sm min-h-[1.5rem] font-medium text-red-400';
    toast('更新异常', 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalHTML;
  }
}

checkAdmin();
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
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%236366f1' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M19 14c1.49-1.46 3-3.21 3-5.5A5.5 5.5 0 0 0 16.5 3c-1.76 0-3 .5-4.5 2-1.5-1.5-2.74-2-4.5-2A5.5 5.5 0 0 0 2 8.5c0 2.3 1.5 4.05 3 5.5l7 7Z'/></svg>" />
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
<script>
tailwind.config = {
  darkMode: ['class', '[data-theme="dark"]'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
      },
      colors: {
        premium: {
          bg: {
            dark: '#050511', // Deep space blue/black
            light: '#F5F5F7', // Apple light gray
          },
          card: {
            dark: 'rgba(20, 20, 35, 0.6)',
            light: 'rgba(255, 255, 255, 0.7)',
          },
          primary: '#6366f1', // Indigo
          accent: '#8b5cf6', // Violet
          success: '#10b981',
          warning: '#f59e0b',
          error: '#ef4444',
        }
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'hero-glow': 'conic-gradient(from 180deg at 50% 50%, #2a8af6 0deg, #a853ba 180deg, #e92a67 360deg)',
      },
      backdropBlur: {
        xs: '2px',
      }
    }
  }
}
</script>
<style>
:root {
  --glass-border-light: rgba(255, 255, 255, 0.5);
  --glass-border-dark: rgba(255, 255, 255, 0.08);
  --glass-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.07);
}

html {
  scroll-behavior: smooth;
}

body {
  font-family: 'Inter', -apple-system, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  transition: background-color 0.3s ease, color 0.3s ease;
}

/* Light Mode Base */
body {
  background: #F5F5F7;
  color: #1d1d1f;
  background-image: 
    radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
    radial-gradient(at 100% 0%, rgba(139, 92, 246, 0.15) 0px, transparent 50%);
  background-attachment: fixed;
}

/* Dark Mode Base */
body[data-theme="dark"] {
  background: #050511; /* Deep dark background */
  color: #f5f5f7;
  background-image: 
    radial-gradient(circle at 15% 50%, rgba(76, 29, 149, 0.15), transparent 25%), 
    radial-gradient(circle at 85% 30%, rgba(59, 130, 246, 0.15), transparent 25%);
  background-attachment: fixed;
}

/* Glassmorphism Utilities */
.glass {
  background: rgba(255, 255, 255, 0.7);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid rgba(255, 255, 255, 0.5);
  box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.07);
}

/* Dark Mode Overrides for Glass, Panel, and Card */
body[data-theme="dark"] .glass,
body[data-theme="dark"] .panel,
body[data-theme="dark"] .card {
  background: rgba(20, 20, 35, 0.75); /* Darker background for contrast */
  border: 1px solid rgba(255, 255, 255, 0.08);
  box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.4);
  color: #f5f5f7; /* Ensure text is white */
}

/* Panel & Card Base */
.panel, .card {
  @apply glass rounded-2xl transition-all duration-300;
}

/* Hover Effects */
.panel:hover, .card:hover {
  transform: translateY(-2px);
  box-shadow: 0 12px 40px -8px rgba(0, 0, 0, 0.15);
  border-color: rgba(255, 255, 255, 0.8);
}

body[data-theme="dark"] .panel:hover, 
body[data-theme="dark"] .card:hover {
  box-shadow: 0 12px 40px -8px rgba(0, 0, 0, 0.6);
  border-color: rgba(255, 255, 255, 0.15);
  background: rgba(25, 25, 40, 0.85); /* Slightly lighter on hover */
}

/* Premium Gradient Border Effect for Featured Cards */
.card.featured {
  position: relative;
  background: linear-gradient(#fff, #fff) padding-box,
              linear-gradient(135deg, #6366f1, #8b5cf6) border-box;
  border: 2px solid transparent;
}

body[data-theme="dark"] .card.featured {
  background: linear-gradient(#0f0f1a, #0f0f1a) padding-box,
              linear-gradient(135deg, #6366f1, #8b5cf6) border-box;
}

/* Gradient Text */
.grad-title {
  background: linear-gradient(135deg, #1d1d1f 0%, #434344 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

body[data-theme="dark"] .grad-title {
  background: linear-gradient(135deg, #fff 0%, #a5b4fc 100%);
  text-shadow: 0 0 30px rgba(165, 180, 252, 0.3);
}

.grad-title-animated {
  background: linear-gradient(-45deg, #6366f1, #8b5cf6, #ec4899, #6366f1);
  background-size: 300%;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  animation: animatedText 6s ease-in-out infinite;
}

@keyframes animatedText {
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}

/* Buttons */
.btn-primary {
  background: #1d1d1f;
  color: white;
  padding: 10px 20px;
  border-radius: 12px;
  font-weight: 500;
  transition: all 0.2s;
  border: 1px solid transparent;
  box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}

.btn-primary:hover {
  transform: scale(1.02);
  box-shadow: 0 6px 16px rgba(0,0,0,0.15);
}

.btn-primary:active {
  transform: scale(0.98);
}

body[data-theme="dark"] .btn-primary {
  background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
  box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
}

body[data-theme="dark"] .btn-primary:hover {
  box-shadow: 0 0 20px rgba(99, 102, 241, 0.5);
}

.btn-secondary {
  background: rgba(0,0,0,0.05);
  color: #1d1d1f;
  padding: 8px 16px;
  border-radius: 10px;
  font-weight: 500;
  transition: all 0.2s;
  border: 1px solid transparent;
}

.btn-secondary:hover {
  background: rgba(0,0,0,0.1);
}

body[data-theme="dark"] .btn-secondary {
  background: rgba(255,255,255,0.1);
  color: #f5f5f7;
  border: 1px solid rgba(255,255,255,0.1);
}

body[data-theme="dark"] .btn-secondary:hover {
  background: rgba(255,255,255,0.15);
  border-color: rgba(255,255,255,0.2);
}

/* Inputs */
input, select, textarea {
  background: rgba(255,255,255,0.8);
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  padding: 10px 14px;
  transition: all 0.2s;
  color: #1d1d1f;
}

input:focus, select:focus, textarea:focus {
  outline: none;
  border-color: #6366f1;
  box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
  background: #fff;
}

body[data-theme="dark"] input, 
body[data-theme="dark"] select, 
body[data-theme="dark"] textarea {
  background: rgba(0,0,0,0.3);
  border-color: rgba(255,255,255,0.1);
  color: #f5f5f7;
}

body[data-theme="dark"] input:focus, 
body[data-theme="dark"] select:focus, 
body[data-theme="dark"] textarea:focus {
  border-color: #8b5cf6;
  box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.2);
  background: rgba(0,0,0,0.5);
}

/* Scrollbar */
::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}
::-webkit-scrollbar-track {
  background: transparent;
}
::-webkit-scrollbar-thumb {
  background: rgba(0,0,0,0.2);
  border-radius: 4px;
}
body[data-theme="dark"] ::-webkit-scrollbar-thumb {
  background: rgba(255,255,255,0.2);
}
::-webkit-scrollbar-thumb:hover {
  background: rgba(0,0,0,0.3);
}
body[data-theme="dark"] ::-webkit-scrollbar-thumb:hover {
  background: rgba(255,255,255,0.3);
}

/* Animations */
@keyframes fadeIn {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}

.animate-in {
  animation: fadeIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards;
}

.animate-slide-in {
  animation: slideIn 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
  opacity: 0;
}

@keyframes slideIn {
  from { opacity: 0; transform: translateX(-20px); }
  to { opacity: 1; transform: translateX(0); }
}

@keyframes slideDown {
  from { opacity: 0; transform: translateY(-10px); }
  to { opacity: 1; transform: translateY(0); }
}
@keyframes scaleUp {
  from { opacity: 0; transform: scale(0.95); }
  to { opacity: 1; transform: scale(1); }
}
@keyframes spin {
  to { transform: rotate(360deg); }
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}
@keyframes slideInFromBottom {
  from {
    opacity: 0;
    transform: translateY(30px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
@keyframes slideOut {
  from {
    opacity: 1;
    transform: translateX(0) scale(1);
  }
  to {
    opacity: 0;
    transform: translateX(-50px) scale(0.9);
  }
}

.animate-in {
  animation: slideUpAndFade 0.3s ease-out;
}
.animate-fade-in {
  animation: fadeIn 0.3s ease-out;
}
.animate-slide-in {
  animation: slideInFromBottom 0.4s ease-out forwards;
}

/* ========== 加载指示器 ========== */
.loading-spinner {
  width: 20px;
  height: 20px;
  border: 2px solid transparent;
  border-top-color: #007AFF;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}
body[data-theme="dark"] .loading-spinner {
  border-top-color: #0A84FF;
}

/* ========== 骨架屏 ========== */
.skeleton {
  background: linear-gradient(
    90deg,
    rgba(220, 220, 225, 0.6) 0%,
    rgba(235, 235, 240, 0.8) 50%,
    rgba(220, 220, 225, 0.6) 100%
  );
  background-size: 200% 100%;
  animation: skeletonLoading 1.5s ease-in-out infinite;
  border-radius: 8px;
}
@keyframes skeletonLoading {
  0% { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}
body[data-theme="dark"] .skeleton {
  background: linear-gradient(
    90deg,
    rgba(44, 44, 46, 0.6) 0%,
    rgba(56, 56, 58, 0.8) 50%,
    rgba(44, 44, 46, 0.6) 100%
  );
  background-size: 200% 100%;
  animation: skeletonLoading 1.5s ease-in-out infinite;
}

/* 骨架屏卡片 */
.skeleton-card {
  padding: 20px;
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.85);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid rgba(255, 255, 255, 0.6);
}
body[data-theme="dark"] .skeleton-card {
  background: rgba(28, 28, 30, 0.8);
  border-color: rgba(56, 56, 58, 0.6);
}

.skeleton-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
}
.skeleton-avatar {
  width: 48px;
  height: 48px;
  border-radius: 50%;
}
.skeleton-title {
  height: 20px;
  width: 40%;
  border-radius: 4px;
}
.skeleton-text {
  height: 16px;
  width: 100%;
  border-radius: 4px;
  margin-bottom: 8px;
}
.skeleton-text.short {
  width: 60%;
}
.skeleton-text.medium {
  width: 80%;
}

/* ========== 弹窗内文本块 ========== */
.modal-text-block {
  word-break: break-all;
  overflow-wrap: anywhere;
  white-space: pre-wrap;
  max-height: 260px;
  overflow-y: auto;
  padding: 8px 12px;
  border-radius: 8px;
  background: rgba(245, 245, 247, 0.9);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border: 1px solid rgba(210, 210, 215, 0.8);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  font-size: 13px;
  line-height: 1.5;
}
body[data-theme="dark"] .modal-text-block {
  background: rgba(44, 44, 46, 0.9);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border-color: rgba(56, 56, 58, 0.8);
  color: #f5f5f7;
}

/* ========== 文字样式 ========== */
.muted {
  color: #6b6b6f;
}
body[data-theme="dark"] .muted {
  color: #a8a8ad;
}

.grad-title {
  color: #1d1d1f;
  font-weight: 700;
  text-shadow: 0 1px 2px rgba(255, 255, 255, 0.5);
}
body[data-theme="dark"] .grad-title {
  color: #f5f5f7;
  text-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}

/* ========== 流光渐变标题 ========== */
.grad-title-animated {
  background: linear-gradient(
    90deg,
    #8b5cf6 0%,
    #a855f7 25%,
    #d946ef 50%,
    #a855f7 75%,
    #8b5cf6 100%
  );
  background-size: 200% auto;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  animation: gradientFlow 3s linear infinite;
  font-weight: 700;
}

@keyframes gradientFlow {
  0% { background-position: 0% center; }
  100% { background-position: 200% center; }
}

body[data-theme="dark"] .grad-title-animated {
  background: linear-gradient(
    90deg,
    #a78bfa 0%,
    #c084fc 25%,
    #e879f9 50%,
    #c084fc 75%,
    #a78bfa 100%
  );
  background-size: 200% auto;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

/* ========== Toast 通知 ========== */
#toast-root {
  position: fixed;
  top: 20px;
  left: 50%;
  transform: translateX(-50%);
  z-index: 9999;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  pointer-events: none;
}
.toast {
  padding: 12px 20px;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  color: #1d1d1f;
  border: 1px solid rgba(255, 255, 255, 0.8);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15), 0 0 0 1px rgba(255, 255, 255, 0.8);
  transform: translateY(-20px);
  opacity: 0;
  transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
  pointer-events: auto;
  min-width: 280px;
  max-width: 420px;
  font-size: 14px;
  font-weight: 500;
}
.toast.show {
  transform: translateY(0);
  opacity: 1;
  animation: slideDown 0.25s ease-out;
}
.toast.success {
  border-left: 3px solid #34C759;
}
.toast.error {
  border-left: 3px solid #FF3B30;
}
.toast.warn {
  border-left: 3px solid #FF9500;
}
body[data-theme="dark"] .toast {
  background: rgba(44, 44, 46, 0.9);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  color: #f5f5f7;
  border-color: rgba(56, 56, 58, 0.8);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.7), 0 0 0 1px rgba(56, 56, 58, 0.6);
}
body[data-theme="dark"] .toast.success { border-left-color: #32D74B; }
body[data-theme="dark"] .toast.error { border-left-color: #FF453A; }
body[data-theme="dark"] .toast.warn { border-left-color: #FF9F0A; }

/* ========== 辅助文字 ========== */
.help {
  font-size: 12px;
  color: #86868b;
}
body[data-theme="dark"] .help {
  color: #98989d;
}

/* ========== 警告框 ========== */
.alert-warning {
  background: linear-gradient(135deg, rgba(255, 149, 0, 0.08), rgba(255, 204, 0, 0.05));
  border: 1px solid rgba(255, 149, 0, 0.25);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
}
body[data-theme="dark"] .alert-warning {
  background: linear-gradient(135deg, rgba(255, 159, 10, 0.12), rgba(255, 214, 10, 0.08));
  border-color: rgba(255, 159, 10, 0.3);
}

/* ========== 状态徽章 ========== */
.badge-ok {
  color: #34C759;
  font-weight: 600;
  position: relative;
}
.badge-ok::before {
  content: '';
  position: absolute;
  left: -12px;
  top: 50%;
  transform: translateY(-50%);
  width: 6px;
  height: 6px;
  background: #34C759;
  border-radius: 50%;
  animation: pulse-green 2s ease-in-out infinite;
}
@keyframes pulse-green {
  0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(52, 199, 89, 0.7); }
  50% { opacity: 0.8; box-shadow: 0 0 0 4px rgba(52, 199, 89, 0); }
}
.badge-fail {
  color: #FF3B30;
  font-weight: 600;
}
.badge-idle {
  color: #86868b;
  font-weight: 600;
}
body[data-theme="dark"] .badge-ok { color: #32D74B; }
body[data-theme="dark"] .badge-ok::before { background: #32D74B; }
body[data-theme="dark"] .badge-fail { color: #FF453A; }
body[data-theme="dark"] .badge-idle { color: #98989d; }

/* ========== 主题切换按钮 ========== */
#theme-toggle {
  border-radius: 10px;
  padding: 8px 16px;
  border: 1px solid rgba(210, 210, 215, 0.8);
  background: rgba(255, 255, 255, 0.9);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  color: #1d1d1f;
  font-size: 13px;
  font-weight: 500;
  transition: all 0.15s ease;
  cursor: pointer;
}
#theme-toggle:hover {
  background: rgba(245, 245, 247, 0.95);
  transform: scale(0.98);
}
#theme-toggle:active {
  transform: scale(0.96);
  opacity: 0.8;
}
body[data-theme="dark"] #theme-toggle {
  background: rgba(44, 44, 46, 0.85);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  color: #f5f5f7;
  border-color: rgba(56, 56, 58, 0.8);
}
body[data-theme="dark"] #theme-toggle:hover {
  background: rgba(56, 56, 58, 0.9);
}

/* ========== 统计卡片 ========== */
.stat-card {
  background: rgba(255, 255, 255, 0.85);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  border: 1px solid rgba(255, 255, 255, 0.6);
  border-radius: 12px;
  transition: all 0.2s ease;
  cursor: pointer;
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.06), 0 0 0 1px rgba(255, 255, 255, 0.8);
}
.stat-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1), 0 0 0 1px rgba(255, 255, 255, 0.9);
}
.stat-card:active {
  transform: translateY(-1px) scale(0.98);
}
.stat-card .stat-label {
  font-size: 12px;
  font-weight: 500;
  color: #86868b;
}
.stat-card .stat-value {
  font-size: 28px;
  font-weight: 700;
  color: #007AFF;
}
.stat-card.stat-all .stat-value { color: #007AFF; }
.stat-card.stat-active .stat-value { color: #34C759; }
.stat-card.stat-failed .stat-value { color: #FF3B30; }
.stat-card.stat-inactive .stat-value { color: #FF9500; }
.stat-card.stat-pending .stat-value { color: #FF9500; }
.stat-card.stat-today .stat-value { color: #007AFF; }

body[data-theme="dark"] .stat-card {
  background: rgba(28, 28, 30, 0.8);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  border-color: rgba(56, 56, 58, 0.6);
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(56, 56, 58, 0.5);
}
body[data-theme="dark"] .stat-card:hover {
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(56, 56, 58, 0.8);
}
body[data-theme="dark"] .stat-card .stat-label {
  color: #98989d;
}
body[data-theme="dark"] .stat-card .stat-value {
  color: #0A84FF;
}
body[data-theme="dark"] .stat-card.stat-all .stat-value { color: #0A84FF; }
body[data-theme="dark"] .stat-card.stat-active .stat-value { color: #32D74B; }
body[data-theme="dark"] .stat-card.stat-failed .stat-value { color: #FF453A; }
body[data-theme="dark"] .stat-card.stat-inactive .stat-value { color: #FF9F0A; }
body[data-theme="dark"] .stat-card.stat-pending .stat-value { color: #FF9F0A; }
body[data-theme="dark"] .stat-card.stat-today .stat-value { color: #0A84FF; }

/* ========== 文字大小 ========== */
.text-xs { font-size: 13px; line-height: 1.4; }
.text-sm { font-size: 14px; line-height: 1.45; }

/* ========== 表单元素 ========== */
input, textarea, select {
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  color: #1d1d1f;
  border: 1px solid rgba(210, 210, 215, 0.8);
  border-radius: 10px;
  padding: 10px 14px;
  font-size: 15px;
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
  -webkit-appearance: none;
  -moz-appearance: none;
  appearance: none;
  position: relative;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-rendering: optimizeLegibility;
  font-feature-settings: "kern" 1;
}
select {
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 14 14'%3E%3Cpath fill='%231d1d1f' stroke='%231d1d1f' stroke-width='0.5' d='M7 10L2 5h10z'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 12px center;
  background-size: 12px;
  padding-right: 40px;
  cursor: pointer;
}
optgroup {
  font-weight: 600;
  color: #6b6b6f;
  font-size: 14px;
  padding: 10px 14px;
  background: #f5f5f7;
  text-rendering: optimizeLegibility;
  font-feature-settings: "kern" 1;
}
option {
  padding: 10px 14px;
  color: #1d1d1f;
  background: #ffffff;
  font-size: 14.5px;
  font-weight: 400;
  line-height: 1.6;
  text-rendering: optimizeLegibility;
  font-feature-settings: "kern" 1;
  letter-spacing: 0.01em;
}
option:hover,
option:focus {
  background: #f5f5f7;
  color: #000000;
}
input:hover, textarea:hover, select:hover {
  border-color: #86868b;
  transform: translateY(-1px);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
}
input:focus, textarea:focus, select:focus {
  border-color: #8b5cf6;
  box-shadow: 0 0 0 4px rgba(139, 92, 246, 0.12), 0 2px 8px rgba(139, 92, 246, 0.15);
  outline: none;
  transform: translateY(-2px);
}
input::placeholder,
textarea::placeholder {
  color: #86868b;
  transition: opacity 0.2s ease;
}
input:focus::placeholder,
textarea:focus::placeholder {
  opacity: 0.5;
}
input:disabled, textarea:disabled, select:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  background: #f5f5f7;
}

/* 输入框错误状态 */
input.error, textarea.error, select.error {
  border-color: #FF3B30;
  animation: shake 0.3s ease;
}
@keyframes shake {
  0%, 100% { transform: translateX(0); }
  25% { transform: translateX(-8px); }
  75% { transform: translateX(8px); }
}

/* 输入框成功状态 */
input.success, textarea.success, select.success {
  border-color: #34C759;
}

body[data-theme="dark"] input,
body[data-theme="dark"] textarea,
body[data-theme="dark"] select {
  background: rgba(44, 44, 46, 0.95);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  color: #f5f5f7;
  border-color: rgba(56, 56, 58, 0.8);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-rendering: optimizeLegibility;
  font-feature-settings: "kern" 1;
}
body[data-theme="dark"] select {
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 14 14'%3E%3Cpath fill='%23f5f5f7' stroke='%23f5f5f7' stroke-width='0.5' d='M7 10L2 5h10z'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 12px center;
  background-size: 12px;
}
body[data-theme="dark"] optgroup {
  color: #d1d1d6;
  background: #1c1c1e;
  font-size: 14px;
  font-weight: 600;
  padding: 10px 14px;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-rendering: optimizeLegibility;
  font-feature-settings: "kern" 1;
  border: none;
}
body[data-theme="dark"] option {
  color: #f5f5f7;
  background: #2c2c2e;
  font-size: 14.5px;
  font-weight: 400;
  padding: 10px 14px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-rendering: optimizeLegibility;
  font-feature-settings: "kern" 1;
  letter-spacing: 0.01em;
}
body[data-theme="dark"] option:hover,
body[data-theme="dark"] option:focus {
  background: #3a3a3c;
  color: #ffffff;
}
body[data-theme="dark"] input:hover,
body[data-theme="dark"] textarea:hover,
body[data-theme="dark"] select:hover {
  border-color: #98989d;
  transform: translateY(-1px);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}
body[data-theme="dark"] input:focus,
body[data-theme="dark"] textarea:focus,
body[data-theme="dark"] select:focus {
  border-color: #8b5cf6;
  box-shadow: 0 0 0 4px rgba(139, 92, 246, 0.18), 0 2px 8px rgba(139, 92, 246, 0.2);
  transform: translateY(-2px);
}
body[data-theme="dark"] input.error,
body[data-theme="dark"] textarea.error,
body[data-theme="dark"] select.error {
  border-color: #FF453A;
}
body[data-theme="dark"] input.success,
body[data-theme="dark"] textarea.success,
body[data-theme="dark"] select.success {
  border-color: #32D74B;
}
body[data-theme="dark"] input::placeholder,
body[data-theme="dark"] textarea::placeholder {
  color: #98989d;
}
body[data-theme="dark"] input:disabled,
body[data-theme="dark"] textarea:disabled,
body[data-theme="dark"] select:disabled {
  background: #1c1c1e;
}

/* ========== 按钮 ========== */
button {
  transition: all 0.15s ease;
  cursor: pointer;
  font-weight: 500;
  border-radius: 10px;
  -webkit-tap-highlight-color: transparent;
}
button:hover {
  opacity: 0.85;
  transform: scale(0.98);
}
button:active {
  opacity: 0.7;
  transform: scale(0.96);
}
button:disabled {
  opacity: 0.4;
  cursor: not-allowed;
  transform: none!important;
}

/* 主按钮（渐变蓝色背景）*/
.btn-primary {
  background: #007AFF;
  color: #ffffff;
  border: none;
  padding: 12px 24px;
  font-size: 15px;
  box-shadow: 0 2px 8px rgba(0, 122, 255, 0.2);
  position: relative;
  overflow: hidden;
}
.btn-primary:hover {
  background: #0077ED;
  box-shadow: 0 4px 12px rgba(0, 122, 255, 0.3);
}
.btn-primary.loading {
  pointer-events: none;
  opacity: 0.8;
}
.btn-primary.loading::after {
  content: '';
  position: absolute;
  width: 16px;
  height: 16px;
  border: 2px solid #ffffff;
  border-top-color: transparent;
  border-radius: 50%;
  animation: spin 0.6s linear infinite;
  margin-left: 8px;
}
.btn-primary.success {
  background: #34C759;
  animation: successPulse 0.5s ease;
}
.btn-primary.error {
  background: #FF3B30;
  animation: errorShake 0.4s ease;
}
@keyframes successPulse {
  0% { transform: scale(1); }
  50% { transform: scale(1.05); box-shadow: 0 0 20px rgba(52, 199, 89, 0.5); }
  100% { transform: scale(1); }
}
@keyframes errorShake {
  0%, 100% { transform: translateX(0); }
  25% { transform: translateX(-10px); }
  75% { transform: translateX(10px); }
}
body[data-theme="dark"] .btn-primary {
  background: #0A84FF;
  box-shadow: 0 2px 8px rgba(10, 132, 255, 0.3);
}
body[data-theme="dark"] .btn-primary:hover {
  background: #0077ED;
}
body[data-theme="dark"] .btn-primary.success {
  background: #32D74B;
}
body[data-theme="dark"] .btn-primary.error {
  background: #FF453A;
}

/* 次要按钮（边框按钮）*/
.btn-secondary {
  background: transparent;
  color: #1d1d1f;
  border: 1px solid #d2d2d7;
  padding: 8px 16px;
  font-size: 13px;
}
.btn-secondary:hover {
  background: #f5f5f7;
  opacity: 1;
}
body[data-theme="dark"] .btn-secondary {
  color: #f5f5f7;
  border-color: #38383a;
}
body[data-theme="dark"] .btn-secondary:hover {
  background: #2c2c2e;
}

/* 危险按钮（删除等）*/
.btn-danger {
  background: transparent;
  color: #FF3B30;
  border: 1px solid #FF3B30;
  padding: 8px 16px;
  font-size: 13px;
}
.btn-danger:hover {
  background: #FF3B30;
  color: #ffffff;
  opacity: 1;
}
body[data-theme="dark"] .btn-danger {
  color: #FF453A;
  border-color: #FF453A;
}
body[data-theme="dark"] .btn-danger:hover {
  background: #FF453A;
}

/* ========== 响应式设计 ========== */
@media(max-width: 640px) {
  html, body {
    font-size: 14px;
  }
  .grad-title {
    font-size: 24px;
    line-height: 1.3;
  }
  .panel, .card {
    border-radius: 12px;
  }
  button {
    min-height: 44px;
    min-width: 44px;
  }
  .toast {
    min-width: 260px;
    max-width: calc(100vw - 40px);
  }
  /* 移动端卡片可左右滑动 */
  .swipeable {
    touch-action: pan-y;
    user-select: none;
  }
}

/* ========== 数字计数动画 ========== */
.count-up {
  display: inline-block;
  animation: countUp 0.8s cubic-bezier(0.4, 0, 0.2, 1);
}
@keyframes countUp {
  0% {
    opacity: 0;
    transform: translateY(20px) scale(0.8);
  }
  100% {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}

/* ========== 进度条动画 ========== */
.progress-bar {
  transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
}

/* ========== ECharts 地图容器 ========== */
#server-map-chart {
  border-radius: 12px;
  overflow: hidden;
  background: rgba(255, 255, 255, 0.5);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
}
body[data-theme="dark"] #server-map-chart {
  background: rgba(28, 28, 30, 0.5);
}

/* ========== 卡片展开/收起 ========== */
/* 这里的旧样式已被 Grid 动画取代 */

/* 展开/收起按钮样式优化 */
.toggle-expand {
  user-select: none;
  -webkit-user-select: none;
  -moz-user-select: none;
}
.toggle-expand:active {
  transform: scale(0.95);
}
body[data-theme="dark"] .toggle-expand:hover {
  background: rgba(10, 132, 255, 0.1);
  border-color: rgba(10, 132, 255, 0.3);
}

/* ========== 链接样式 ========== */
a {
  color: #007AFF;
  text-decoration: none;
  transition: all 0.2s ease;
}
a:hover {
  opacity: 0.8;
}
body[data-theme="dark"] a {
  color: #0A84FF;
}

/* ========== Code 标签 ========== */
code {
  padding: 2px 6px;
  border-radius: 4px;
  background: rgba(0, 0, 0, 0.05);
  color: #1d1d1f;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.9em;
}
body[data-theme="dark"] code {
  background: rgba(255, 255, 255, 0.1);
  color: #f5f5f7;
}

/* ========== 可访问性 ========== */
button:focus-visible,
input:focus-visible,
textarea:focus-visible,
select:focus-visible,
a:focus-visible {
  outline: 2px solid #007AFF;
  outline-offset: 2px;
}
body[data-theme="dark"] button:focus-visible,
body[data-theme="dark"] input:focus-visible,
body[data-theme="dark"] textarea:focus-visible,
body[data-theme="dark"] select:focus-visible,
body[data-theme="dark"] a:focus-visible {
  outline-color: #0A84FF;
}

/* ========== 滚动条样式 ========== */
::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}
::-webkit-scrollbar-track {
  background: transparent;
}
::-webkit-scrollbar-thumb {
  background: #d2d2d7;
  border-radius: 4px;
}
::-webkit-scrollbar-thumb:hover {
  background: #86868b;
}
body[data-theme="dark"] ::-webkit-scrollbar-thumb {
  background: #38383a;
}
body[data-theme="dark"] ::-webkit-scrollbar-thumb:hover {
  background: #98989d;
}
</style>
  <script>
/* ========== SVG 图标定义 ========== */
const ICONS = {
  crown: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="m2 4 3 12h14l3-12-6 7-4-7-4 7-6-7zm3 16h14"/></svg>',
  trophy: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M6 9H4.5a2.5 2.5 0 0 1 0-5H6"/><path d="M18 9h1.5a2.5 2.5 0 0 0 0-5H18"/><path d="M4 22h16"/><path d="M10 14.66V17c0 .55-.47.98-.97 1.21C7.85 18.75 7 20.24 7 22"/><path d="M14 14.66V17c0 .55.47.98.97 1.21C16.15 18.75 17 20.24 17 22"/><path d="M18 2H6v7a6 6 0 0 0 12 0V2Z"/></svg>',
  medal: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><circle cx="12" cy="8" r="7"/><polyline points="8.21 13.89 7 23 12 20 17 23 15.79 13.88"/></svg>',
  star: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>',
  server: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/></svg>',
  globe: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><circle cx="12" cy="12" r="10"/><line x1="2" x2="22" y1="12" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
  chart: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M3 3v18h18"/><path d="M18 17V9"/><path d="M13 17V5"/><path d="M8 17v-3"/></svg>',
  calendar: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><rect width="18" height="18" x="3" y="4" rx="2" ry="2"/><line x1="16" x2="16" y1="2" y2="6"/><line x1="8" x2="8" y1="2" y2="6"/><line x1="3" x2="21" y1="10" y2="10"/></svg>',
  cpu: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/></svg>',
  message: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>',
  chevronDown: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="m6 9 6 6 6-6"/></svg>',
  check: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><polyline points="20 6 9 17 4 12"/></svg>',
  x: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M18 6 6 18"/><path d="m6 6 18 18"/></svg>',
  info: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>',
  user: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
  clock: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
  search: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><circle cx="11" cy="11" r="8"/><line x1="21" x2="16.65" y1="21" y2="16.65"/></svg>',
  edit: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>',
  trash: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
  settings: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
  note: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" x2="8" y1="13" y2="13"/><line x1="16" x2="8" y1="17" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>',
  alert: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg>',
  key: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>',
  lock: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  save: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>',
  plug: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M12 22v-5"/><path d="M9 8V2"/><path d="M15 8V2"/><path d="M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z"/></svg>',
  bulb: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M15 14c.2-1 .7-1.7 1.5-2.5 1-1 1.5-2.4 1.5-3.8 0-3.3-2.7-6-6-6 0 0-6 .7-6 6 0 1.4.5 2.8 1.5 3.8.8.8 1.3 1.5 1.5 2.5"/><path d="M9 18h6"/><path d="M10 22h4"/></svg>'
};
  (function () {
    const saved = localStorage.getItem('theme') || 'dark';
    const accent = localStorage.getItem('accent-color') || 'blue';
    document.documentElement.setAttribute('data-theme', saved);
    document.documentElement.setAttribute('data-accent', accent);
    document.addEventListener('DOMContentLoaded', () => {
      document.body.setAttribute('data-theme', saved);
      document.body.setAttribute('data-accent', accent);
    });
  })();

function toggleTheme() {
  const cur = document.body.getAttribute('data-theme') || 'dark';
  const nxt = cur === 'dark' ? 'light' : 'dark';
  document.body.setAttribute('data-theme', nxt);
  document.documentElement.setAttribute('data-theme', nxt);
  localStorage.setItem('theme', nxt);
  updateThemeBtn && updateThemeBtn();

  // 触发主题切换事件，通知地图更新
  window.dispatchEvent(new Event('themeChanged'));
}

function updateThemeBtn() {
  const b = document.getElementById('theme-toggle');
  if (b) {
    const cur = document.body.getAttribute('data-theme') || 'dark';
    b.textContent = cur === 'dark' ? '浅色模式' : '深色模式';
  }
}

// 主题色切换（可选功能）
function setAccentColor(color) {
  document.body.setAttribute('data-accent', color);
  document.documentElement.setAttribute('data-accent', color);
  localStorage.setItem('accent-color', color);
}

function toast(msg, type = 'info', ms = 2600) {
  let root = document.getElementById('toast-root');
  if (!root) {
    root = document.createElement('div');
    root.id = 'toast-root';
    document.body.appendChild(root);
  }
  const el = document.createElement('div');
  el.className = 'toast ' + (type === 'success' ? 'success' : type === 'error' ? 'error' : type === 'warn' ? 'warn' : '');
  el.textContent = msg;
  root.appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));
  setTimeout(() => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 250);
  }, ms);
}

function copyToClipboard(text) {
  if (!text) {
    toast('没有可复制的内容', 'warn');
    return;
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => toast('已复制到剪贴板', 'success')).catch(() => toast('复制失败', 'error'));
  } else {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    ta.style.top = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      toast('已复制到剪贴板', 'success');
    } catch (e) {
      toast('复制失败', 'error');
    }
    document.body.removeChild(ta);
  }
}

function modalEdit(title, fields, onOk) {
  const wrap = document.createElement('div');
  wrap.style.cssText = 'position:fixed;inset:0;z-index:9998;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;backdrop-filter:blur(8px);animation:fadeIn 0.2s ease-out;';
  const card = document.createElement('div');
  card.className = 'panel border p-6';
  card.style.width = 'min(680px,92vw)';
  card.style.animation = 'scaleUp 0.25s ease-out';
  const h = document.createElement('div');
  h.className = 'text-lg font-semibold mb-4';
  h.textContent = title;
  card.appendChild(h);
  const form = document.createElement('div');
  form.className = 'grid grid-cols-2 gap-4 text-sm';
  fields.forEach(f => {
    const box = document.createElement('div');
    const lab = document.createElement('div');
    lab.className = 'muted text-xs mb-2 font-medium';
    lab.textContent = f.label;
    const inp = f.type === 'textarea' ? document.createElement('textarea') : document.createElement('input');
    if (f.type !== 'textarea') inp.type = 'text';
    inp.value = f.value || '';
    inp.placeholder = f.placeholder || '';
    if (f.type === 'textarea') inp.rows = 3;
    inp.className = 'w-full';
    box.appendChild(lab);
    box.appendChild(inp);
    box._get = () => inp.value;
    box._key = f.key;
    form.appendChild(box);
  });
  card.appendChild(form);
  const actions = document.createElement('div');
  actions.className = 'mt-6 flex items-center justify-end gap-3';
  const btn1 = document.createElement('button');
  btn1.textContent = '取消';
  btn1.className = 'btn-secondary';
  btn1.onclick = () => wrap.remove();
  const btn2 = document.createElement('button');
  btn2.textContent = '保存';
  btn2.className = 'btn-primary';
  btn2.onclick = () => { const data = {}; form.childNodes.forEach((n) => { data[n._key] = n._get(); }); try { onOk(data, () => wrap.remove()); } catch (e) { console.error(e); } };
  actions.append(btn1, btn2);
  card.appendChild(actions);
  wrap.appendChild(card);
  document.body.appendChild(wrap);

  // 添加 ESC 键关闭
  const handleEsc = (e) => {
    if (e.key === 'Escape') {
      wrap.remove();
      document.removeEventListener('keydown', handleEsc);
    }
  };
  document.addEventListener('keydown', handleEsc);

  // 点击背景关闭
  wrap.addEventListener('click', (e) => {
    if (e.target === wrap) {
      wrap.remove();
      document.removeEventListener('keydown', handleEsc);
    }
  });

  // 聚焦第一个输入框
  setTimeout(() => {
    const firstInput = form.querySelector('input, textarea');
    if (firstInput) firstInput.focus();
  }, 100);
}

function guessCountryFlag(v) {
  const txt = ((v.country || "") + " " + (v.ipLocation || "")).toLowerCase();

  const rules = [
    // ========= 东亚 / 东北亚 =========
    { k: ["china", "prc", "cn", "中国", "beijing", "shanghai", "guangzhou"], f: "🇨🇳" },
    { k: ["hong kong", "hk", "香港"], f: "🇭🇰" },
    { k: ["macau", "macao", "澳门"], f: "🇲🇴" },
    { k: ["taiwan", "台灣", "台湾"], f: "🇹🇼" },
    { k: ["japan", "tokyo", "osaka", "日本"], f: "🇯🇵" },
    { k: ["korea", "south korea", "republic of korea", "首尔", "韓國", "韩国", "seoul"], f: "🇰🇷" },
    { k: ["north korea", "dprk", "朝鲜", "pyongyang"], f: "🇰🇵" },
    { k: ["mongolia", "蒙古"], f: "🇲🇳" },

    // ========= 东南亚 =========
    { k: ["vietnam", "越南", "hanoi", "ho chi minh"], f: "🇻🇳" },
    { k: ["thailand", "泰国", "bangkok"], f: "🇹🇭" },
    { k: ["malaysia", "马来西亚", "kuala lumpur"], f: "🇲🇾" },
    { k: ["singapore", "新加坡"], f: "🇸🇬" },
    { k: ["philippines", "菲律宾", "manila"], f: "🇵🇭" },
    { k: ["indonesia", "印尼", "jakarta"], f: "🇮🇩" },
    { k: ["myanmar", "burma", "缅甸"], f: "🇲🇲" },
    { k: ["cambodia", "柬埔寨", "phnom penh"], f: "🇰🇭" },
    { k: ["laos", "老挝", "vientiane"], f: "🇱🇦" },
    { k: ["brunei", "文莱"], f: "🇧🇳" },
    { k: ["timor-leste", "east timor", "timor", "东帝汶"], f: "🇹🇱" },

    // ========= 南亚 =========
    { k: ["india", "印度", "new delhi", "mumbai"], f: "🇮🇳" },
    { k: ["pakistan", "巴基斯坦", "islamabad"], f: "🇵🇰" },
    { k: ["bangladesh", "孟加拉", "dhaka"], f: "🇧🇩" },
    { k: ["nepal", "尼泊尔", "kathmandu"], f: "🇳🇵" },
    { k: ["sri lanka", "斯里兰卡", "colombo"], f: "🇱🇰" },
    { k: ["maldives", "马尔代夫"], f: "🇲🇻" },
    { k: ["bhutan", "不丹"], f: "🇧🇹" },
    { k: ["afghanistan", "阿富汗"], f: "🇦🇫" },

    // ========= 中东 / 西亚 =========
    { k: ["saudi arabia", "saudi", "沙特", "riyadh"], f: "🇸🇦" },
    { k: ["united arab emirates", "uae", "dubai", "abu dhabi", "阿联酋"], f: "🇦🇪" },
    { k: ["israel", "以色列", "tel aviv", "jerusalem"], f: "🇮🇱" },
    { k: ["iran", "伊朗", "tehran"], f: "🇮🇷" },
    { k: ["iraq", "伊拉克", "baghdad"], f: "🇮🇶" },
    { k: ["turkey", "turkiye", "土耳其", "ankara", "istanbul"], f: "🇹🇷" },
    { k: ["qatar", "卡塔尔", "doha"], f: "🇶🇦" },
    { k: ["kuwait", "科威特"], f: "🇰🇼" },
    { k: ["bahrain", "巴林"], f: "🇧🇭" },
    { k: ["oman", "阿曼", "muscat"], f: "🇴🇲" },
    { k: ["jordan", "约旦", "amman"], f: "🇯🇴" },
    { k: ["lebanon", "黎巴嫩", "beirut"], f: "🇱🇧" },
    { k: ["yemen", "也门"], f: "🇾🇪" },
    { k: ["syria", "syrian arab republic", "叙利亚"], f: "🇸🇾" },
    { k: ["palestine", "palestinian", "巴勒斯坦"], f: "🇵🇸" },

    // ========= 欧洲（西欧 / 北欧 / 南欧 / 东欧） =========
    { k: ["united kingdom", "uk", "great britain", "england", "london", "英国"], f: "🇬🇧" },
    { k: ["france", "paris", "法国"], f: "🇫🇷" },
    { k: ["germany", "berlin", "德国"], f: "🇩🇪" },
    { k: ["netherlands", "amsterdam", "荷兰"], f: "🇳🇱" },
    { k: ["belgium", "比利时", "brussels"], f: "🇧🇪" },
    { k: ["luxembourg", "卢森堡"], f: "🇱🇺" },
    { k: ["switzerland", "瑞士", "zurich", "geneva"], f: "🇨🇭" },
    { k: ["austria", "奥地利", "vienna"], f: "🇦🇹" },
    { k: ["ireland", "爱尔兰", "dublin"], f: "🇮🇪" },
    { k: ["iceland", "冰岛", "reykjavik"], f: "🇮🇸" },
    { k: ["denmark", "丹麦", "copenhagen"], f: "🇩🇰" },
    { k: ["sweden", "瑞典", "stockholm"], f: "🇸🇪" },
    { k: ["norway", "挪威", "oslo"], f: "🇳🇴" },
    { k: ["finland", "芬兰", "helsinki"], f: "🇫🇮" },

    { k: ["spain", "madrid", "barcelona", "西班牙"], f: "🇪🇸" },
    { k: ["portugal", "里斯本", "葡萄牙"], f: "🇵🇹" },
    { k: ["italy", "rome", "milan", "意大利"], f: "🇮🇹" },
    { k: ["greece", "雅典", "希腊"], f: "🇬🇷" },
    { k: ["malta", "马耳他"], f: "🇲🇹" },
    { k: ["cyprus", "塞浦路斯"], f: "🇨🇾" },

    { k: ["poland", "波兰"], f: "🇵🇱" },
    { k: ["czech", "czech republic", "捷克"], f: "🇨🇿" },
    { k: ["slovakia", "斯洛伐克"], f: "🇸🇰" },
    { k: ["hungary", "匈牙利"], f: "🇭🇺" },
    { k: ["romania", "罗马尼亚"], f: "🇷🇴" },
    { k: ["bulgaria", "保加利亚"], f: "🇧🇬" },
    { k: ["slovenia", "斯洛文尼亚"], f: "🇸🇮" },
    { k: ["croatia", "克罗地亚"], f: "🇭🇷" },
    { k: ["serbia", "塞尔维亚"], f: "🇷🇸" },
    { k: ["bosnia", "bosnia and herzegovina", "波黑", "波斯尼亚"], f: "🇧🇦" },
    { k: ["montenegro", "黑山"], f: "🇲🇪" },
    { k: ["north macedonia", "macedonia", "北马其顿"], f: "🇲🇰" },
    { k: ["albania", "阿尔巴尼亚"], f: "🇦🇱" },
    { k: ["kosovo", "科索沃"], f: "🇽🇰" },
    { k: ["moldova", "moldovan", "moldavia", "chisinau", "摩尔多瓦"], f: "🇲🇩" },
    { k: ["ukraine", "乌克兰", "kyiv", "kiev"], f: "🇺🇦" },
    { k: ["belarus", "白俄罗斯"], f: "🇧🇾" },
    { k: ["russia", "russian federation", "moscow", "俄罗斯"], f: "🇷🇺" },
    { k: ["estonia", "爱沙尼亚"], f: "🇪🇪" },
    { k: ["latvia", "拉脱维亚"], f: "🇱🇻" },
    { k: ["lithuania", "立陶宛"], f: "🇱🇹" },

    // ========= 北美 =========
    { k: ["united states", "usa", "u.s.", "america", "los angeles", "new york", "美国"], f: "🇺🇸" },
    { k: ["canada", "toronto", "vancouver", "canadian", "加拿大"], f: "🇨🇦" },
    { k: ["mexico", "mexican", "墨西哥", "mexico city"], f: "🇲🇽" },
    { k: ["greenland", "格陵兰"], f: "🇬🇱" },

    // ========= 中美洲 & 加勒比 =========
    { k: ["cuba", "古巴", "havana"], f: "🇨🇺" },
    { k: ["dominican republic", "dominican", "多米尼加"], f: "🇩🇴" },
    { k: ["haiti", "海地"], f: "🇭🇹" },
    { k: ["jamaica", "牙买加"], f: "🇯🇲" },
    { k: ["puerto rico", "波多黎各"], f: "🇵🇷" },
    { k: ["panama", "巴拿马"], f: "🇵🇦" },
    { k: ["costa rica", "哥斯达黎加"], f: "🇨🇷" },
    { k: ["guatemala", "危地马拉"], f: "🇬🇹" },
    { k: ["honduras", "洪都拉斯"], f: "🇭🇳" },
    { k: ["nicaragua", "尼加拉瓜"], f: "🇳🇮" },
    { k: ["el salvador", "萨尔瓦多"], f: "🇸🇻" },
    { k: ["belize", "伯利兹"], f: "🇧🇿" },
    { k: ["trinidad and tobago", "trinidad", "特立尼达和多巴哥"], f: "🇹🇹" },
    { k: ["barbados", "巴巴多斯"], f: "🇧🇧" },
    { k: ["bahamas", "巴哈马"], f: "🇧🇸" },
    { k: ["grenada", "格林纳达"], f: "🇬🇩" },
    { k: ["saint lucia", "圣卢西亚"], f: "🇱🇨" },
    { k: ["saint kitts", "kitts and nevis", "圣基茨"], f: "🇰🇳" },
    { k: ["saint vincent", "st vincent", "圣文森特"], f: "🇻🇨" },

    // ========= 南美 =========
    { k: ["brazil", "brasil", "巴西"], f: "🇧🇷" },
    { k: ["argentina", "阿根廷"], f: "🇦🇷" },
    { k: ["chile", "智利"], f: "🇨🇱" },
    { k: ["colombia", "哥伦比亚"], f: "🇨🇴" },
    { k: ["peru", "秘鲁"], f: "🇵🇪" },
    { k: ["uruguay", "乌拉圭"], f: "🇺🇾" },
    { k: ["paraguay", "巴拉圭"], f: "🇵🇾" },
    { k: ["bolivia", "玻利维亚"], f: "🇧🇴" },
    { k: ["ecuador", "厄瓜多尔"], f: "🇪🇨" },
    { k: ["venezuela", "委内瑞拉"], f: "🇻🇪" },
    { k: ["guyana", "圭亚那"], f: "🇬🇾" },
    { k: ["suriname", "苏里南"], f: "🇸🇷" },

    // ========= 大洋洲 =========
    { k: ["australia", "悉尼", "melbourne", "澳大利亚"], f: "🇦🇺" },
    { k: ["new zealand", "新西兰", "auckland"], f: "🇳🇿" },
    { k: ["fiji", "斐济"], f: "🇫🇯" },
    { k: ["papua new guinea", "巴布亚新几内亚"], f: "🇵🇬" },
    { k: ["samoa", "萨摩亚"], f: "🇼🇸" },
    { k: ["tonga", "汤加"], f: "🇹🇴" },
    { k: ["vanuatu", "瓦努阿图"], f: "🇻🇺" },
    { k: ["solomon islands", "所罗门群岛"], f: "🇸🇧" },
    { k: ["palau", "帕劳"], f: "🇵🇼" },
    { k: ["micronesia", "密克罗尼西亚"], f: "🇫🇲" },
    { k: ["marshall islands", "马绍尔群岛"], f: "🇲🇭" },
    { k: ["kiribati", "基里巴斯"], f: "🇰🇮" },
    { k: ["nauru", "瑙鲁"], f: "🇳🇷" },
    { k: ["tuvalu", "图瓦卢"], f: "🇹🇻" },

    // ========= 非洲 =========
    { k: ["south africa", "南非", "johannesburg"], f: "🇿🇦" },
    { k: ["egypt", "埃及", "cairo"], f: "🇪🇬" },
    { k: ["nigeria", "尼日利亚"], f: "🇳🇬" },
    { k: ["kenya", "肯尼亚", "nairobi"], f: "🇰🇪" },
    { k: ["ethiopia", "埃塞俄比亚"], f: "🇪🇹" },
    { k: ["ghana", "加纳"], f: "🇬🇭" },
    { k: ["morocco", "摩洛哥"], f: "🇲🇦" },
    { k: ["algeria", "阿尔及利亚"], f: "🇩🇿" },
    { k: ["tunisia", "突尼斯"], f: "🇹🇳" },
    { k: ["libya", "利比亚"], f: "🇱🇾" },
    { k: ["sudan", "苏丹"], f: "🇸🇩" },
    { k: ["south sudan", "南苏丹"], f: "🇸🇸" },
    { k: ["tanzania", "坦桑尼亚"], f: "🇹🇿" },
    { k: ["uganda", "乌干达"], f: "🇺🇬" },
    { k: ["angola", "安哥拉"], f: "🇦🇴" },
    { k: ["mozambique", "莫桑比克"], f: "🇲🇿" },
    { k: ["zambia", "赞比亚"], f: "🇿🇲" },
    { k: ["zimbabwe", "津巴布韦"], f: "🇿🇼" },
    { k: ["rwanda", "卢旺达"], f: "🇷🇼" },
    { k: ["burundi", "布隆迪"], f: "🇧🇮" },
    { k: ["botswana", "博茨瓦纳"], f: "🇧🇼" },
    { k: ["namibia", "纳米比亚"], f: "🇳🇦" },
    { k: ["madagascar", "马达加斯加"], f: "🇲🇬" },
    { k: ["seychelles", "塞舌尔"], f: "🇸🇨" },
    { k: ["mauritius", "毛里求斯"], f: "🇲🇺" },
    { k: ["senegal", "塞内加尔"], f: "🇸🇳" },
    { k: ["mali", "马里"], f: "🇲🇱" },
    { k: ["niger", "尼日尔"], f: "🇳🇪" },
    { k: ["cameroon", "喀麦隆"], f: "🇨🇲" },
    { k: ["ivory coast", "cote d ivoire", "科特迪瓦"], f: "🇨🇮" },
    { k: ["gabon", "加蓬"], f: "🇬🇦" },
    { k: ["congo", "republic of the congo", "刚果共和国"], f: "🇨🇬" },
    { k: ["dr congo", "democratic republic of the congo", "刚果金"], f: "🇨🇩" },
    { k: ["guinea", "几内亚"], f: "🇬🇳" },
    { k: ["guinea-bissau", "几内亚比绍"], f: "🇬🇼" },
    { k: ["sierra leone", "塞拉利昂"], f: "🇸🇱" },
    { k: ["liberia", "利比里亚"], f: "🇱🇷" },
    { k: ["eritrea", "厄立特里亚"], f: "🇪🇷" },
    { k: ["djibouti", "吉布提"], f: "🇩🇯" },
    { k: ["somalia", "索马里"], f: "🇸🇴" }
  ];

  for (const r of rules) {
    if (r.k.some(k => txt.includes(k.toLowerCase()))) {
      return r.f;
    }
  }
  return "";
}




/* 重要：重写的 VPS 登录信息弹窗，支持长密钥换行+滚动+复制 */
function modalLoginInfo(v) {
  const wrap = document.createElement('div');
  wrap.style.cssText = 'position:fixed;inset:0;z-index:9998;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;backdrop-filter:blur(8px);animation:fadeIn 0.2s ease-out;';
  const card = document.createElement('div');
  card.className = 'panel border p-6';
  card.style.width = 'min(640px,96vw)';
  card.style.maxHeight = '90vh';
  card.style.overflowY = 'auto';
  card.style.animation = 'scaleUp 0.25s ease-out';

  const title = document.createElement('div');
  title.className = 'text-lg font-semibold mb-4';
  title.textContent = 'VPS 登录信息（仅管理员可见）';
  card.appendChild(title);

  const rows = document.createElement('div');
  rows.className = 'space-y-4 text-sm';

  function addRow(label, value, canCopy = true, isCode = false) {
    const row = document.createElement('div');
    row.className = 'space-y-2';

    const head = document.createElement('div');
    head.className = 'muted text-xs font-medium';
    head.textContent = label;
    row.appendChild(head);

    const body = document.createElement('div');
    body.className = 'flex items-start gap-2';

    const val = isCode ? document.createElement('pre') : document.createElement('div');
    val.className = 'flex-1 modal-text-block';
    val.textContent = value || '-';
    body.appendChild(val);

    if (canCopy && value) {
      const btn = document.createElement('button');
      btn.className = 'btn-secondary text-xs px-3 py-2 whitespace-nowrap self-start';
      btn.textContent = '复制';
      btn.onclick = () => copyToClipboard(value);
      body.appendChild(btn);
    }

    row.appendChild(body);
    rows.appendChild(row);
  }

  const sponsor = v.donatedByUsername || '';
  if (sponsor) {
    addRow('赞助人', '@' + sponsor, true, false);
  }

  const flag = guessCountryFlag(v);
  const ipLoc = (v.country || '未填写') + (v.region ? ' · ' + v.region : '') + (v.ipLocation ? ' · ' + v.ipLocation : '');
  addRow('IP 归属', (flag ? flag + ' ' : '') + ipLoc, true, false);

  addRow('IP 地址', v.ip || '', true, false);
  addRow('端口', String(v.port || ''), true, false);

  addRow('系统用户名', v.username || '', true, false);
  addRow('认证方式', v.authType === 'key' ? '密钥' : '密码', false, false);

  if (v.authType === 'password') {
    addRow('登录密码', v.password || '', true, true);
  } else {
    addRow('SSH 私钥', v.privateKey || '', true, true);
  }

  const statusText = v.verifyStatus || 'unknown';
  const extra = v.verifyErrorMsg ? ('（' + v.verifyErrorMsg + '）') : '';
  addRow('验证状态', statusText + extra, false, false);

  card.appendChild(rows);

  const footer = document.createElement('div');
  footer.className = 'mt-6 flex justify-end';
  const closeBtn = document.createElement('button');
  closeBtn.textContent = '关闭';
  closeBtn.className = 'btn-secondary';
  closeBtn.onclick = () => {
    wrap.remove();
    document.removeEventListener('keydown', handleEsc);
  };
  footer.appendChild(closeBtn);
  card.appendChild(footer);

  wrap.appendChild(card);
  document.body.appendChild(wrap);

  // 添加 ESC 键关闭
  const handleEsc = (e) => {
    if (e.key === 'Escape') {
      wrap.remove();
      document.removeEventListener('keydown', handleEsc);
    }
  };
  document.addEventListener('keydown', handleEsc);

  // 点击背景关闭
  wrap.addEventListener('click', (e) => {
    if (e.target === wrap) {
      wrap.remove();
      document.removeEventListener('keydown', handleEsc);
    }
  });
}



function medalByRank(i) {
  const colors = [
    'text-amber-500', // Gold
    'text-slate-400', // Silver
    'text-orange-700', // Bronze
    'text-indigo-400'  // Others
  ];
  const color = colors[i] || colors[3];
  
  if (i === 0) return '<div class="' + color + ' w-8 h-8">' + ICONS.crown + '</div>';
  if (i === 1) return '<div class="' + color + ' w-8 h-8">' + ICONS.medal + '</div>';
  if (i === 2) return '<div class="' + color + ' w-8 h-8">' + ICONS.medal + '</div>';
  return '<div class="' + color + ' w-8 h-8 opacity-60">' + ICONS.trophy + '</div>';
}

// 勋章系统
function getBadge(count) {
  if (count >= 10) return { icon: ICONS.crown, name: '超级赞助商', color: '#FFD700', desc: '投喂10台+' };
  if (count >= 5) return { icon: ICONS.star, name: '白金赞助商', color: '#E5E4E2', desc: '投喂5-9台' };
  if (count >= 3) return { icon: ICONS.trophy, name: '金牌赞助商', color: '#CD7F32', desc: '投喂3-4台' };
  if (count >= 2) return { icon: ICONS.medal, name: '银牌赞助商', color: '#C0C0C0', desc: '投喂2台' };
  return { icon: ICONS.star, name: '新星赞助商', color: '#4A90E2', desc: '投喂1台' };
}

function renderBadge(badge) {
  return '<div class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold shadow-sm backdrop-blur-sm" ' +
    'style="background:' + badge.color + '15;border:1px solid ' + badge.color + '30;color:' + badge.color + '">' +
    '<div class="w-3.5 h-3.5">' + badge.icon + '</div>' +
    '<span>' + badge.name + '</span>' +
    '</div>';
}

// 数字计数动画
function animateNumber(element, target, duration = 800) {
  const start = 0;
  const startTime = performance.now();

  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const easeProgress = 1 - Math.pow(1 - progress, 3); // easeOutCubic
    const current = Math.floor(start + (target - start) * easeProgress);

    element.textContent = current;

    if (progress < 1) {
      requestAnimationFrame(update);
    } else {
      element.textContent = target;
    }
  }

  requestAnimationFrame(update);
}
</script>
  `;
}

/* ==================== 导出 ==================== */
export default app;
