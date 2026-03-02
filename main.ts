/// <reference lib="deno.unstable" />

import { Hono, Context, Next } from 'https://deno.land/x/hono@v3.11.7/mod.ts';
import { cors } from 'https://deno.land/x/hono@v3.11.7/middleware.ts';
import { setCookie, getCookie } from 'https://deno.land/x/hono@v3.11.7/helper.ts';

declare const Deno: any;

/* ==================== Types ==================== */
interface OAuthConfig { clientId: string; clientSecret: string; redirectUri: string; }
interface VPSServer {
  id: string; ip: string; port: number; username: string;
  authType: 'password' | 'key'; password?: string; privateKey?: string;
  donatedBy: string; donatedByUsername: string; donatedAt: number;
  status: 'active' | 'inactive' | 'failed'; note?: string; adminNote?: string;
  country: string; region?: string; traffic: string; expiryDate: string;
  specs: string; ipLocation?: string;
  verifyStatus: 'pending' | 'verified' | 'failed';
  verifyCode?: string; verifyFilePath?: string; sshFingerprint?: string;
  lastVerifyAt?: number; verifyErrorMsg?: string;
}
interface User { linuxDoId: string; username: string; avatarUrl?: string; isAdmin: boolean; createdAt: number; }
interface Session { id: string; userId: string; username: string; avatarUrl?: string; isAdmin: boolean; expiresAt: number; }

const kv = await Deno.openKv();
const DISABLE_LOGS = Deno.env.get('DISABLE_LOGS') === '1';
function log(...args: any[]) { if (!DISABLE_LOGS) console.log(...args); }

/* ==================== SVG Icons ==================== */
const ICONS: Record<string, string> = {
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
  settings: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
  note: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" x2="8" y1="13" y2="13"/><line x1="16" x2="8" y1="17" y2="17"/></svg>',
  alert: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg>',
  key: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>',
  lock: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  save: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>',
  plug: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M12 22v-5"/><path d="M9 8V2"/><path d="M15 8V2"/><path d="M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z"/></svg>',
  bulb: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M15 14c.2-1 .7-1.7 1.5-2.5 1-1 1.5-2.4 1.5-3.8 0-3.3-2.7-6-6-6 0 0-6 .7-6 6 0 1.4.5 2.8 1.5 3.8.8.8 1.3 1.5 1.5 2.5"/><path d="M9 18h6"/><path d="M10 22h4"/></svg>',
  heart: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="w-full h-full"><path d="m12 21.35-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35Z"/></svg>',
  rocket: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"/><path d="m12 15-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"/><path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"/><path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"/></svg>',
  upload: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" x2="12" y1="3" y2="15"/></svg>',
  shield: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  checkCircle: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
  warning: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" x2="12" y1="9" y2="13"/><line x1="12" x2="12.01" y1="17" y2="17"/></svg>',
  arrowLeft: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><line x1="19" x2="5" y1="12" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>',
  logout: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>',
  download: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/></svg>',
  refresh: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>',
  link: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>',
  zap: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
  activity: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-full h-full"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
};

/* ==================== Utilities ==================== */
const genId = () => crypto.randomUUID();

function cleanIPInput(raw: string): string {
  let s = String(raw);
  s = s.replace(/[\uff10-\uff19]/g, c => String.fromCharCode(c.charCodeAt(0) - 0xfee0));
  s = s.replace(/\uff1a/g, ':').replace(/\uff0e/g, '.').replace(/\u3002/g, '.');
  s = s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, '');
  s = s.replace(/[\u200b-\u200f\u2028-\u202f\u2060\ufeff\ufff0-\uffff]/g, '');
  s = s.trim();
  s = s.replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
  return s;
}

async function getIPLocation(ip: string): Promise<string> {
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=country,regionName,city`, { signal: AbortSignal.timeout(5000) });
    if (res.ok) {
      const d = await res.json();
      const parts = [d.country, d.regionName, d.city].filter(Boolean);
      if (parts.length) return parts.join(', ');
    }
  } catch (_) { }
  return '未知地区';
}

const isIPv4 = (ip: string) => {
  const t = cleanIPInput(ip);
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(t)) return false;
  return t.split('.').every(p => { const n = parseInt(p, 10); return n >= 0 && n <= 255; });
};

const isIPv6 = (ip: string) => {
  const t = cleanIPInput(ip).replace(/^\[|\]$/g, '');
  return /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/.test(t);
};

const isValidIP = (ip: string) => isIPv4(ip) || isIPv6(ip);

/* ==================== Database ==================== */
async function getAllVPS(): Promise<VPSServer[]> {
  const iter = kv.list({ prefix: ['vps'] });
  const arr: VPSServer[] = [];
  for await (const e of iter) arr.push(e.value);
  return arr.sort((a, b) => b.donatedAt - a.donatedAt);
}

async function ipDup(ip: string, port: number) {
  return (await getAllVPS()).some(v => v.ip === ip && v.port === port);
}

async function portOK(ip: string, port: number, timeoutMs = 5000): Promise<boolean> {
  try {
    const conn = await Promise.race([
      Deno.connect({ hostname: ip.replace(/^\[|\]$/g, ''), port, transport: 'tcp' }),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('timeout')), timeoutMs)),
    ]);
    try { conn.close(); } catch { }
    return true;
  } catch { return false; }
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
  if (u.value) await kv.set(['user_donations', r.value.donatedBy], u.value.filter((x: string) => x !== id));
  return true;
}

async function updVPSStatus(id: string, s: VPSServer['status']) {
  const r = await kv.get(['vps', id]);
  if (!r.value) return false;
  r.value.status = s;
  await kv.set(['vps', id], r.value);
  return true;
}

/* ==================== Config & Sessions ==================== */
const getOAuth = async () => (await kv.get(['config', 'oauth'])).value || null;
const setOAuth = async (c: OAuthConfig) => { await kv.set(['config', 'oauth'], c); };
const getAdminPwd = async () => (await kv.get(['config', 'admin_password'])).value || 'admin123';
const setAdminPwd = async (p: string) => { await kv.set(['config', 'admin_password'], p); };

async function getSession(id: string) {
  const r = await kv.get(['sessions', id]);
  if (!r.value) return null;
  if (r.value.expiresAt < Date.now()) { await kv.delete(['sessions', id]); return null; }
  return r.value;
}

async function createSession(userId: string, username: string, avatarUrl: string | undefined, isAdmin: boolean) {
  const s: Session = { id: genId(), userId, username, avatarUrl, isAdmin, expiresAt: Date.now() + 7 * 24 * 3600 * 1000 };
  await kv.set(['sessions', s.id], s);
  return s.id;
}

async function getUser(linuxDoId: string) { return (await kv.get(['users', linuxDoId])).value || null; }

async function upsertUser(linuxDoId: string, username: string, avatarUrl?: string) {
  const old = await getUser(linuxDoId);
  const u: User = { linuxDoId, username, avatarUrl, isAdmin: old?.isAdmin || false, createdAt: old?.createdAt || Date.now() };
  await kv.set(['users', linuxDoId], u);
  return u;
}

/* ==================== OAuth ==================== */
async function tokenByCode(code: string, cfg: OAuthConfig) {
  const res = await fetch('https://connect.linux.do/oauth2/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: cfg.clientId, client_secret: cfg.clientSecret, code, redirect_uri: cfg.redirectUri, grant_type: 'authorization_code' })
  });
  return res.json();
}

async function linuxDoUser(accessToken: string) {
  const r = await fetch('https://connect.linux.do/api/user', { headers: { Authorization: `Bearer ${accessToken}` } });
  return r.json();
}

/* ==================== Middleware ==================== */
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

/* ==================== Hono App ==================== */
const app = new Hono();
app.use('*', cors());

app.get('/', (c: Context) => c.redirect('/donate'));

app.get('/favicon.ico', (c: Context) => {
  const svg = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%236366f1' stroke-width='2'><path d='M19 14c1.49-1.46 3-3.21 3-5.5A5.5 5.5 0 0 0 16.5 3c-1.76 0-3 .5-4.5 2-1.5-1.5-2.74-2-4.5-2A5.5 5.5 0 0 0 2 8.5c0 2.3 1.5 4.05 3 5.5l7 7Z'/></svg>`;
  return c.body(svg, 200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' });
});

/* ---- OAuth Routes ---- */
app.get('/oauth/login', async (c: Context) => {
  const redirectPath = c.req.query('redirect') || '/donate/vps';
  const cfg = await getOAuth();
  if (!cfg) return c.html('<!doctype html><body><h1>配置错误</h1><p>OAuth 未设置</p><a href="/donate">返回</a></body>');
  const url = new URL('https://connect.linux.do/oauth2/authorize');
  url.searchParams.set('client_id', cfg.clientId);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('redirect_uri', cfg.redirectUri);
  url.searchParams.set('scope', 'openid profile');
  url.searchParams.set('state', typeof redirectPath === 'string' ? redirectPath : '/donate/vps');
  return c.redirect(url.toString());
});

app.get('/oauth/callback', async (c: Context) => {
  const code = c.req.query('code'), error = c.req.query('error'), state = c.req.query('state') || '/donate';
  if (error) return c.html(`<!doctype html><body><h1>登录失败</h1><p>${error}</p><a href="/donate">返回</a></body>`);
  if (!code) return c.text('Missing code', 400);
  try {
    const cfg = await getOAuth();
    if (!cfg) return c.html('<!doctype html><body><h1>配置错误</h1><a href="/donate">返回</a></body>');
    const token = await tokenByCode(code, cfg);
    const info = await linuxDoUser(token.access_token);
    let avatar = info.avatar_template as string | undefined;
    if (avatar) { avatar = avatar.replace('{size}', '120'); if (avatar.startsWith('//')) avatar = 'https:' + avatar; else if (avatar.startsWith('/')) avatar = 'https://connect.linux.do' + avatar; }
    const user = await upsertUser(String(info.id), info.username, avatar);
    const sid = await createSession(user.linuxDoId, user.username, user.avatarUrl, user.isAdmin);
    const isProd = Deno.env.get('DENO_DEPLOYMENT_ID') !== undefined;
    setCookie(c, 'session_id', sid, { maxAge: 7 * 24 * 3600, httpOnly: true, secure: isProd, sameSite: 'Lax', path: '/' });
    return c.redirect(typeof state === 'string' && state.startsWith('/') ? state : '/donate');
  } catch (e: any) {
    return c.html(`<!doctype html><body><h1>登录失败</h1><p>${e.message || e}</p><a href="/donate">返回</a></body>`);
  }
});

/* ---- User API ---- */
app.get('/api/logout', async (c: Context) => {
  const sid = getCookie(c, 'session_id');
  if (sid) await kv.delete(['sessions', sid]);
  setCookie(c, 'session_id', '', { maxAge: 0, path: '/' });
  return c.json({ success: true });
});

app.get('/api/user/info', requireAuth, async (c: Context) => {
  const s = c.get('session');
  const r = await kv.get(['user_donations', s.userId]);
  return c.json({ success: true, data: { username: s.username, avatarUrl: s.avatarUrl, isAdmin: s.isAdmin, donationCount: (r.value || []).length } });
});

app.get('/api/user/donations', requireAuth, async (c: Context) => {
  const s = c.get('session');
  const ids = (await kv.get(['user_donations', s.userId])).value || [];
  const arr: VPSServer[] = [];
  for (const id of ids) { const r = await kv.get(['vps', id]); if (r.value) arr.push(r.value); }
  const safe = arr.sort((a, b) => b.donatedAt - a.donatedAt).map(d => ({
    id: d.id, ip: d.ip, port: d.port, username: d.username, authType: d.authType,
    donatedAt: d.donatedAt, status: d.status, note: d.note, country: d.country, region: d.region,
    traffic: d.traffic, expiryDate: d.expiryDate, specs: d.specs, ipLocation: d.ipLocation,
    verifyStatus: d.verifyStatus, lastVerifyAt: d.lastVerifyAt, verifyErrorMsg: d.verifyErrorMsg, donatedByUsername: d.donatedByUsername
  }));
  return c.json({ success: true, data: safe });
});

app.put('/api/user/donations/:id/note', requireAuth, async (c: Context) => {
  const s = c.get('session'), id = c.req.param('id');
  const { note } = await c.req.json();
  const r = await kv.get(['vps', id]);
  if (!r.value) return c.json({ success: false, message: 'VPS 不存在' }, 404);
  if (r.value.donatedBy !== s.userId) return c.json({ success: false, message: '无权修改' }, 403);
  r.value.note = (note || '').toString();
  await kv.set(['vps', id], r.value);
  return c.json({ success: true, message: '备注已更新' });
});

/* ---- Public Leaderboard API ---- */
app.get('/api/leaderboard', async (c: Context) => {
  try {
    const all = await getAllVPS();
    const map = new Map<string, { username: string; count: number; servers: any[] }>();
    for (const v of all) {
      const rec = map.get(v.donatedBy) || { username: v.donatedByUsername, count: 0, servers: [] };
      rec.count++;
      rec.servers.push({ ipLocation: v.ipLocation || '未知地区', country: v.country || '未填写', region: v.region || '', traffic: v.traffic || '未填写', expiryDate: v.expiryDate || '未填写', specs: v.specs || '未填写', status: v.status, donatedAt: v.donatedAt, note: v.note || '' });
      map.set(v.donatedBy, rec);
    }
    return c.json({ success: true, data: Array.from(map.values()).sort((a, b) => b.count - a.count) });
  } catch (err) {
    console.error('Leaderboard error:', err);
    return c.json({ success: false, message: '加载失败' }, 500);
  }
});

/* ---- Donate API ---- */
app.post('/api/donate', requireAuth, async (c: Context) => {
  const s = c.get('session');
  const body = await c.req.json();
  const { ip, port, username, authType, password, privateKey, country, region, traffic, expiryDate, specs, note } = body;
  if (!ip || !port || !username || !authType) return c.json({ success: false, message: 'IP / 端口 / 用户名 / 认证方式 必填' }, 400);
  if (!country || !traffic || !expiryDate || !specs) return c.json({ success: false, message: '国家、流量、到期、配置 必填' }, 400);
  if (authType === 'password' && !password) return c.json({ success: false, message: '密码认证需要密码' }, 400);
  if (authType === 'key' && !privateKey) return c.json({ success: false, message: '密钥认证需要私钥' }, 400);

  const ipClean = cleanIPInput(ip);
  if (!isValidIP(ipClean)) return c.json({ success: false, message: 'IP 格式不正确' }, 400);
  const p = parseInt(String(port), 10);
  if (p < 1 || p > 65535) return c.json({ success: false, message: '端口范围 1 ~ 65535' }, 400);
  if (await ipDup(ipClean, p)) return c.json({ success: false, message: '该 IP:端口 已被投喂' }, 400);
  if (!(await portOK(ipClean, p))) return c.json({ success: false, message: '无法连接到该服务器，请确认 IP / 端口 是否正确、且对外开放' }, 400);

  const ipLoc = await getIPLocation(ipClean);
  const now = Date.now();
  const v = await addVPS({
    ip: ipClean, port: p, username, authType, password, privateKey,
    country, region: region ? String(region).trim() : undefined, traffic, expiryDate, specs, note,
    donatedBy: s.userId, donatedByUsername: s.username, donatedAt: now,
    status: 'active', ipLocation: ipLoc, verifyStatus: 'verified', lastVerifyAt: now, verifyErrorMsg: ''
  });
  return c.json({ success: true, message: '投喂成功，已通过连通性验证，感谢支持！', data: { id: v.id, ipLocation: v.ipLocation } });
});

/* ---- Admin API ---- */
app.get('/api/admin/check-session', async (c: Context) => {
  try {
    const sid = getCookie(c, 'admin_session_id');
    if (!sid) return c.json({ success: false, isAdmin: false });
    const s = await getSession(sid);
    if (!s) return c.json({ success: false, isAdmin: false });
    return c.json({ success: true, isAdmin: !!s.isAdmin, username: s.username });
  } catch { return c.json({ success: false, isAdmin: false }); }
});

app.post('/api/admin/login', async (c: Context) => {
  const { password } = await c.req.json();
  if (password !== await getAdminPwd()) return c.json({ success: false, message: '密码错误' }, 401);
  const sid = genId();
  const sess: Session = { id: sid, userId: 'admin', username: 'Administrator', avatarUrl: undefined, isAdmin: true, expiresAt: Date.now() + 7 * 24 * 3600 * 1000 };
  await kv.set(['sessions', sid], sess);
  const isProd = Deno.env.get('DENO_DEPLOYMENT_ID') !== undefined;
  setCookie(c, 'admin_session_id', sid, { maxAge: 7 * 24 * 3600, httpOnly: true, secure: isProd, sameSite: 'Lax', path: '/' });
  return c.json({ success: true, message: '登录成功' });
});

app.get('/api/admin/logout', async (c: Context) => {
  const sid = getCookie(c, 'admin_session_id');
  if (sid) await kv.delete(['sessions', sid]);
  setCookie(c, 'admin_session_id', '', { maxAge: 0, path: '/' });
  return c.json({ success: true });
});

app.get('/api/admin/vps', requireAdmin, async c => {
  try { return c.json({ success: true, data: await getAllVPS() }); }
  catch (err) { console.error('Admin VPS list error:', err); return c.json({ success: false, message: '加载失败' }, 500); }
});

app.delete('/api/admin/vps/:id', requireAdmin, async (c: Context) => {
  const ok = await delVPS(c.req.param('id'));
  return c.json(ok ? { success: true, message: 'VPS 已删除' } : { success: false, message: '不存在' }, ok ? 200 : 404);
});

app.put('/api/admin/vps/:id/status', requireAdmin, async (c: Context) => {
  const { status } = await c.req.json();
  if (!['active', 'inactive', 'failed'].includes(status)) return c.json({ success: false, message: '无效状态' }, 400);
  const ok = await updVPSStatus(c.req.param('id'), status as VPSServer['status']);
  return c.json(ok ? { success: true, message: '状态已更新' } : { success: false, message: '不存在' }, ok ? 200 : 404);
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
  return c.json({ success: true, data: (await getOAuth()) || {} });
});

app.put('/api/admin/config/oauth', requireAdmin, async (c: Context) => {
  const { clientId, clientSecret, redirectUri } = await c.req.json();
  if (!clientId || !clientSecret || !redirectUri) return c.json({ success: false, message: '字段必填' }, 400);
  await setOAuth({ clientId, clientSecret, redirectUri });
  return c.json({ success: true, message: 'OAuth 配置已更新' });
});

app.put('/api/admin/config/password', requireAdmin, async (c: Context) => {
  const { password } = await c.req.json();
  if (!password || String(password).length < 6) return c.json({ success: false, message: '密码至少 6 位' }, 400);
  await setAdminPwd(String(password));
  return c.json({ success: true, message: '管理员密码已更新' });
});

app.put('/api/admin/vps/:id/config', requireAdmin, async (c: Context) => {
  const id = c.req.param('id');
  const { ip, port, username, authType, password, privateKey } = await c.req.json();
  if (!ip || !port || !username || !authType) return c.json({ success: false, message: 'IP / 端口 / 用户名 / 认证方式 必填' }, 400);
  if (authType === 'password' && !password) return c.json({ success: false, message: '密码认证需要密码' }, 400);
  if (authType === 'key' && !privateKey) return c.json({ success: false, message: '密钥认证需要私钥' }, 400);
  const ipClean = cleanIPInput(ip);
  if (!isValidIP(ipClean)) return c.json({ success: false, message: 'IP 格式不正确' }, 400);
  const p = parseInt(String(port), 10);
  if (p < 1 || p > 65535) return c.json({ success: false, message: '端口范围 1 ~ 65535' }, 400);
  const r = await kv.get(['vps', id]);
  if (!r.value) return c.json({ success: false, message: 'VPS 不存在' }, 404);
  r.value.ip = ipClean; r.value.port = p; r.value.username = String(username).trim(); r.value.authType = authType;
  if (authType === 'password') { r.value.password = String(password); r.value.privateKey = undefined; }
  else { r.value.privateKey = String(privateKey); r.value.password = undefined; }
  const isConn = await portOK(ipClean, p);
  r.value.lastVerifyAt = Date.now();
  if (isConn) { r.value.status = 'active'; r.value.verifyStatus = 'verified'; r.value.verifyErrorMsg = ''; }
  else { r.value.verifyStatus = 'failed'; r.value.verifyErrorMsg = '无法连接到该服务器'; }
  await kv.set(['vps', id], r.value);
  return c.json({ success: true, message: isConn ? '配置更新成功，连通性验证通过' : '配置已保存，但无法连接到服务器', data: { id: r.value.id, status: r.value.status, verifyStatus: r.value.verifyStatus, lastVerifyAt: r.value.lastVerifyAt, verifyErrorMsg: r.value.verifyErrorMsg } });
});

app.get('/api/admin/stats', requireAdmin, async (c: Context) => {
  try {
    const all = await getAllVPS();
    const tzOff = 8 * 60;
    const now = new Date(); const utcMs = now.getTime() + now.getTimezoneOffset() * 60000; const cn = new Date(utcMs + tzOff * 60000);
    const cy = cn.getFullYear(), cm = cn.getMonth(), cd = cn.getDate();
    const isTodayCN = (ts: number | undefined) => { if (!ts) return false; const d = new Date(ts); const u = d.getTime() + d.getTimezoneOffset() * 60000; const c2 = new Date(u + tzOff * 60000); return c2.getFullYear() === cy && c2.getMonth() === cm && c2.getDate() === cd; };
    const uStats = new Map<string, number>();
    for (const v of all) uStats.set(v.donatedByUsername, (uStats.get(v.donatedByUsername) || 0) + 1);
    const top = Array.from(uStats.entries()).map(([username, count]) => ({ username, count })).sort((a, b) => b.count - a.count).slice(0, 10);
    return c.json({ success: true, data: { totalVPS: all.length, activeVPS: all.filter(v => v.status === 'active').length, failedVPS: all.filter(v => v.status === 'failed').length, inactiveVPS: all.filter(v => v.status === 'inactive').length, pendingVPS: all.filter(v => v.verifyStatus === 'pending').length, verifiedVPS: all.filter(v => v.verifyStatus === 'verified').length, todayNewVPS: all.filter(v => isTodayCN(v.donatedAt)).length, topDonors: top } });
  } catch (err) { console.error('Admin stats error:', err); return c.json({ success: false, message: '加载失败' }, 500); }
});

app.post('/api/admin/vps/:id/mark-verified', requireAdmin, async (c: Context) => {
  const r = await kv.get(['vps', c.req.param('id')]);
  if (!r.value) return c.json({ success: false, message: '不存在' }, 404);
  r.value.verifyStatus = 'verified'; r.value.status = 'active'; r.value.lastVerifyAt = Date.now(); r.value.verifyErrorMsg = '';
  await kv.set(['vps', c.req.param('id')], r.value);
  return c.json({ success: true, message: '已标记为验证通过' });
});

app.post('/api/admin/vps/:id/verify', requireAdmin, async (c: Context) => {
  const id = c.req.param('id');
  const r = await kv.get(['vps', id]);
  if (!r.value) return c.json({ success: false, message: '不存在' }, 404);
  const v = r.value;
  const ok = await portOK(v.ip, v.port);
  v.lastVerifyAt = Date.now();
  if (ok) { v.status = 'active'; v.verifyStatus = 'verified'; v.verifyErrorMsg = ''; }
  else { v.status = 'failed'; v.verifyStatus = 'failed'; v.verifyErrorMsg = '无法连接VPS'; }
  await kv.set(['vps', id], v);
  return c.json({ success: ok, message: ok ? '验证成功，VPS 连通正常' : '验证失败，无法连接VPS', data: { status: v.status, verifyStatus: v.verifyStatus, verifyErrorMsg: v.verifyErrorMsg, lastVerifyAt: v.lastVerifyAt } });
});

app.post('/api/admin/verify-all', requireAdmin, async (c: Context) => {
  const all = await getAllVPS();
  let total = 0, success = 0, failed = 0;
  for (const v of all) {
    total++;
    const ok = await portOK(v.ip, v.port);
    v.lastVerifyAt = Date.now();
    if (ok) { v.status = 'active'; v.verifyStatus = 'verified'; v.verifyErrorMsg = ''; success++; }
    else { v.status = 'failed'; v.verifyStatus = 'failed'; v.verifyErrorMsg = '无法连接'; failed++; }
    await kv.set(['vps', v.id], v);
  }
  return c.json({ success: true, message: `验证完成: ${success} 成功 / ${failed} 失败 / ${total} 总计` });
});

/* ==================== commonHead: CSS Design System ==================== */
function commonHead(title: string): string {
  return `
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>${title}</title>
<link rel="icon" href="/favicon.ico" />
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"><\/script>
<script>
tailwind.config = {
  darkMode: 'class',
  theme: { extend: {
    fontFamily: { sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'] },
  }}
}
<\/script>
<style>
:root {
  --bg-primary: #0a0a1a;
  --bg-card: rgba(15, 15, 35, 0.8);
  --bg-card-hover: rgba(25, 25, 55, 0.9);
  --border-color: rgba(255, 255, 255, 0.06);
  --border-hover: rgba(99, 102, 241, 0.3);
  --text-primary: #e2e8f0;
  --text-secondary: #94a3b8;
  --text-muted: #64748b;
  --accent: #6366f1;
  --accent-light: #818cf8;
  --accent-glow: rgba(99, 102, 241, 0.15);
  --success: #10b981;
  --warning: #f59e0b;
  --error: #ef4444;
  --glass-blur: 16px;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  font-family: 'Inter', -apple-system, sans-serif;
  -webkit-font-smoothing: antialiased;
  background: var(--bg-primary);
  color: var(--text-primary);
  min-height: 100vh;
}

/* Glass Card */
.glass-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 1.25rem;
  backdrop-filter: blur(var(--glass-blur));
  -webkit-backdrop-filter: blur(var(--glass-blur));
  transition: all 0.3s ease;
}
.glass-card:hover {
  border-color: var(--border-hover);
  background: var(--bg-card-hover);
  box-shadow: 0 0 30px var(--accent-glow);
}

/* Buttons */
.btn-primary {
  display: inline-flex; align-items: center; justify-content: center; gap: 0.5rem;
  padding: 0.75rem 1.5rem; border-radius: 0.75rem; font-weight: 600; font-size: 0.875rem;
  background: linear-gradient(135deg, var(--accent), #8b5cf6);
  color: white; border: none; cursor: pointer;
  transition: all 0.3s ease; position: relative; overflow: hidden;
}
.btn-primary:hover { transform: translateY(-1px); box-shadow: 0 8px 25px rgba(99,102,241,0.35); }
.btn-primary:active { transform: translateY(0); }
.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }

.btn-secondary {
  display: inline-flex; align-items: center; justify-content: center; gap: 0.5rem;
  padding: 0.625rem 1.25rem; border-radius: 0.75rem; font-weight: 500; font-size: 0.875rem;
  background: rgba(255,255,255,0.05); color: var(--text-primary);
  border: 1px solid var(--border-color); cursor: pointer;
  transition: all 0.2s ease;
}
.btn-secondary:hover { background: rgba(255,255,255,0.1); border-color: var(--border-hover); }

.btn-danger {
  display: inline-flex; align-items: center; justify-content: center; gap: 0.5rem;
  padding: 0.5rem 1rem; border-radius: 0.5rem; font-weight: 500; font-size: 0.8rem;
  background: rgba(239,68,68,0.1); color: #f87171;
  border: 1px solid rgba(239,68,68,0.2); cursor: pointer; transition: all 0.2s ease;
}
.btn-danger:hover { background: rgba(239,68,68,0.2); }

.btn-sm {
  padding: 0.375rem 0.75rem; font-size: 0.75rem; border-radius: 0.5rem;
}

/* Inputs */
.input-field {
  width: 100%; padding: 0.75rem 1rem; padding-left: 2.75rem;
  background: rgba(0,0,0,0.3);
  border: 1px solid var(--border-color); border-radius: 0.75rem;
  color: var(--text-primary); font-size: 0.9rem; outline: none;
  transition: all 0.2s ease;
}
.input-field:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }
.input-field::placeholder { color: var(--text-muted); }
.input-field.error { border-color: var(--error); box-shadow: 0 0 0 3px rgba(239,68,68,0.15); }
.input-field.success { border-color: var(--success); box-shadow: 0 0 0 3px rgba(16,185,129,0.15); }

.select-field {
  width: 100%; padding: 0.75rem 1rem; padding-left: 2.75rem;
  background: rgba(0,0,0,0.3);
  border: 1px solid var(--border-color); border-radius: 0.75rem;
  color: var(--text-primary); font-size: 0.9rem; outline: none;
  appearance: none; cursor: pointer; transition: all 0.2s ease;
}
.select-field:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }
.select-field option { background: #1a1a2e; color: var(--text-primary); }

.textarea-field {
  width: 100%; padding: 0.75rem 1rem; padding-left: 2.75rem;
  background: rgba(0,0,0,0.3);
  border: 1px solid var(--border-color); border-radius: 0.75rem;
  color: var(--text-primary); font-size: 0.9rem; outline: none;
  resize: vertical; min-height: 80px; transition: all 0.2s ease;
}
.textarea-field:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }

/* Status Badges */
.badge { display: inline-flex; align-items: center; gap: 0.375rem; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.7rem; font-weight: 600; }
.badge-ok { background: rgba(16,185,129,0.1); color: #34d399; border: 1px solid rgba(16,185,129,0.2); }
.badge-fail { background: rgba(239,68,68,0.1); color: #f87171; border: 1px solid rgba(239,68,68,0.2); }
.badge-idle { background: rgba(100,116,139,0.1); color: #94a3b8; border: 1px solid rgba(100,116,139,0.2); }
.badge-warn { background: rgba(245,158,11,0.1); color: #fbbf24; border: 1px solid rgba(245,158,11,0.2); }
.badge-info { background: rgba(99,102,241,0.1); color: #818cf8; border: 1px solid rgba(99,102,241,0.2); }

/* Toast */
#toast-root { position: fixed; top: 1.5rem; right: 1.5rem; z-index: 9999; display: flex; flex-direction: column; gap: 0.75rem; pointer-events: none; }
.toast-item {
  pointer-events: auto; display: flex; align-items: center; gap: 0.75rem;
  padding: 0.875rem 1.25rem; border-radius: 0.875rem;
  background: rgba(20, 20, 40, 0.95); border: 1px solid var(--border-color);
  backdrop-filter: blur(16px); color: var(--text-primary); font-size: 0.875rem;
  box-shadow: 0 8px 32px rgba(0,0,0,0.4); min-width: 280px;
  animation: toast-in 0.35s cubic-bezier(0.21, 1.02, 0.73, 1) forwards;
}
.toast-item.removing { animation: toast-out 0.3s ease forwards; }
.toast-icon { width: 1.25rem; height: 1.25rem; flex-shrink: 0; }
.toast-success .toast-icon { color: var(--success); }
.toast-error .toast-icon { color: var(--error); }
.toast-warn .toast-icon { color: var(--warning); }
.toast-info .toast-icon { color: var(--accent-light); }

/* Animations */
@keyframes toast-in { from { opacity: 0; transform: translateX(100%); } to { opacity: 1; transform: translateX(0); } }
@keyframes toast-out { from { opacity: 1; transform: translateX(0); } to { opacity: 0; transform: translateX(100%); } }
@keyframes fade-in { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
@keyframes slide-up { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
@keyframes pulse-glow { 0%, 100% { box-shadow: 0 0 20px var(--accent-glow); } 50% { box-shadow: 0 0 40px rgba(99,102,241,0.3); } }
@keyframes spin { to { transform: rotate(360deg); } }
.animate-fade-in { animation: fade-in 0.5s ease forwards; }
.animate-slide-up { animation: slide-up 0.6s ease forwards; opacity: 0; }

/* Loading Spinner */
.loading-spinner { width: 1.5rem; height: 1.5rem; border: 2px solid var(--border-color); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; }

/* Skeleton */
.skeleton { background: linear-gradient(90deg, rgba(255,255,255,0.04) 25%, rgba(255,255,255,0.08) 50%, rgba(255,255,255,0.04) 75%); background-size: 200% 100%; animation: skeleton-loading 1.5s ease-in-out infinite; border-radius: 0.5rem; }
@keyframes skeleton-loading { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }

/* Scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }

/* Alert boxes */
.alert-info { background: rgba(99,102,241,0.08); border: 1px solid rgba(99,102,241,0.15); border-radius: 0.75rem; padding: 1rem; color: #a5b4fc; }
.alert-warning { background: rgba(245,158,11,0.08); border: 1px solid rgba(245,158,11,0.15); border-radius: 0.75rem; padding: 1rem; color: #fcd34d; }

/* Modal */
.modal-overlay { position: fixed; inset: 0; z-index: 50; display: flex; align-items: center; justify-content: center; padding: 1rem; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); }
.modal-content { width: 100%; max-width: 40rem; max-height: 90vh; overflow-y: auto; background: #13141f; border: 1px solid var(--border-color); border-radius: 1.25rem; }
</style>
<script>
// Toast system
function toast(msg, type='info', duration=3000) {
  let root = document.getElementById('toast-root');
  if (!root) { root = document.createElement('div'); root.id = 'toast-root'; document.body.appendChild(root); }
  const icons = {
    success: '${ICONS.checkCircle}',
    error: '${ICONS.x}',
    warn: '${ICONS.warning}',
    info: '${ICONS.info}'
  };
  const el = document.createElement('div');
  el.className = 'toast-item toast-' + type;
  el.innerHTML = '<div class="toast-icon">' + (icons[type] || icons.info) + '</div><span>' + msg + '</span>';
  root.appendChild(el);
  setTimeout(() => { el.classList.add('removing'); setTimeout(() => el.remove(), 300); }, duration);
}

// Prompt modal
function promptModal(title, fields, onSubmit) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  let html = '<div class="modal-content"><div class="p-6 border-b border-white/5"><h3 class="text-lg font-bold">' + title + '</h3></div><div class="p-6 space-y-4">';
  fields.forEach((f, i) => {
    html += '<div><label class="block text-sm text-slate-400 mb-1.5">' + f.label + '</label>';
    if (f.type === 'textarea') html += '<textarea id="pm-f-'+i+'" class="textarea-field !pl-3" rows="3">' + (f.value||'') + '</textarea>';
    else html += '<input id="pm-f-'+i+'" type="'+(f.type||'text')+'" value="'+(f.value||'')+'" class="input-field !pl-3" />';
    html += '</div>';
  });
  html += '</div><div class="p-6 border-t border-white/5 flex gap-3 justify-end"><button id="pm-cancel" class="btn-secondary">取消</button><button id="pm-ok" class="btn-primary">确定</button></div></div>';
  overlay.innerHTML = html;
  document.body.appendChild(overlay);
  const close = () => overlay.remove();
  overlay.querySelector('#pm-cancel').addEventListener('click', close);
  overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
  overlay.querySelector('#pm-ok').addEventListener('click', () => {
    const data = fields.map((f, i) => document.getElementById('pm-f-'+i).value);
    onSubmit(data, close);
  });
}
<\/script>
`;
}

/* ==================== Page: /donate (Leaderboard) ==================== */
function getBadge(count: number) {
  if (count >= 10) return { icon: ICONS.crown, name: '超级赞助商', color: '#FFD700' };
  if (count >= 5) return { icon: ICONS.star, name: '白金赞助商', color: '#E5E4E2' };
  if (count >= 3) return { icon: ICONS.trophy, name: '金牌赞助商', color: '#CD7F32' };
  if (count >= 2) return { icon: ICONS.medal, name: '银牌赞助商', color: '#C0C0C0' };
  return { icon: ICONS.star, name: '新星赞助商', color: '#4A90E2' };
}
function renderBadgeHTML(b: ReturnType<typeof getBadge>) {
  return `<div class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold" style="background:${b.color}15;border:1px solid ${b.color}30;color:${b.color}"><div class="w-3.5 h-3.5">${b.icon}</div><span>${b.name}</span></div>`;
}
function rankIcon(i: number) {
  const colors = ['text-yellow-400', 'text-slate-300', 'text-amber-600', 'text-slate-500'];
  const c = colors[i] || colors[3];
  if (i === 0) return `<div class="${c} w-8 h-8">${ICONS.crown}</div>`;
  if (i <= 2) return `<div class="${c} w-8 h-8">${ICONS.medal}</div>`;
  return `<div class="${c} w-8 h-8 opacity-60">${ICONS.trophy}</div>`;
}

app.get('/donate', async (c: Context) => {
  const head = commonHead('VPS 投喂榜');
  const html = `<!doctype html><html lang="zh-CN"><head>${head}</head>
<body>
<div class="fixed inset-0 -z-10 overflow-hidden pointer-events-none">
  <div class="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-indigo-600/10 rounded-full blur-[120px]"></div>
  <div class="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-purple-600/10 rounded-full blur-[120px]"></div>
</div>
<div class="max-w-7xl mx-auto px-4 sm:px-6 py-8 md:py-16">
  <!-- Header -->
  <header class="text-center mb-16 animate-fade-in">
    <div class="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 text-sm font-medium mb-6">
      <div class="w-4 h-4">${ICONS.heart}</div><span>公益节点网络</span>
    </div>
    <h1 class="text-4xl md:text-6xl font-extrabold text-white mb-4 tracking-tight">VPS 投喂榜</h1>
    <p class="text-lg text-slate-400 max-w-2xl mx-auto">感谢每一位无私奉献的赞助商，共建公益机场节点网络</p>
    <div class="flex items-center justify-center gap-4 mt-8">
      <a href="/oauth/login?redirect=/donate/vps" class="btn-primary text-base px-8 py-3">
        <div class="w-5 h-5">${ICONS.rocket}</div> 我要投喂 VPS
      </a>
    </div>
  </header>

  <!-- Stats -->
  <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-12 animate-slide-up" style="animation-delay:0.1s">
    <div class="glass-card p-5 text-center"><div class="text-3xl font-bold text-white" id="stat-total">-</div><div class="text-sm text-slate-400 mt-1">总投喂数</div></div>
    <div class="glass-card p-5 text-center"><div class="text-3xl font-bold text-emerald-400" id="stat-active">-</div><div class="text-sm text-slate-400 mt-1">运行中</div></div>
    <div class="glass-card p-5 text-center"><div class="text-3xl font-bold text-indigo-400" id="stat-donors">-</div><div class="text-sm text-slate-400 mt-1">赞助商</div></div>
    <div class="glass-card p-5 text-center"><div class="text-3xl font-bold text-purple-400" id="stat-regions">-</div><div class="text-sm text-slate-400 mt-1">覆盖地区</div></div>
  </div>


  <!-- Globe -->
  <div class="glass-card mb-12 overflow-hidden animate-slide-up" style="animation-delay:0.2s">
    <div id="globe-container" style="width:100%;height:500px;position:relative;"></div>
  </div>

  <!-- Leaderboard -->
  <section class="animate-slide-up" style="animation-delay:0.3s">
    <div class="flex items-center gap-3 mb-8">
      <div class="w-8 h-8 text-indigo-400">${ICONS.chart}</div>
      <h2 class="text-2xl font-bold text-white">排行榜</h2>
    </div>
    <div id="leaderboard" class="space-y-4">
      <div class="glass-card p-8 text-center"><div class="loading-spinner mx-auto mb-3"></div><div class="text-sm text-slate-400">加载中...</div></div>
    </div>
  </section>

  <footer class="mt-20 pb-8 text-center">
    <div class="inline-flex items-center gap-2 px-6 py-3 rounded-full bg-white/5 border border-white/5 text-slate-500 text-sm">
      <div class="w-4 h-4">${ICONS.heart}</div> 感谢您为公益事业做出的贡献
    </div>
  </footer>
</div>
<div id="toast-root"></div>
<script src="https://unpkg.com/globe.gl@2.27.0/dist/globe.gl.min.js"><\/script>
<script>
const ICONS_CLIENT = {
  server: '${ICONS.server}', globe: '${ICONS.globe}', calendar: '${ICONS.calendar}',
  cpu: '${ICONS.cpu}', clock: '${ICONS.clock}', chart: '${ICONS.chart}',
  crown: '${ICONS.crown}', medal: '${ICONS.medal}', trophy: '${ICONS.trophy}',
  star: '${ICONS.star}', heart: '${ICONS.heart}', activity: '${ICONS.activity}',
  zap: '${ICONS.zap}', checkCircle: '${ICONS.checkCircle}', x: '${ICONS.x}'
};

function getBadgeClient(count) {
  if (count >= 10) return { icon: ICONS_CLIENT.crown, name: '超级赞助商', color: '#FFD700' };
  if (count >= 5) return { icon: ICONS_CLIENT.star, name: '白金赞助商', color: '#E5E4E2' };
  if (count >= 3) return { icon: ICONS_CLIENT.trophy, name: '金牌赞助商', color: '#CD7F32' };
  if (count >= 2) return { icon: ICONS_CLIENT.medal, name: '银牌赞助商', color: '#C0C0C0' };
  return { icon: ICONS_CLIENT.star, name: '新星赞助商', color: '#4A90E2' };
}

function renderBadge(b) {
  return '<div class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold" style="background:'+b.color+'15;border:1px solid '+b.color+'30;color:'+b.color+'"><div class="w-3.5 h-3.5">'+b.icon+'</div><span>'+b.name+'</span></div>';
}

function rankIconClient(i) {
  const c = ['text-yellow-400','text-slate-300','text-amber-600','text-slate-500'][Math.min(i,3)];
  if (i===0) return '<div class="'+c+' w-8 h-8">'+ICONS_CLIENT.crown+'</div>';
  if (i<=2) return '<div class="'+c+' w-8 h-8">'+ICONS_CLIENT.medal+'</div>';
  return '<div class="'+c+' w-7 h-7 opacity-60">'+ICONS_CLIENT.trophy+'</div>';
}

async function loadLeaderboard() {
  try {
    const res = await fetch('/api/leaderboard',{cache:'no-store'});
    const j = await res.json();
    if (!j.success) return;
    const data = j.data || [];
    const lb = document.getElementById('leaderboard');
    if (!data.length) { lb.innerHTML = '<div class="glass-card p-12 text-center text-slate-400">暂无投喂记录</div>'; return; }

    let totalServers=0, activeServers=0, regions=new Set();
    data.forEach(d => { totalServers+=d.count; d.servers.forEach(s => { if(s.status==='active') activeServers++; if(s.ipLocation) regions.add(s.ipLocation.split(',')[0].trim()); }); });
    document.getElementById('stat-total').textContent = totalServers;
    document.getElementById('stat-active').textContent = activeServers;
    document.getElementById('stat-donors').textContent = data.length;
    document.getElementById('stat-regions').textContent = regions.size;

    lb.innerHTML = '';
    data.forEach((donor, i) => {
      const badge = getBadgeClient(donor.count);
      const card = document.createElement('div');
      card.className = 'glass-card p-6 transition-all';
      let serversHTML = donor.servers.map(s => {
        const statusBadge = s.status==='active' ? '<span class="badge badge-ok"><div class="w-3 h-3">'+ICONS_CLIENT.checkCircle+'</div>运行中</span>' : '<span class="badge badge-fail"><div class="w-3 h-3">'+ICONS_CLIENT.x+'</div>离线</span>';
        return '<div class="flex items-center justify-between py-2 px-3 rounded-lg bg-white/[0.02] mb-1.5 text-sm">' +
          '<div class="flex items-center gap-2"><div class="w-3.5 h-3.5 text-slate-500">'+ICONS_CLIENT.server+'</div><span class="text-slate-300">'+(s.ipLocation||'未知地区')+'</span></div>' +
          '<div class="flex items-center gap-3">'+statusBadge+'<span class="text-slate-500 text-xs">'+(s.specs||'')+'</span></div></div>';
      }).join('');
      card.innerHTML = '<div class="flex items-center gap-4 mb-4">' +
        '<div class="flex-shrink-0">'+rankIconClient(i)+'</div>' +
        '<div class="flex-1 min-w-0"><div class="flex items-center gap-3 flex-wrap"><a href="https://linux.do/u/'+encodeURIComponent(donor.username)+'" target="_blank" class="text-lg font-bold text-white hover:text-indigo-400 transition-colors">'+donor.username+'</a>'+renderBadge(badge)+'</div>' +
        '<div class="text-sm text-slate-400 mt-1">共投喂 '+donor.count+' 台服务器</div></div>' +
        '<div class="text-2xl font-bold text-indigo-400">#'+(i+1)+'</div></div>' +
        '<div class="space-y-0.5">'+serversHTML+'</div>';
      lb.appendChild(card);
    });

    // Init Globe
    initGlobe(data);
  } catch(err) {
    console.error('Leaderboard error:', err);
    document.getElementById('leaderboard').innerHTML = '<div class="glass-card p-8 text-center text-red-400">加载失败</div>';
  }
}

const LOCATION_DB = {
  'Hong Kong':{ lat:22.3193, lng:114.1694 }, '香港':{ lat:22.3193, lng:114.1694 },
  'Japan':{ lat:35.6762, lng:139.6503 }, '日本':{ lat:35.6762, lng:139.6503 }, 'Tokyo':{ lat:35.6762, lng:139.6503 }, '东京':{ lat:35.6762, lng:139.6503 }, 'Osaka':{ lat:34.6937, lng:135.5023 }, '大阪':{ lat:34.6937, lng:135.5023 },
  'Singapore':{ lat:1.3521, lng:103.8198 }, '新加坡':{ lat:1.3521, lng:103.8198 },
  'Taiwan':{ lat:25.0330, lng:121.5654 }, '台湾':{ lat:25.0330, lng:121.5654 }, 'Taipei':{ lat:25.0330, lng:121.5654 },
  'Korea':{ lat:37.5665, lng:126.9780 }, '韩国':{ lat:37.5665, lng:126.9780 }, 'Seoul':{ lat:37.5665, lng:126.9780 },
  'US':{ lat:37.0902, lng:-95.7129 }, 'USA':{ lat:37.0902, lng:-95.7129 }, '美国':{ lat:37.0902, lng:-95.7129 },
  'Los Angeles':{ lat:34.0522, lng:-118.2437 }, '洛杉矶':{ lat:34.0522, lng:-118.2437 },
  'San Jose':{ lat:37.3382, lng:-121.8863 }, '圣何塞':{ lat:37.3382, lng:-121.8863 },
  'New York':{ lat:40.7128, lng:-74.0060 }, '纽约':{ lat:40.7128, lng:-74.0060 },
  'Seattle':{ lat:47.6062, lng:-122.3321 }, 'Chicago':{ lat:41.8781, lng:-87.6298 },
  'UK':{ lat:51.5074, lng:-0.1278 }, '英国':{ lat:51.5074, lng:-0.1278 }, 'London':{ lat:51.5074, lng:-0.1278 },
  'Germany':{ lat:50.1109, lng:8.6821 }, '德国':{ lat:50.1109, lng:8.6821 }, 'Frankfurt':{ lat:50.1109, lng:8.6821 },
  'France':{ lat:48.8566, lng:2.3522 }, '法国':{ lat:48.8566, lng:2.3522 }, 'Paris':{ lat:48.8566, lng:2.3522 },
  'Netherlands':{ lat:52.3676, lng:4.9041 }, '荷兰':{ lat:52.3676, lng:4.9041 }, 'Amsterdam':{ lat:52.3676, lng:4.9041 },
  'Australia':{ lat:-33.8688, lng:151.2093 }, '澳大利亚':{ lat:-33.8688, lng:151.2093 }, 'Sydney':{ lat:-33.8688, lng:151.2093 },
  'Canada':{ lat:43.6532, lng:-79.3832 }, '加拿大':{ lat:43.6532, lng:-79.3832 }, 'Toronto':{ lat:43.6532, lng:-79.3832 },
  'Russia':{ lat:55.7558, lng:37.6173 }, '俄罗斯':{ lat:55.7558, lng:37.6173 }, 'Moscow':{ lat:55.7558, lng:37.6173 },
  'India':{ lat:19.0760, lng:72.8777 }, '印度':{ lat:19.0760, lng:72.8777 }, 'Mumbai':{ lat:19.0760, lng:72.8777 },
  'Brazil':{ lat:-23.5505, lng:-46.6333 }, '巴西':{ lat:-23.5505, lng:-46.6333 },
  'Turkey':{ lat:41.0082, lng:28.9784 }, '土耳其':{ lat:41.0082, lng:28.9784 },
  'China':{ lat:39.9042, lng:116.4074 }, '中国':{ lat:39.9042, lng:116.4074 }, 'Beijing':{ lat:39.9042, lng:116.4074 }, 'Shanghai':{ lat:31.2304, lng:121.4737 }, '上海':{ lat:31.2304, lng:121.4737 }, '广州':{ lat:23.1291, lng:113.2644 }, '深圳':{ lat:22.5431, lng:114.0579 },
};

function resolveLocation(loc) {
  if (!loc) return null;
  const clean = loc.trim();
  if (LOCATION_DB[clean]) return LOCATION_DB[clean];
  const lower = clean.toLowerCase();
  for (const [k, v] of Object.entries(LOCATION_DB)) {
    if (k.toLowerCase().includes(lower) || lower.includes(k.toLowerCase())) return v;
  }
  const parts = clean.split(/[,，\s]+/);
  for (const p of parts) {
    const pl = p.trim().toLowerCase();
    for (const [k, v] of Object.entries(LOCATION_DB)) {
      if (k.toLowerCase().includes(pl) || pl.includes(k.toLowerCase())) return v;
    }
  }
  return null;
}

const FLAG_MAP = {
  'HK':'🇭🇰','JP':'🇯🇵','SG':'🇸🇬','TW':'🇹🇼','KR':'🇰🇷','US':'🇺🇸','USA':'🇺🇸','DE':'🇩🇪','GB':'🇬🇧','UK':'🇬🇧',
  'CN':'🇨🇳','IN':'🇮🇳','TH':'🇹🇭','VN':'🇻🇳','MY':'🇲🇾','PH':'🇵🇭','ID':'🇮🇩','FR':'🇫🇷','NL':'🇳🇱','RU':'🇷🇺',
  'SE':'🇸🇪','FI':'🇫🇮','PL':'🇵🇱','IT':'🇮🇹','ES':'🇪🇸','CH':'🇨🇭','AT':'🇦🇹','CA':'🇨🇦','BR':'🇧🇷','AU':'🇦🇺',
  'NZ':'🇳🇿','TR':'🇹🇷','ZA':'🇿🇦','AE':'🇦🇪','IL':'🇮🇱','MX':'🇲🇽','AR':'🇦🇷','NO':'🇳🇴','DK':'🇩🇰','IE':'🇮🇪',
  'PT':'🇵🇹','BE':'🇧🇪','CZ':'🇨🇿','UA':'🇺🇦','RO':'🇷🇴','HU':'🇭🇺','EG':'🇪🇬','SA':'🇸🇦','CL':'🇨🇱','CO':'🇨🇴',
  'Hong Kong':'🇭🇰','Japan':'🇯🇵','Singapore':'🇸🇬','Taiwan':'🇹🇼','Korea':'🇰🇷',
  '香港':'🇭🇰','日本':'🇯🇵','新加坡':'🇸🇬','台湾':'🇹🇼','韩国':'🇰🇷','美国':'🇺🇸','德国':'🇩🇪','英国':'🇬🇧',
  '中国':'🇨🇳','法国':'🇫🇷','荷兰':'🇳🇱','俄罗斯':'🇷🇺','加拿大':'🇨🇦','澳大利亚':'🇦🇺','巴西':'🇧🇷','印度':'🇮🇳',
  '土耳其':'🇹🇷','瑞典':'🇸🇪','芬兰':'🇫🇮','波兰':'🇵🇱','意大利':'🇮🇹','西班牙':'🇪🇸','瑞士':'🇨🇭','泰国':'🇹🇭','越南':'🇻🇳',
};

const CODE_MAP = {
  'HK':'344','JP':'392','SG':'702','TW':'158','KR':'410','US':'840','USA':'840','DE':'276','GB':'826','UK':'826',
  'CN':'156','IN':'356','TH':'764','VN':'704','MY':'458','PH':'608','ID':'360','FR':'250','NL':'528','RU':'643',
  'SE':'752','FI':'246','PL':'616','IT':'380','ES':'724','CH':'756','AT':'040','CA':'124','BR':'076','AU':'036',
  'NZ':'554','TR':'792','ZA':'710','AE':'784','IL':'376','MX':'484','AR':'032','NO':'578','DK':'208','IE':'372',
  'Hong Kong':'344','Japan':'392','Singapore':'702','Taiwan':'158','Korea':'410',
  '香港':'344','日本':'392','新加坡':'702','台湾':'158','韩国':'410','美国':'840','德国':'276','英国':'826',
  '中国':'156','法国':'250','荷兰':'528','俄罗斯':'643','加拿大':'124','澳大利亚':'036','巴西':'076','印度':'356','土耳其':'792',
};

function getFlag(c) {
  if (!c) return '🌍';
  if (FLAG_MAP[c]) return FLAG_MAP[c];
  for (const [k,v] of Object.entries(FLAG_MAP)) { if (c.toLowerCase().includes(k.toLowerCase())) return v; }
  return '🌍';
}
function getISO3(c) {
  if (!c) return null;
  if (CODE_MAP[c]) return CODE_MAP[c];
  for (const [k,v] of Object.entries(CODE_MAP)) { if (c.toLowerCase().includes(k.toLowerCase())) return v; }
  return null;
}

let geoData = null;
async function loadGeoJSON() {
  try {
    const r = await fetch('https://unpkg.com/world-atlas@2/countries-110m.json');
    const topo = await r.json();
    // Convert TopoJSON to GeoJSON
    const countries = topo.objects.countries;
    const arcs = topo.arcs;
    function decodeArc(arcIdx) {
      const reverse = arcIdx < 0;
      const arc = arcs[reverse ? ~arcIdx : arcIdx];
      const coords = [];
      let x = 0, y = 0;
      for (const [dx, dy] of arc) {
        x += dx; y += dy;
        coords.push([
          x * topo.transform.scale[0] + topo.transform.translate[0],
          y * topo.transform.scale[1] + topo.transform.translate[1]
        ]);
      }
      if (reverse) coords.reverse();
      return coords;
    }
    function decodeRing(arcIndices) {
      let coords = [];
      for (const idx of arcIndices) {
        const decoded = decodeArc(idx);
        coords = coords.concat(decoded);
      }
      return coords;
    }
    const features = countries.geometries.map(g => {
      let coordinates;
      if (g.type === 'Polygon') {
        coordinates = g.arcs.map(ring => decodeRing(ring));
      } else if (g.type === 'MultiPolygon') {
        coordinates = g.arcs.map(polygon => polygon.map(ring => decodeRing(ring)));
      }
      return { type: 'Feature', id: g.id, properties: g.properties || {}, geometry: { type: g.type, coordinates } };
    });
    geoData = features;
    return features;
  } catch(err) { console.error('GeoJSON load error:', err); return []; }
}

function initGlobe(data) {
  if (typeof Globe === 'undefined') { document.getElementById('globe-container').innerHTML='<div class="flex items-center justify-center h-full text-slate-500">地球加载失败</div>'; return; }
  const container = document.getElementById('globe-container');

  const countryMap = new Map();
  data.forEach(d => d.servers.forEach(s => {
    const key = s.country || s.ipLocation || '未知';
    const coords = resolveLocation(s.ipLocation) || resolveLocation(s.country);
    if (coords) {
      const rec = countryMap.get(key) || { country: key, lat: coords.lat, lng: coords.lng, count: 0 };
      rec.count++;
      countryMap.set(key, rec);
    }
  }));
  const countries = Array.from(countryMap.values());

  const arcs = [];
  for (let i = 0; i < countries.length; i++) {
    for (let j = i + 1; j < countries.length; j++) {
      arcs.push({ startLat: countries[i].lat, startLng: countries[i].lng, endLat: countries[j].lat, endLng: countries[j].lng });
    }
  }

  const activeISO3 = new Set();
  countries.forEach(c => { const iso = getISO3(c.country); if (iso) activeISO3.add(iso); });

  loadGeoJSON().then(geo => {
    const activePolygons = geo.filter(f => activeISO3.has(f.id));

    try {
      const globe = Globe()(container)
        .width(container.clientWidth)
        .height(container.clientHeight)
        .globeImageUrl('//unpkg.com/three-globe/example/img/earth-night.jpg')
        .bumpImageUrl('//unpkg.com/three-globe/example/img/earth-topology.png')
        .backgroundColor('rgba(0,0,0,0)')
        .atmosphereColor('rgba(99,102,241,0.25)')
        .atmosphereAltitude(0.2)
        .showGraticules(false)
        .polygonsData(activePolygons)
        .polygonCapColor(() => 'rgba(99,102,241,0.2)')
        .polygonSideColor(() => 'rgba(99,102,241,0.08)')
        .polygonStrokeColor(() => 'rgba(99,102,241,0.6)')
        .polygonAltitude(0.006)
        .arcsData(arcs)
        .arcStartLat(d => d.startLat).arcStartLng(d => d.startLng)
        .arcEndLat(d => d.endLat).arcEndLng(d => d.endLng)
        .arcColor(() => ['rgba(99,102,241,0.3)', 'rgba(139,92,246,0.3)'])
        .arcStroke(0.4)
        .arcDashLength(0.5)
        .arcDashGap(0.3)
        .arcDashAnimateTime(2500)
        .arcDashInitialGap(() => Math.random());
      globe.controls().autoRotate = true;
      globe.controls().autoRotateSpeed = 0.4;
      globe.controls().enableZoom = true;
      globe.controls().enableRotate = true;
      window.addEventListener('resize', () => { globe.width(container.clientWidth).height(container.clientHeight); });
    } catch(err) { console.error('Globe error:', err); }
  });
}

loadLeaderboard();
<\/script>
</body></html>`;
  return c.html(html);
});

/* ==================== Page: /donate/vps (VPS Donation Form) ==================== */
app.get('/donate/vps', (c: Context) => {
  const head = commonHead('VPS 投喂中心');
  const today = new Date();
  const minDate = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`;
  const html = `<!doctype html><html lang="zh-CN"><head>${head}</head>
<body>
<div class="fixed inset-0 -z-10 overflow-hidden pointer-events-none">
  <div class="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-indigo-600/10 rounded-full blur-[120px]"></div>
  <div class="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-purple-600/10 rounded-full blur-[120px]"></div>
</div>
<div class="max-w-[1500px] mx-auto px-4 sm:px-6 py-8 md:py-12">
  <header class="mb-10 animate-fade-in flex flex-col md:flex-row md:items-center justify-between gap-4">
    <div>
      <h1 class="text-3xl md:text-4xl font-bold text-white mb-2 flex items-center gap-3">
        <div class="w-8 h-8 text-indigo-400">${ICONS.rocket}</div> VPS 投喂中心
      </h1>
      <p class="text-slate-400 flex items-center gap-2"><div class="w-4 h-4 text-pink-500">${ICONS.heart}</div> 共建公益节点网络</p>
    </div>
    <div class="flex items-center gap-3">
      <div id="user-info" class="hidden md:block px-4 py-2 rounded-full text-sm border border-white/5 bg-white/5 text-slate-300"></div>
      <a href="/donate" class="btn-secondary"><div class="w-4 h-4">${ICONS.arrowLeft}</div> 首页</a>
      <button onclick="doLogout()" class="btn-secondary hover:!border-red-500/30 hover:!text-red-300"><div class="w-4 h-4">${ICONS.logout}</div> 退出</button>
    </div>
  </header>

  <div class="grid lg:grid-cols-12 gap-8 items-start">
    <!-- Left: Form -->
    <section class="lg:col-span-7 animate-slide-up" style="animation-delay:0.1s">
      <div class="glass-card p-8">
        <div class="flex items-center gap-4 mb-6">
          <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-white"><div class="w-6 h-6">${ICONS.server}</div></div>
          <div><h2 class="text-xl font-bold text-white">提交新节点</h2><p class="text-slate-400 text-sm mt-0.5">请填写服务器连接信息</p></div>
        </div>
        <div class="alert-info flex gap-3 mb-6 text-sm"><div class="w-5 h-5 flex-shrink-0 mt-0.5">${ICONS.info}</div><span>请确保服务器是你有控制权的机器。禁止提交被黑/扫描到的机器。</span></div>

        <form id="donate-form" class="space-y-6">
          <div class="grid md:grid-cols-2 gap-5">
            <div><label class="block mb-2 text-sm font-medium text-slate-400">服务器 IP <span class="text-red-400">*</span></label>
              <div class="relative"><div class="absolute left-3.5 top-3 w-5 h-5 text-slate-500">${ICONS.globe}</div>
              <input name="ip" required placeholder="1.2.3.4" class="input-field" /></div>
              <div class="text-xs text-slate-600 mt-1.5">支持 IPv4 / IPv6</div></div>
            <div><label class="block mb-2 text-sm font-medium text-slate-400">端口 <span class="text-red-400">*</span></label>
              <div class="relative"><div class="absolute left-3.5 top-3 w-5 h-5 text-slate-500">${ICONS.plug}</div>
              <input name="port" required type="number" min="1" max="65535" placeholder="22" class="input-field" /></div></div>
          </div>
          <div class="grid md:grid-cols-2 gap-5">
            <div><label class="block mb-2 text-sm font-medium text-slate-400">用户名 <span class="text-red-400">*</span></label>
              <div class="relative"><div class="absolute left-3.5 top-3 w-5 h-5 text-slate-500">${ICONS.user}</div>
              <input name="username" required placeholder="root" class="input-field" /></div></div>
            <div><label class="block mb-2 text-sm font-medium text-slate-400">认证方式 <span class="text-red-400">*</span></label>
              <div class="relative"><div class="absolute left-3.5 top-3 w-5 h-5 text-slate-500">${ICONS.lock}</div>
              <select name="authType" class="select-field"><option value="password">密码认证</option><option value="key">私钥认证</option></select>
              <div class="absolute right-3 top-3.5 w-4 h-4 text-slate-500 pointer-events-none">${ICONS.chevronDown}</div></div></div>
          </div>
          <div id="password-field"><label class="block mb-2 text-sm font-medium text-slate-400">密码</label>
            <div class="relative"><div class="absolute left-3.5 top-3 w-5 h-5 text-slate-500">${ICONS.key}</div>
            <input name="password" type="password" placeholder="SSH 密码" class="input-field" /></div></div>
          <div id="private-key-field" class="hidden"><label class="block mb-2 text-sm font-medium text-slate-400">私钥</label>
            <div class="relative"><div class="absolute left-3.5 top-3 w-5 h-5 text-slate-500">${ICONS.key}</div>
            <textarea name="privateKey" rows="4" placeholder="粘贴 SSH 私钥内容" class="textarea-field"></textarea></div></div>
          <div class="grid md:grid-cols-2 gap-5">
            <div><label class="block mb-2 text-sm font-medium text-slate-400">国家/地区 <span class="text-red-400">*</span></label>
              <div class="relative"><div class="absolute left-3.5 top-3 w-5 h-5 text-slate-500">${ICONS.globe}</div>
              <select name="country" required class="select-field">
                <option value="" disabled selected>请选择国家/地区</option>
                <optgroup label="热门地区">
                  <option value="HK">🇭🇰 香港 (Hong Kong)</option>
                  <option value="JP">🇯🇵 日本 (Japan)</option>
                  <option value="SG">🇸🇬 新加坡 (Singapore)</option>
                  <option value="TW">🇹🇼 台湾 (Taiwan)</option>
                  <option value="KR">🇰🇷 韩国 (Korea)</option>
                  <option value="US">🇺🇸 美国 (USA)</option>
                  <option value="DE">🇩🇪 德国 (Germany)</option>
                  <option value="GB">🇬🇧 英国 (UK)</option>
                  <option value="NL">🇳🇱 荷兰 (Netherlands)</option>
                  <option value="FR">🇫🇷 法国 (France)</option>
                </optgroup>
                <optgroup label="亚洲">
                  <option value="CN">🇨🇳 中国 (China)</option>
                  <option value="IN">🇮🇳 印度 (India)</option>
                  <option value="TH">🇹🇭 泰国 (Thailand)</option>
                  <option value="VN">🇻🇳 越南 (Vietnam)</option>
                  <option value="MY">🇲🇾 马来西亚 (Malaysia)</option>
                  <option value="PH">🇵🇭 菲律宾 (Philippines)</option>
                  <option value="ID">🇮🇩 印尼 (Indonesia)</option>
                  <option value="BD">🇧🇩 孟加拉 (Bangladesh)</option>
                  <option value="PK">🇵🇰 巴基斯坦 (Pakistan)</option>
                  <option value="MM">🇲🇲 缅甸 (Myanmar)</option>
                  <option value="KH">🇰🇭 柬埔寨 (Cambodia)</option>
                  <option value="LA">🇱🇦 老挝 (Laos)</option>
                  <option value="MN">🇲🇳 蒙古 (Mongolia)</option>
                  <option value="NP">🇳🇵 尼泊尔 (Nepal)</option>
                  <option value="LK">🇱🇰 斯里兰卡 (Sri Lanka)</option>
                  <option value="KZ">🇰🇿 哈萨克斯坦 (Kazakhstan)</option>
                  <option value="UZ">🇺🇿 乌兹别克斯坦 (Uzbekistan)</option>
                  <option value="MO">🇲🇴 澳门 (Macau)</option>
                </optgroup>
                <optgroup label="欧洲">
                  <option value="RU">🇷🇺 俄罗斯 (Russia)</option>
                  <option value="SE">🇸🇪 瑞典 (Sweden)</option>
                  <option value="FI">🇫🇮 芬兰 (Finland)</option>
                  <option value="NO">🇳🇴 挪威 (Norway)</option>
                  <option value="DK">🇩🇰 丹麦 (Denmark)</option>
                  <option value="PL">🇵🇱 波兰 (Poland)</option>
                  <option value="IT">🇮🇹 意大利 (Italy)</option>
                  <option value="ES">🇪🇸 西班牙 (Spain)</option>
                  <option value="PT">🇵🇹 葡萄牙 (Portugal)</option>
                  <option value="CH">🇨🇭 瑞士 (Switzerland)</option>
                  <option value="AT">🇦🇹 奥地利 (Austria)</option>
                  <option value="BE">🇧🇪 比利时 (Belgium)</option>
                  <option value="IE">🇮🇪 爱尔兰 (Ireland)</option>
                  <option value="CZ">🇨🇿 捷克 (Czech Republic)</option>
                  <option value="RO">🇷🇴 罗马尼亚 (Romania)</option>
                  <option value="HU">🇭🇺 匈牙利 (Hungary)</option>
                  <option value="UA">🇺🇦 乌克兰 (Ukraine)</option>
                  <option value="BG">🇧🇬 保加利亚 (Bulgaria)</option>
                  <option value="HR">🇭🇷 克罗地亚 (Croatia)</option>
                  <option value="LT">🇱🇹 立陶宛 (Lithuania)</option>
                  <option value="LV">🇱🇻 拉脱维亚 (Latvia)</option>
                  <option value="EE">🇪🇪 爱沙尼亚 (Estonia)</option>
                  <option value="GR">🇬🇷 希腊 (Greece)</option>
                  <option value="LU">🇱🇺 卢森堡 (Luxembourg)</option>
                  <option value="IS">🇮🇸 冰岛 (Iceland)</option>
                  <option value="MD">🇲🇩 摩尔多瓦 (Moldova)</option>
                  <option value="RS">🇷🇸 塞尔维亚 (Serbia)</option>
                </optgroup>
                <optgroup label="美洲">
                  <option value="CA">🇨🇦 加拿大 (Canada)</option>
                  <option value="BR">🇧🇷 巴西 (Brazil)</option>
                  <option value="AR">🇦🇷 阿根廷 (Argentina)</option>
                  <option value="MX">🇲🇽 墨西哥 (Mexico)</option>
                  <option value="CL">🇨🇱 智利 (Chile)</option>
                  <option value="CO">🇨🇴 哥伦比亚 (Colombia)</option>
                  <option value="PE">🇵🇪 秘鲁 (Peru)</option>
                  <option value="PA">🇵🇦 巴拿马 (Panama)</option>
                  <option value="CR">🇨🇷 哥斯达黎加 (Costa Rica)</option>
                </optgroup>
                <optgroup label="中东">
                  <option value="AE">🇦🇪 阿联酋 (UAE)</option>
                  <option value="SA">🇸🇦 沙特 (Saudi Arabia)</option>
                  <option value="IL">🇮🇱 以色列 (Israel)</option>
                  <option value="TR">🇹🇷 土耳其 (Turkey)</option>
                  <option value="QA">🇶🇦 卡塔尔 (Qatar)</option>
                  <option value="BH">🇧🇭 巴林 (Bahrain)</option>
                  <option value="OM">🇴🇲 阿曼 (Oman)</option>
                  <option value="IR">🇮🇷 伊朗 (Iran)</option>
                  <option value="IQ">🇮🇶 伊拉克 (Iraq)</option>
                </optgroup>
                <optgroup label="大洋洲">
                  <option value="AU">🇦🇺 澳大利亚 (Australia)</option>
                  <option value="NZ">🇳🇿 新西兰 (New Zealand)</option>
                  <option value="FJ">🇫🇯 斐济 (Fiji)</option>
                </optgroup>
                <optgroup label="非洲">
                  <option value="ZA">🇿🇦 南非 (South Africa)</option>
                  <option value="EG">🇪🇬 埃及 (Egypt)</option>
                  <option value="NG">🇳🇬 尼日利亚 (Nigeria)</option>
                  <option value="KE">🇰🇪 肯尼亚 (Kenya)</option>
                  <option value="MA">🇲🇦 摩洛哥 (Morocco)</option>
                  <option value="TN">🇹🇳 突尼斯 (Tunisia)</option>
                </optgroup>
                <optgroup label="其他">
                  <option value="OTHER">🌍 其他 (Other)</option>
                </optgroup>
              </select>
              <div class="absolute right-3 top-3.5 w-4 h-4 text-slate-500 pointer-events-none">${ICONS.chevronDown}</div></div></div>
            <div><label class="block mb-2 text-sm font-medium text-slate-400">地区/城市</label>
              <div class="relative"><div class="absolute left-3.5 top-3 w-5 h-5 text-slate-500">${ICONS.globe}</div>
              <input name="region" placeholder="如：东京、洛杉矶" class="input-field" /></div></div>
          </div>
          <div class="grid md:grid-cols-3 gap-5">
            <div><label class="block mb-2 text-sm font-medium text-slate-400">流量 <span class="text-red-400">*</span></label>
              <div class="relative"><div class="absolute left-3.5 top-3 w-5 h-5 text-slate-500">${ICONS.activity}</div>
              <input name="traffic" required placeholder="如：1TB/月" class="input-field" /></div></div>
            <div><label class="block mb-2 text-sm font-medium text-slate-400">到期时间 <span class="text-red-400">*</span></label>
              <div class="relative"><div class="absolute left-3.5 top-3 w-5 h-5 text-slate-500">${ICONS.calendar}</div>
              <input name="expiryDate" required type="date" min="${minDate}" class="input-field" /></div></div>
            <div><label class="block mb-2 text-sm font-medium text-slate-400">配置 <span class="text-red-400">*</span></label>
              <div class="relative"><div class="absolute left-3.5 top-3 w-5 h-5 text-slate-500">${ICONS.cpu}</div>
              <input name="specs" required placeholder="如：2C4G" class="input-field" /></div></div>
          </div>
          <div><label class="block mb-2 text-sm font-medium text-slate-400">备注 <span class="text-slate-600 text-xs">(可选)</span></label>
            <div class="relative"><div class="absolute left-3.5 top-3 w-5 h-5 text-slate-500">${ICONS.message}</div>
            <textarea name="note" rows="2" placeholder="三网回程优化，解锁流媒体..." class="textarea-field"></textarea></div></div>
          <div id="donate-message" class="text-sm min-h-[1.25rem] font-medium text-center"></div>
          <button id="donate-submit-btn" type="submit" class="btn-primary w-full py-4 text-lg">
            <div class="w-5 h-5">${ICONS.rocket}</div> 提交投喂
          </button>
        </form>
      </div>
    </section>

    <!-- Right: My Donations -->
    <section class="lg:col-span-5 animate-slide-up" style="animation-delay:0.2s">
      <div class="glass-card p-6">
        <div class="flex items-center justify-between mb-6">
          <div class="flex items-center gap-3"><div class="w-6 h-6 text-indigo-400">${ICONS.server}</div><h3 class="text-lg font-bold text-white">我的投喂</h3></div>
          <button onclick="exportDonations()" class="btn-secondary btn-sm"><div class="w-3.5 h-3.5">${ICONS.download}</div> 导出</button>
        </div>
        <div id="donations-list" class="space-y-3"></div>
      </div>
    </section>
  </div>
</div>
<div id="toast-root"></div>
<script>
function clientCleanIP(raw){
  let s=String(raw||'');
  s=s.replace(/[\\uff10-\\uff19]/g,c=>String.fromCharCode(c.charCodeAt(0)-0xfee0));
  s=s.replace(/\\uff1a/g,':').replace(/\\uff0e/g,'.').replace(/\\u3002/g,'.');
  s=s.replace(/[\\u0000-\\u0008\\u000b\\u000c\\u000e-\\u001f\\u007f-\\u009f]/g,'');
  s=s.replace(/[\\u200b-\\u200f\\u2028-\\u202f\\u2060\\ufeff]/g,'');
  s=s.trim().replace(/^https?:\\/\\//i,'').replace(/\\/.*$/,'');
  return s;
}
const isIPv4=ip=>{const t=ip.trim();if(!/^(\\d{1,3}\\.){3}\\d{1,3}$/.test(t))return false;return t.split('.').every(p=>{const n=parseInt(p,10);return n>=0&&n<=255;});};
const isIPv6=ip=>/^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/.test(ip.trim().replace(/^\\[|\\]$/g,''));

async function ensureLogin(){try{const r=await fetch('/api/user/info',{credentials:'same-origin',cache:'no-store'});if(!r.ok){location.href='/donate';return;}const j=await r.json();if(j.success&&j.data){const d=j.data;const el=document.getElementById('user-info');if(el){el.textContent=d.username;el.classList.remove('hidden');}}}catch{location.href='/donate';}}
async function doLogout(){try{await fetch('/api/logout',{credentials:'same-origin'});}catch{}location.href='/donate';}

function bindAuthType(){
  const sel=document.querySelector('select[name="authType"]');
  const pwd=document.getElementById('password-field'),key=document.getElementById('private-key-field');
  if(sel&&pwd&&key){sel.addEventListener('change',()=>{if(sel.value==='password'){pwd.classList.remove('hidden');key.classList.add('hidden');}else{pwd.classList.add('hidden');key.classList.remove('hidden');}});}
}

async function submitDonate(e){
  e.preventDefault();
  const form=e.target,msg=document.getElementById('donate-message'),btn=document.getElementById('donate-submit-btn');
  msg.textContent='';msg.className='text-sm min-h-[1.25rem]';
  const fd=new FormData(form);
  const ip=clientCleanIP(fd.get('ip'));
  const payload={ip,port:Number(fd.get('port')||''),username:fd.get('username')?.toString().trim(),authType:fd.get('authType')?.toString(),password:fd.get('password')?.toString(),privateKey:fd.get('privateKey')?.toString(),country:fd.get('country')?.toString().trim(),region:fd.get('region')?.toString().trim(),traffic:fd.get('traffic')?.toString().trim(),expiryDate:fd.get('expiryDate')?.toString().trim(),specs:fd.get('specs')?.toString().trim(),note:fd.get('note')?.toString().trim()};
  btn.disabled=true;const origHTML=btn.innerHTML;btn.innerHTML='<span>提交中...</span>';
  try{
    const r=await fetch('/api/donate',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const j=await r.json();
    if(!r.ok||!j.success){msg.textContent=j.message||'提交失败';msg.className='text-sm min-h-[1.25rem] text-red-400';toast(j.message||'投喂失败','error');}
    else{msg.textContent=j.message||'投喂成功';msg.className='text-sm min-h-[1.25rem] text-emerald-400';toast(j.message||'投喂成功','success');setTimeout(()=>{form.reset();loadDonations();},1500);}
  }catch{msg.textContent='提交异常';msg.className='text-sm min-h-[1.25rem] text-red-400';toast('提交异常','error');}
  finally{setTimeout(()=>{btn.disabled=false;btn.innerHTML=origHTML;},500);}
}

async function loadDonations(){
  const box=document.getElementById('donations-list');
  box.innerHTML='<div class="flex items-center justify-center py-8"><div class="loading-spinner"></div></div>';
  try{
    const r=await fetch('/api/user/donations',{credentials:'same-origin',cache:'no-store'});
    const j=await r.json();
    if(!r.ok||!j.success){box.innerHTML='<div class="text-sm text-slate-500 text-center py-4">加载失败</div>';return;}
    const data=j.data||[];
    if(!data.length){box.innerHTML='<div class="text-sm text-slate-500 text-center py-8">暂无投喂记录</div>';return;}
    box.innerHTML='';
    data.forEach(v=>{
      const sBadge=v.status==='active'?'<span class="badge badge-ok">运行中</span>':(v.status==='failed'?'<span class="badge badge-fail">失败</span>':'<span class="badge badge-idle">未启用</span>');
      const dt=v.donatedAt?new Date(v.donatedAt).toLocaleString():'';
      const div=document.createElement('div');
      div.className='p-4 rounded-xl bg-white/[0.03] border border-white/5 hover:border-indigo-500/20 transition-all';
      div.innerHTML='<div class="flex items-center justify-between mb-2"><span class="text-sm font-medium text-white">'+v.ip+':'+v.port+'</span>'+sBadge+'</div><div class="grid grid-cols-2 gap-2 text-xs text-slate-400"><span>'+(v.ipLocation||v.country||'')+'</span><span>'+v.specs+'</span><span>'+(v.traffic||'')+'</span><span>到期: '+(v.expiryDate||'')+'</span></div>'+(dt?'<div class="text-xs text-slate-600 mt-2">'+dt+'</div>':'');
      box.appendChild(div);
    });
  }catch{box.innerHTML='<div class="text-sm text-red-400 text-center py-4">加载异常</div>';}
}

async function exportDonations(){
  try{const r=await fetch('/api/user/donations',{credentials:'same-origin',cache:'no-store'});const j=await r.json();if(!r.ok||!j.success){toast('导出失败','error');return;}
  const blob=new Blob([JSON.stringify(j.data,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='my-vps-'+Date.now()+'.json';a.click();URL.revokeObjectURL(a.href);toast('导出成功','success');}catch{toast('导出异常','error');}
}

// IP realtime validation
const ipInput=document.querySelector('input[name="ip"]');
if(ipInput){let t=null;ipInput.addEventListener('input',function(){const v=clientCleanIP(this.value);if(t)clearTimeout(t);if(!v){this.classList.remove('error','success');return;}t=setTimeout(()=>{if(isIPv4(v)||isIPv6(v)){this.classList.remove('error');this.classList.add('success');}else{this.classList.remove('success');this.classList.add('error');}},300);});ipInput.addEventListener('focus',function(){this.classList.remove('error','success');});}

ensureLogin();bindAuthType();
document.getElementById('donate-form').addEventListener('submit',submitDonate);
loadDonations();
<\/script>
</body></html>`;
  return c.html(html);
});

/* ==================== Page: /admin (Admin Panel) ==================== */
app.get('/admin', (c: Context) => {
  const head = commonHead('管理后台');
  const html = `<!doctype html><html lang="zh-CN"><head>${head}</head>
<body>
<div class="fixed inset-0 -z-10 overflow-hidden pointer-events-none">
  <div class="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-indigo-600/8 rounded-full blur-[120px]"></div>
  <div class="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-purple-600/8 rounded-full blur-[120px]"></div>
</div>
<div id="admin-root" class="max-w-7xl mx-auto px-4 sm:px-6 py-8">
  <!-- Login Form (shown initially) -->
  <div id="login-panel" class="min-h-screen flex items-center justify-center">
    <div class="glass-card p-10 max-w-md w-full text-center">
      <div class="w-16 h-16 mx-auto mb-6 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-white"><div class="w-8 h-8">${ICONS.shield}</div></div>
      <h1 class="text-2xl font-bold text-white mb-2">管理后台</h1>
      <p class="text-slate-400 text-sm mb-8">请输入管理员密码</p>
      <div class="relative mb-4"><div class="absolute left-3.5 top-3 w-5 h-5 text-slate-500">${ICONS.lock}</div>
        <input id="admin-pwd" type="password" placeholder="管理员密码" class="input-field" onkeydown="if(event.key==='Enter')doAdminLogin()" /></div>
      <button onclick="doAdminLogin()" class="btn-primary w-full py-3">登录</button>
      <a href="/donate" class="block mt-4 text-sm text-slate-500 hover:text-indigo-400 transition-colors">返回首页</a>
    </div>
  </div>

  <!-- Admin Dashboard (hidden initially) -->
  <div id="admin-dashboard" class="hidden">
    <header class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 text-indigo-400">${ICONS.shield}</div>
        <h1 class="text-2xl font-bold text-white">管理后台</h1>
      </div>
      <div class="flex gap-3">
        <a href="/donate" class="btn-secondary"><div class="w-4 h-4">${ICONS.arrowLeft}</div> 首页</a>
        <button onclick="doAdminLogout()" class="btn-secondary hover:!border-red-500/30 hover:!text-red-300"><div class="w-4 h-4">${ICONS.logout}</div> 退出</button>
      </div>
    </header>
    <div id="admin-stats" class="mb-8"></div>
    <div class="grid md:grid-cols-2 gap-6 mb-8">
      <!-- OAuth Config -->
      <div class="glass-card p-6">
        <div class="flex items-center gap-3 mb-4"><div class="w-5 h-5 text-indigo-400">${ICONS.link}</div><h2 class="font-bold text-white">OAuth 配置</h2></div>
        <div id="oauth-form" class="space-y-3">
          <input id="oauth-cid" placeholder="Client ID" class="input-field !pl-3 text-sm" />
          <input id="oauth-secret" placeholder="Client Secret" type="password" class="input-field !pl-3 text-sm" />
          <input id="oauth-redir" placeholder="Redirect URI" class="input-field !pl-3 text-sm" />
          <button onclick="saveOAuth()" class="btn-primary w-full"><div class="w-4 h-4">${ICONS.save}</div> 保存</button>
        </div>
      </div>
      <!-- Admin Password -->
      <div class="glass-card p-6">
        <div class="flex items-center gap-3 mb-4"><div class="w-5 h-5 text-indigo-400">${ICONS.key}</div><h2 class="font-bold text-white">管理员密码</h2></div>
        <div class="space-y-3">
          <input id="new-pwd" type="password" placeholder="新密码（至少6位）" class="input-field !pl-3 text-sm" />
          <input id="new-pwd2" type="password" placeholder="确认密码" class="input-field !pl-3 text-sm" />
          <button onclick="saveAdminPwd()" class="btn-primary w-full"><div class="w-4 h-4">${ICONS.lock}</div> 保存密码</button>
        </div>
      </div>
    </div>

    <!-- VPS List -->
    <div class="glass-card p-6 mb-6">
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
        <div class="flex items-center gap-3"><div class="w-5 h-5 text-indigo-400">${ICONS.server}</div><h2 class="font-bold text-white">VPS 管理</h2></div>
        <div class="flex gap-2 flex-wrap">
          <button data-status="all" class="btn-secondary btn-sm" onclick="setFilter('all')">全部</button>
          <button data-status="active" class="btn-secondary btn-sm" onclick="setFilter('active')">运行中</button>
          <button data-status="failed" class="btn-secondary btn-sm" onclick="setFilter('failed')">失败</button>
          <button data-status="inactive" class="btn-secondary btn-sm" onclick="setFilter('inactive')">未启用</button>
          <button onclick="verifyAll()" class="btn-primary btn-sm"><div class="w-3.5 h-3.5">${ICONS.refresh}</div> 全部验证</button>
        </div>
      </div>
      <div class="relative mb-4"><div class="absolute left-3.5 top-2.5 w-4 h-4 text-slate-500">${ICONS.search}</div>
        <input id="filter-input" placeholder="搜索 IP / 用户名 / 地区..." class="input-field !py-2.5 text-sm" oninput="searchFilter=this.value;renderVpsList()" /></div>
    </div>
    <div id="vps-list" class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4"></div>
  </div>
</div>
<div id="toast-root"></div>
<script>
let allVpsList=[], statusFilter='all', searchFilter='', userFilter='';

async function doAdminLogin(){
  const pwd=document.getElementById('admin-pwd').value;
  if(!pwd){toast('请输入密码','warn');return;}
  try{const r=await fetch('/api/admin/login',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pwd})});
  const j=await r.json();if(!r.ok||!j.success){toast(j.message||'登录失败','error');return;}
  toast('登录成功','success');initDashboard();}catch{toast('登录异常','error');}
}
async function doAdminLogout(){try{await fetch('/api/admin/logout',{credentials:'same-origin'});}catch{}location.reload();}

async function checkSession(){
  try{const r=await fetch('/api/admin/check-session',{credentials:'same-origin',cache:'no-store'});const j=await r.json();if(j.success&&j.isAdmin)initDashboard();}catch{}
}

function initDashboard(){
  document.getElementById('login-panel').classList.add('hidden');
  document.getElementById('admin-dashboard').classList.remove('hidden');
  loadStats();loadOAuth();loadVps();
}

function setFilter(s){statusFilter=s;userFilter='';renderVpsList();}

async function loadStats(){
  const w=document.getElementById('admin-stats');
  w.innerHTML='<div class="flex justify-center py-6"><div class="loading-spinner"></div></div>';
  try{const r=await fetch('/api/admin/stats',{credentials:'same-origin',cache:'no-store'});const j=await r.json();if(!j.success)return;const d=j.data;
  w.innerHTML='<div class="grid grid-cols-2 md:grid-cols-4 gap-4">'+
    '<div class="glass-card p-5 text-center"><div class="text-2xl font-bold text-white">'+d.totalVPS+'</div><div class="text-xs text-slate-400 mt-1">总投喂</div></div>'+
    '<div class="glass-card p-5 text-center"><div class="text-2xl font-bold text-emerald-400">'+d.activeVPS+'</div><div class="text-xs text-slate-400 mt-1">运行中</div></div>'+
    '<div class="glass-card p-5 text-center"><div class="text-2xl font-bold text-red-400">'+d.failedVPS+'</div><div class="text-xs text-slate-400 mt-1">失败</div></div>'+
    '<div class="glass-card p-5 text-center"><div class="text-2xl font-bold text-amber-400">'+(d.todayNewVPS||0)+'</div><div class="text-xs text-slate-400 mt-1">今日新增</div></div></div>';
  }catch{w.innerHTML='<div class="text-red-400 text-sm">统计加载失败</div>';}
}

async function loadOAuth(){
  try{const r=await fetch('/api/admin/config/oauth',{credentials:'same-origin',cache:'no-store'});const j=await r.json();const d=j.data||{};
  document.getElementById('oauth-cid').value=d.clientId||'';document.getElementById('oauth-secret').value=d.clientSecret||'';document.getElementById('oauth-redir').value=d.redirectUri||'';}catch{}
}
async function saveOAuth(){
  const cid=document.getElementById('oauth-cid').value.trim(),sec=document.getElementById('oauth-secret').value.trim(),redir=document.getElementById('oauth-redir').value.trim();
  if(!cid||!sec||!redir){toast('请填写所有字段','warn');return;}
  try{const r=await fetch('/api/admin/config/oauth',{method:'PUT',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({clientId:cid,clientSecret:sec,redirectUri:redir})});
  const j=await r.json();toast(j.message||'已保存',j.success?'success':'error');}catch{toast('保存异常','error');}
}
async function saveAdminPwd(){
  const p1=document.getElementById('new-pwd').value.trim(),p2=document.getElementById('new-pwd2').value.trim();
  if(!p1||!p2){toast('请填写密码','warn');return;}if(p1!==p2){toast('两次密码不一致','error');return;}if(p1.length<6){toast('密码至少6位','warn');return;}
  try{const r=await fetch('/api/admin/config/password',{method:'PUT',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p1})});
  const j=await r.json();toast(j.message||'已更新',j.success?'success':'error');if(j.success){document.getElementById('new-pwd').value='';document.getElementById('new-pwd2').value='';}}catch{toast('保存异常','error');}
}

async function loadVps(){
  const list=document.getElementById('vps-list');
  list.innerHTML='<div class="col-span-full flex justify-center py-8"><div class="loading-spinner"></div></div>';
  try{const r=await fetch('/api/admin/vps',{credentials:'same-origin',cache:'no-store'});const j=await r.json();
  if(!j.success){list.innerHTML='<div class="text-red-400 text-sm col-span-full">加载失败</div>';return;}
  allVpsList=j.data||[];renderVpsList();}catch(err){list.innerHTML='<div class="text-red-400 text-sm col-span-full">加载异常</div>';}
}

function renderVpsList(){
  const list=document.getElementById('vps-list');list.innerHTML='';
  let filtered=allVpsList;
  if(statusFilter!=='all')filtered=filtered.filter(v=>v.status===statusFilter);
  if(userFilter)filtered=filtered.filter(v=>v.donatedByUsername===userFilter);
  if(searchFilter){const q=searchFilter.toLowerCase();filtered=filtered.filter(v=>(v.ip||'').toLowerCase().includes(q)||(v.donatedByUsername||'').toLowerCase().includes(q)||(v.ipLocation||'').toLowerCase().includes(q)||(v.country||'').toLowerCase().includes(q));}
  if(!filtered.length){list.innerHTML='<div class="col-span-full text-center text-slate-500 py-8">无匹配结果</div>';return;}
  filtered.forEach(v=>{
    const sBadge=v.status==='active'?'<span class="badge badge-ok">运行中</span>':(v.status==='failed'?'<span class="badge badge-fail">失败</span>':'<span class="badge badge-idle">未启用</span>');
    const vBadge=v.verifyStatus==='verified'?'<span class="badge badge-info">已验证</span>':(v.verifyStatus==='failed'?'<span class="badge badge-warn">验证失败</span>':'<span class="badge badge-idle">待验证</span>');
    const card=document.createElement('div');card.className='glass-card p-5';
    card.innerHTML='<div class="flex items-center justify-between mb-3"><span class="text-sm font-mono font-medium text-white">'+v.ip+':'+v.port+'</span><div class="flex gap-1.5">'+sBadge+vBadge+'</div></div>'+
      '<div class="space-y-1.5 text-xs text-slate-400 mb-4"><div class="flex justify-between"><span>用户: <a href="https://linux.do/u/'+encodeURIComponent(v.donatedByUsername)+'" target="_blank" class="text-indigo-400 hover:underline cursor-pointer">'+v.donatedByUsername+'</a></span><span>'+(v.ipLocation||v.country||'')+'</span></div>'+
      '<div class="flex justify-between"><span>配置: '+(v.specs||'-')+'</span><span>流量: '+(v.traffic||'-')+'</span></div>'+
      '<div class="flex justify-between"><span>到期: '+(v.expiryDate||'-')+'</span><span>认证: '+(v.authType||'-')+'</span></div>'+
      (v.verifyErrorMsg?'<div class="text-red-400/70">'+v.verifyErrorMsg+'</div>':'')+
      (v.note?'<div class="text-slate-500 truncate">备注: '+v.note+'</div>':'')+
      '</div><div class="flex gap-2 flex-wrap"><button class="btn-secondary btn-sm" data-act="config">查看配置</button><button class="btn-secondary btn-sm" data-act="verify">验证</button><button class="btn-secondary btn-sm" data-act="edit">编辑</button><button class="btn-danger btn-sm" data-act="delete">删除</button></div>';
    card.querySelectorAll('button[data-act]').forEach(btn=>{
      btn.addEventListener('click',async()=>{
        const act=btn.dataset.act;
        if(act==='config'){showConfigModal(v);}
        else if(act==='delete'){if(!confirm('确定删除此VPS？'))return;try{const r=await fetch('/api/admin/vps/'+v.id,{method:'DELETE',credentials:'same-origin'});const j=await r.json();toast(j.message||'已删除',j.success?'success':'error');await loadVps();await loadStats();}catch{toast('删除异常','error');}}
        else if(act==='verify'){try{const r=await fetch('/api/admin/vps/'+v.id+'/verify',{method:'POST',credentials:'same-origin'});const j=await r.json();toast(j.message||'已验证',j.success?'success':'error');await loadVps();await loadStats();}catch{toast('验证异常','error');}}
        else if(act==='edit'){openEditModal(v.id);}
      });
    });
    list.appendChild(card);
  });
}

function showConfigModal(v) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.id = 'config-modal';
  const maskPwd = (s) => s ? (s.length > 3 ? s.substring(0, 3) + '***' : '***') : '未设置';
  const closeModal = () => { const m = document.getElementById('config-modal'); if(m) m.remove(); };
  const isKey = v.authType !== 'password';
  const secretValue = isKey ? (v.privateKey||'') : (v.password||'');
  const statusColor = v.status==='active' ? 'text-emerald-400' : (v.status==='failed' ? 'text-red-400' : 'text-slate-400');
  const statusText = v.status==='active' ? '运行中' : (v.status==='failed' ? '失败' : '未启用');
  overlay.innerHTML = '<div class="modal-content" style="max-width:44rem"><div class="p-6 border-b border-white/5 flex items-center justify-between"><h3 class="font-bold text-white">VPS 详细配置</h3><button id="cfg-close-x" class="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-white/10"><div class="w-5 h-5 opacity-60">${ICONS.x}</div></button></div>' +
    '<div class="p-6 space-y-4">' +
    '<div class="flex items-center justify-between"><div class="flex items-center gap-3"><span class="text-lg font-mono font-bold text-white">' + v.ip + ':' + v.port + '</span><span class="badge ' + (v.status==='active'?'badge-ok':(v.status==='failed'?'badge-fail':'badge-idle')) + '">' + statusText + '</span></div></div>' +
    '<div class="grid grid-cols-2 gap-3 text-sm">' +
    '<div class="p-3 rounded-lg bg-white/5"><div class="text-xs text-slate-500 mb-1">捐助人</div><a href="https://linux.do/u/' + encodeURIComponent(v.donatedByUsername||'') + '" target="_blank" class="text-indigo-400 hover:underline">' + (v.donatedByUsername||'-') + '</a></div>' +
    '<div class="p-3 rounded-lg bg-white/5"><div class="text-xs text-slate-500 mb-1">国家/地区</div><div class="text-white">' + (v.country||'-') + (v.ipLocation ? ' / '+v.ipLocation : '') + '</div></div>' +
    '<div class="p-3 rounded-lg bg-white/5"><div class="text-xs text-slate-500 mb-1">配置</div><div class="text-white">' + (v.specs||'-') + '</div></div>' +
    '<div class="p-3 rounded-lg bg-white/5"><div class="text-xs text-slate-500 mb-1">流量</div><div class="text-white">' + (v.traffic||'-') + '</div></div>' +
    '<div class="p-3 rounded-lg bg-white/5"><div class="text-xs text-slate-500 mb-1">到期日期</div><div class="text-white">' + (v.expiryDate||'-') + '</div></div>' +
    '<div class="p-3 rounded-lg bg-white/5"><div class="text-xs text-slate-500 mb-1">捐助时间</div><div class="text-white">' + (v.donatedAt ? new Date(v.donatedAt).toLocaleDateString('zh-CN') : '-') + '</div></div>' +
    '</div>' +
    (v.note ? '<div class="p-3 rounded-lg bg-white/5 text-sm"><div class="text-xs text-slate-500 mb-1">备注</div><div class="text-white">' + v.note + '</div></div>' : '') +
    '<hr class="border-white/5" />' +
    '<div class="text-xs text-slate-500 font-medium mb-2">SSH 连接信息</div>' +
    '<div class="grid grid-cols-3 gap-3 text-sm">' +
    '<div class="p-3 rounded-lg bg-white/5"><div class="text-xs text-slate-500 mb-1">用户名</div><div class="text-white font-mono">' + (v.username || 'root') + '</div></div>' +
    '<div class="p-3 rounded-lg bg-white/5"><div class="text-xs text-slate-500 mb-1">端口</div><div class="text-white font-mono">' + v.port + '</div></div>' +
    '<div class="p-3 rounded-lg bg-white/5"><div class="text-xs text-slate-500 mb-1">认证</div><div class="text-white">' + (isKey ? '私钥' : '密码') + '</div></div>' +
    '</div>' +
    '<div><div class="text-xs text-slate-500 mb-1 flex items-center justify-between">' + (isKey ? '私钥内容' : '密码') + ' <button id="toggle-secret" class="text-indigo-400 hover:underline text-xs cursor-pointer">显示</button></div>' +
    (isKey ? '<pre id="secret-display" class="p-2.5 rounded-lg bg-white/5 text-xs text-white font-mono max-h-48 overflow-auto whitespace-pre-wrap">' + maskPwd(secretValue) + '</pre>' :
            '<div id="secret-display" class="p-2.5 rounded-lg bg-white/5 text-sm text-white font-mono break-all">' + maskPwd(secretValue) + '</div>') +
    '</div>' +
    '<div class="flex gap-2"><button id="cfg-copy-ssh" class="btn-primary flex-1">复制 SSH 命令</button><button id="cfg-test-btn" class="btn-secondary flex-1">测试连接</button><button id="cfg-close-btn" class="btn-secondary flex-1">关闭</button></div>' +
    '</div></div>';
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) closeModal(); });
  document.getElementById('cfg-close-x').addEventListener('click', closeModal);
  document.getElementById('cfg-close-btn').addEventListener('click', closeModal);
  let secretShown = false;
  document.getElementById('toggle-secret').addEventListener('click', () => {
    secretShown = !secretShown;
    document.getElementById('secret-display').textContent = secretShown ? secretValue : maskPwd(secretValue);
    document.getElementById('toggle-secret').textContent = secretShown ? '隐藏' : '显示';
  });
  document.getElementById('cfg-copy-ssh').addEventListener('click', () => {
    const cmd = 'ssh ' + (v.username || 'root') + '@' + v.ip + ' -p ' + v.port;
    navigator.clipboard.writeText(cmd).then(() => toast('SSH 命令已复制','success')).catch(() => toast('复制失败','error'));
  });
  document.getElementById('cfg-test-btn').addEventListener('click', async () => {
    const btn = document.getElementById('cfg-test-btn');
    btn.textContent = '测试中...';
    btn.disabled = true;
    try {
      const r = await fetch('/api/admin/vps/' + v.id + '/verify', { method: 'POST', credentials: 'same-origin' });
      const j = await r.json();
      toast(j.message || '测试完成', j.success ? 'success' : 'error');
      btn.textContent = j.success ? '✅ 连接正常' : '❌ 连接失败';
      await loadVps(); await loadStats();
    } catch { toast('测试异常','error'); btn.textContent = '测试连接'; }
    btn.disabled = false;
  });
}

async function verifyAll(){
  if(!allVpsList.length){toast('没有VPS可验证','warn');return;}if(!confirm('确定全部验证？可能需要较长时间'))return;
  try{const r=await fetch('/api/admin/verify-all',{method:'POST',credentials:'same-origin'});const j=await r.json();toast(j.message||'完成',j.success?'success':'error');await loadVps();await loadStats();}catch{toast('验证异常','error');}
}

function openEditModal(id){
  const vps=allVpsList.find(v=>v.id===id);if(!vps)return;
  const overlay=document.createElement('div');overlay.className='modal-overlay';overlay.id='edit-modal';
  overlay.innerHTML='<div class="modal-content"><div class="p-6 border-b border-white/5 flex items-center justify-between"><h3 class="font-bold text-white">编辑配置</h3><button onclick="document.getElementById(\\'edit-modal\\').remove()" class="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-white/10"><div class="w-5 h-5 opacity-60">${ICONS.x}</div></button></div>'+
    '<form id="edit-form" class="p-6 space-y-4"><input type="hidden" name="vpsId" value="'+id+'" />'+
    '<div class="grid grid-cols-2 gap-4"><div><label class="block text-sm text-slate-400 mb-1">IP</label><input name="ip" value="'+vps.ip+'" class="input-field !pl-3 text-sm" /></div>'+
    '<div><label class="block text-sm text-slate-400 mb-1">端口</label><input name="port" type="number" value="'+vps.port+'" class="input-field !pl-3 text-sm" /></div></div>'+
    '<div class="grid grid-cols-2 gap-4"><div><label class="block text-sm text-slate-400 mb-1">用户名</label><input name="username" value="'+vps.username+'" class="input-field !pl-3 text-sm" /></div>'+
    '<div><label class="block text-sm text-slate-400 mb-1">认证方式</label><select name="authType" class="select-field !pl-3 text-sm"><option value="password" '+(vps.authType==='password'?'selected':'')+'>密码</option><option value="key" '+(vps.authType==='key'?'selected':'')+'>私钥</option></select></div></div>'+
    '<div><label class="block text-sm text-slate-400 mb-1">密码</label><input name="password" type="password" placeholder="留空保持不变" class="input-field !pl-3 text-sm" /></div>'+
    '<div><label class="block text-sm text-slate-400 mb-1">私钥</label><textarea name="privateKey" rows="3" placeholder="留空保持不变" class="textarea-field !pl-3 text-sm"></textarea></div>'+
    '<div id="edit-msg" class="text-sm min-h-[1rem]"></div>'+
    '<div class="flex gap-3"><button type="button" onclick="document.getElementById(\\'edit-modal\\').remove()" class="btn-secondary flex-1">取消</button><button type="submit" class="btn-primary flex-1"><div class="w-4 h-4">${ICONS.save}</div> 保存</button></div></form></div>';
  document.body.appendChild(overlay);
  overlay.addEventListener('click',e=>{if(e.target===overlay)overlay.remove();});
  document.getElementById('edit-form').addEventListener('submit',async e=>{
    e.preventDefault();const fd=new FormData(e.target);const msg=document.getElementById('edit-msg');
    const payload={ip:fd.get('ip'),port:Number(fd.get('port')),username:fd.get('username'),authType:fd.get('authType'),password:fd.get('password')||vps.password,privateKey:fd.get('privateKey')||vps.privateKey};
    try{const r=await fetch('/api/admin/vps/'+id+'/config',{method:'PUT',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const j=await r.json();if(j.success){toast(j.message||'已更新','success');setTimeout(()=>{overlay.remove();loadVps();loadStats();},800);}
    else{msg.textContent=j.message||'更新失败';msg.className='text-sm text-red-400';toast(j.message||'失败','error');}}catch{toast('更新异常','error');}
  });
}

checkSession();
<\/script>
</body></html>`;
  return c.html(html);
});

export default app;
