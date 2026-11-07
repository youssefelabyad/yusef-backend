
// Youssef Elabyad - Social Media Intelligence Platform - Backend V22.1
// Instagram + TikTok - Production Readiness Fixes (Audit V21)
// Instagram logic preserved (profile/media/insights internal logic untouched, only auth wrapper + health). V21.3: Separate Instagram session (NOT TikTok session) + Single /api/health + Fail-fast before listen + CSRF for POSTs.
// Identity vs Platform: yusef_session grants ['tiktok'] only, ig_session grants ['instagram'] only. TikTok session NEVER grants Instagram.
// TikTok V21.2: Postgres MANDATORY in Production + CSRF state + Single-flight Refresh + Secure Disconnect + Encryption fail-fast + Session Auth for TikTok endpoints.
// Single-user (user_id='default') - storage designed for future multi-user upgrade (see dbSaveToken/dbLoadToken userId param).
// Secrets/Tokens NEVER in frontend, NEVER in logs. Tokens encrypted with TOKEN_ENCRYPTION_KEY (Railway Env Var).
// If DATABASE_URL not set -> fallback to memory (with warning) + instructions in /api/health. No secrets invented.
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const app = express();
app.use(express.json());

// ===== CORS - Allowlist only (V21.1 Fix) - NOT a replacement for auth =====
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://yusef-delta.vercel.app').split(',').map(s=>s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // curl / Postman / server-to-server (no Origin header) - still requires no secret in URL, endpoints are not auth-gated beyond tokens in backend
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error('CORS: Origin not allowed: ' + origin));
  },
  credentials: true, // required for HttpOnly session cookie cross-site (Vercel -> Railway)
}));


// ===== COOKIES + SESSION (V21.2) - HttpOnly, Secure, SameSite=None for cross-site Vercel -> Railway =====
function parseCookies(req){
  const out = {};
  const h = req.headers.cookie || '';
  h.split(';').forEach(part => { const idx = part.indexOf('='); if (idx > -1) out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx+1).trim()); });
  return out;
}
function setCookie(res, name, value, opts){
  const parts = [`${name}=${encodeURIComponent(value)}`, 'Path=' + (opts.path || '/'), 'HttpOnly', 'Secure', 'SameSite=None'];
  if (opts.maxAge) parts.push('Max-Age=' + opts.maxAge);
  if (opts.expires) parts.push('Expires=' + opts.expires);
  res.append('Set-Cookie', parts.join('; '));
}
function clearCookie(res, name, path){
  setCookie(res, name, '', { path: path || '/', expires: 'Thu, 01 Jan 1970 00:00:00 GMT', maxAge: 0 });
}
// Session store: sessionId -> { createdAt, expiresAt } - in-memory session IDs only (no tokens in cookie)
const SESSIONS = new Map();
function createSession(){
  const id = crypto.randomBytes(32).toString('hex');
  SESSIONS.set(id, { createdAt: Date.now(), expiresAt: Date.now() + 24*3600*1000 });
  return id;
}
function isValidSession(req){
  const cookies = parseCookies(req);
  const sid = cookies['yusef_session'];
  if (!sid) return false;
  const s = SESSIONS.get(sid);
  if (!s) return false;
  if (Date.now() > s.expiresAt) { SESSIONS.delete(sid); return false; }
  return true;
}
function requireSession(req, res, next){
  if (!isValidSession(req)) return res.status(401).json({ error: 'Unauthorized - login via /api/tiktok/login first', code: 'unauthorized' });
  return next();
}
function destroySession(req, res){
  const cookies = parseCookies(req);
  if (cookies['yusef_session']) SESSIONS.delete(cookies['yusef_session']);
  clearCookie(res, 'yusef_session', '/');
}

// ===== INSTAGRAM SESSION (V21.3) - SEPARATE from TikTok session, NOT interchangeable =====
// yusef_session (TikTok) grants ['tiktok'] only. ig_session grants ['instagram'] only.
// Instagram login requires DASHBOARD_ADMIN_KEY (Railway env, never in Frontend/localStorage).
// Frontend sends the key ONCE via POST /api/instagram/login -> backend sets HttpOnly cookie, frontend never stores it.
const IG_SESSIONS = new Map();
function createInstagramSession(){
  const id = crypto.randomBytes(32).toString('hex');
  IG_SESSIONS.set(id, { createdAt: Date.now(), expiresAt: Date.now() + 24*3600*1000, grants: ['instagram'] });
  return id;
}
function isValidInstagramSession(req){
  const cookies = parseCookies(req);
  const sid = cookies['ig_session'];
  if (!sid) return false;
  const s = IG_SESSIONS.get(sid);
  if (!s) return false;
  if (Date.now() > s.expiresAt) { IG_SESSIONS.delete(sid); return false; }
  if (!s.grants || !s.grants.includes('instagram')) return false;
  return true;
}
function requireInstagram(req, res, next){
  if (!isValidInstagramSession(req)) return res.status(401).json({ error: 'Unauthorized - login to Instagram dashboard via POST /api/instagram/login first', code: 'unauthorized_instagram' });
  return next();
}
function destroyInstagramSession(req, res){
  const cookies = parseCookies(req);
  if (cookies['ig_session']) IG_SESSIONS.delete(cookies['ig_session']);
  clearCookie(res, 'ig_session', '/');
}
const YT_SESSIONS=new Map();
function createYouTubeSession(){ const id=crypto.randomBytes(32).toString('hex'); YT_SESSIONS.set(id,{createdAt:Date.now(),expiresAt:Date.now()+24*3600*1000,grants:['youtube']}); return id; }
function isValidYouTubeSession(req){ const c=parseCookies(req); const sid=c['yt_session']; if(!sid) return false; const v=YT_SESSIONS.get(sid); if(!v) return false; if(Date.now()>v.expiresAt){ YT_SESSIONS.delete(sid); return false; } if(!v.grants||!v.grants.includes('youtube')) return false; return true; }
function requireYouTube(req,res,next){ if(!isValidYouTubeSession(req)) return res.status(401).json({error:'Unauthorized - login via /api/youtube/login first',code:'unauthorized_youtube'}); return next(); }
function destroyYouTubeSession(req,res){ const c=parseCookies(req); if(c['yt_session']) YT_SESSIONS.delete(c['yt_session']); clearCookie(res,'yt_session','/'); }
function createYouTubeOAuthState(res){ const st=crypto.randomBytes(32).toString('hex'); setCookie(res,'youtube_oauth_state',st,{path:'/api/youtube/callback',maxAge:600}); return st; }
function validateYouTubeOAuthState(req){ const c=parseCookies(req); const a=c['youtube_oauth_state']; const q=req.query.state; if(!a||!q) return false; try{ const x=Buffer.from(a,'utf8'); const y=Buffer.from(String(q),'utf8'); if(x.length!==y.length) return false; return crypto.timingSafeEqual(x,y); }catch{ return false; } }

// ===== RATE LIMITING for Instagram Login (V21.4) - Prevent guessing DASHBOARD_ADMIN_KEY =====
// Per-IP: max 5 failed attempts per 15 min window, then blocked for 15 min.
// No key is logged, no key is returned. Error messages are generic (do not reveal if key was close).
// Block applies even to correct key while blocked (prevents brute-force timing).
const LOGIN_ATTEMPTS = new Map();
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_BLOCK_MS = 15 * 60 * 1000;
function getClientIp(req){
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return String(fwd).split(',')[0].trim();
  return req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
}
function isLoginBlocked(ip){
  const rec = LOGIN_ATTEMPTS.get(ip);
  if (!rec) return false;
  if (rec.blockedUntil && Date.now() < rec.blockedUntil) return true;
  if (rec.blockedUntil && Date.now() >= rec.blockedUntil) { LOGIN_ATTEMPTS.delete(ip); return false; }
  if (Date.now() - rec.firstAttemptAt > LOGIN_WINDOW_MS) { LOGIN_ATTEMPTS.delete(ip); return false; }
  return false;
}
function recordLoginFailure(ip){
  const now = Date.now();
  let rec = LOGIN_ATTEMPTS.get(ip);
  if (!rec || now - rec.firstAttemptAt > LOGIN_WINDOW_MS) rec = { count: 0, firstAttemptAt: now, blockedUntil: null };
  rec.count += 1;
  if (rec.count >= LOGIN_MAX_ATTEMPTS) rec.blockedUntil = now + LOGIN_BLOCK_MS;
  LOGIN_ATTEMPTS.set(ip, rec);
  return rec;
}
function clearLoginAttempts(ip){ LOGIN_ATTEMPTS.delete(ip); }

// ===== CSRF for Session POSTs (V21.3) =====
// Attacker site cannot set X-Requested-With without a preflight, and preflight fails CORS if Origin not allowed.
// So POSTs require: (1) Origin (if present) in ALLOWED_ORIGINS, (2) X-Requested-With: XMLHttpRequest header.
// Cookies are SameSite=None; Secure for Vercel->Railway, so Origin check is the CSRF boundary (not CORS alone).
function requireCSRF(req, res, next){
  const origin = req.headers.origin;
  if (origin && !ALLOWED_ORIGINS.includes(origin)) return res.status(403).json({ error: 'CSRF: Origin not allowed', code: 'csrf_origin' });
  const referer = req.headers.referer;
  if (!origin && referer) {
    try { const refOrigin = new URL(referer).origin; if (!ALLOWED_ORIGINS.includes(refOrigin)) return res.status(403).json({ error: 'CSRF: Referer not allowed', code: 'csrf_referer' }); } catch {}
  }
  if (req.headers['x-requested-with'] !== 'XMLHttpRequest') return res.status(403).json({ error: 'CSRF: Missing X-Requested-With header - use fetch with credentials:include + X-Requested-With', code: 'csrf_header' });
  return next();
}


// ===== CSRF STATE (V21.2) =====
function createOAuthState(res){
  const state = crypto.randomBytes(32).toString('hex');
  setCookie(res, 'tiktok_oauth_state', state, { path: '/api/tiktok/callback', maxAge: 600 });
  return state;
}
function validateOAuthState(req){
  const cookies = parseCookies(req);
  const cookieState = cookies['tiktok_oauth_state'];
  const queryState = req.query.state;
  // Single-use: clear cookie immediately (even on failure, to prevent replay)
  // Note: clear is done by caller via res, but we return result first
  if (!cookieState || !queryState) return false;
  try {
    const a = Buffer.from(cookieState, 'utf8'); const c = Buffer.from(String(queryState), 'utf8');
    if (a.length !== c.length) return false;
    return crypto.timingSafeEqual(a, c);
  } catch { return false; }
}

// ===== PLATFORMS REGISTRY - Single source of truth (V21.1 Fix: no duplicate lists) =====
const PLATFORMS = {
  instagram: { id: 'instagram', name: 'Instagram', scopes: ['instagram_basic'] },
  tiktok: { id: 'tiktok', name: 'TikTok', scopes: ['user.info.profile','user.info.stats','video.list'] },
  youtube: { id: 'youtube', name: 'YouTube', scopes: ['https://www.googleapis.com/auth/youtube.readonly'] },
  facebook: { id: 'facebook', name: 'Facebook', scopes: [], status: 'coming_soon' },
  linkedin: { id: 'linkedin', name: 'LinkedIn', scopes: [], status: 'coming_soon' },
  x: { id: 'x', name: 'X', scopes: [], status: 'coming_soon' },
  snapchat: { id: 'snapchat', name: 'Snapchat', scopes: [], status: 'coming_soon' },
  pinterest: { id: 'pinterest', name: 'Pinterest', scopes: [], status: 'coming_soon' },
};
function getPlatformsStatus(){
  return Object.values(PLATFORMS).map(p => {
    if (p.id === 'instagram') return { id: p.id, name: p.name, status: (process.env.INSTAGRAM_ACCESS_TOKEN ? 'connected' : 'not_connected'), scopes: p.scopes };
    if (p.id === 'tiktok') return { id: p.id, name: p.name, status: (TIKTOK_STORE.access_token ? 'connected' : 'not_connected'), scopes: p.scopes };
    if (p.id === 'youtube') return { id: p.id, name: p.name, status: (YOUTUBE_STORE.access_token ? 'connected' : 'not_connected'), scopes: p.scopes };
    return { id: p.id, name: p.name, status: p.status || 'coming_soon', scopes: p.scopes };
  });
}

// ===== ENCRYPTION - AES-256-GCM, key from TOKEN_ENCRYPTION_KEY (never logged) =====
function getEncryptionKey(){
  const k = process.env.TOKEN_ENCRYPTION_KEY;
  if (!k) return null;
  try {
    if (/^[0-9a-fA-F]{64}$/.test(k)) return Buffer.from(k, 'hex');
    const b = Buffer.from(k, 'base64');
    if (b.length === 32) return b;
    return null;
  } catch { return null; }
}
function encryptToken(plain){
  const key = getEncryptionKey();
  if (!key) throw new Error('TOKEN_ENCRYPTION_KEY missing or invalid - set 64 hex chars (32 bytes) in Railway');
  if (!plain) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + tag.toString('hex') + ':' + enc.toString('hex');
}
function decryptToken(stored){
  const key = getEncryptionKey();
  if (!key) throw new Error('TOKEN_ENCRYPTION_KEY missing or invalid');
  if (!stored) return null;
  const parts = stored.split(':');
  if (parts.length !== 3) throw new Error('Invalid encrypted token format');
  const iv = Buffer.from(parts[0], 'hex'); const tag = Buffer.from(parts[1], 'hex'); const enc = Buffer.from(parts[2], 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}

// ===== PERSISTENT TOKEN STORAGE - Railway PostgreSQL + Memory fallback (V21.1 Fix) =====
let pgPool = null;
try {
  if (process.env.DATABASE_URL) {
    const { Pool } = require('pg');
    pgPool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    pgPool.on('error', (err) => { console.log('[DB] pool error (no secrets):', err.message); });
  }
} catch (e) { console.log('[DB] pg not available, using memory fallback:', e.message); pgPool = null; }
async function dbInit(){
  if (!pgPool) return false;
  try {
    await pgPool.query(`CREATE TABLE IF NOT EXISTS tiktok_tokens (id INT PRIMARY KEY CHECK (id = 1), access_token TEXT, refresh_token TEXT, expires_at BIGINT, open_id TEXT, scope TEXT, updated_at TIMESTAMPTZ DEFAULT NOW())`);
    await pgPool.query(`CREATE TABLE IF NOT EXISTS youtube_tokens (id INT PRIMARY KEY CHECK (id = 1), access_token TEXT, refresh_token TEXT, expires_at BIGINT, channel_id TEXT, scope TEXT, updated_at TIMESTAMPTZ DEFAULT NOW())`);
    return true;
  } catch (e) { console.log('[DB] init failed (no secrets):', e.message); return false; }
}
// Storage design: single-user now (user_id='default', row id=1). Future multi-user upgrade:
// ALTER TABLE tiktok_tokens ADD COLUMN user_id TEXT; CREATE UNIQUE INDEX ON tiktok_tokens(user_id);
// Then change queries to WHERE user_id=$1 with per-user session userId. Current calls pass userId='default' so no break.
async function dbSaveToken(store, userId = 'default'){
  if (!pgPool) return false;
  const encAccess = store.access_token ? encryptToken(store.access_token) : null;
  const encRefresh = store.refresh_token ? encryptToken(store.refresh_token) : null;
  await pgPool.query(`INSERT INTO tiktok_tokens (id, access_token, refresh_token, expires_at, open_id, scope, updated_at) VALUES (1, $1, $2, $3, $4, $5, NOW()) ON CONFLICT (id) DO UPDATE SET access_token = EXCLUDED.access_token, refresh_token = EXCLUDED.refresh_token, expires_at = EXCLUDED.expires_at, open_id = EXCLUDED.open_id, scope = EXCLUDED.scope, updated_at = NOW()`, [encAccess, encRefresh, store.expires_at, store.open_id, store.scope]);
  return true;
}
async function failFastProduction(reason){
  console.log('[FATAL] ' + reason);
  console.log('[FATAL] Server will NOT start in Production without Postgres + valid TOKEN_ENCRYPTION_KEY. Set DATABASE_URL + TOKEN_ENCRYPTION_KEY in Railway, or ALLOW_MEMORY_FALLBACK=true for local dev only.');
  process.exit(1);
}
async function validateBootConfig(){
  const allowMemory = process.env.ALLOW_MEMORY_FALLBACK === 'true';
  const hasDb = !!process.env.DATABASE_URL;
  const hasKey = !!getEncryptionKey();
  if (!hasDb && !allowMemory) {
    await failFastProduction('DATABASE_URL missing - Postgres is MANDATORY in Production for TikTok token storage.');
  }
  if (hasDb && !hasKey && !allowMemory) {
    await failFastProduction('TOKEN_ENCRYPTION_KEY missing or invalid - set 64 hex chars (32 bytes) in Railway. Server will NOT start without it when DATABASE_URL is set.');
  }
  if (hasDb) {
    const ok = await dbInit();
    if (!ok && !allowMemory) await failFastProduction('Postgres connection failed - cannot start in Production without DB.');
    if (!ok && allowMemory) console.log('[DB] init failed, ALLOW_MEMORY_FALLBACK=true - starting in local-dev memory mode (NOT production-safe).');
  } else if (allowMemory) {
    console.log('[DB] ALLOW_MEMORY_FALLBACK=true - starting in local-dev memory mode (NOT production-safe, tokens will NOT survive restart).');
  }
}
async function dbLoadToken(userId = 'default'){
  if (!pgPool) return null;
  const r = await pgPool.query(`SELECT access_token, refresh_token, expires_at, open_id, scope FROM tiktok_tokens WHERE id = 1`);
  if (!r.rows.length) return null;
  const row = r.rows[0];
  return { access_token: row.access_token ? decryptToken(row.access_token) : null, refresh_token: row.refresh_token ? decryptToken(row.refresh_token) : null, expires_at: row.expires_at ? Number(row.expires_at) : null, open_id: row.open_id, scope: row.scope };
}
async function dbClearToken(userId = 'default'){
  if (!pgPool) return false;
  await pgPool.query(`DELETE FROM tiktok_tokens WHERE id = 1`);
  return true;
}
async function dbSaveYouTubeToken(store){ if(!pgPool) return false; const a=store.access_token?encryptToken(store.access_token):null; const b=store.refresh_token?encryptToken(store.refresh_token):null; await pgPool.query(`INSERT INTO youtube_tokens (id, access_token, refresh_token, expires_at, channel_id, scope, updated_at) VALUES (1, $1, $2, $3, $4, $5, NOW()) ON CONFLICT (id) DO UPDATE SET access_token=EXCLUDED.access_token, refresh_token=EXCLUDED.refresh_token, expires_at=EXCLUDED.expires_at, channel_id=EXCLUDED.channel_id, scope=EXCLUDED.scope, updated_at=NOW()`,[a,b,store.expires_at,store.channel_id,store.scope]); return true; }
async function dbLoadYouTubeToken(){ if(!pgPool) return null; const r=await pgPool.query(`SELECT access_token, refresh_token, expires_at, channel_id, scope FROM youtube_tokens WHERE id = 1`); if(!r.rows.length) return null; const row=r.rows[0]; return { access_token: row.access_token?decryptToken(row.access_token):null, refresh_token: row.refresh_token?decryptToken(row.refresh_token):null, expires_at: row.expires_at?Number(row.expires_at):null, channel_id: row.channel_id, scope: row.scope }; }
async function dbClearYouTubeToken(){ if(!pgPool) return false; await pgPool.query(`DELETE FROM youtube_tokens WHERE id = 1`); return true; }
const YOUTUBE_STORE={access_token:null,refresh_token:null,expires_at:null,channel_id:null,scope:null};
async function persistYouTubeToken(){ if(!pgPool) return false; if(!dbReady) dbReady=await dbInit(); try{ await dbSaveYouTubeToken(YOUTUBE_STORE); return true; }catch(e){ console.log('[DB] YouTube persist failed:',e.message); return false; } }
async function loadYouTubeTokenOnBoot(){ if(!pgPool) return; try{ const l=await dbLoadYouTubeToken(); if(l&&l.access_token){ Object.assign(YOUTUBE_STORE,l); console.log('[DB] YouTube token restored.'); } else console.log('[DB] No persisted YouTube token.'); }catch(e){ console.log('[DB] YouTube load failed:',e.message); } }
// Token store in memory mirrors DB (fast read). DB is source of truth on restart.
const TIKTOK_STORE = { access_token: null, refresh_token: null, expires_at: null, open_id: null, scope: null };
let dbReady = false;
async function persistToken(){
  // Never delete old before confirming new saved: DB save first, then memory update is done by caller only on success.
  if (!pgPool) { console.log('[DB] No DATABASE_URL - using memory only (token will NOT survive restart). Set DATABASE_URL + TOKEN_ENCRYPTION_KEY in Railway.'); return false; }
  if (!dbReady) dbReady = await dbInit();
  try { await dbSaveToken(TIKTOK_STORE); return true; } catch (e) { console.log('[DB] persist failed (no secrets):', e.message); return false; }
}
async function loadTokenOnBoot(){
  if (!pgPool) { console.log('[DB] No DATABASE_URL - memory only.'); return; }
  dbReady = await dbInit();
  try {
    const loaded = await dbLoadToken();
    if (loaded && loaded.access_token) { Object.assign(TIKTOK_STORE, loaded); console.log('[DB] TikTok token restored from Postgres (no secrets logged).'); }
    else console.log('[DB] No persisted TikTok token found.');
  } catch (e) { console.log('[DB] load failed (no secrets):', e.message); }
}

// ===== INSTAGRAM (preserved exactly) =====
const IG_ID = process.env.INSTAGRAM_ID || '17841405344844788';
const TOKEN = process.env.INSTAGRAM_ACCESS_TOKEN;
const FB_API = 'https://graph.facebook.com/v21.0';
async function fbFetch(path) {
  if (!TOKEN) throw new Error('Missing INSTAGRAM_ACCESS_TOKEN env var');
  const url = `${FB_API}${path}${path.includes('?') ? '&' : '?'}access_token=${TOKEN}`;
  const r = await fetch(url);
  const data = await r.json();
  if (data.error) throw new Error(data.error.message);
  return data;
}
app.get('/api/health', (req, res) => res.json({ ok: true, version: 'V21.4', status: 'online', db: pgPool ? 'Postgres' : 'Memory (dev only)', db_configured: !!pgPool, encryption_configured: !!getEncryptionKey(), tiktok_connected: !!TIKTOK_STORE.access_token, youtube_connected: !!YOUTUBE_STORE.access_token, instagram_configured: !!TOKEN, timestamp: new Date().toISOString() }));
app.get('/api/me', requireInstagram, async (req, res) => {
  try { const data = await fbFetch(`/me/accounts?fields=id,name,instagram_business_account{id,username}`); res.json(data); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/profile', requireInstagram, async (req, res) => {
  try { const data = await fbFetch(`/${IG_ID}?fields=id,username,name,biography,media_count,followers_count,follows_count,profile_picture_url,website`); res.json({ ...data, source: 'Live API' }); }
  catch (e) { res.status(500).json({ error: e.message, source: 'Live API' }); }
});
app.get('/api/media', requireInstagram, async (req, res) => {
  try { const limit = req.query.limit || 25; const data = await fbFetch(`/${IG_ID}/media?fields=id,caption,media_type,media_url,permalink,timestamp,like_count,comments_count&limit=${limit}`); res.json({ ...data, source: 'Live API' }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/insights', requireInstagram, async (req, res) => {
  try { const metrics = 'reach,views,accounts_engaged,total_interactions,profile_views'; const data = await fbFetch(`/${IG_ID}/insights?metric=${metrics}&period=day&metric_type=total_value`); res.json({ ...data, source: 'Live API' }); }
  catch (e) { res.status(500).json({ error: e.message, note: 'Insights may be Unavailable if permission missing' }); }
});

// ===== TIKTOK CONNECTOR (Modular - TikTokConnector) - V21.1: persistent + rate-limit =====
const TIKTOK_KEY = process.env.TIKTOK_CLIENT_KEY;
const TIKTOK_SECRET = process.env.TIKTOK_CLIENT_SECRET;
const TIKTOK_REDIRECT = process.env.TIKTOK_REDIRECT_URI || 'https://yusef-backend-production.up.railway.app/api/tiktok/callback';
function isTikTokExpired(){ if(!TIKTOK_STORE.expires_at) return false; return Date.now() > TIKTOK_STORE.expires_at - 60000; }
let refreshPromise = null;
async function tiktokRefresh(){
  // Single-flight: concurrent callers wait for the SAME refresh, never use old refresh token twice
  if (refreshPromise) return refreshPromise;
  refreshPromise = (async () => {
    if(!TIKTOK_STORE.refresh_token) throw new Error('No refresh token - re-login required');
    const oldRefresh = TIKTOK_STORE.refresh_token;
    const r = await fetch('https://open.tiktokapis.com/v2/oauth/token/', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_key: TIKTOK_KEY, client_secret: TIKTOK_SECRET, grant_type: 'refresh_token', refresh_token: oldRefresh }) });
    const data = await r.json();
    if(data.error) throw new Error(data.error_description || data.error);
    const next = { access_token: data.access_token, refresh_token: data.refresh_token || oldRefresh, expires_at: data.expires_in ? Date.now() + data.expires_in*1000 : TIKTOK_STORE.expires_at, open_id: TIKTOK_STORE.open_id, scope: TIKTOK_STORE.scope };
    const prev = { ...TIKTOK_STORE };
    Object.assign(TIKTOK_STORE, next);
    const ok = await persistToken();
    if (!ok) {
      // Persist failed -> restore old, do NOT consider new token valid, return 503-style error
      Object.assign(TIKTOK_STORE, prev);
      throw new Error('Refresh succeeded but persist failed (storage_degraded) - old token kept, retry later');
    }
    return TIKTOK_STORE;
  })();
  try { return await refreshPromise; } finally { refreshPromise = null; }
}
async function getValidTikTokToken(){
  if(!TIKTOK_STORE.access_token) throw new Error('Not connected - open /api/tiktok/login first');
  if(isTikTokExpired()){ try{ await tiktokRefresh(); }catch(e){ throw new Error('Session expired - re-login required: ' + e.message); } }
  return TIKTOK_STORE.access_token;
}
function sleep(ms){ return new Promise(res=>setTimeout(res, ms)); }
// Rate Limit: 429 + Exponential Backoff + Retry-After, max 3 attempts, clear message
async function tiktokApi(path, opts={}){
  let lastErr = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const token = await getValidTikTokToken();
      const r = await fetch(path, { ...opts, headers: { ...(opts.headers||{}), Authorization: `Bearer ${token}` } });
      if (r.status === 429) {
        const retryAfter = r.headers.get('retry-after');
        const waitMs = retryAfter ? Math.min(Number(retryAfter)*1000, 10000) : Math.min(1000 * Math.pow(2, attempt), 4000);
        console.log(`[TikTok] 429 rate limit, attempt ${attempt+1}/3, waiting ${waitMs}ms`);
        if (attempt === 2) throw new Error('TikTok rate limit - please retry in a few seconds (429, 3 attempts)');
        await sleep(waitMs);
        continue;
      }
      const data = await r.json();
      if(data.error && data.error.code && data.error.code !== 'ok') {
        if (data.error.code === 'rate_limit' || String(data.error.message||'').toLowerCase().includes('rate limit')) {
          if (attempt === 2) throw new Error('TikTok rate limit - please retry in a few seconds');
          await sleep(Math.min(1000 * Math.pow(2, attempt), 4000));
          continue;
        }
        throw new Error(data.error.message || data.error.code);
      }
      return data;
    } catch (e) {
      lastErr = e;
      if (e.message && e.message.includes('rate limit')) { if (attempt === 2) throw e; await sleep(1000 * Math.pow(2, attempt)); continue; }
      throw e;
    }
  }
  throw lastErr || new Error('TikTok API failed after retries');
}
function computeTikTokAnalytics(profile, videos){
  const list = videos || [];
  const totalViews = list.reduce((s,v)=>s+(v.view_count||0),0);
  const totalLikes = list.reduce((s,v)=>s+(v.like_count||0),0);
  const totalComments = list.reduce((s,v)=>s+(v.comment_count||0),0);
  const totalShares = list.reduce((s,v)=>s+(v.share_count||0),0);
  const avgViews = list.length ? Math.round(totalViews/list.length) : 0;
  const engagementRate = totalViews ? Number((((totalLikes+totalComments+totalShares)/totalViews)*100).toFixed(2)) : null;
  const sorted = [...list].sort((a,b)=>(b.view_count||0)-(a.view_count||0));
  const now = Date.now();
  const inDays = (d)=> list.filter(v=> v.create_time && (now - v.create_time*1000) < d*86400000);
  const sumViews = (arr)=> arr.reduce((s,v)=>s+(v.view_count||0),0);
  let bestHour = null;
  if(list.length >= 3){
    const byHour = {};
    list.forEach(v=>{ const h = new Date(v.create_time*1000).getHours(); byHour[h]=(byHour[h]||0)+(v.view_count||0); });
    let bestH=0, bestV=-1; for(const h in byHour){ if(byHour[h]>bestV){bestV=byHour[h]; bestH=Number(h);} } bestHour = bestH;
  }
  return {
    source: 'Live TikTok API', computed_from: list.length + ' videos',
    account: { display_name: profile?.display_name || null, follower_count: profile?.follower_count ?? null, following_count: profile?.following_count ?? null, likes_count: profile?.likes_count ?? null, video_count: profile?.video_count ?? null, bio_description: profile?.bio_description || null, avatar_url: profile?.avatar_url || null, is_verified: profile?.is_verified ?? null },
    content: { total_videos: list.length, total_views: totalViews, total_likes: totalLikes, total_comments: totalComments, total_shares: totalShares, avg_views: avgViews, engagement_rate_pct: engagementRate, best_video: sorted[0]||null, worst_video: sorted[sorted.length-1]||null, videos: sorted },
    performance: { last_7d_views: sumViews(inDays(7)), last_30d_views: sumViews(inDays(30)), last_90d_views: sumViews(inDays(90)), last_7d_count: inDays(7).length, last_30d_count: inDays(30).length, last_90d_count: inDays(90).length, best_posting_hour: bestHour, best_posting_hour_status: bestHour===null ? 'Unavailable - need at least 3 videos' : 'Real - computed from video create_time' },
    audience: { status: 'Unavailable', reason: 'TikTok Login Kit (user.info.profile / user.info.stats / video.list) does not provide demographics or follower growth history. Requires TikTok Research API + approval.', demographics: null, follower_growth: null },
    transparency: { real: ['follower_count','following_count','likes_count','video_count','video views/likes/comments/shares','create_time'], unavailable: ['audience demographics','follower growth history','trend data','competitor data'], permission_required: ['Research API for trends/competitors/audience'] }
  };
}

app.get('/api/platforms', (req, res) => res.json({ platforms: getPlatformsStatus(), source: 'Backend V21.1 - PLATFORMS registry (single source)' }));

// ===== INSTAGRAM LOGIN (V21.3) - Separate auth, NOT TikTok session =====
// Body: { key: DASHBOARD_ADMIN_KEY } OR header x-admin-key. Key checked with timingSafeEqual, never logged, never returned.
// Frontend sends key ONCE via this endpoint, backend sets HttpOnly ig_session cookie. Frontend never stores key in localStorage.
app.post('/api/instagram/login', requireCSRF, async (req, res) => {
  const ip = getClientIp(req);
  if (isLoginBlocked(ip)) return res.status(429).json({ error: 'Too many login attempts - try again later', code: 'rate_limited' });
  const expected = process.env.DASHBOARD_ADMIN_KEY || '';
  if (!expected) return res.status(503).json({ error: 'DASHBOARD_ADMIN_KEY not configured in Railway - set it first, then retry login', code: 'admin_key_not_configured' });
  const provided = (req.body && req.body.key) || req.headers['x-admin-key'] || '';
  let ok = false;
  try {
    const a = Buffer.from(String(provided), 'utf8'); const e = Buffer.from(expected, 'utf8');
    ok = a.length === e.length && crypto.timingSafeEqual(a, e);
  } catch { ok = false; }
  if (!ok) { recordLoginFailure(ip); return res.status(401).json({ error: 'Invalid dashboard key', code: 'invalid_key' }); }
  clearLoginAttempts(ip);
  const sid = createInstagramSession();
  setCookie(res, 'ig_session', sid, { path: '/', maxAge: 24*3600 });
  res.json({ ok: true, instagram_connected: !!TOKEN, message: 'Instagram dashboard session created (HttpOnly cookie).' });
});
app.post('/api/instagram/logout', requireCSRF, (req, res) => {
  destroyInstagramSession(req, res);
  res.json({ ok: true, message: 'Instagram session cleared.' });
});
app.get('/api/tiktok/status', requireSession, (req, res) => res.json({ ok: true, connected: !!TIKTOK_STORE.access_token, has_key: !!TIKTOK_KEY, has_secret: !!TIKTOK_SECRET, has_refresh_token: !!TIKTOK_STORE.refresh_token, expires_at: TIKTOK_STORE.expires_at, open_id: TIKTOK_STORE.open_id, redirect_uri: TIKTOK_REDIRECT, scopes: ['user.info.profile','user.info.stats','video.list'], storage: pgPool ? 'Postgres (persistent, encrypted)' : 'Memory (fallback - will NOT survive restart)' }));
app.get('/api/tiktok/login', (req, res) => {
  if (!TIKTOK_KEY) return res.status(500).json({ error: 'Missing TIKTOK_CLIENT_KEY env var' });
  const scope = 'user.info.profile,user.info.stats,video.list';
  const state = createOAuthState(res);
  const url = `https://www.tiktok.com/v2/auth/authorize?client_key=${TIKTOK_KEY}&scope=${scope}&response_type=code&redirect_uri=${encodeURIComponent(TIKTOK_REDIRECT)}&state=${state}`;
  res.redirect(url);
});
app.get('/api/tiktok/callback', async (req, res) => {
  const { code, error } = req.query;
  // CSRF: state must match cookie, single-use (clear cookie now to prevent replay)
  const stateOk = validateOAuthState(req);
  clearCookie(res, 'tiktok_oauth_state', '/api/tiktok/callback');
  if (!stateOk) return res.status(403).send('Invalid or missing OAuth state (CSRF protection) - please start login again via /api/tiktok/login');
  if (error) return res.status(400).send(`TikTok auth error: ${error}`);
  if (!code) return res.status(400).send('Missing code');
  try {
    const r = await fetch('https://open.tiktokapis.com/v2/oauth/token/', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_key: TIKTOK_KEY, client_secret: TIKTOK_SECRET, grant_type: 'authorization_code', code, redirect_uri: TIKTOK_REDIRECT }) });
    const data = await r.json();
    if (data.error) throw new Error(data.error_description || data.error);
    const prev = { ...TIKTOK_STORE };
    Object.assign(TIKTOK_STORE, { access_token: data.access_token, refresh_token: data.refresh_token || null, open_id: data.open_id || null, scope: data.scope || null, expires_at: data.expires_in ? Date.now() + data.expires_in*1000 : null });
    const ok = await persistToken();
    if (!ok) {
      // Persist failed -> do NOT show Connected, clear memory, return 503 storage_degraded
      Object.assign(TIKTOK_STORE, prev);
      return res.status(503).send('storage_degraded: Token received but NOT persisted in Postgres. Check DATABASE_URL + TOKEN_ENCRYPTION_KEY, then retry login. Not connected.');
    }
    // Success: create session (HttpOnly, Secure, SameSite=None) - browser will send it on subsequent API calls with credentials:include
    const sid = createSession();
    setCookie(res, 'yusef_session', sid, { path: '/', maxAge: 24*3600 });
    res.send(`<h1>TikTok connected</h1><p>Token + Refresh Token saved in Postgres (encrypted, persistent). Session created. You can close this and open your dashboard.</p><p><a href="https://yusef-delta.vercel.app">Open Dashboard</a></p>`);
  } catch (e) { res.status(500).send(`Token exchange failed: ${e.message}`); }
});
app.get('/api/tiktok/refresh', requireSession, async (req, res) => {
  try { const s = await tiktokRefresh(); res.json({ ok: true, has_token: !!s.access_token, expires_at: s.expires_at, storage: pgPool ? 'Postgres' : 'Memory' }); }
  catch(e){ res.status(500).json({ error: e.message }); }
});
app.post('/api/tiktok/disconnect', requireSession, requireCSRF, async (req, res) => {
  // Step 1: Revoke at TikTok (official) - attempt, but report failure clearly (do not hide it)
  let revokeOk = null, revokeError = null;
  const tokenToRevoke = TIKTOK_STORE.access_token;
  if (tokenToRevoke) {
    try {
      const rr = await fetch('https://open.tiktokapis.com/v2/oauth/revoke/', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_key: TIKTOK_KEY, client_secret: TIKTOK_SECRET, token: tokenToRevoke }) });
      const rj = await rr.json().catch(()=>({}));
      if (rj.error && rj.error.code && rj.error.code !== 'ok') { revokeOk = false; revokeError = rj.error.message || rj.error.code; }
      else revokeOk = true;
    } catch(e){ revokeOk = false; revokeError = e.message; }
  } else { revokeOk = null; }
  // Step 2: Delete from Postgres - if fails, DO NOT clear memory, DO NOT clear session, DO NOT claim disconnected
  try {
    if (pgPool) { await dbClearToken(); }
    else { return res.status(503).json({ error: 'storage_degraded: Postgres not available, cannot safely disconnect - tokens still stored locally', code: 'storage_degraded', connected: true }); }
  } catch(e){
    console.log('[DB] clear failed (no secrets):', e.message);
    return res.status(503).json({ error: 'storage_degraded: Failed to delete tokens from Postgres - still connected. Retry later.', code: 'storage_degraded', connected: true, revoke_ok: revokeOk, revoke_error: revokeError });
  }
  // Step 3: Only after DB delete succeeded, clear memory (ALL fields incl. scope) + session
  TIKTOK_STORE.access_token = null; TIKTOK_STORE.refresh_token = null; TIKTOK_STORE.expires_at = null; TIKTOK_STORE.open_id = null; TIKTOK_STORE.scope = null;
  destroySession(req, res);
  res.json({ ok: true, connected: false, message: 'TikTok disconnected. Re-login via /api/tiktok/login to reconnect.', revoke_ok: revokeOk, revoke_error: revokeError });
});
app.get('/api/tiktok/profile', requireSession, async (req, res) => {
  try {
    const data = await tiktokApi('https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_url,display_name,bio_description,profile_deep_link,is_verified,follower_count,following_count,likes_count,video_count', {});
    res.json({ ...data.data.user, source: 'Live TikTok API', transparency: 'Real' });
  } catch (e) { res.status(500).json({ error: e.message, source: 'Live TikTok API', transparency: e.message.includes('Not connected') ? 'Not connected' : 'Error' }); }
});
app.post('/api/tiktok/videos', requireSession, requireCSRF, async (req, res) => {
  try {
    const data = await tiktokApi('https://open.tiktokapis.com/v2/video/list/?fields=id,title,cover_image_url,share_url,view_count,like_count,comment_count,share_count,create_time', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ max_count: 20 }) });
    res.json({ ...data.data, source: 'Live TikTok API', transparency: 'Real' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/tiktok/analytics', requireSession, async (req, res) => {
  try {
    const p = await tiktokApi('https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_url,display_name,bio_description,profile_deep_link,is_verified,follower_count,following_count,likes_count,video_count', {});
    const profile = p.data.user;
    let videos = [];
    try {
      const v = await tiktokApi('https://open.tiktokapis.com/v2/video/list/?fields=id,title,cover_image_url,share_url,view_count,like_count,comment_count,share_count,create_time', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ max_count: 20 }) });
      videos = v.data?.videos || [];
    } catch(e){ }
    res.json(computeTikTokAnalytics(profile, videos));
  } catch (e) { res.status(500).json({ error: e.message }); }
});


// ===== YOUTUBE CONNECTOR (V22.1) =====
const YOUTUBE_CLIENT_ID = process.env.YOUTUBE_CLIENT_ID;
const YOUTUBE_CLIENT_SECRET = process.env.YOUTUBE_CLIENT_SECRET;
const YOUTUBE_REDIRECT = process.env.YOUTUBE_REDIRECT_URI || 'https://yusef-backend-production.up.railway.app/api/youtube/callback';
const YOUTUBE_SCOPES = ['https://www.googleapis.com/auth/youtube.readonly', 'openid', 'email'];
function isYouTubeExpired(){ if(!YOUTUBE_STORE.expires_at) return false; return Date.now() > YOUTUBE_STORE.expires_at - 60000; }
let youtubeRefreshPromise = null;
async function youtubeRefresh(){
  if (youtubeRefreshPromise) return youtubeRefreshPromise;
  youtubeRefreshPromise = (async () => {
    if(!YOUTUBE_STORE.refresh_token) throw new Error('No refresh token - re-login required');
    const oldRefresh = YOUTUBE_STORE.refresh_token;
    const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: YOUTUBE_CLIENT_ID, client_secret: YOUTUBE_CLIENT_SECRET, grant_type: 'refresh_token', refresh_token: oldRefresh }) });
    const data = await r.json();
    if(data.error) throw new Error(data.error_description || data.error);
    const next = { access_token: data.access_token, refresh_token: data.refresh_token || oldRefresh, expires_at: data.expires_in ? Date.now() + data.expires_in*1000 : YOUTUBE_STORE.expires_at, channel_id: YOUTUBE_STORE.channel_id, scope: YOUTUBE_STORE.scope };
    const prev = { ...YOUTUBE_STORE };
    Object.assign(YOUTUBE_STORE, next);
    const ok = await persistYouTubeToken();
    if (!ok) { Object.assign(YOUTUBE_STORE, prev); throw new Error('Refresh succeeded but persist failed - old token kept'); }
    return YOUTUBE_STORE;
  })();
  try { return await youtubeRefreshPromise; } finally { youtubeRefreshPromise = null; }
}
async function getValidYouTubeToken(){
  if(!YOUTUBE_STORE.access_token) throw new Error('Not connected - open /api/youtube/login first');
  if(isYouTubeExpired()){ try{ await youtubeRefresh(); }catch(e){ throw new Error('Session expired - re-login required: ' + e.message); } }
  return YOUTUBE_STORE.access_token;
}
async function youtubeApi(path){
  let lastErr = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const token = await getValidYouTubeToken();
      const r = await fetch('https://www.googleapis.com/youtube/v3/' + path, { headers: { Authorization: 'Bearer ' + token } });
      if (r.status === 429) { if (attempt === 2) throw new Error('YouTube rate limit - please retry in a few seconds'); await sleep(Math.min(1000 * Math.pow(2, attempt), 4000)); continue; }
      const data = await r.json();
      if (data.error) throw new Error(data.error.message || 'YouTube API error');
      return data;
    } catch (e) { lastErr = e; if (e.message && e.message.includes('rate limit')) { if (attempt === 2) throw e; await sleep(1000 * Math.pow(2, attempt)); continue; } throw e; }
  }
  throw lastErr || new Error('YouTube API failed');
}
function computeYouTubeAnalytics(channel, videos){
  const list = videos || [];
  const totalViews = list.reduce((a,v)=>a+(v.viewCount||0),0);
  const totalLikes = list.reduce((a,v)=>a+(v.likeCount||0),0);
  const totalComments = list.reduce((a,v)=>a+(v.commentCount||0),0);
  const avgViews = list.length ? Math.round(totalViews/list.length) : 0;
  const engagementRate = totalViews ? Number((((totalLikes+totalComments)/totalViews)*100).toFixed(2)) : null;
  const sorted = [...list].sort((a,b)=>(b.viewCount||0)-(a.viewCount||0));
  const now = Date.now();
  const inDays = (d)=> list.filter(v=> v.publishedAt && (now - new Date(v.publishedAt).getTime()) < d*86400000);
  const sumViews = (arr)=> arr.reduce((a,v)=>a+(v.viewCount||0),0);
  let bestHour = null;
  if(list.length >= 3){ const byHour={}; list.forEach(v=>{ const h=new Date(v.publishedAt).getHours(); byHour[h]=(byHour[h]||0)+(v.viewCount||0); }); let bh=0,bv=-1; for(const h in byHour){ if(byHour[h]>bv){bv=byHour[h]; bh=Number(h);} } bestHour=bh; }
  const stats = channel?.statistics || {}; const sn = channel?.snippet || {};
  return { source:'Live YouTube API', computed_from: list.length+' videos', account:{ channel_id: channel?.id||null, title: sn.title||null, custom_url: sn.customUrl||null, description: sn.description||null, thumbnail_url: sn.thumbnails?.default?.url||sn.thumbnails?.medium?.url||null, subscriber_count: stats.subscriberCount?Number(stats.subscriberCount):null, video_count: stats.videoCount?Number(stats.videoCount):null, view_count: stats.viewCount?Number(stats.viewCount):null, hidden_subscriber_count: stats.hiddenSubscriberCount??null }, content:{ total_videos:list.length, total_views:totalViews, total_likes:totalLikes, total_comments:totalComments, avg_views:avgViews, engagement_rate_pct:engagementRate, best_video:sorted[0]||null, worst_video:sorted[sorted.length-1]||null, videos:sorted }, performance:{ last_7d_views:sumViews(inDays(7)), last_30d_views:sumViews(inDays(30)), last_90d_views:sumViews(inDays(90)), last_7d_count:inDays(7).length, last_30d_count:inDays(30).length, last_90d_count:inDays(90).length, best_posting_hour:bestHour, best_posting_hour_status: bestHour===null?'Unavailable - need at least 3 videos':'Real - computed from video publishedAt' }, audience:{ status:'Unavailable', reason:'YouTube Data API v3 (youtube.readonly) does not provide demographics or subscriber growth history. Requires YouTube Analytics API + approval.', demographics:null, subscriber_growth:null }, transparency:{ real:['subscriber_count','video_count','view_count','video views/likes/comments','publishedAt'], unavailable:['audience demographics','subscriber growth history','trend data','competitor data'], permission_required:['YouTube Analytics API for demographics/growth'] } };
}
app.get('/api/youtube/status', requireYouTube, (req, res) => res.json({ ok:true, connected: !!YOUTUBE_STORE.access_token, has_client_id: !!YOUTUBE_CLIENT_ID, has_client_secret: !!YOUTUBE_CLIENT_SECRET, has_refresh_token: !!YOUTUBE_STORE.refresh_token, expires_at: YOUTUBE_STORE.expires_at, channel_id: YOUTUBE_STORE.channel_id, redirect_uri: YOUTUBE_REDIRECT, scopes: YOUTUBE_SCOPES, storage: pgPool ? 'Postgres (persistent, encrypted)' : 'Memory (fallback)' }));
app.get('/api/youtube/login', (req, res) => {
  if (!YOUTUBE_CLIENT_ID) return res.status(500).json({ error: 'Missing YOUTUBE_CLIENT_ID env var' });
  const state = createYouTubeOAuthState(res);
  const scope = encodeURIComponent(YOUTUBE_SCOPES.join(' '));
  const url = 'https://accounts.google.com/o/oauth2/v2/auth?client_id=' + encodeURIComponent(YOUTUBE_CLIENT_ID) + '&redirect_uri=' + encodeURIComponent(YOUTUBE_REDIRECT) + '&response_type=code&scope=' + scope + '&access_type=offline&prompt=consent&state=' + state;
  res.redirect(url);
});
app.get('/api/youtube/callback', async (req, res) => {
  const { code, error } = req.query;
  const stateOk = validateYouTubeOAuthState(req);
  clearCookie(res, 'youtube_oauth_state', '/api/youtube/callback');
  if (!stateOk) return res.status(403).send('Invalid or missing OAuth state (CSRF protection) - please start login again via /api/youtube/login');
  if (error) return res.status(400).send('YouTube auth error: ' + error);
  if (!code) return res.status(400).send('Missing code');
  try {
    const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ code, client_id: YOUTUBE_CLIENT_ID, client_secret: YOUTUBE_CLIENT_SECRET, redirect_uri: YOUTUBE_REDIRECT, grant_type: 'authorization_code' }) });
    const data = await r.json();
    if (data.error) throw new Error(data.error_description || data.error);
    const prev = { ...YOUTUBE_STORE };
    Object.assign(YOUTUBE_STORE, { access_token: data.access_token, refresh_token: data.refresh_token || null, channel_id: null, scope: data.scope || null, expires_at: data.expires_in ? Date.now() + data.expires_in*1000 : null });
    try { const ch = await fetch('https://www.googleapis.com/youtube/v3/channels?part=id&mine=true', { headers: { Authorization: 'Bearer ' + YOUTUBE_STORE.access_token } }); const cj = await ch.json(); if (cj.items && cj.items[0]) YOUTUBE_STORE.channel_id = cj.items[0].id; } catch {}
    const ok = await persistYouTubeToken();
    if (!ok) { Object.assign(YOUTUBE_STORE, prev); return res.status(503).send('storage_degraded: Token received but NOT persisted in Postgres. Check DATABASE_URL + TOKEN_ENCRYPTION_KEY, then retry login. Not connected.'); }
    const sid = createYouTubeSession();
    setCookie(res, 'yt_session', sid, { path: '/', maxAge: 24*3600 });
    res.send('<h1>YouTube connected</h1><p>Token + Refresh Token saved in Postgres (encrypted, persistent). Session created. You can close this and open your dashboard.</p><p><a href="https://yusef-delta.vercel.app">Open Dashboard</a></p>');
  } catch (e) { res.status(500).send('Token exchange failed: ' + e.message); }
});
app.get('/api/youtube/refresh', requireYouTube, async (req, res) => { try { const s = await youtubeRefresh(); res.json({ ok:true, has_token: !!s.access_token, expires_at: s.expires_at, storage: pgPool ? 'Postgres' : 'Memory' }); } catch(e){ res.status(500).json({ error: e.message }); } });
app.post('/api/youtube/disconnect', requireYouTube, requireCSRF, async (req, res) => {
  let revokeOk = null, revokeError = null;
  const t = YOUTUBE_STORE.access_token;
  if (t) { try { const rr = await fetch('https://oauth2.googleapis.com/revoke', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token: t }) }); if (rr.status === 200) revokeOk = true; else { const rj = await rr.json().catch(()=>({})); revokeOk = false; revokeError = rj.error_description || rj.error || ('HTTP ' + rr.status); } } catch(e){ revokeOk = false; revokeError = e.message; } }
  try { if (pgPool) { await dbClearYouTubeToken(); } else { return res.status(503).json({ error: 'storage_degraded: Postgres not available', code: 'storage_degraded', connected: true }); } } catch(e){ return res.status(503).json({ error: 'storage_degraded: Failed to delete tokens - still connected.', code: 'storage_degraded', connected: true, revoke_ok: revokeOk, revoke_error: revokeError }); }
  YOUTUBE_STORE.access_token = null; YOUTUBE_STORE.refresh_token = null; YOUTUBE_STORE.expires_at = null; YOUTUBE_STORE.channel_id = null; YOUTUBE_STORE.scope = null;
  destroyYouTubeSession(req, res);
  res.json({ ok:true, connected:false, message:'YouTube disconnected. Re-login via /api/youtube/login to reconnect.', revoke_ok: revokeOk, revoke_error: revokeError });
});
app.get('/api/youtube/channel', requireYouTube, async (req, res) => {
  try { const data = await youtubeApi('channels?part=snippet,statistics,contentDetails&mine=true'); const ch = (data.items && data.items[0]) || null; if (!ch) return res.status(404).json({ error: 'No YouTube channel found for this account' }); if (ch.id) YOUTUBE_STORE.channel_id = ch.id; res.json({ ...ch, source: 'Live YouTube API', transparency: 'Real' }); } catch (e) { res.status(500).json({ error: e.message, source: 'Live YouTube API' }); }
});
app.get('/api/youtube/videos', requireYouTube, async (req, res) => {
  try {
    let cid = YOUTUBE_STORE.channel_id;
    if (!cid) { const ch = await youtubeApi('channels?part=id&mine=true'); cid = ch.items?.[0]?.id; if (cid) YOUTUBE_STORE.channel_id = cid; }
    if (!cid) return res.status(404).json({ error: 'No YouTube channel found' });
    const search = await youtubeApi('search?part=snippet&channelId=' + encodeURIComponent(cid) + '&maxResults=20&order=date&type=video');
    const ids = (search.items || []).map(it => it.id?.videoId).filter(Boolean);
    if (!ids.length) return res.json({ items: [], videos: [], source: 'Live YouTube API', transparency: 'Real' });
    const vids = await youtubeApi('videos?part=snippet,statistics,contentDetails&id=' + encodeURIComponent(ids.join(',')));
    const videos = (vids.items || []).map(v => ({ id: v.id, title: v.snippet?.title || null, description: v.snippet?.description || null, publishedAt: v.snippet?.publishedAt || null, thumbnail_url: v.snippet?.thumbnails?.medium?.url || v.snippet?.thumbnails?.default?.url || null, viewCount: v.statistics?.viewCount ? Number(v.statistics.viewCount) : 0, likeCount: v.statistics?.likeCount ? Number(v.statistics.likeCount) : 0, commentCount: v.statistics?.commentCount ? Number(v.statistics.commentCount) : 0, share_url: 'https://www.youtube.com/watch?v=' + v.id }));
    res.json({ items: videos, videos, source: 'Live YouTube API', transparency: 'Real' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/youtube/analytics', requireYouTube, async (req, res) => {
  try {
    const chData = await youtubeApi('channels?part=snippet,statistics,contentDetails&mine=true');
    const channel = (chData.items && chData.items[0]) || null;
    if (!channel) return res.status(404).json({ error: 'No YouTube channel found' });
    if (channel.id) YOUTUBE_STORE.channel_id = channel.id;
    let videos = [];
    try {
      const search = await youtubeApi('search?part=snippet&channelId=' + encodeURIComponent(channel.id) + '&maxResults=20&order=date&type=video');
      const ids = (search.items || []).map(it => it.id?.videoId).filter(Boolean);
      if (ids.length) { const vids = await youtubeApi('videos?part=snippet,statistics,contentDetails&id=' + encodeURIComponent(ids.join(','))); videos = (vids.items || []).map(v => ({ id: v.id, title: v.snippet?.title || null, publishedAt: v.snippet?.publishedAt || null, thumbnail_url: v.snippet?.thumbnails?.medium?.url || null, viewCount: v.statistics?.viewCount ? Number(v.statistics.viewCount) : 0, likeCount: v.statistics?.likeCount ? Number(v.statistics.likeCount) : 0, commentCount: v.statistics?.commentCount ? Number(v.statistics.commentCount) : 0, share_url: 'https://www.youtube.com/watch?v=' + v.id })); }
    } catch(e){}
    res.json(computeYouTubeAnalytics(channel, videos));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

const PORT = process.env.PORT || 3000;
// Fail-fast BEFORE listen (V21.3): validate Postgres + encryption key FIRST, only then listen.
// If validation fails in Production, server does NOT start listening at all.
(async () => {
  await validateBootConfig();
  await loadTokenOnBoot();
  await loadYouTubeTokenOnBoot();
  app.listen(PORT, () => { console.log(`Backend V22.1 running on ${PORT} | DB: ${pgPool ? 'Postgres (mandatory)' : 'Memory fallback (local-dev only)'} | CORS: ${ALLOWED_ORIGINS.join(', ')} | Session Auth: TikTok=yusef_session, Instagram=ig_session, YouTube=yt_session (separate)`); });
})();
