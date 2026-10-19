const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { DISCORD_CLIENT_ID: CID, DISCORD_CLIENT_SECRET: SEC, BASE_URL, SESSION_SECRET: SS0, PORT = 3000 } = process.env;
// Everything is optional: with no settings at all, players log in with a username + password.
const DISCORD_ON = !!(CID && SEC && BASE_URL);
const SESSION_SECRET = SS0 || crypto.randomBytes(32).toString('hex');
if (!SS0) console.warn('SESSION_SECRET is not set: using a random one (everyone is logged out after each restart). Set it to avoid that.');
const REDIRECT = BASE_URL ? BASE_URL.replace(/\/$/, '') + '/auth/callback' : '';
const SECURE = !!BASE_URL && BASE_URL.startsWith('https');

// ---- tiny JSON "database" (one entry per Discord user id) ----
const DB = path.join(__dirname, 'data', 'users.json');
fs.mkdirSync(path.dirname(DB), { recursive: true });
let store = { users: {}, gifts: {}, offers: {}, box: {} };
try {
  const j = JSON.parse(fs.readFileSync(DB, 'utf8'));
  store = j.users ? { users: j.users, gifts: j.gifts || {}, offers: j.offers || {}, box: j.box || {} } : { users: j, gifts: {}, offers: {}, box: {} };
} catch (e) {}
const db = store.users;      // discord id -> { user, state }
const gifts = store.gifts;   // code -> { from, a, i, r, t }
store.offers = store.offers || {};
const offers = store.offers; // id -> { from, to, give, want, t }
store.box = store.box || {};
const box = store.box;       // id -> { from, to, a, i, r, t }  (sealed boxes for players who are not friends)
let timer = null;

// ---- optional Postgres (set DATABASE_URL) so cards survive redeploys; otherwise the JSON file is used ----
const DATABASE_URL = process.env.DATABASE_URL;
let pool = null;
if (DATABASE_URL) {
  const { Pool } = require('pg');
  const local = /localhost|127\.0\.0\.1/.test(DATABASE_URL);
  pool = new Pool({ connectionString: DATABASE_URL, ssl: local ? false : { rejectUnauthorized: false } });
  pool.on('error', (e) => console.error('pg pool error', e.message));
}
async function initStore() {
  if (!pool) return;
  await pool.query('CREATE TABLE IF NOT EXISTS kv (key text PRIMARY KEY, value jsonb NOT NULL, updated timestamptz DEFAULT now())');
  const r = await pool.query("SELECT value FROM kv WHERE key = 'store'");
  if (r.rows.length) {
    const j = r.rows[0].value || {};
    Object.assign(db, j.users || {});
    Object.assign(gifts, j.gifts || {});
    Object.assign(offers, j.offers || {});
    Object.assign(box, j.box || {});
    console.log('Loaded', Object.keys(db).length, 'users from Postgres');
  } else {
    await saveNow(); // first run: migrate whatever came from data/users.json
    console.log('Postgres initialised with', Object.keys(db).length, 'users from file');
  }
}
async function saveNow() {
  if (pool) {
    await pool.query("INSERT INTO kv (key, value, updated) VALUES ('store', $1::jsonb, now()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated = now()", [JSON.stringify(store)]);
  } else {
    const tmp = DB + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(store));
    fs.renameSync(tmp, DB);
  }
}
function persist() {
  clearTimeout(timer);
  timer = setTimeout(() => saveNow().catch((e) => console.error('save failed', e.message)), 300);
}
async function flushAndExit() {
  clearTimeout(timer);
  try { await saveNow(); } catch (e) { console.error('final save failed', e.message); }
  process.exit(0);
}
process.on('SIGTERM', flushAndExit);
process.on('SIGINT', flushAndExit);

// ---- signed cookies ----
const sign = (v) => crypto.createHmac('sha256', SESSION_SECRET).update(v).digest('base64url');
function safeEq(a, b) {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function cookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) {
      const v = p.slice(i + 1).trim();
      let d = v;
      try { d = decodeURIComponent(v); } catch (e) { /* malformed cookie: keep it raw instead of crashing the request */ }
      o[p.slice(0, i).trim()] = d;
    }
  });
  return o;
}
function setCookie(res, name, val, maxAge) {
  res.append('Set-Cookie', `${name}=${encodeURIComponent(val)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${SECURE || (res.req && res.req.secure) ? '; Secure' : ''}`);
}
function sessionId(req) {
  const c = cookies(req).sid;
  if (!c) return null;
  const [id, exp, sig] = c.split('.');
  if (!sig || !safeEq(sig, sign(id + '.' + exp)) || Date.now() > Number(exp)) return null;
  return db[id] ? id : null;
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '200kb' }));

// ---- Discord OAuth2 ----
app.get('/auth/login', (req, res) => {
  if (!DISCORD_ON) return res.status(404).send('Discord login is not configured.');
  const state = crypto.randomBytes(16).toString('hex');
  setCookie(res, 'oauth_state', state, 600);
  const params = new URLSearchParams({
    client_id: CID,
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: 'identify',
    state
  });
  res.redirect('https://discord.com/api/oauth2/authorize?' + params);
});
app.get('/auth/callback', async (req, res) => {
  if (!DISCORD_ON) return res.status(404).end();
  const { code, state } = req.query;
  if (!code || !state || state !== cookies(req).oauth_state) return res.status(400).send('bad oauth');
  setCookie(res, 'oauth_state', '', 0);
  try {
    const tok = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CID,
        client_secret: SEC,
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT
      })
    }).then(r => r.json());
    if (!tok.access_token) throw new Error('no token');
    const user = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: 'Bearer ' + tok.access_token }
    }).then(r => r.json());
    if (!user.id) throw new Error('no user');
    if (!db[user.id]) db[user.id] = { user: { id: user.id, username: user.username, avatar: user.avatar }, state: null };
    else {
      db[user.id].user.username = user.username;
      db[user.id].user.avatar = user.avatar;
    }
    persist();
    startSession(res, user.id);
    res.redirect('/');
  } catch (e) {
    console.error('oauth', e.message);
    res.status(500).send('oauth failed');
  }
});
app.post('/auth/logout', (req, res) => {
  setCookie(res, 'sid', '', 0);
  res.json({ ok: true });
});

// ---- local accounts (username + password) ----
const UNAME = /^[a-zA-Z0-9_]{3,20}$/;
function bodyOf(u) {
  if (typeof u !== 'string') return '';
  u = u.trim();
  if (u.startsWith('@')) u = u.slice(1);
  return u;
}
function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(pw, salt, 32);
  return salt.toString('hex') + ':' + hash.toString('hex');
}
function checkPw(pw, stored) {
  if (!stored || typeof stored !== 'string') return false;
  const [s, h] = stored.split(':');
  if (!s || !h) return false;
  try {
    const salt = Buffer.from(s, 'hex');
    const hash = crypto.scryptSync(pw, salt, 32);
    return safeEq(hash.toString('hex'), h);
  } catch (e) { return false; }
}
function findLocal(name) {
  name = name.toLowerCase();
  for (const id of Object.keys(db)) {
    const u = db[id].user;
    if (db[id].local && u && typeof u.username === 'string' && u.username.toLowerCase() === '@' + name) return id;
  }
  return null;
}
function findSimilar(name) {
  name = name.toLowerCase();
  for (const id of Object.keys(db)) {
    const u = db[id].user;
    if (u && typeof u.username === 'string' && u.username.toLowerCase().replace(/^@/, '') === name) return id;
  }
  return null;
}
// One-time migration: accounts made before the "@" rule get it added to their name.
function addAtToOldNames() {
  let n = 0;
  for (const id of Object.keys(db)) {
    const u = db[id].user;
    if (db[id].local && u && typeof u.username === 'string' && !u.username.startsWith('@')) { u.username = '@' + u.username; n++; }
  }
  if (n) { console.log('Added @ to', n, 'usernames'); persist(); }
}
function startSession(res, id) {
  const exp = Date.now() + 30 * 24 * 3600 * 1000;
  setCookie(res, 'sid', `${id}.${exp}.${sign(id + '.' + exp)}`, 30 * 24 * 3600);
}
function tooMany(req, name) {
  const k = req.ip + '|' + name.toLowerCase(), now = Date.now();
  authFail[k] = (authFail[k] || []).filter((t) => t > now - 600000);
  return { k, over: authFail[k].length >= 10 };
}
const authFail = {};
app.get('/api/config', (req, res) => res.json({ discord: DISCORD_ON }));

app.post('/auth/register', (req, res) => {
  const b = req.body || {}, body = bodyOf(b.username), pw = String(b.password || '');
  if (!UNAME.test(body)) return res.status(400).json({ error: 'bad username' });
  if (pw.length < 6 || pw.length > 72) return res.status(400).json({ error: 'bad password' });
  if (pw !== String(b.confirm === undefined ? '' : b.confirm)) return res.status(400).json({ error: 'mismatch' });
  const name = '@' + body;
  if (findLocal(name) || findSimilar(name)) return res.status(409).json({ error: 'taken' });
  if (Object.keys(db).length >= 50000) return res.status(503).json({ error: 'full' });
  let id;
  do { id = '9' + String(crypto.randomInt(0, 1e14)).padStart(14, '0'); } while (db[id]);
  db[id] = { user: { id, username: name, avatar: null }, state: null, pw: hashPw(pw), local: true };
  persist();
  startSession(res, id);
  res.json({ ok: true });
});

app.post('/auth/loginpw', (req, res) => {
  const b = req.body || {}, name = bodyOf(b.username), pw = String(b.password || '');
  const t = tooMany(req, name);
  if (t.over) return res.status(429).json({ error: 'too many' });
  const id = name && pw.length <= 72 ? findLocal(name) : null;
  if (!id || !checkPw(pw, db[id].pw)) { authFail[t.k].push(Date.now()); return res.status(401).json({ error: 'invalid' }); }
  startSession(res, id);
  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, 'public')));
initStore()
  .then(() => { addAtToOldNames(); })
  .then(() => app.listen(PORT, () => console.log('Running on port ' + PORT)))
  .catch((e) => { console.error('Database init failed:', e.message); process.exit(1); });
