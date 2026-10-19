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
  const q = new URLSearchParams({ client_id: CID, redirect_uri: REDIRECT, response_type: 'code', scope: 'identify', state, prompt: 'none' });
  res.redirect('https://discord.com/oauth2/authorize?' + q);
});

app.get('/auth/callback', async (req, res) => {
  if (!DISCORD_ON) return res.status(404).send('Discord login is not configured.');
  try {
    const { code, state } = req.query;
    const saved = cookies(req).oauth_state;
    if (!code || !state || !saved || !safeEq(String(state), saved)) return res.status(400).send('Invalid login state. Go back and try again.');
    const tr = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: CID, client_secret: SEC, grant_type: 'authorization_code', code: String(code), redirect_uri: REDIRECT }),
    });
    if (!tr.ok) return res.status(400).send('Discord refused the login.');
    const tok = await tr.json();
    const ur = await fetch('https://discord.com/api/users/@me', { headers: { Authorization: 'Bearer ' + tok.access_token } });
    if (!ur.ok) return res.status(400).send('Could not read your Discord profile.');
    const u = await ur.json();
    const user = { id: u.id, username: u.global_name || u.username, avatar: u.avatar ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png?size=128` : null };
    db[u.id] = Object.assign(db[u.id] || {}, { user, state: (db[u.id] && db[u.id].state) || null });
    persist();
    const exp = Date.now() + 30 * 24 * 3600 * 1000;
    setCookie(res, 'sid', `${u.id}.${exp}.${sign(u.id + '.' + exp)}`, 30 * 24 * 3600);
    setCookie(res, 'oauth_state', '', 0);
    res.redirect('/');
  } catch (e) {
    console.error(e);
    res.status(500).send('Login failed.');
  }
});

app.get('/auth/logout', (req, res) => {
  setCookie(res, 'sid', '', 0);
  res.redirect('/');
});

// ---- API ----
app.get('/api/me', (req, res) => {
  const id = sessionId(req);
  if (!id) return res.status(401).json({ user: null });
  res.json({ user: { ...db[id].user, pic: db[id].pic || null, local: !!db[id].local } });
});
app.get('/api/state', (req, res) => {
  const id = sessionId(req);
  if (!id) return res.status(401).json({});
  res.json({ state: db[id].state });
});
app.put('/api/state', (req, res) => {
  const id = sessionId(req);
  if (!id) return res.status(401).json({});
  const b = req.body;
  if (!b || typeof b !== 'object' || !b.a || typeof b.a !== 'object') return res.status(400).json({ error: 'bad state' });
  const cur = db[id].state;
  // Stale client (e.g. an old tab after a gift): send back the real state instead of overwriting it.
  if (cur && (Number(b.rev) || 0) !== (cur.rev || 0)) return res.status(409).json({ state: cur });
  // The client may only change cosmetic fields. Cards, streaks and weekly rolls are written by the server alone.
  const bg = b.bg && typeof b.bg.id === 'string' && /^[\w-]{1,20}$/.test(b.bg.id) && Number.isInteger(b.bg.i) ? { id: b.bg.id, i: b.bg.i } : null;
  db[id].state = { off: 0, cur: Math.max(0, Math.min(9, Number(b.cur) | 0)), bg, a: cur ? cur.a : {}, d: cur ? cur.d : undefined, rev: (cur ? cur.rev || 0 : 0) + 1 };
  persist();
  res.json({ ok: true, rev: db[id].state.rev });
});

// ---- Gift codes: a duplicate card leaves the sender and waits in escrow until someone redeems the code ----
const RAR = ['iron', 'silver', 'gold', 'diamond', 'legendary'];
const CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const failed = {};
function newCode() {
  for (;;) {
    let c = '';
    for (let i = 0; i < 8; i++) c += CHARS[crypto.randomInt(CHARS.length)];
    if (!gifts[c]) return c;
  }
}
function stateOf(u) {
  if (!u.state) u.state = { off: 0, cur: 0, bg: null, a: {}, rev: 0 };
  return u.state;
}
function addCard(st, a, i, r) {
  const A = (st.a[a] = st.a[a] || { last: '', streak: 0, got: {} });
  A.got = A.got || {};
  const G = (A.got[i] = A.got[i] || {});
  G[r] = (G[r] || 0) + 1;
  st.rev = (st.rev || 0) + 1;
}

app.post('/api/gift', (req, res) => {
  const id = sessionId(req);
  if (!id) return res.status(401).json({});
  const { a, i, r } = req.body || {};
  if (typeof a !== 'string' || !/^[\w-]{1,20}$/.test(a) || !Number.isInteger(i) || i < 0 || i > 99 || !RAR.includes(r) || (a === 'leg') !== (r === 'legendary')) return res.status(400).json({ error: 'bad request' });
  if (Object.values(gifts).filter((g) => g.from === id).length >= 20) return res.status(400).json({ error: 'too many pending codes' });
  const st = stateOf(db[id]);
  const have = (((st.a[a] || {}).got || {})[i] || {})[r] || 0;
  if (have < 1) return res.status(400).json({ error: 'not owned' }); // any card can be gifted; it leaves the sender
  st.a[a].got[i][r] = have - 1;
  st.rev = (st.rev || 0) + 1;
  const code = newCode();
  gifts[code] = { from: id, a, i, r, t: Date.now() };
  persist();
  res.json({ code, state: st });
});

app.get('/api/gifts', (req, res) => {
  const id = sessionId(req);
  if (!id) return res.status(401).json({});
  res.json({ gifts: Object.entries(gifts).filter(([, g]) => g.from === id).map(([code, g]) => ({ code, a: g.a, i: g.i, r: g.r, t: g.t })) });
});

app.delete('/api/gift/:code', (req, res) => {
  const id = sessionId(req);
  if (!id) return res.status(401).json({});
  const code = String(req.params.code).toUpperCase();
  const g = gifts[code];
  if (!g || g.from !== id) return res.status(404).json({ error: 'not found' });
  const st = stateOf(db[id]);
  addCard(st, g.a, g.i, g.r);
  delete gifts[code];
  persist();
  res.json({ state: st });
});

app.post('/api/redeem', (req, res) => {
  const id = sessionId(req);
  if (!id) return res.status(401).json({});
  const now = Date.now();
  failed[id] = (failed[id] || []).filter((t) => t > now - 600000);
  if (failed[id].length >= 10) return res.status(429).json({ error: 'too many tries' });
  const code = String((req.body || {}).code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  const g = gifts[code];
  if (!g) { failed[id].push(now); return res.status(404).json({ error: 'invalid code' }); }
  if (g.from === id) return res.status(400).json({ error: 'own code' });
  const st = stateOf(db[id]);
  addCard(st, g.a, g.i, g.r);
  delete gifts[code];
  persist();
  res.json({ state: st, card: { a: g.a, i: g.i, r: g.r } });
});

// ---- Server-side game logic (cannot be faked from the browser console) ----
const COUNTS = { naruto: 8, dbz: 8, ds: 8, bb: 6, bc: 8, hxh: 8, mha: 8, jjk: 7, op: 8 };
const CUTE_COUNT = 9;
const LEG_COUNT = 10, LEG_NOTHING = 40; // percent chance of getting nothing in the weekly legendary card
const TZ = 'Africa/Algiers';
const dfmt = new Intl.DateTimeFormat('en-US', { timeZone: TZ, year: 'numeric', month: 'numeric', day: 'numeric' });
function dstr(off = 0) {
  const m = {};
  dfmt.formatToParts(new Date(Date.now() + off * 864e5)).forEach((x) => (m[x.type] = x.value));
  return `${m.year}-${m.month}-${m.day}`;
}
function weekKey() {
  const [y, m, d] = dstr().split('-').map(Number);
  const t = Date.UTC(y, m - 1, d), dow = new Date(t).getUTCDay();
  const q = new Date(t - ((dow + 6) % 7) * 864e5);
  return `${q.getUTCFullYear()}-${q.getUTCMonth() + 1}-${q.getUTCDate()}`;
}
const W_NORMAL = [55, 30, 12, 3], W_BOOST = [0, 0, 70, 30], W_CUTE = [25, 35, 30, 10];
function pickRarity(boost, weights) {
  const w = weights || (boost ? W_BOOST : W_NORMAL);
  let r = crypto.randomInt(100);
  for (let i = 0; i < 4; i++) { r -= w[i]; if (r < 0) return i; }
  return 0;
}
app.post('/api/open', (req, res) => {
  // One pack per day in total. Luck picks the anime, the character and the rarity.
  const id = sessionId(req);
  if (!id) return res.status(401).json({});
  const st = stateOf(db[id]);
  const D = (st.d = st.d || { last: '', streak: 0 });
  if (D.last === dstr()) return res.status(409).json({ error: 'already opened', state: st });
  const ns = D.last === dstr(-1) ? (D.streak || 0) + 1 : 1;
  const boost = ns >= 7;
  const ids = Object.keys(COUNTS);
  const a = ids[crypto.randomInt(ids.length)];
  const r = RAR[pickRarity(boost)], i = crypto.randomInt(COUNTS[a]);
  D.last = dstr();
  D.streak = boost ? 0 : ns;
  const A = (st.a[a] = st.a[a] || { last: '', streak: 0, got: {} });
  A.got = A.got || {};
  const G = (A.got[i] = A.got[i] || {});
  G[r] = (G[r] || 0) + 1;
  st.rev = (st.rev || 0) + 1;
  persist();
  res.json({ ok: true, state: st, card: { a, i, r, boost } });
});
app.post('/api/legendary', (req, res) => {
  const id = sessionId(req);
  if (!id) return res.status(401).json({});
  const st = stateOf(db[id]);
  const L = (st.a.leg = st.a.leg || { last: '', streak: 0, got: {} });
  L.got = L.got || {};
  const wk = weekKey();
  if (L.last === wk) return res.status(409).json({ error: 'already opened this week', state: st });
  L.last = wk;
  let card = null;
  if (crypto.randomInt(100) >= LEG_NOTHING) {
    const i = crypto.randomInt(LEG_COUNT);
    const G = (L.got[i] = L.got[i] || {});
    G.legendary = (G.legendary || 0) + 1;
    card = { i };
  }
  st.rev = (st.rev || 0) + 1;
  persist();
  res.json({ ok: true, state: st, card });
});

app.post('/api/cute', (req, res) => {
  // Weekly cute pack: one pack per week, always one card (from the 9 cute cards).
  const id = sessionId(req);
  if (!id) return res.status(401).json({});
  const st = stateOf(db[id]);
  const C = (st.a.cute = st.a.cute || { last: '', streak: 0, got: {} });
  C.got = C.got || {};
  const wk = weekKey();
  if (C.last === wk) return res.status(409).json({ error: 'already opened this week', state: st });
  C.last = wk;
  const i = crypto.randomInt(CUTE_COUNT), r = RAR[pickRarity(false, W_CUTE)];
  const G = (C.got[i] = C.got[i] || {});
  G[r] = (G[r] || 0) + 1;
  st.rev = (st.rev || 0) + 1;
  persist();
  res.json({ ok: true, state: st, card: { a: 'cute', i, r } });
});

// ---- Friends + trade offers (swap one card for one card, friends only) ----
const isId = (x) => typeof x === 'string' && /^\d{5,25}$/.test(x);
function socOf(id) { const u = db[id]; if (!u.soc) u.soc = { f: [], i: [], o: [] }; return u.soc; }
function pub(id) { const u = db[id]; return u && u.user ? { id, username: u.user.username, avatar: u.user.avatar, pic: u.pic || null } : null; }
function validCard(c) {
  return c && typeof c.a === 'string' && /^[\w-]{1,20}$/.test(c.a) && Number.isInteger(c.i) && c.i >= 0 && c.i <= 99 && RAR.includes(c.r) && (c.a === 'leg') === (c.r === 'legendary');
}
function owns(st, c) { return ((((st.a[c.a] || {}).got || {})[c.i] || {})[c.r] || 0) >= 1; }
function takeCard(st, c) { st.a[c.a].got[c.i][c.r] -= 1; st.rev = (st.rev || 0) + 1; }
const clean = (c) => ({ a: c.a, i: c.i, r: c.r });
function dropOffers(x, y) {
  for (const k of Object.keys(offers)) {
    const o = offers[k];
    if ((o.from === x && o.to === y) || (o.from === y && o.to === x)) delete offers[k];
  }
}
function need(req, res) { const id = sessionId(req); if (!id) res.status(401).json({}); return id; }
function befriend(a, b) {
  const A = socOf(a), B = socOf(b);
  A.i = A.i.filter((x) => x !== b); A.o = A.o.filter((x) => x !== b);
  B.i = B.i.filter((x) => x !== a); B.o = B.o.filter((x) => x !== a);
  if (!A.f.includes(b)) A.f.push(b);
  if (!B.f.includes(a)) B.f.push(a);
}

app.get('/api/social', (req, res) => {
  const id = need(req, res); if (!id) return;
  const s = socOf(id), list = (a) => a.map(pub).filter(Boolean);
  const mine = Object.entries(offers).filter(([, o]) => o.from === id || o.to === id)
    .map(([oid, o]) => ({ id: oid, from: pub(o.from), to: pub(o.to), give: o.give, want: o.want, t: o.t, mine: o.from === id }));
  res.json({ friends: list(s.f), inc: list(s.i), out: list(s.o), offers: mine });
});

app.get('/api/users/search', (req, res) => {
  const id = need(req, res); if (!id) return;
  const qq = String(req.query.q || '').trim().toLowerCase();
  if (qq.length < 2) return res.json({ users: [] });
  const s = socOf(id), out = [];
  for (const [uid, u] of Object.entries(db)) {
    if (uid === id || !u.user) continue;
    if (String(u.user.username).toLowerCase().includes(qq) || uid === qq) {
      out.push({ ...pub(uid), rel: s.f.includes(uid) ? 'friend' : s.o.includes(uid) ? 'out' : s.i.includes(uid) ? 'in' : '' });
      if (out.length >= 10) break;
    }
  }
  res.json({ users: out });
});

app.post('/api/friend/add', (req, res) => {
  const id = need(req, res); if (!id) return;
  const t = String((req.body || {}).id || '');
  if (!isId(t) || t === id) return res.status(400).json({ error: 'bad id' });
  if (!db[t]) return res.status(404).json({ error: 'not found' });
  const a = socOf(id), b = socOf(t);
  if (a.f.includes(t)) return res.json({ ok: true });
  if (a.i.includes(t)) befriend(id, t); // they already asked me: now friends
  else {
    if (a.f.length >= 200 || a.o.length >= 50) return res.status(400).json({ error: 'limit' });
    if (!a.o.includes(t)) a.o.push(t);
    if (!b.i.includes(id)) b.i.push(id);
  }
  persist();
  res.json({ ok: true });
});

app.post('/api/friend/accept', (req, res) => {
  const id = need(req, res); if (!id) return;
  const t = String((req.body || {}).id || '');
  if (!isId(t) || !db[t] || !socOf(id).i.includes(t)) return res.status(404).json({ error: 'no request' });
  befriend(id, t);
  persist();
  res.json({ ok: true });
});

app.post('/api/friend/remove', (req, res) => { // also used to decline / cancel a request
  const id = need(req, res); if (!id) return;
  const t = String((req.body || {}).id || '');
  if (!isId(t) || !db[t]) return res.status(404).json({ error: 'not found' });
  const A = socOf(id), B = socOf(t);
  for (const k of ['f', 'i', 'o']) { A[k] = A[k].filter((x) => x !== t); B[k] = B[k].filter((x) => x !== id); }
  dropOffers(id, t);
  persist();
  res.json({ ok: true });
});

app.get('/api/friend/:id/cards', (req, res) => {
  const id = need(req, res); if (!id) return;
  const t = String(req.params.id);
  if (!isId(t) || !db[t] || !socOf(id).f.includes(t)) return res.status(403).json({ error: 'not friends' });
  const st = db[t].state, cards = [];
  for (const [a, A] of Object.entries((st && st.a) || {}))
    for (const [i, G] of Object.entries((A && A.got) || {}))
      for (const [r, n] of Object.entries(G || {}))
        if (n > 0 && RAR.includes(r)) cards.push({ a, i: +i, r, n });
  res.json({ cards });
});

app.post('/api/offer', (req, res) => {
  const id = need(req, res); if (!id) return;
  const { to, give, want } = req.body || {};
  if (!isId(to) || !db[to] || !socOf(id).f.includes(to)) return res.status(403).json({ error: 'not friends' });
  if (!validCard(give) || !validCard(want)) return res.status(400).json({ error: 'bad card' });
  if (!owns(stateOf(db[id]), give)) return res.status(400).json({ error: 'you do not own that card' });
  if (!owns(stateOf(db[to]), want)) return res.status(400).json({ error: 'friend does not own that card' });
  if (Object.values(offers).filter((o) => o.from === id).length >= 10) return res.status(400).json({ error: 'too many pending offers' });
  const oid = crypto.randomBytes(6).toString('hex');
  offers[oid] = { from: id, to, give: clean(give), want: clean(want), t: Date.now() };
  persist();
  res.json({ ok: true });
});

app.post('/api/offer/:oid/accept', (req, res) => {
  const id = need(req, res); if (!id) return;
  const oid = String(req.params.oid), o = offers[oid];
  if (!o || o.to !== id) return res.status(404).json({ error: 'not found' });
  if (!socOf(id).f.includes(o.from)) { delete offers[oid]; persist(); return res.status(404).json({ error: 'not found' }); }
  const me = stateOf(db[id]), them = stateOf(db[o.from]);
  if (!owns(them, o.give) || !owns(me, o.want)) { // one side no longer has the card
    delete offers[oid]; persist();
    return res.status(409).json({ error: 'card no longer available', state: me });
  }
  takeCard(them, o.give); takeCard(me, o.want);
  addCard(them, o.want.a, o.want.i, o.want.r);
  addCard(me, o.give.a, o.give.i, o.give.r);
  delete offers[oid];
  persist();
  res.json({ ok: true, state: me });
});

app.delete('/api/offer/:oid', (req, res) => {
  const id = need(req, res); if (!id) return;
  const oid = String(req.params.oid), o = offers[oid];
  if (!o || (o.from !== id && o.to !== id)) return res.status(404).json({ error: 'not found' });
  delete offers[oid]; persist();
  res.json({ ok: true });
});

// ---- Send a card to a player. Friends: it lands straight in their collection (no code).
//      Not friends: it waits in a sealed box; they open it and it goes straight into their collection. ----
app.post('/api/send', (req, res) => {
  const id = need(req, res); if (!id) return;
  const { to, card } = req.body || {};
  if (!isId(to) || to === id || !db[to] || !db[to].user) return res.status(404).json({ error: 'player not found' });
  if (!validCard(card)) return res.status(400).json({ error: 'bad card' });
  const mine = stateOf(db[id]);
  if (!owns(mine, card)) return res.status(400).json({ error: 'you do not own that card' });
  const friends = socOf(id).f.includes(to);
  if (!friends) {
    const all = Object.values(box);
    if (all.filter((b) => b.to === to).length >= 100) return res.status(400).json({ error: 'their box is full' });
    if (all.filter((b) => b.from === id).length >= 50) return res.status(400).json({ error: 'too many pending boxes' });
  }
  takeCard(mine, card);
  if (friends) addCard(stateOf(db[to]), card.a, card.i, card.r);
  else {
    const bid = crypto.randomBytes(6).toString('hex');
    box[bid] = { from: id, to, a: card.a, i: card.i, r: card.r, t: Date.now() };
  }
  persist();
  res.json({ ok: true, direct: friends, state: mine });
});

app.get('/api/box', (req, res) => {
  const id = need(req, res); if (!id) return;
  const rows = Object.entries(box).sort((x, y) => x[1].t - y[1].t);
  res.json({
    // incoming boxes stay sealed: the card is only revealed when it is opened
    in: rows.filter(([, b]) => b.to === id).map(([bid, b]) => ({ id: bid, from: pub(b.from), t: b.t })),
    out: rows.filter(([, b]) => b.from === id).map(([bid, b]) => ({ id: bid, to: pub(b.to), card: { a: b.a, i: b.i, r: b.r }, t: b.t })),
  });
});

app.post('/api/box/:bid/open', (req, res) => {
  const id = need(req, res); if (!id) return;
  const bid = String(req.params.bid), b = box[bid];
  if (!b || b.to !== id) return res.status(404).json({ error: 'not found' });
  const st = stateOf(db[id]);
  addCard(st, b.a, b.i, b.r);
  delete box[bid];
  persist();
  res.json({ ok: true, state: st, card: { a: b.a, i: b.i, r: b.r }, from: pub(b.from) });
});

app.delete('/api/box/:bid', (req, res) => { // the sender takes an unopened box back
  const id = need(req, res); if (!id) return;
  const bid = String(req.params.bid), b = box[bid];
  if (!b || b.from !== id) return res.status(404).json({ error: 'not found' });
  const st = stateOf(db[id]);
  addCard(st, b.a, b.i, b.r);
  delete box[bid];
  persist();
  res.json({ ok: true, state: st });
});

app.post('/api/profile/pic', (req, res) => {
  // Use one of your own cards as profile picture (a: null goes back to the Discord avatar).
  const id = need(req, res); if (!id) return;
  const b = req.body || {};
  if (b.a === null || b.a === undefined) { delete db[id].pic; persist(); return res.json({ ok: true, pic: null }); }
  if (typeof b.a !== 'string' || !/^[\w-]{1,20}$/.test(b.a) || !Number.isInteger(b.i) || b.i < 0 || b.i > 99) return res.status(400).json({ error: 'bad card' });
  const G = ((stateOf(db[id]).a[b.a] || {}).got || {})[b.i] || {};
  if (!Object.values(G).some((n) => n > 0)) return res.status(400).json({ error: 'you do not own that card' });
  db[id].pic = { a: b.a, i: b.i };
  persist();
  res.json({ ok: true, pic: db[id].pic });
});

// ---- Username + password accounts (no external service needed) ----
const authFail = {};
function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  return salt.toString('hex') + ':' + crypto.scryptSync(pw, salt, 32).toString('hex');
}
function checkPw(pw, stored) {
  const [s, h] = String(stored || '').split(':');
  if (!s || !h) return false;
  return safeEq(crypto.scryptSync(pw, Buffer.from(s, 'hex'), 32).toString('hex'), h);
}
const UNAME = /^[\p{L}\p{N}_.-]{3,20}$/u; // the part after the "@"
// "@Carlo", "carlo" and " @@carlo " are all the same name: strip the @ and whitespace, keep the body.
const bodyOf = (raw) => String(raw || '').trim().replace(/^@+/, '');
// Similarity key: names that look alike ("Carlo", "carl0", "c.a_rlo", "Cárlo", "carlooo") get the same key.
const LOOK = { '0': 'o', '1': 'l', 'i': 'l', '|': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '$': 's', '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c', '\u0445': 'x', '\u0456': 'l', '\u0131': 'l' };
function skel(raw) {
  let k = String(raw || '').normalize('NFKD').replace(/[\u0300-\u036f\u064b-\u065f\u0670\u0640]/g, '').toLowerCase();
  k = k.replace(/^@+/, '').replace(/[\s_.\-]/g, '');
  k = Array.from(k, (c) => LOOK[c] || c).join('');
  return k.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/(.)\1+/g, '$1');
}
function findLocal(name) {
  const k = bodyOf(name).toLowerCase();
  return Object.keys(db).find((id) => db[id].pw && db[id].user && bodyOf(db[id].user.username).toLowerCase() === k);
}
function findSimilar(name) {
  const k = skel(name);
  return Object.keys(db).some((id) => db[id].user && skel(db[id].user.username) === k);
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
