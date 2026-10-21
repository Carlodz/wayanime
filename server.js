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
  store = j.users ? { users: j.users, gifts: j.gifts || {}, offers: j.offers || {}, box: j.box || {}, log: j.log || [], custom: j.custom, notes: j.notes, ann: j.ann, resets: j.resets, smsg: j.smsg, removed: j.removed, shop: j.shop } : { users: j, gifts: {}, offers: {}, box: {}, log: [] };
} catch (e) {}
const db = store.users;      // discord id -> { user, state }
const gifts = store.gifts;   // code -> { from, a, i, r, t }
store.offers = store.offers || {};
const offers = store.offers; // id -> { from, to, give, want, t }
store.box = store.box || {};
const box = store.box;
store.custom = store.custom || {}; store.custom.packs = store.custom.packs || {}; store.custom.cards = store.custom.cards || {};
store.notes = store.notes || {}; store.ann = Array.isArray(store.ann) ? store.ann : [];
store.resets = store.resets || {};
store.smsg = store.smsg || {};
store.removed = store.removed || {}; // lowercase staff name -> true: staff the owner removed (they lose admin + staff card)
store.shop = store.shop || { items: {} }; store.shop.items = store.shop.items || {};
const shop = store.shop; // admin store: items { id -> {id,type:'banner'|'pic',img,price,t,off} }
const PTS = { iron: 5, silver: 10, gold: 15, diamond: 20, legendary: 50, cute: 25, aura: 100 }; // points won per card
function addPts(id, n) { if (db[id] && n > 0) db[id].pts = (db[id].pts || 0) + n; }
const custom = store.custom; // admin content: packs { id -> {id,ar,en,logo,g} } and extra cards { packId|cute|leg -> [{img,ar,en}] }
const notes = store.notes;   // userId -> [{ id, t, type, title, text, read }]
const smsg = store.smsg;     // staffId -> userId -> { t, msgs: [{ t, text }] } — messages users sent to staff, shown on the staff card until hidden
const resets = store.resets; // token -> { uid, exp } — admin-initiated password reset requests; the admin never sees the new password
const ann = store.ann;       // announcements shown to everybody       // id -> { from, to, a, i, r, t }  (sealed boxes for players who are not friends)
store.log = Array.isArray(store.log) ? store.log : [];
const evlog = store.log;     // activity log for the admin page: { t, id, u, type, text }
function logEvent(id, type, text) {
  const u = id && db[id] && db[id].user ? db[id].user.username : null;
  evlog.push({ t: Date.now(), id: id || null, u, type, text });
  if (evlog.length > 2000) evlog.splice(0, evlog.length - 2000);
}
const cname = (a, i, r) => a + '#' + i + (r ? ' (' + r + ')' : '');
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
    if (Array.isArray(j.log)) evlog.push(...j.log);
    if (j.custom) { Object.assign(custom.packs, j.custom.packs || {}); Object.assign(custom.cards, j.custom.cards || {}); }
    Object.assign(notes, j.notes || {});
    Object.assign(smsg, j.smsg || {});
    if (Array.isArray(j.ann)) ann.push(...j.ann);
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
app.use(express.json({ limit: '700kb' }));

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
    autoCountry(req, u.id);
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
  autoCountry(req, id); // old accounts get their flag too (shows on the next refresh)
  res.json({ user: { pts: db[id].pts || 0, ...db[id].user, pic: db[id].pic || null, banner: db[id].banner || null, bg: db[id].bg || null, gender: db[id].gender || null, country: db[id].country || null, status: db[id].status || '', theme: db[id].theme || null, role: roleOf(id), leg: db[id].gender === 'm' && hasLeg(db[id]), cute: db[id].gender === 'f' && hasCute(db[id]), aura: hasAura(db[id]), ver: (db[id].trades || 0) >= VERIFY_AT || isAdmin(id), gold: isAdmin(id), trades: db[id].trades || 0, local: !!db[id].local, admin: isAdmin(id) } });
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
  db[id].state = { off: 0, cur: Math.max(0, Math.min(99, Number(b.cur) | 0)), bg, a: cur ? cur.a : {}, d: cur ? cur.d : undefined, rev: (cur ? cur.rev || 0 : 0) + 1 };
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
  if (a === 'aura') return res.status(400).json({ error: 'aura cards cannot be gifted' });
  if (typeof a !== 'string' || !/^[\w-]{1,20}$/.test(a) || !Number.isInteger(i) || i < 0 || i > 99 || !RAR.includes(r) || (a === 'leg') !== (r === 'legendary')) return res.status(400).json({ error: 'bad request' });
  if (Object.values(gifts).filter((g) => g.from === id).length >= 20) return res.status(400).json({ error: 'too many pending codes' });
  const st = stateOf(db[id]);
  const have = (((st.a[a] || {}).got || {})[i] || {})[r] || 0;
  if (have < 1) return res.status(400).json({ error: 'not owned' }); // any card can be gifted; it leaves the sender
  st.a[a].got[i][r] = have - 1;
  st.rev = (st.rev || 0) + 1;
  const code = newCode();
  gifts[code] = { from: id, a, i, r, t: Date.now() };
  logEvent(id, 'gift', 'Created gift code ' + code + ' with ' + cname(a, i, r));
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
  logEvent(id, 'gift', 'Cancelled gift code ' + code);
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
  logEvent(id, 'gift', 'Redeemed code ' + code + ' (' + cname(g.a, g.i, g.r) + ') from ' + (db[g.from] && db[g.from].user ? db[g.from].user.username : '?'));
  persist();
  res.json({ state: st, card: { a: g.a, i: g.i, r: g.r } });
});

// ---- Server-side game logic (cannot be faked from the browser console) ----
const COUNTS = { naruto: 8, dbz: 8, ds: 8, bb: 6, bc: 8, hxh: 8, mha: 8, jjk: 7, op: 8, aot: 7 };
const CUTE_COUNT = 15;
const LEG_COUNT = 10, LEG_NOTHING = 90;   // percent chance of getting nothing in the weekly legendary card (boys only) -> 10% to win
const AURA_COUNT = 6, AURA_WIN = 1;         // monthly Aura card (everyone): AURA_WIN % chance (1 in 100) to win one of the 6 aura cards
const CUTE_NOTHING = 75;                    // percent chance of getting nothing in the weekly cute pack (girls only) -> 25% to win
function countOf(a) { // base cards shipped with the site + cards added from the admin page
  const base = a === 'cute' ? CUTE_COUNT : a === 'leg' ? LEG_COUNT : (COUNTS[a] || 0);
  return base + (custom.cards[a] || []).length;
}
const TZ = 'Africa/Algiers';
const dfmt = new Intl.DateTimeFormat('en-US', { timeZone: TZ, year: 'numeric', month: 'numeric', day: 'numeric' });
function dstr(off = 0) {
  const m = {};
  dfmt.formatToParts(new Date(Date.now() + off * 864e5)).forEach((x) => (m[x.type] = x.value));
  return `${m.year}-${m.month}-${m.day}`;
}
function monthKey() { return dstr().split('-').slice(0, 2).join('-'); }
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
  // One pack per day in total. Each pack holds 3 cards; luck picks the anime, the character and the rarity of each one, and the same card can drop twice.
  // Day 7 of a streak: the first card is guaranteed Gold or Diamond.
  const id = sessionId(req);
  if (!id) return res.status(401).json({});
  const st = stateOf(db[id]);
  const D = (st.d = st.d || { last: '', streak: 0 });
  if (D.last === dstr()) return res.status(409).json({ error: 'already opened', state: st });
  const ns = D.last === dstr(-1) ? (D.streak || 0) + 1 : 1;
  const boost = ns >= 7;
  const ids = Object.keys(COUNTS).concat(Object.keys(custom.packs)).filter((k) => countOf(k) > 0);
  D.last = dstr();
  D.streak = boost ? 0 : ns;
  const cards = [];
  for (let n = 0; n < 3; n++) {
    const a = ids[crypto.randomInt(ids.length)];
    const b = boost && n === 0;
    const r = RAR[pickRarity(b)], i = crypto.randomInt(countOf(a));
    addCard(st, a, i, r); addPts(id, PTS[r]);
    cards.push({ a, i, r, boost: b });
  }
  logEvent(id, 'pack', 'Opened daily pack (3 cards): ' + cards.map((c) => cname(c.a, c.i, c.r)).join(', ') + (boost ? ' [boost]' : ''));
  persist();
  res.json({ ok: true, state: st, card: cards[0], cards });
});
app.post('/api/legendary', (req, res) => {
  const id = sessionId(req);
  if (!id) return res.status(401).json({});
  if (db[id].gender !== 'm' && !isAdmin(id)) return res.status(403).json({ error: 'boys only' });
  const st = stateOf(db[id]);
  const L = (st.a.leg = st.a.leg || { last: '', streak: 0, got: {} });
  L.got = L.got || {};
  const wk = weekKey();
  if (L.last === wk) return res.status(409).json({ error: 'already opened this week', state: st });
  L.last = wk;
  let card = null;
  if (crypto.randomInt(100) >= LEG_NOTHING) {
    const i = crypto.randomInt(countOf('leg'));
    const G = (L.got[i] = L.got[i] || {});
    G.legendary = (G.legendary || 0) + 1; addPts(id, PTS.legendary);
    card = { i };
  }
  st.rev = (st.rev || 0) + 1;
  logEvent(id, 'pack', 'Opened weekly legendary pack: ' + (card ? 'leg#' + card.i : 'nothing'));
  persist();
  res.json({ ok: true, state: st, card });
});

app.post('/api/aura', (req, res) => {
  // Monthly Aura roll: one try per calendar month, 1% (1 in 100) chance to win one of the aura cards. Rolled on the server only.
  const id = sessionId(req);
  if (!id) return res.status(401).json({});
  const st = stateOf(db[id]);
  const A = (st.a.aura = st.a.aura || { last: '', streak: 0, got: {} });
  A.got = A.got || {};
  const mk = monthKey();
  if (A.last === mk) return res.status(409).json({ error: 'already opened this month', state: st });
  A.last = mk;
  let card = null;
  if (crypto.randomInt(100) < AURA_WIN) {
    const i = crypto.randomInt(AURA_COUNT);
    const G = (A.got[i] = A.got[i] || {});
    G.aura = (G.aura || 0) + 1; addPts(id, PTS.aura);
    card = { i };
  }
  st.rev = (st.rev || 0) + 1;
  logEvent(id, 'pack', 'Opened monthly aura pack: ' + (card ? 'aura#' + card.i : 'nothing'));
  persist();
  res.json({ ok: true, state: st, card });
});

app.post('/api/cute', (req, res) => {
  // Weekly cute pack (girls only): one pack per week, low chance (100 - CUTE_NOTHING %) to get a cute card.
  const id = sessionId(req);
  if (!id) return res.status(401).json({});
  if (db[id].gender !== 'f' && !isAdmin(id)) return res.status(403).json({ error: 'girls only' });
  const st = stateOf(db[id]);
  const C = (st.a.cute = st.a.cute || { last: '', streak: 0, got: {} });
  C.got = C.got || {};
  const wk = weekKey();
  if (C.last === wk) return res.status(409).json({ error: 'already opened this week', state: st });
  C.last = wk;
  if (crypto.randomInt(100) < CUTE_NOTHING) {
    st.rev = (st.rev || 0) + 1;
    logEvent(id, 'pack', 'Opened weekly cute pack: nothing');
    persist();
    return res.json({ ok: true, state: st, card: null });
  }
  const i = crypto.randomInt(countOf('cute')), r = RAR[pickRarity(false, W_CUTE)];
  const G = (C.got[i] = C.got[i] || {});
  G[r] = (G[r] || 0) + 1; addPts(id, PTS.cute);
  st.rev = (st.rev || 0) + 1;
  logEvent(id, 'pack', 'Opened weekly cute pack: ' + cname('cute', i, r));
  persist();
  res.json({ ok: true, state: st, card: { a: 'cute', i, r } });
});

// ---- Friends + trade offers (swap one card for one card, friends only) ----
const isId = (x) => typeof x === 'string' && /^\d{5,25}$/.test(x);
function socOf(id) { const u = db[id]; if (!u.soc) u.soc = { f: [], i: [], o: [] }; return u.soc; }
const BG_KEYS = ['g1', 'g2', 'g3', 'g4', 'g5', 'g6', 'g7', 'g8']; // popup background colours (the client draws them)
const BANNER_PRESETS = ['sky', 'night', 'eyes', 'meadow', 'ban01', 'ban02', 'ban03', 'ban04', 'ban05', 'ban06', 'ban07', 'ban08', 'ban09', 'ban10', 'ban11', 'ban12', 'ban13', 'pf01', 'pf02', 'pf03', 'pf04', 'pf05', 'pf06', 'pf07', 'pf08', 'pf09', 'pf10', 'pf11', 'pf12', 'pf13', 'pf14']; // files in public/banners
const VERIFY_AT = 100; // completed trades needed for the verified badge
function hasLeg(u) {
  const g = (((u.state || {}).a || {}).leg || {}).got || {};
  return Object.values(g).some((o) => o && Object.values(o).some((n) => n > 0));
}
function hasAura(u) {
  const g = (((u.state || {}).a || {}).aura || {}).got || {};
  return Object.values(g).some((o) => o && Object.values(o).some((n) => n > 0));
}
function auraList(u) {
  const g = (((u.state || {}).a || {}).aura || {}).got || {};
  return Object.keys(g).filter((i) => g[i] && Object.values(g[i]).some((n) => n > 0)).map(Number).filter((i) => i >= 0 && i < 6);
}
function hasCute(u) {
  const g = (((u.state || {}).a || {}).cute || {}).got || {};
  return Object.values(g).some((o) => o && Object.values(o).some((n) => n > 0));
}
function pub(id) { const u = db[id]; return u && u.user ? { id, username: u.user.username, avatar: u.user.avatar, pic: u.pic || null, banner: u.banner || null, bg: u.bg || null, country: u.country || null, status: u.status || '', role: roleOf(id), leg: u.gender === 'm' && hasLeg(u), cute: u.gender === 'f' && hasCute(u), aura: hasAura(u), auras: auraList(u), ver: (u.trades || 0) >= VERIFY_AT || isAdmin(id), gold: isAdmin(id) } : null; }
function validCard(c) {
  return c && c.a !== 'aura' && typeof c.a === 'string' && /^[\w-]{1,20}$/.test(c.a) && Number.isInteger(c.i) && c.i >= 0 && c.i <= 99 && RAR.includes(c.r) && (c.a === 'leg') === (c.r === 'legendary');
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
  logEvent(id, 'friend', 'Friend request / add -> ' + db[t].user.username);
  persist();
  res.json({ ok: true });
});

app.post('/api/friend/accept', (req, res) => {
  const id = need(req, res); if (!id) return;
  const t = String((req.body || {}).id || '');
  if (!isId(t) || !db[t] || !socOf(id).i.includes(t)) return res.status(404).json({ error: 'no request' });
  befriend(id, t);
  logEvent(id, 'friend', 'Accepted friend ' + db[t].user.username);
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
  logEvent(id, 'friend', 'Removed / declined ' + db[t].user.username);
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
  res.json({ cards, auras: auraList(db[t]) }); // Aura cards are visible to friends but can never be traded
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
  logEvent(id, 'offer', 'Trade offer to ' + db[to].user.username + ': gives ' + cname(give.a, give.i, give.r) + ' for ' + cname(want.a, want.i, want.r));
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
  db[id].trades = (db[id].trades || 0) + 1; db[o.from].trades = (db[o.from].trades || 0) + 1; // every completed trade counts for both sides
  logEvent(id, 'trade', 'TRADE completed with ' + db[o.from].user.username + ': got ' + cname(o.give.a, o.give.i, o.give.r) + ', gave ' + cname(o.want.a, o.want.i, o.want.r));
  delete offers[oid];
  persist();
  res.json({ ok: true, state: me });
});

app.delete('/api/offer/:oid', (req, res) => {
  const id = need(req, res); if (!id) return;
  const oid = String(req.params.oid), o = offers[oid];
  if (!o || (o.from !== id && o.to !== id)) return res.status(404).json({ error: 'not found' });
  logEvent(id, 'offer', 'Trade offer ' + (o.from === id ? 'cancelled' : 'declined'));
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
  logEvent(id, 'send', 'Sent ' + cname(card.a, card.i, card.r) + ' to ' + db[to].user.username + (friends ? '' : ' (sealed box)'));
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
  logEvent(id, 'send', 'Opened box with ' + cname(b.a, b.i, b.r) + ' from ' + (db[b.from] && db[b.from].user ? db[b.from].user.username : '?'));
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

app.post('/api/profile/bg', (req, res) => {
  // Profile popup background, separate from the banner: { g: 'g1'..'g8' } colour, { p: preset } picture, {} = same as banner.
  const id = need(req, res); if (!id) return;
  const b = req.body || {};
  if (typeof b.g === 'string') {
    if (!BG_KEYS.includes(b.g)) return res.status(400).json({ error: 'bad background' });
    db[id].bg = { g: b.g };
  } else if (typeof b.p === 'string') {
    if (!BANNER_PRESETS.includes(b.p)) return res.status(400).json({ error: 'bad background' });
    db[id].bg = { p: b.p };
  } else if (b.au !== undefined && b.au !== null && b.au !== '') {
    const k = Number(b.au);
    if (!Number.isInteger(k) || !auraList(db[id]).includes(k)) return res.status(400).json({ error: 'you do not own that aura card' });
    db[id].bg = { au: k };
  } else delete db[id].bg;
  persist(); res.json({ ok: true, bg: db[id].bg || null });
});

app.post('/api/profile/banner', (req, res) => {
  // Use one of your own cards as profile banner (a: null removes the banner).
  const id = need(req, res); if (!id) return;
  const b = req.body || {};
  if (typeof b.p !== 'string' && (b.a === null || b.a === undefined)) { delete db[id].banner; persist(); return res.json({ ok: true, banner: null }); }
  if (typeof b.p === 'string') { // ready-made banner
    if (!BANNER_PRESETS.includes(b.p)) return res.status(400).json({ error: 'bad banner' });
    db[id].banner = { p: b.p }; persist(); return res.json({ ok: true, banner: db[id].banner });
  }
  if (typeof b.a !== 'string' || !/^[\w-]{1,20}$/.test(b.a) || !Number.isInteger(b.i) || b.i < 0 || b.i > 99) return res.status(400).json({ error: 'bad card' });
  const G = ((stateOf(db[id]).a[b.a] || {}).got || {})[b.i] || {};
  if (!Object.values(G).some((n) => n > 0)) return res.status(400).json({ error: 'you do not own that card' });
  db[id].banner = { a: b.a, i: b.i };
  persist();
  res.json({ ok: true, banner: db[id].banner });
});

app.post('/api/profile/pic', (req, res) => {
  // Use one of your own cards as profile picture (a: null goes back to the Discord avatar).
  const id = need(req, res); if (!id) return;
  const b = req.body || {};
  if (typeof b.p === 'string') { // ready-made profile photo (same files as the banner presets)
    if (!BANNER_PRESETS.includes(b.p)) return res.status(400).json({ error: 'bad photo' });
    db[id].pic = { p: b.p }; persist(); return res.json({ ok: true, pic: db[id].pic });
  }
  if (b.a === null || b.a === undefined) { delete db[id].pic; persist(); return res.json({ ok: true, pic: null }); }
  if (typeof b.a !== 'string' || !/^[\w-]{1,20}$/.test(b.a) || !Number.isInteger(b.i) || b.i < 0 || b.i > 99) return res.status(400).json({ error: 'bad card' });
  const G = ((stateOf(db[id]).a[b.a] || {}).got || {})[b.i] || {};
  if (!Object.values(G).some((n) => n > 0)) return res.status(400).json({ error: 'you do not own that card' });
  db[id].pic = { a: b.a, i: b.i };
  persist();
  res.json({ ok: true, pic: db[id].pic });
});

// ---- automatic country: from the visitor's IP (CDN header if present, else a free IP->country lookup). The IP itself is never stored. ----
const ipCache = new Map(), ipBusy = new Set(), ipTried = {}; // ip -> code, users being looked up, uid -> last attempt time
function privateIp(ip) { return !ip || ip === '::1' || /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|f[cd]|fe80)/i.test(ip); }
async function lookupCountry(ip) {
  if (ipCache.has(ip)) return ipCache.get(ip);
  const tries = [
    async () => { const r = await fetch('https://api.country.is/' + encodeURIComponent(ip), { signal: AbortSignal.timeout(3000) }); return r.ok ? (await r.json()).country : null; },
    async () => { const r = await fetch('https://ipwho.is/' + encodeURIComponent(ip) + '?fields=success,country_code', { signal: AbortSignal.timeout(3000) }); const j = r.ok ? await r.json() : null; return j && j.success ? j.country_code : null; },
  ];
  for (const t of tries) {
    try { const c = String(await t() || '').toUpperCase(); if (/^[A-Z]{2}$/.test(c)) { if (ipCache.size > 5000) ipCache.clear(); ipCache.set(ip, c); return c; } } catch (e) {}
  }
  return null;
}
async function autoCountry(req, id) {
  try {
    const u = db[id]; if (!u || u.country || u.countryManual || ipBusy.has(id)) return;
    if (Date.now() - (ipTried[id] || 0) < 6 * 3600 * 1000) return; // retry at most every 6h
    ipTried[id] = Date.now(); ipBusy.add(id);
    let c = String(req.headers['cf-ipcountry'] || '').toUpperCase();
    if (!/^[A-Z]{2}$/.test(c) || c === 'XX' || c === 'T1') c = privateIp(req.ip) ? null : await lookupCountry(req.ip.replace(/^::ffff:/, ''));
    if (c && COUNTRIES.has(c) && db[id] && !db[id].country && !db[id].countryManual) { db[id].country = c; persist(); }
  } catch (e) {} finally { ipBusy.delete(id); }
}
const COUNTRIES = new Set('AD AE AF AG AI AL AM AO AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GT GU GW GY HK HN HR HT HU ID IE IL IM IN IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'.split(' ')); // ISO 3166-1 alpha-2 codes a player can show as a flag next to their name
app.post('/api/profile/status', (req, res) => {
  // Short profile status (text + emoji), max 60 characters. Empty string clears it.
  const id = need(req, res); if (!id) return;
  const raw = (req.body || {}).s;
  if (raw !== null && raw !== undefined && typeof raw !== 'string') return res.status(400).json({ error: 'bad status' });
  const t = Array.from(String(raw || '').replace(/[\u0000-\u001f\u007f<>]/g, ' ').replace(/\s+/g, ' ').trim()).slice(0, 60).join('').trim();
  if (t) db[id].status = t; else delete db[id].status;
  persist();
  res.json({ ok: true, status: db[id].status || '' });
});

app.post('/api/profile/country', (req, res) => {
  const id = need(req, res); if (!id) return;
  const c = (req.body || {}).c;
  if (c === null || c === undefined || c === '') { delete db[id].country; delete db[id].countryManual; persist(); autoCountry(req, id); return res.json({ ok: true, country: null }); } // cleared: go back to auto-detect
  if (typeof c !== 'string' || !COUNTRIES.has(c.toUpperCase())) return res.status(400).json({ error: 'bad country' });
  db[id].country = c.toUpperCase(); db[id].countryManual = true; // a manual choice is never overwritten by auto-detect
  persist();
  res.json({ ok: true, country: db[id].country });
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

// ---- one special account: always verified, can see the admin log page ----
const ADMINS = { carlodz: { pass: 'Skikda2121', role: 'owner' }, youzix: { pass: 'Skikda2121', role: 'mod' }, sunny: { pass: 'Skikda2121', role: 'mod' } }; // owner: crown + red check, mod: key + yellow check
function roleOf(id) {
  const u = db[id] && db[id].user;
  const k = u ? bodyOf(u.username).toLowerCase() : '';
  if (!Object.prototype.hasOwnProperty.call(ADMINS, k)) return null;
  if (ADMINS[k].role !== 'owner' && store.removed[k]) return null;
  return ADMINS[k].role;
}
function ownerId(req, res) { // owner-only actions (carlodz): password reset links, removing / restoring staff
  const id = adminId(req, res); if (!id) return null;
  if (roleOf(id) !== 'owner') { res.status(403).json({ error: 'owner only' }); return null; }
  return id;
}
function isAdmin(id) {
  const u = db[id] && db[id].user;
  return !!roleOf(id);
}
async function ensureAdminAccount() {
  for (const name of Object.keys(ADMINS)) {
    if (findLocal('@' + name)) continue; // already exists, don't touch its password
    let id;
    do { id = '9' + String(crypto.randomInt(0, 1e14)).padStart(14, '0'); } while (db[id]);
    db[id] = { user: { id, username: '@' + name, avatar: null }, state: null, pw: hashPw(ADMINS[name].pass), local: true, created: Date.now() };
    persist();
    console.log('Admin account @' + name + ' created');
  }
}
function adminId(req, res) {
  const id = need(req, res); if (!id) return null;
  if (!isAdmin(id)) { res.status(403).json({ error: 'not admin' }); return null; }
  return id;
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
app.post('/api/gender', (req, res) => { // old / Discord accounts pick once
  const id = need(req, res); if (!id) return;
  const g = (req.body || {}).gender;
  if (g !== 'f' && g !== 'm') return res.status(400).json({ error: 'bad gender' });
  if (db[id].gender) return res.status(409).json({ error: 'already set', gender: db[id].gender });
  db[id].gender = g; logEvent(id, 'gender', 'Chose gender: ' + g); persist();
  res.json({ ok: true, gender: g });
});
// ---- STORE: players spend points (won from pack cards) on profile photos / banners that the admin adds ----
app.get('/shop/img/:id', (req, res) => {
  const it = shop.items[req.params.id]; const m = it && /^data:(image\/[a-z]+);base64,(.+)$/.exec(it.img);
  if (!m) return res.status(404).end();
  res.set('Cache-Control', 'public, max-age=86400').type(m[1]).send(Buffer.from(m[2], 'base64'));
});
// Site color themes sold in the Store (built in, not uploaded). The owned id is 'theme-<key>'; the equipped key is db[id].theme.
const THEMES = { blue: 300, red: 300, pink: 300 };
app.get('/api/store', (req, res) => {
  const id = need(req, res); if (!id) return;
  const own = db[id].owned || [];
  const items = Object.values(shop.items).filter((x) => !x.off || own.includes(x.id)).sort((a, b) => b.t - a.t)
    .map((x) => ({ id: x.id, type: x.type, price: x.price, owned: own.includes(x.id), off: !!x.off }));
  const pic = db[id].pic && db[id].pic.s, ban = db[id].banner && db[id].banner.s;
  const themes = Object.keys(THEMES).map((k) => ({ id: 'theme-' + k, key: k, price: THEMES[k], owned: own.includes('theme-' + k) }));
  res.json({ pts: db[id].pts || 0, items, themes, theme: db[id].theme || null, pic: pic || null, banner: ban || null, rates: PTS });
});
app.post('/api/store/buy', (req, res) => {
  const id = need(req, res); if (!id) return;
  const bid = String((req.body || {}).id);
  const it = /^theme-/.test(bid) ? (THEMES[bid.slice(6)] !== undefined ? { id: bid, type: 'theme', price: THEMES[bid.slice(6)] } : null) : shop.items[bid];
  if (!it || it.off) return res.status(404).json({ error: 'not found' });
  const u = db[id]; u.owned = u.owned || [];
  if (u.owned.includes(it.id)) return res.status(409).json({ error: 'already owned' });
  if ((u.pts || 0) < it.price) return res.status(402).json({ error: 'not enough points', pts: u.pts || 0 });
  u.pts -= it.price; u.owned.push(it.id);
  logEvent(id, 'store', 'Bought ' + it.type + ' ' + it.id + ' for ' + it.price + ' points');
  persist(); res.json({ ok: true, pts: u.pts });
});
app.post('/api/store/equip', (req, res) => {
  const id = need(req, res); if (!id) return;
  const b = req.body || {}, u = db[id], eid = String(b.id);
  if (eid === 'theme-default') { delete u.theme; persist(); return res.json({ ok: true, pic: u.pic || null, banner: u.banner || null, theme: null }); }
  if (/^theme-/.test(eid)) {
    const k = eid.slice(6);
    if (THEMES[k] === undefined || !(u.owned || []).includes(eid)) return res.status(403).json({ error: 'not owned' });
    u.theme = k; persist();
    return res.json({ ok: true, pic: u.pic || null, banner: u.banner || null, theme: k });
  }
  const it = shop.items[eid];
  if (!it || !(u.owned || []).includes(it.id)) return res.status(403).json({ error: 'not owned' });
  if (it.type === 'pic') u.pic = { s: it.id }; else u.banner = { s: it.id };
  persist(); res.json({ ok: true, pic: u.pic || null, banner: u.banner || null, theme: u.theme || null });
});
app.get('/api/admin/shop', (req, res) => {
  const me = adminId(req, res); if (!me) return;
  res.json({ items: Object.values(shop.items).sort((a, b) => b.t - a.t).map((x) => ({ id: x.id, type: x.type, price: x.price, off: !!x.off })) });
});
app.post('/api/admin/shop', (req, res) => { // add a profile photo or banner with its price in points
  const me = adminId(req, res); if (!me) return;
  const b = req.body || {}, price = Number(b.price);
  if (b.type !== 'pic' && b.type !== 'banner') return res.status(400).json({ error: 'type must be pic or banner' });
  if (!okImg(b.img)) return res.status(400).json({ error: 'image required (png/jpeg/webp/gif, small)' });
  if (!Number.isInteger(price) || price < 0 || price > 100000) return res.status(400).json({ error: 'bad price' });
  let id; do { id = 's' + crypto.randomBytes(4).toString('hex'); } while (shop.items[id]);
  shop.items[id] = { id, type: b.type, img: b.img, price, t: Date.now() };
  logEvent(me, 'admin', 'Store item added: ' + b.type + ' ' + id + ' (' + price + ' pts)');
  persist(); res.json({ ok: true, id });
});
app.post('/api/admin/points', (req, res) => { // give (or remove with a negative number) points to one user
  const me = adminId(req, res); if (!me) return;
  const b = req.body || {}, n = Number(b.amount);
  const id = db[b.user] && db[b.user].user ? b.user : byName(b.user);
  if (!id) return res.status(404).json({ error: 'user not found' });
  if (!Number.isInteger(n) || n === 0 || Math.abs(n) > 100000) return res.status(400).json({ error: 'amount must be a whole number (not 0)' });
  db[id].pts = Math.max(0, (db[id].pts || 0) + n);
  if (n > 0) pushNote(id, 'dm', 'Points', 'You received ' + n + ' points from the admin.', roleOf(me));
  logEvent(me, 'admin', (n > 0 ? 'Sent ' : 'Removed ') + Math.abs(n) + ' points ' + (n > 0 ? 'to ' : 'from ') + db[id].user.username);
  persist(); res.json({ ok: true, to: db[id].user.username, pts: db[id].pts });
});
app.post('/api/admin/shop/:id', (req, res) => { // change price or hide / show an item (owners keep it)
  const me = adminId(req, res); if (!me) return;
  const it = shop.items[req.params.id]; if (!it) return res.status(404).json({ error: 'not found' });
  const b = req.body || {};
  if (b.price !== undefined) { const p = Number(b.price); if (!Number.isInteger(p) || p < 0 || p > 100000) return res.status(400).json({ error: 'bad price' }); it.price = p; }
  if (b.off !== undefined) it.off = !!b.off;
  logEvent(me, 'admin', 'Store item updated: ' + it.id); persist(); res.json({ ok: true });
});

app.get('/api/config', (req, res) => res.json({ discord: DISCORD_ON }));

app.post('/auth/register', (req, res) => {
  const b = req.body || {}, body = bodyOf(b.username), pw = String(b.password || '');
  if (!UNAME.test(body)) return res.status(400).json({ error: 'bad username' });
  if (pw.length < 6 || pw.length > 72) return res.status(400).json({ error: 'bad password' });
  if (pw !== String(b.confirm === undefined ? '' : b.confirm)) return res.status(400).json({ error: 'mismatch' });
  if (b.gender !== 'f' && b.gender !== 'm') return res.status(400).json({ error: 'bad gender' });
  const name = '@' + body;
  if (findLocal(name) || findSimilar(name)) return res.status(409).json({ error: 'taken' });
  if (Object.keys(db).length >= 50000) return res.status(503).json({ error: 'full' });
  let id;
  do { id = '9' + String(crypto.randomInt(0, 1e14)).padStart(14, '0'); } while (db[id]);
  db[id] = { user: { id, username: name, avatar: null }, state: null, pw: hashPw(pw), gender: b.gender, local: true, created: Date.now(), lastLogin: Date.now() };
  logEvent(id, 'register', 'New account created');
  persist();
  autoCountry(req, id);
  startSession(res, id);
  res.json({ ok: true });
});

app.post('/auth/loginpw', (req, res) => {
  const b = req.body || {}, name = bodyOf(b.username), pw = String(b.password || '');
  const t = tooMany(req, name);
  if (t.over) return res.status(429).json({ error: 'too many' });
  const id = name && pw.length <= 72 ? findLocal(name) : null;
  if (!id || !checkPw(pw, db[id].pw)) { authFail[t.k].push(Date.now()); logEvent(id || null, 'login_fail', 'Failed login attempt for @' + name); persist(); return res.status(401).json({ error: 'invalid' }); }
  db[id].lastLogin = Date.now();
  logEvent(id, 'login', 'Logged in');
  persist();
  autoCountry(req, id);
  startSession(res, id);
  res.json({ ok: true });
});

// ---- admin log page: read-only list of every local account ----
app.get('/api/admin/users', (req, res) => {
  const me = adminId(req, res); if (!me) return;
  const rows = Object.keys(db).filter((id) => db[id].local).map((id) => {
    const u = db[id];
    const cards = Object.values((u.state && u.state.a) || {}).reduce((n, A) => n + Object.values(A.got || {}).reduce((m, G) => m + Object.values(G).reduce((k, c) => k + c, 0), 0), 0);
    return {
      id,
      username: u.user.username,
      trades: u.trades || 0,
      verified: (u.trades || 0) >= VERIFY_AT || isAdmin(id),
      admin: isAdmin(id),
      cards,
      created: u.created || null,
      lastLogin: u.lastLogin || null,
    };
  }).sort((a, b) => (b.lastLogin || 0) - (a.lastLogin || 0));
  res.json({ users: rows, me: roleOf(me) });
});

app.get('/api/admin/log', (req, res) => {
  const me = adminId(req, res); if (!me) return;
  const since = Number(req.query.since) || 0;
  const owner = roleOf(me) === 'owner';
  const hide = (e) => !owner && (e.type === 'reset' || /password reset/i.test(e.text || ''));
  res.json({ events: evlog.filter((e) => e.t > since && !hide(e)).slice(-500).reverse(), total: evlog.length });
});


// ---- admin: packs, cards, notifications, announcements, direct messages ----
const IMG_RE = /^data:image\/(png|jpeg|webp|gif);base64,[A-Za-z0-9+\/=]+$/;
const okImg = (x) => typeof x === 'string' && x.length < 450000 && IMG_RE.test(x);
const txt = (x, n) => (typeof x === 'string' ? x.trim().slice(0, n) : '');
const baseOf = (a) => (a === 'cute' ? CUTE_COUNT : a === 'leg' ? LEG_COUNT : (COUNTS[a] || 0));
const rid = () => crypto.randomBytes(6).toString('hex');
const byName = (q) => { const k = bodyOf(String(q || '')).toLowerCase(); return k ? Object.keys(db).find((id) => db[id].user && bodyOf(db[id].user.username).toLowerCase() === k) : undefined; };
function pushNote(uid, type, title, text, from, link) {
  const L = (notes[uid] = notes[uid] || []);
  L.push({ id: rid(), t: Date.now(), type, title, text, from: from || null, link: link || null, read: false });
  if (L.length > 100) L.splice(0, L.length - 100);
}

// ---- admin-initiated password reset: admin only triggers it, the user picks the new password themselves ----
const RESET_TTL = 30 * 60 * 1000; // 30 minutes
function cleanResets() {
  const now = Date.now();
  for (const t of Object.keys(resets)) if (resets[t].exp < now) delete resets[t];
}
app.post('/api/admin/reset-request', (req, res) => {
  const me = ownerId(req, res); if (!me) return;
  const b = req.body || {};
  const id = db[b.user] && db[b.user].user ? b.user : byName(b.user);
  if (!id || !db[id].local) return res.status(404).json({ error: 'user not found' });
  cleanResets();
  const token = crypto.randomBytes(24).toString('hex');
  resets[token] = { uid: id, exp: Date.now() + RESET_TTL };
  const link = '/reset.html?token=' + token;
  pushNote(id, 'reset', 'Password reset requested', 'An admin requested a password reset for your account. If this was you, open the link below within 30 minutes and choose a new password. If it was not you, ignore this message — your password stays the same.', roleOf(me), link);
  logEvent(me, 'admin', 'Password reset link sent to ' + db[id].user.username);
  persist();
  res.json({ ok: true, to: db[id].user.username, link });
});
app.get('/api/auth/reset-check', (req, res) => {
  cleanResets();
  const r = resets[String(req.query.token || '')];
  if (!r || !db[r.uid]) return res.status(404).json({ error: 'invalid or expired link' });
  res.json({ ok: true, username: db[r.uid].user.username });
});
app.post('/api/auth/reset-confirm', (req, res) => {
  cleanResets();
  const b = req.body || {};
  const token = String(b.token || '');
  const r = resets[token];
  if (!r || !db[r.uid]) return res.status(404).json({ error: 'invalid or expired link' });
  const pw = String(b.password || '');
  if (pw.length < 6 || pw.length > 72) return res.status(400).json({ error: 'bad password' });
  if (pw !== String(b.confirm === undefined ? '' : b.confirm)) return res.status(400).json({ error: 'mismatch' });
  db[r.uid].pw = hashPw(pw); // the admin never receives or sees this value
  delete resets[token];
  logEvent(r.uid, 'reset', 'Password changed via admin-initiated reset link');
  persist();
  res.json({ ok: true });
});

app.get('/api/custom', (req, res) => { // public: the client merges this into its built-in packs
  res.set('Cache-Control', 'no-cache');
  res.json({ packs: Object.values(custom.packs), cards: custom.cards, base: { cute: CUTE_COUNT, leg: LEG_COUNT } });
});

app.post('/api/admin/pack', (req, res) => {
  const me = adminId(req, res); if (!me) return;
  const b = req.body || {};
  const ar = txt(b.ar, 40), en = txt(b.en, 40);
  const old = b.id ? custom.packs[b.id] : null;
  if (b.id && !old) return res.status(404).json({ error: 'pack not found' });
  if (!ar || !en) return res.status(400).json({ error: 'Arabic and English names are required' });
  if (!old && !okImg(b.logo)) return res.status(400).json({ error: 'logo image required (png/jpeg/webp, small)' });
  if (b.logo && !okImg(b.logo)) return res.status(400).json({ error: 'bad logo image' });
  let id = old ? old.id : '';
  while (!id || custom.packs[id] || COUNTS[id]) id = 'p' + crypto.randomBytes(3).toString('hex');
  const g = Array.isArray(b.g) && b.g.length === 3 && b.g.every((c) => /^#[0-9a-f]{6}$/i.test(c)) ? b.g : (old ? old.g : ['#2a0f4d', '#7c3aed', '#ff7ad9']);
  custom.packs[id] = { id, ar, en, logo: b.logo || old.logo, g };
  logEvent(me, 'admin', (old ? 'Pack updated: ' : 'Pack created: ') + en);
  persist(); res.json({ ok: true, pack: custom.packs[id] });
});

app.post('/api/admin/card', (req, res) => { // add a card to a pack (or edit one that was added from here)
  const me = adminId(req, res); if (!me) return;
  const b = req.body || {};
  const pack = String(b.pack || '');
  if (!(COUNTS[pack] || custom.packs[pack] || pack === 'cute' || pack === 'leg')) return res.status(400).json({ error: 'unknown pack' });
  const ar = txt(b.ar, 40), en = txt(b.en, 40);
  const base = baseOf(pack);
  const L = custom.cards[pack] || [];
  if (Number.isInteger(b.idx)) { // edit
    const c = L[b.idx - base];
    if (!c) return res.status(404).json({ error: 'only cards added from the admin page can be edited' });
    if (ar) c.ar = ar; if (en) c.en = en;
    if (b.img) { if (!okImg(b.img)) return res.status(400).json({ error: 'bad image' }); c.img = b.img; }
    logEvent(me, 'admin', 'Card edited: ' + pack + '#' + b.idx); persist();
    return res.json({ ok: true, idx: b.idx });
  }
  if (!ar || !en || !okImg(b.img)) return res.status(400).json({ error: 'image + Arabic name + English name required' });
  if (base + L.length >= 100) return res.status(400).json({ error: 'a pack holds 100 cards at most' });
  custom.cards[pack] = L;
  L.push({ img: b.img, ar, en });
  logEvent(me, 'admin', 'Card added to ' + pack + ': ' + en);
  persist(); res.json({ ok: true, idx: base + L.length - 1 });
});

app.post('/api/admin/notify', (req, res) => { // notification to everybody or to a chosen group
  const me = adminId(req, res); if (!me) return;
  const b = req.body || {};
  const title = txt(b.title, 80), text = txt(b.text, 500);
  if (!title || !text) return res.status(400).json({ error: 'title and text required' });
  let ids = [], missing = [];
  if (b.to === 'all') ids = Object.keys(db).filter((id) => db[id].user);
  else {
    const raw = [].concat(Array.isArray(b.ids) ? b.ids : [], Array.isArray(b.names) ? b.names : []).slice(0, 500);
    raw.forEach((q) => { const id = db[q] && db[q].user ? q : byName(q); if (id) { if (!ids.includes(id)) ids.push(id); } else missing.push(String(q).slice(0, 30)); });
  }
  ids.forEach((id) => pushNote(id, 'notice', title, text, roleOf(me)));
  logEvent(me, 'admin', 'Notification "' + title + '" sent to ' + ids.length + ' user(s)');
  persist(); res.json({ ok: true, sent: ids.length, missing });
});

app.post('/api/admin/dm', (req, res) => { // custom message to one user
  const me = adminId(req, res); if (!me) return;
  const b = req.body || {};
  const text = txt(b.text, 500), title = txt(b.title, 80) || 'Message from admin';
  const id = db[b.user] && db[b.user].user ? b.user : byName(b.user);
  if (!id) return res.status(404).json({ error: 'user not found' });
  if (!text) return res.status(400).json({ error: 'message required' });
  pushNote(id, 'dm', title, text, roleOf(me));
  logEvent(me, 'admin', 'Message sent to ' + db[id].user.username);
  persist(); res.json({ ok: true, to: db[id].user.username });
});

const AURA_NAMES = ['Madara', 'Kira', 'Sukuna', 'Shanks', 'Jinwoo', 'Itachi']; // same order as the aura cards in the client (index 0..5)
app.post('/api/admin/aura-card', (req, res) => { // give one Aura card (chosen character) to one user
  const me = adminId(req, res); if (!me) return;
  const b = req.body || {};
  const id = db[b.user] && db[b.user].user ? b.user : byName(b.user);
  if (!id) return res.status(404).json({ error: 'user not found' });
  const i = Number(b.i);
  if (!Number.isInteger(i) || i < 0 || i >= AURA_COUNT) return res.status(400).json({ error: 'pick a character' });
  addCard(stateOf(db[id]), 'aura', i, 'aura');
  const note = txt(b.text, 300);
  pushNote(id, 'dm', 'Aura card', 'You received the Aura card ' + AURA_NAMES[i] + ' from the admin.' + (note ? ' ' + note : ''), roleOf(me));
  logEvent(me, 'admin', 'Gave Aura card ' + AURA_NAMES[i] + ' to ' + db[id].user.username);
  logEvent(id, 'gift', 'Received Aura card ' + AURA_NAMES[i] + ' from the admin');
  persist(); res.json({ ok: true, to: db[id].user.username, card: AURA_NAMES[i] });
});

app.get('/api/announcements', (req, res) => {
  const now = Date.now();
  res.set('Cache-Control', 'no-cache');
  res.json({ items: ann.filter((a) => !a.until || a.until > now).slice(-5).reverse() });
});
app.get('/api/admin/announce', (req, res) => { const me = adminId(req, res); if (!me) return; res.json({ items: ann.slice().reverse() }); });
app.post('/api/admin/announce', (req, res) => { // a "pub": banner shown to every visitor (e.g. a new pack is coming)
  const me = adminId(req, res); if (!me) return;
  const b = req.body || {};
  const title = txt(b.title, 80), text = txt(b.text, 300);
  if (!title) return res.status(400).json({ error: 'title required' });
  if (b.img && !okImg(b.img)) return res.status(400).json({ error: 'bad image' });
  const days = Math.max(0, Math.min(365, Number(b.days) || 0));
  const a = { id: rid(), t: Date.now(), title, text, img: b.img || null, until: days ? Date.now() + days * 864e5 : null };
  ann.push(a); if (ann.length > 50) ann.splice(0, ann.length - 50);
  logEvent(me, 'admin', 'Announcement: ' + title);
  persist(); res.json({ ok: true, item: a });
});
app.delete('/api/admin/announce/:id', (req, res) => {
  const me = adminId(req, res); if (!me) return;
  const i = ann.findIndex((a) => a.id === req.params.id);
  if (i < 0) return res.status(404).json({ error: 'not found' });
  ann.splice(i, 1); persist(); res.json({ ok: true });
});

app.get('/api/inbox', (req, res) => {
  const id = need(req, res); if (!id) return;
  const L = notes[id] || [];
  res.set('Cache-Control', 'no-store');
  res.json({ items: L.slice(-50).reverse(), unread: L.filter((n) => !n.read).length });
});
app.post('/api/inbox/read', (req, res) => {
  const id = need(req, res); if (!id) return;
  (notes[id] || []).forEach((n) => { n.read = true; });
  persist(); res.json({ ok: true });
});

// ---- owner only: list / remove / restore staff ----
app.get('/api/admin/staff', (req, res) => {
  const me = ownerId(req, res); if (!me) return;
  res.json({ staff: Object.keys(ADMINS).filter((n) => ADMINS[n].role !== 'owner').map((n) => ({ name: n, active: !store.removed[n] })) });
});
app.post('/api/admin/staff/remove', (req, res) => {
  const me = ownerId(req, res); if (!me) return;
  const k = bodyOf(String((req.body || {}).name || '')).toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(ADMINS, k) || ADMINS[k].role === 'owner') return res.status(400).json({ error: 'not removable' });
  store.removed[k] = true; logEvent(me, 'admin', 'Removed staff @' + k); persist(); res.json({ ok: true });
});
app.post('/api/admin/staff/restore', (req, res) => {
  const me = ownerId(req, res); if (!me) return;
  const k = bodyOf(String((req.body || {}).name || '')).toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(ADMINS, k)) return res.status(400).json({ error: 'unknown' });
  delete store.removed[k]; logEvent(me, 'admin', 'Restored staff @' + k); persist(); res.json({ ok: true });
});

// ---- staff contact: every user sees the owner + admin profiles (photo, banner, role only) and can message them; the message shows in the admin log ----
const contactT = {}; // user id -> timestamps of recent messages (anti-spam)
function staffList() { return Object.keys(ADMINS).map((n) => findLocal('@' + n)).filter((x) => x && roleOf(x)); }
app.get('/api/staff', (req, res) => {
  const id = need(req, res); if (!id) return;
  res.set('Cache-Control', 'no-store');
  const staff = staffList().filter((s) => s !== id).map((s) => { const u = pub(s); return { id: u.id, username: u.username, pic: u.pic, banner: u.banner, role: u.role }; })
    .sort((a, b) => (a.role === 'owner' ? 0 : 1) - (b.role === 'owner' ? 0 : 1));
  res.json({ staff });
});
app.post('/api/contact', (req, res) => {
  const id = need(req, res); if (!id) return;
  const b = req.body || {};
  const to = String(b.to || ''), text = txt(b.text, 500);
  if (!staffList().includes(to) || to === id) return res.status(404).json({ error: 'not found' });
  if (!text) return res.status(400).json({ error: 'message required' });
  const now = Date.now();
  contactT[id] = (contactT[id] || []).filter((t) => t > now - 10 * 60 * 1000);
  if (contactT[id].length >= 5) return res.status(429).json({ error: 'wait' });
  contactT[id].push(now);
  logEvent(id, 'message', '[to ' + roleOf(to) + '] ' + text);
  const box2 = (smsg[to] = smsg[to] || {});
  const c = (box2[id] = box2[id] || { t: now, msgs: [] });
  c.t = now; c.msgs.push({ t: now, text }); if (c.msgs.length > 20) c.msgs.splice(0, c.msgs.length - 20);
  persist();
  res.json({ ok: true });
});
// staff only: conversations people started with me (card with avatar + messages) until I hide them
app.get('/api/staff/inbox', (req, res) => {
  const me = adminId(req, res); if (!me) return;
  res.set('Cache-Control', 'no-store');
  const mine = smsg[me] || {};
  const items = Object.keys(mine).filter((u) => db[u] && db[u].user).map((u) => { const p = pub(u); return { user: { id: p.id, username: p.username, pic: p.pic, banner: p.banner, role: p.role }, t: mine[u].t, msgs: mine[u].msgs }; })
    .sort((a, b) => b.t - a.t);
  res.json({ items });
});
app.post('/api/staff/inbox/hide', (req, res) => {
  const me = adminId(req, res); if (!me) return;
  const from = String((req.body || {}).from || '');
  if (smsg[me]) delete smsg[me][from];
  persist(); res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, 'public')));
initStore()
  .then(() => { addAtToOldNames(); return ensureAdminAccount(); })
  .then(() => app.listen(PORT, () => console.log('Running on port ' + PORT)))
  .catch((e) => { console.error('Database init failed:', e.message); process.exit(1); });
