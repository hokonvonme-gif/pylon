const express = require('express'), http = require('http'), crypto = require('crypto'), cors = require('cors');
const { MongoClient } = require('mongodb');
const { WebSocketServer } = require('ws');

const client = new MongoClient(process.env.MONGODB_URI);
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
let projects, users, db = {};
const dirty = new Set();

async function flush() {
  if (!projects || !dirty.size) return;
  const ids = [...dirty]; dirty.clear();
  const ops = ids.filter(id => db[id]).map(id => ({ replaceOne: { filter: { _id: id }, replacement: { ...db[id] }, upsert: true } }));
  try { if (ops.length) await projects.bulkWrite(ops); }
  catch (e) { ids.forEach(id => dirty.add(id)); console.error('MongoDB :', e.message); }
}
setInterval(flush, 3000);
async function stop() { await flush(); process.exit(0); }
process.on('SIGTERM', stop); process.on('SIGINT', stop);

// ---------- Outils ----------
const sha = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const rand = (p, n) => p + crypto.randomBytes(n).toString('hex');
const hashPw = pw => new Promise((ok, ko) => { const s = crypto.randomBytes(16).toString('hex'); crypto.scrypt(pw, s, 32, (e, d) => e ? ko(e) : ok(s + ':' + d.toString('hex'))); });
const checkPw = (pw, h) => new Promise((ok, ko) => { const [s, x] = h.split(':'); crypto.scrypt(pw, s, 32, (e, d) => e ? ko(e) : ok(crypto.timingSafeEqual(d, Buffer.from(x, 'hex')))); });
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
const mkToken = email => { const b = Buffer.from(JSON.stringify({ e: email, x: Date.now() + 30 * 864e5 })).toString('base64url'); return b + '.' + sign(b); };
const readToken = t => {
  try {
    const [b, s] = String(t).split('.');
    if (!b || !s || !crypto.timingSafeEqual(Buffer.from(sign(b)), Buffer.from(s))) return null;
    const p = JSON.parse(Buffer.from(b, 'base64url')); return p.x > Date.now() ? p.e : null;
  } catch { return null; }
};

// Limitation par IP (en mémoire)
const hits = {};
const limited = (key, max, ms) => {
  const now = Date.now(), a = (hits[key] || []).filter(t => now - t < ms);
  if (a.length >= max) { hits[key] = a; return true; }
  a.push(now); hits[key] = a; return false;
};
setInterval(() => { for (const k in hits) { hits[k] = hits[k].filter(t => Date.now() - t < 3600000); if (!hits[k].length) delete hits[k]; } }, 600000);

const live = {};
const L = pk => live[pk] || (live[pk] = { dash: new Set(), waiters: [], queue: [], seen: 0 });
const online = pk => Date.now() - L(pk).seen < 35000;
const push = (pk, msg) => { const m = JSON.stringify(msg); L(pk).dash.forEach(ws => ws.readyState === 1 && ws.send(m)); };
const touch = pk => { const was = online(pk); L(pk).seen = Date.now(); if (!was) push(pk, { type: 'status', online: true }); };
const addLog = (pk, entry) => { const p = db[pk]; p.log.push(entry); p.log = p.log.slice(-50); dirty.add(pk); };

function check(pk, sk) {
  const p = db[pk];
  if (!p || !sk) return null;
  const a = Buffer.from(sha(sk)), b = Buffer.from(p.hash);
  return a.length === b.length && crypto.timingSafeEqual(a, b) ? p : null;
}
const guard = (req, res, next) => {
  const pk = req.get('x-public-key'), p = check(pk, req.get('x-private-key'));
  if (!p) return res.status(401).json({ error: 'Clés invalides' });
  req.pk = pk; req.p = p; next();
};
const authUser = (req, res, next) => {
  const e = readToken((req.get('authorization') || '').replace('Bearer ', ''));
  if (!e) return res.status(401).json({ error: 'Session expirée, reconnectez-vous' });
  req.email = e; next();
};
const owned = (req, res, next) => {
  const p = db[req.params.pk];
  if (!p || p.owner !== req.email) return res.status(404).json({ error: 'Projet introuvable' });
  req.pk = req.params.pk; req.p = p; next();
};

const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '100kb' }));
app.get('/', (_, res) => res.json({ service: 'pylon', ok: true }));

// ---------- Comptes ----------
app.post('/api/register', async (req, res) => {
  if (limited('reg:' + req.ip, 5, 3600000)) return res.status(429).json({ error: 'Trop de créations de compte, réessayez plus tard' });
  const email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 120) return res.status(400).json({ error: 'Adresse email invalide' });
  if (pw.length < 8 || pw.length > 200) return res.status(400).json({ error: 'Mot de passe : 8 caractères minimum' });
  try { await users.insertOne({ _id: email, hash: await hashPw(pw), created: Date.now() }); }
  catch { return res.status(409).json({ error: 'Cet email possède déjà un compte' }); }
  res.json({ token: mkToken(email), email });
});
app.post('/api/login', async (req, res) => {
  if (limited('log:' + req.ip, 10, 900000)) return res.status(429).json({ error: 'Trop de tentatives, réessayez dans 15 minutes' });
  const email = String(req.body.email || '').trim().toLowerCase();
  const u = await users.findOne({ _id: email });
  if (!u || !(await checkPw(String(req.body.password || ''), u.hash))) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  res.json({ token: mkToken(email), email });
});

// ---------- Projets (tableau de bord) ----------
app.get('/api/projects', authUser, (req, res) =>
  res.json(Object.entries(db).filter(([, p]) => p.owner === req.email)
    .map(([pk, p]) => ({ pk, name: p.name, created: p.created, online: online(pk), values: Object.keys(p.state).length }))
    .sort((a, b) => b.created - a.created)));

app.post('/api/projects', authUser, (req, res) => {
  if (limited('prj:' + req.ip, 5, 3600000)) return res.status(429).json({ error: 'Limite atteinte : 5 projets par heure' });
  if (Object.values(db).filter(p => p.owner === req.email).length >= 10) return res.status(400).json({ error: 'Maximum 10 projets par compte' });
  const name = String(req.body.name || 'Mon projet').trim().slice(0, 40) || 'Mon projet';
  const pk = rand('pk_', 8), privateKey = rand('sk_', 24);
  db[pk] = { owner: req.email, name, hash: sha(privateKey), state: {}, log: [], created: Date.now() };
  dirty.add(pk);
  res.json({ pk, name, privateKey });
});

app.get('/api/projects/:pk', authUser, owned, (req, res) =>
  res.json({ pk: req.pk, name: req.p.name, state: req.p.state, log: req.p.log, online: online(req.pk) }));

app.post('/api/projects/:pk/regenerate', authUser, owned, (req, res) => {
  const privateKey = rand('sk_', 24);
  req.p.hash = sha(privateKey); dirty.add(req.pk);
  res.json({ privateKey });
});

app.delete('/api/projects/:pk', authUser, owned, async (req, res) => {
  const l = L(req.pk);
  l.dash.forEach(w => w.close()); l.waiters.forEach(w => { clearTimeout(w.t); w.reply([]); });
  delete live[req.pk]; delete db[req.pk]; dirty.delete(req.pk);
  try { await projects.deleteOne({ _id: req.pk }); } catch (e) { console.error(e.message); }
  res.json({ ok: true });
});

app.post('/api/projects/:pk/command', authUser, owned, (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 40);
  const value = String(req.body.value ?? '').slice(0, 200);
  if (!name) return res.status(400).json({ error: 'Le nom de la commande est requis' });
  const l = L(req.pk), t = Date.now();
  l.queue.push({ name, value, t });
  addLog(req.pk, { t, kind: 'out', data: { [name]: value } });
  push(req.pk, { type: 'command', t, data: { [name]: value } });
  const w = l.waiters.shift();
  if (w) { clearTimeout(w.t); w.reply(l.queue.splice(0)); }
  res.json({ ok: true, online: online(req.pk) });
});

// ---------- Cartes (ESP32, Raspberry Pi) ----------
app.post('/api/device/data', guard, (req, res) => {
  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) return res.status(400).json({ error: 'Objet JSON attendu' });
  const t = Date.now();
  Object.keys(body).slice(0, 50).forEach(k => { req.p.state[k] = { v: body[k], t }; });
  addLog(req.pk, { t, kind: 'in', data: body });
  touch(req.pk);
  push(req.pk, { type: 'data', t, data: body });
  res.json({ ok: true });
});

app.get('/api/device/commands', guard, (req, res) => {
  const l = L(req.pk), text = req.query.format === 'text';
  const reply = c => text ? res.type('text').send(c.map(x => `${x.name}=${x.value}`).join('\n')) : res.json({ commands: c });
  touch(req.pk);
  if (l.queue.length) return reply(l.queue.splice(0));
  const wait = Math.min(25, req.query.wait === undefined ? 25 : +req.query.wait || 0) * 1000;
  if (!wait) return reply([]);
  const w = { reply };
  w.t = setTimeout(() => { l.waiters = l.waiters.filter(x => x !== w); reply([]); }, wait);
  l.waiters.push(w);
  res.on('close', () => { clearTimeout(w.t); l.waiters = l.waiters.filter(x => x !== w); });
});

// ---------- Temps réel (tableau de bord) ----------
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
wss.on('connection', (ws, req) => {
  const q = new URL(req.url, 'http://x').searchParams, pk = q.get('pk'), p = db[pk], email = readToken(q.get('token'));
  if (!email || !p || p.owner !== email) return ws.close(4001);
  L(pk).dash.add(ws);
  ws.on('close', () => L(pk).dash.delete(ws));
  ws.send(JSON.stringify({ type: 'snapshot', state: p.state, log: p.log, online: online(pk) }));
});
setInterval(() => Object.keys(live).forEach(pk => push(pk, { type: 'status', online: online(pk) })), 10000);

(async () => {
  await client.connect();
  const d = client.db(process.env.MONGODB_DB || 'pylon');
  projects = d.collection('projects'); users = d.collection('users');
  (await projects.find().toArray()).forEach(({ _id, ...p }) => { db[_id] = p; });
  server.listen(process.env.PORT || 3000, () => console.log(`Pylon prêt, ${Object.keys(db).length} projet(s) chargé(s)`));
})();
