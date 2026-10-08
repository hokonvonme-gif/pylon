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
const mkToken = (email, ttl = 30 * 864e5) => { const b = Buffer.from(JSON.stringify({ e: email, x: Date.now() + ttl })).toString('base64url'); return b + '.' + sign(b); };
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
  db[pk] = { owner: req.email, name, hash: sha(privateKey), state: {}, log: [], series: {}, controls: [], created: Date.now() };
  dirty.add(pk);
  res.json({ pk, name, privateKey });
});

app.get('/api/projects/:pk', authUser, owned, (req, res) =>
  res.json({ pk: req.pk, name: req.p.name, state: req.p.state, log: req.p.log, series: req.p.series || {}, controls: req.p.controls || [], tunnel: tunnelOn(req.pk), online: online(req.pk) }));

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
  if (l.queue.length > 50) l.queue.shift();
  if (l.lastCmd !== name + '=' + value) {
    l.lastCmd = name + '=' + value;
    addLog(req.pk, { t, kind: 'out', data: { [name]: value } });
    push(req.pk, { type: 'command', t, data: { [name]: value } });
  }
  const w = l.waiters.shift();
  if (w) { clearTimeout(w.t); w.reply(l.queue.splice(0)); }
  res.json({ ok: true, online: online(req.pk) });
});

app.put('/api/projects/:pk/controls', authUser, owned, (req, res) => {
  const ok = ['button', 'switch', 'slider', 'dpad'];
  req.p.controls = (Array.isArray(req.body) ? req.body : []).slice(0, 16)
    .filter(c => c && ok.includes(c.type) && String(c.name || '').trim())
    .map(c => ({ type: c.type, label: String(c.label || c.name).slice(0, 30), name: String(c.name).trim().slice(0, 40), min: +c.min || 0, max: isFinite(+c.max) ? +c.max : 100, value: String(c.value ?? '1').slice(0, 40) }));
  dirty.add(req.pk); res.json({ ok: true });
});

// ---------- Cartes (ESP32, Raspberry Pi) ----------
app.post('/api/device/data', guard, (req, res) => {
  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) return res.status(400).json({ error: 'Objet JSON attendu' });
  const t = Date.now();
  const sr = req.p.series = req.p.series || {};
  Object.keys(body).slice(0, 50).forEach(k => {
    req.p.state[k] = { v: body[k], t };
    if (typeof body[k] === 'number' && isFinite(body[k])) {
      const a = sr[k] = sr[k] || [];
      if (!a.length || t - a[a.length - 1][0] > 1000) { a.push([t, body[k]]); if (a.length > 100) a.shift(); }
    }
  });
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

// Caméra : la carte envoie des images JPEG, le tableau de bord affiche la dernière
app.post('/api/device/frame', guard, express.raw({ type: () => true, limit: '300kb' }), (req, res) => {
  if (!Buffer.isBuffer(req.body) || req.body.length < 100) return res.status(400).json({ error: 'Image JPEG attendue' });
  const t = Date.now(); L(req.pk).frame = { buf: req.body, t };
  touch(req.pk); push(req.pk, { type: 'frame', t });
  res.json({ ok: true });
});
app.get('/api/projects/:pk/frame', (req, res) => {
  const e = readToken(req.query.token), p = db[req.params.pk], f = live[req.params.pk]?.frame;
  if (!e || !p || p.owner !== e || !f) return res.status(404).end();
  res.set('Cache-Control', 'no-store').type('image/jpeg').send(f.buf);
});

// ---------- Tunnel : la page web locale de l'appareil, accessible depuis n'importe où ----------
const T = pk => { const l = L(pk); return l.t || (l.t = { queue: [], waiters: [], seen: 0 }); };
const tunnelOn = pk => Date.now() - (live[pk]?.t?.seen || 0) < 40000;
const pending = {};
const give = pk => {
  const t = T(pk);
  while (t.queue.length && t.waiters.length) { const w = t.waiters.shift(); clearTimeout(w.t); w.send(t.queue.shift()); }
};
function rewrite(html, pk) {
  const P = '/t/' + pk;
  const shim = `<script>(function(){var P="${P}";function f(u){return typeof u==="string"&&u[0]==="/"&&u[1]!=="/"&&u.indexOf(P+"/")!==0?P+u:u}var F=window.fetch;window.fetch=function(u,o){return F.call(this,f(u),o)};var O=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){arguments[1]=f(u);return O.apply(this,arguments)}})();<\/script>`;
  html = html.replace(/(\s(?:href|src|action)\s*=\s*["'])\/(?!\/)/gi, '$1' + P + '/');
  return /<head[^>]*>/i.test(html) ? html.replace(/<head[^>]*>/i, m => m + shim) : shim + html;
}

app.post('/api/projects/:pk/viewlink', authUser, owned, (req, res) =>
  res.json({ url: `${req.protocol}://${req.get('host')}/t/${req.pk}/?v=${mkToken(req.email, 120000)}` }));

// L'agent (carte ou Raspberry Pi) récupère la prochaine requête web à relayer
app.get('/api/tunnel/next', guard, (req, res) => {
  const t = T(req.pk), was = tunnelOn(req.pk);
  t.seen = Date.now();
  if (!was) push(req.pk, { type: 'status', online: online(req.pk), tunnel: true });
  const text = req.query.format === 'text';
  const send = j => {
    const v = { id: j.id, method: j.method, path: j.path, headers: j.headers, body: j.body };
    text ? res.type('text').send([v.id, v.method, v.path, Buffer.from(v.body, 'base64').toString('utf8')].join('\n')) : res.json(v);
  };
  if (t.queue.length) return send(t.queue.shift());
  const w = { send, t: setTimeout(() => { t.waiters = t.waiters.filter(x => x !== w); t.seen = Date.now(); res.status(204).end(); }, Math.min(25, +req.query.wait || 20) * 1000) };
  t.waiters.push(w);
  res.on('close', () => { clearTimeout(w.t); t.waiters = t.waiters.filter(x => x !== w); });
});

// L'agent renvoie la réponse de la page locale
app.post('/api/tunnel/respond/:id', guard, express.raw({ type: () => true, limit: '2mb' }), (req, res) => {
  const j = pending[req.params.id];
  if (!j || j.pk !== req.pk) return res.status(404).json({ error: 'Requête expirée' });
  delete pending[j.id]; clearTimeout(j.timer);
  const ct = req.get('x-content-type') || 'application/octet-stream';
  let body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  if (/text\/html/i.test(ct)) body = Buffer.from(rewrite(body.toString('utf8'), j.pk));
  const loc = req.get('x-location');
  if (loc) j.res.set('Location', loc.startsWith('/') ? '/t/' + j.pk + loc : loc);
  j.res.status(Math.min(599, Math.max(100, +req.get('x-status') || 200))).set('Content-Type', ct).set('Cache-Control', 'no-store').send(body);
  res.json({ ok: true });
});

// Adresse publique de la page : /t/<clé publique>/ (réservée au propriétaire du projet)
app.all(/^\/t\/(pk_[0-9a-f]+)(\/.*)?$/, express.raw({ type: () => true, limit: '2mb' }), (req, res) => {
  const pk = req.params[0], p = db[pk];
  const rest = req.originalUrl.slice(('/t/' + pk).length) || '/';
  if (req.query.v) {
    const e = readToken(req.query.v);
    if (!e || !p || p.owner !== e) return res.status(401).type('text').send('Lien expiré. Rouvrez la page depuis votre tableau de bord Pylon.');
    res.cookie('pylon_t', mkToken(e, 12 * 3600e3), { httpOnly: true, secure: true, sameSite: 'lax', path: '/t/' + pk, maxAge: 12 * 3600e3 });
    return res.redirect('/t/' + pk + '/');
  }
  const e = readToken((/(?:^|;\s*)pylon_t=([^;]+)/.exec(req.headers.cookie || '') || [])[1]);
  if (!e || !p || p.owner !== e) return res.status(401).type('text').send('Accès refusé : ouvrez cette page depuis votre tableau de bord Pylon.');
  if (!tunnelOn(pk)) return res.status(502).type('html').send("<body style='font-family:sans-serif;padding:40px'><h2>Appareil hors ligne</h2><p>L'agent du tunnel ne répond pas. Vérifiez qu'il tourne sur votre carte ou votre Raspberry Pi.</p></body>");
  const t = T(pk), id = rand('r', 6), hdr = {};
  ['content-type', 'accept'].forEach(h => { if (req.headers[h]) hdr[h] = req.headers[h]; });
  const job = { id, pk, res, method: req.method, path: rest, headers: hdr, body: Buffer.isBuffer(req.body) ? req.body.toString('base64') : '' };
  job.timer = setTimeout(() => { delete pending[id]; t.queue = t.queue.filter(x => x !== job); res.status(504).type('text').send("L'appareil n'a pas répondu à temps."); }, 25000);
  pending[id] = job; t.queue.push(job); give(pk);
});

// ---------- Temps réel (tableau de bord) ----------
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
wss.on('connection', (ws, req) => {
  const q = new URL(req.url, 'http://x').searchParams, pk = q.get('pk'), p = db[pk], email = readToken(q.get('token'));
  if (!email || !p || p.owner !== email) return ws.close(4001);
  L(pk).dash.add(ws);
  ws.on('close', () => L(pk).dash.delete(ws));
  ws.send(JSON.stringify({ type: 'snapshot', state: p.state, log: p.log, series: p.series || {}, frame: live[pk]?.frame?.t || 0, tunnel: tunnelOn(pk), online: online(pk) }));
});
setInterval(() => Object.keys(live).forEach(pk => push(pk, { type: 'status', online: online(pk), tunnel: tunnelOn(pk) })), 10000);

(async () => {
  await client.connect();
  const d = client.db(process.env.MONGODB_DB || 'pylon');
  projects = d.collection('projects'); users = d.collection('users');
  (await projects.find().toArray()).forEach(({ _id, ...p }) => { db[_id] = p; });
  server.listen(process.env.PORT || 3000, () => console.log(`Pylon prêt, ${Object.keys(db).length} projet(s) chargé(s)`));
})();
