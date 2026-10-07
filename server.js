const express = require('express'), http = require('http'), crypto = require('crypto'), fs = require('fs'), cors = require('cors');
const { WebSocketServer } = require('ws');

const { MongoClient } = require('mongodb');
const client = new MongoClient(process.env.MONGODB_URI);
let col, db = {};
const dirty = new Set();

async function flush() {
  if (!col || !dirty.size) return;
  const ids = [...dirty]; dirty.clear();
  const ops = ids.filter(id => db[id]).map(id => ({ replaceOne: { filter: { _id: id }, replacement: { ...db[id] }, upsert: true } }));
  try { if (ops.length) await col.bulkWrite(ops); }
  catch (e) { ids.forEach(id => dirty.add(id)); console.error('MongoDB :', e.message); }
}
setInterval(flush, 3000);
async function stop() { await flush(); process.exit(0); }
process.on('SIGTERM', stop);
process.on('SIGINT', stop);

const sha = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const rand = (p, n) => p + crypto.randomBytes(n).toString('hex');
const live = {};
const L = pk => live[pk] || (live[pk] = { dash: new Set(), waiters: [], queue: [], seen: 0 });
const online = pk => Date.now() - L(pk).seen < 35000;
const push = (pk, msg) => { const m = JSON.stringify(msg); L(pk).dash.forEach(ws => ws.readyState === 1 && ws.send(m)); };
const touch = pk => { const was = online(pk); L(pk).seen = Date.now(); if (!was) push(pk, { type: 'status', online: true }); };

function check(pk, sk) {
  const p = db[pk];
  if (!p || !sk) return null;
  const a = Buffer.from(sha(sk)), b = Buffer.from(p.hash);
  return crypto.timingSafeEqual(a, b) ? p : null;
}
const guard = (req, res, next) => {
  const pk = req.get('x-public-key'), p = check(pk, req.get('x-private-key'));
  if (!p) return res.status(401).json({ error: 'Clés invalides' });
  req.pk = pk; req.p = p; next();
};
const addLog = (pk, entry) => { const p = db[pk]; p.log.push(entry); p.log = p.log.slice(-50); dirty.add(pk); };

const app = express();
app.use(cors());
app.use(express.json({ limit: '100kb' }));
app.get('/', (_, res) => res.json({ service: 'pylon', ok: true }));

// Création d'un projet : génère la paire de clés
app.post('/api/projects', (req, res) => {
  const name = String(req.body.name || 'Mon projet').slice(0, 40);
  const publicKey = rand('pk_', 8), privateKey = rand('sk_', 24);
  db[publicKey] = { name, hash: sha(privateKey), state: {}, log: [], created: Date.now() };
  dirty.add(publicKey);
  res.json({ name, publicKey, privateKey });
});

app.get('/api/state', guard, (req, res) =>
  res.json({ name: req.p.name, state: req.p.state, log: req.p.log, online: online(req.pk) }));

// Carte -> serveur : envoi de valeurs
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

// Serveur -> carte : commandes en attente (long polling, ?wait=secondes, ?format=text)
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

// Tableau de bord -> carte
app.post('/api/command', guard, (req, res) => {
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

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
wss.on('connection', (ws, req) => {
  const q = new URL(req.url, 'http://x').searchParams, pk = q.get('pk'), p = check(pk, q.get('sk'));
  if (!p) return ws.close(4001);
  L(pk).dash.add(ws);
  ws.on('close', () => L(pk).dash.delete(ws));
  ws.send(JSON.stringify({ type: 'snapshot', state: p.state, log: p.log, online: online(pk) }));
});
setInterval(() => Object.keys(live).forEach(pk => push(pk, { type: 'status', online: online(pk) })), 10000);

(async () => {
  await client.connect();
  col = client.db(process.env.MONGODB_DB || 'pylon').collection('projects');
  (await col.find().toArray()).forEach(({ _id, ...p }) => { db[_id] = p; });
  server.listen(process.env.PORT || 3000, () => console.log(`Pylon prêt, ${Object.keys(db).length} projet(s) chargé(s)`));
})();
