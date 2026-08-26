import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import { WebSocketServer } from 'ws';
import http from 'http';
import { URL } from 'url';

const { Pool } = pg;
const PORT = process.env.PORT || 8080;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
if (!DATABASE_URL) { console.error('Falta DATABASE_URL'); process.exit(1); }

const pool = new Pool({ connectionString: DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false });
await pool.query(`
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  username VARCHAR(40) UNIQUE NOT NULL,
  email VARCHAR(160) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'user',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS chat_messages (
  id BIGSERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  username VARCHAR(40) NOT NULL,
  message VARCHAR(500) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`);

const app = express();
app.use(cors()); app.use(express.json({ limit: '64kb' }));
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });
const sign = user => jwt.sign({ sub: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
function publicUser(row) { return { id: row.id, name: row.name, username: row.username, email: row.email, role: row.role }; }
function auth(req, res, next) {
  const raw = req.headers.authorization || ''; const token = raw.startsWith('Bearer ') ? raw.slice(7) : '';
  try { req.user = jwt.verify(token, JWT_SECRET); next(); } catch { res.status(401).json({ error: 'No autorizado' }); }
}

app.get('/health', (_, res) => res.json({ ok: true, service: 'Ludo Activo', version: '0.2.0' }));
app.post('/api/auth/register', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim(); const username = String(req.body.username || '').trim().toLowerCase();
    const email = String(req.body.email || '').trim().toLowerCase(); const password = String(req.body.password || '');
    if (name.length < 2 || !/^[a-z0-9_.-]{3,40}$/.test(username) || !email.includes('@') || password.length < 6) return res.status(400).json({ error: 'Datos inválidos' });
    const hash = await bcrypt.hash(password, 12);
    const q = await pool.query('INSERT INTO users(name,username,email,password_hash) VALUES($1,$2,$3,$4) RETURNING *', [name, username, email, hash]);
    const user = publicUser(q.rows[0]); res.status(201).json({ token: sign(user), user });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Usuario o correo ya registrado' });
    console.error(e); res.status(500).json({ error: 'Error del servidor' });
  }
});
app.post('/api/auth/login', async (req, res) => {
  try {
    const login = String(req.body.login || '').trim().toLowerCase(); const password = String(req.body.password || '');
    const q = await pool.query('SELECT * FROM users WHERE username=$1 OR email=$1 LIMIT 1', [login]);
    if (!q.rowCount || !(await bcrypt.compare(password, q.rows[0].password_hash))) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const user = publicUser(q.rows[0]); res.json({ token: sign(user), user });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error del servidor' }); }
});
app.get('/api/auth/me', auth, async (req, res) => {
  const q = await pool.query('SELECT * FROM users WHERE id=$1', [Number(req.user.sub)]);
  if (!q.rowCount) return res.status(404).json({ error: 'Usuario no existe' }); res.json({ user: publicUser(q.rows[0]) });
});
app.get('/api/chat/history', auth, async (_, res) => {
  const q = await pool.query('SELECT id,user_id,username,message,created_at FROM chat_messages ORDER BY id DESC LIMIT 100');
  res.json({ messages: q.rows.reverse() });
});

wss.on('connection', (ws, request, user) => {
  ws.send(JSON.stringify({ username: 'LudoActivo', message: 'Conectado al chat en vivo ✅', created_at: new Date().toISOString() }));
  ws.on('message', async data => {
    try {
      const body = JSON.parse(data.toString()); const message = String(body.message || '').trim().slice(0, 500);
      if (!message) return;
      const q = await pool.query('INSERT INTO chat_messages(user_id,username,message) VALUES($1,$2,$3) RETURNING id,user_id,username,message,created_at', [Number(user.sub), user.username, message]);
      const payload = JSON.stringify(q.rows[0]);
      for (const client of wss.clients) if (client.readyState === 1) client.send(payload);
    } catch (e) { console.error('chat error', e); }
  });
});
server.on('upgrade', (request, socket, head) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (url.pathname !== '/ws/chat') return socket.destroy();
    const token = url.searchParams.get('token'); const user = jwt.verify(token, JWT_SECRET);
    wss.handleUpgrade(request, socket, head, ws => wss.emit('connection', ws, request, user));
  } catch { socket.destroy(); }
});

server.listen(PORT, '0.0.0.0', () => console.log(`Ludo Activo backend en puerto ${PORT}`));
