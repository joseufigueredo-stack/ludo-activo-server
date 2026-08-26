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

const CLOUDFLARE_ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID;
const CLOUDFLARE_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const CLOUDFLARE_LIVE_INPUT_ID = process.env.CLOUDFLARE_LIVE_INPUT_ID;

if (!DATABASE_URL) {
  console.error('Falta DATABASE_URL');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl:
    process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false
});

// Migración compatible con tu tabla existente.
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

ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_yape VARCHAR(20);
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'active';
ALTER TABLE users ADD COLUMN IF NOT EXISTS muted_until TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_reason VARCHAR(250);

CREATE UNIQUE INDEX IF NOT EXISTS users_phone_yape_unique
ON users(phone_yape)
WHERE phone_yape IS NOT NULL;

CREATE TABLE IF NOT EXISTS chat_messages (
  id BIGSERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  username VARCHAR(40) NOT NULL,
  message VARCHAR(500) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS deleted_by INTEGER;

CREATE TABLE IF NOT EXISTS blocked_words (
  id SERIAL PRIMARY KEY,
  word VARCHAR(80) UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`);

const app = express();
app.use(cors());
app.use(express.json({ limit: '8mb' }));

const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

const sign = user =>
  jwt.sign(
    {
      sub: user.id,
      username: user.username,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: '30d' }
  );

function publicUser(row, includePrivate = false) {
  const user = {
    id: row.id,
    name: row.name,
    username: row.username,
    role: row.role,
    avatarUrl: row.avatar_url || null,
    status: row.status || 'active'
  };

  if (includePrivate) {
    user.email = row.email;
    user.phoneYape = row.phone_yape || '';
    user.mutedUntil = row.muted_until || null;
  }

  return user;
}

function auth(req, res, next) {
  const raw = req.headers.authorization || '';
  const token = raw.startsWith('Bearer ') ? raw.slice(7) : '';

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'No autorizado' });
  }
}

async function requireActiveUser(userId) {
  const q = await pool.query(
    'SELECT * FROM users WHERE id=$1 LIMIT 1',
    [Number(userId)]
  );
  if (!q.rowCount) return { ok: false, code: 404, error: 'Usuario no existe' };
  const user = q.rows[0];
  if (user.status === 'blocked') {
    return { ok: false, code: 403, error: 'Cuenta bloqueada', user };
  }
  return { ok: true, user };
}

function moderatorOnly(req, res, next) {
  if (!['moderator', 'admin'].includes(req.currentUser?.role)) {
    return res.status(403).json({ error: 'Requiere permisos de moderación' });
  }
  next();
}

async function activeAuth(req, res, next) {
  auth(req, res, async () => {
    try {
      const state = await requireActiveUser(req.user.sub);
      if (!state.ok) return res.status(state.code).json({ error: state.error });
      req.currentUser = state.user;
      next();
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Error del servidor' });
    }
  });
}

async function filterBadWords(message) {
  const q = await pool.query('SELECT word FROM blocked_words');
  let clean = message;
  for (const row of q.rows) {
    const word = String(row.word || '').trim();
    if (!word) continue;
    const escaped = word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    clean = clean.replace(new RegExp(`\\b${escaped}\\b`, 'gi'), '*'.repeat(word.length));
  }
  return clean;
}

function broadcast(payload) {
  const data = JSON.stringify(payload);
  for (const client of wss.clients) {
    if (client.readyState === 1) client.send(data);
  }
}

function disconnectUser(userId, reason = 'Sesión cerrada') {
  for (const client of wss.clients) {
    if (Number(client.userId) === Number(userId)) {
      try {
        client.send(JSON.stringify({ type: 'forced_logout', reason }));
        client.close(4003, reason);
      } catch {}
    }
  }
}

app.get('/health', (_, res) =>
  res.json({
    ok: true,
    service: 'Ludo Activo',
    version: '0.5.0'
  })
);

/*
  =========================================================
  LIVE ACTUAL DE CLOUDFLARE
  =========================================================

  La app llama:
      GET /api/live/current

  Railway consulta Cloudflare usando el token privado.

  Si hay transmisión:
      {
        "live": true,
        "videoUID": "...",
        "hls": "https://.../manifest/video.m3u8"
      }

  Si no hay transmisión:
      {
        "live": false,
        "videoUID": null,
        "hls": null
      }
*/
app.get('/api/live/debug', async (_req, res) => {
  try {
    if (
      !CLOUDFLARE_ACCOUNT_ID ||
      !CLOUDFLARE_API_TOKEN ||
      !CLOUDFLARE_LIVE_INPUT_ID
    ) {
      return res.status(500).json({
        ok: false,
        error: 'Faltan variables de Cloudflare en Railway',
        hasAccountId: Boolean(CLOUDFLARE_ACCOUNT_ID),
        hasApiToken: Boolean(CLOUDFLARE_API_TOKEN),
        hasLiveInputId: Boolean(CLOUDFLARE_LIVE_INPUT_ID)
      });
    }

    const url =
      `https://api.cloudflare.com/client/v4/accounts/` +
      `${CLOUDFLARE_ACCOUNT_ID}/stream/live_inputs/` +
      `${CLOUDFLARE_LIVE_INPUT_ID}/videos`;

    const cfResponse = await fetch(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
        Accept: 'application/json'
      }
    });

    const data = await cfResponse.json();

    const videos = Array.isArray(data?.result)
      ? data.result
      : [];

    const samples = videos.slice(0, 5).map(video => ({
      uid: video?.uid || null,
      state: video?.status?.state || null,
      readyToStream: video?.readyToStream ?? null,
      liveInput: video?.liveInput || null,
      hls: video?.playback?.hls || null
    }));

    return res.status(cfResponse.ok ? 200 : 502).json({
      ok: cfResponse.ok,
      cloudflareStatus: cfResponse.status,
      success: data?.success ?? null,
      resultCount: videos.length,
      errors: data?.errors || [],
      messages: data?.messages || [],
      samples
    });
  } catch (e) {
    console.error('live debug error', e);

    return res.status(500).json({
      ok: false,
      error: String(e?.message || e)
    });
  }
});

app.get('/api/live/current', async (_req, res) => {
  try {
    if (
      !CLOUDFLARE_ACCOUNT_ID ||
      !CLOUDFLARE_API_TOKEN ||
      !CLOUDFLARE_LIVE_INPUT_ID
    ) {
      return res.status(500).json({
        live: false,
        videoUID: null,
        hls: null,
        error: 'Faltan variables de Cloudflare en Railway'
      });
    }

    const url =
      `https://api.cloudflare.com/client/v4/accounts/` +
      `${CLOUDFLARE_ACCOUNT_ID}/stream/live_inputs/` +
      `${CLOUDFLARE_LIVE_INPUT_ID}/videos`;

    const cfResponse = await fetch(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
        Accept: 'application/json'
      }
    });

    const data = await cfResponse.json();

    if (!cfResponse.ok || data?.success === false) {
      console.error(
        'Cloudflare API error:',
        JSON.stringify(data)
      );

      return res.status(502).json({
        live: false,
        videoUID: null,
        hls: null,
        error: 'Cloudflare no respondió correctamente'
      });
    }

    const videos = Array.isArray(data?.result)
      ? data.result
      : [];

    // SOLO reproducimos el broadcast realmente activo.
    // "ready" significa una grabación terminada, no el live actual.
    const activeVideo =
      videos.find(video => {
        const state =
          String(video?.status?.state || '').toLowerCase();

        return state === 'live-inprogress';
      }) || null;

    if (!activeVideo) {
      return res.json({
        live: false,
        videoUID: null,
        hls: null
      });
    }

    const videoUID =
      activeVideo?.uid || null;

    const hls =
      activeVideo?.playback?.hls ||
      (
        videoUID
          ? `https://customer-wjqmkt5ikziq5i6i.cloudflarestream.com/${videoUID}/manifest/video.m3u8`
          : null
      );

    return res.json({
      live: Boolean(videoUID && hls),
      videoUID,
      hls
    });
  } catch (e) {
    console.error(
      'Error consultando live actual:',
      e
    );

    return res.status(500).json({
      live: false,
      videoUID: null,
      hls: null,
      error: 'No se pudo consultar el live actual'
    });
  }
});


app.post('/api/auth/register', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const username = String(req.body.username || '').trim().toLowerCase();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const phoneYape = String(req.body.phoneYape || req.body.phone_yape || '')
      .replace(/\D/g, '');

    if (
      name.length < 2 ||
      !/^[a-z0-9_.-]{3,40}$/.test(username) ||
      !email.includes('@') ||
      password.length < 6 ||
      !/^9\d{8}$/.test(phoneYape)
    ) {
      return res.status(400).json({
        error: 'Datos inválidos. El teléfono Yape debe tener 9 dígitos y comenzar en 9.'
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const q = await pool.query(
      `INSERT INTO users(name,username,email,password_hash,phone_yape)
       VALUES($1,$2,$3,$4,$5)
       RETURNING *`,
      [name, username, email, hash, phoneYape]
    );

    const user = publicUser(q.rows[0], true);
    res.status(201).json({ token: sign(user), user });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(409).json({
        error: 'Usuario, correo o teléfono Yape ya registrado'
      });
    }
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const login = String(req.body.login || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    const q = await pool.query(
      'SELECT * FROM users WHERE username=$1 OR email=$1 LIMIT 1',
      [login]
    );

    if (
      !q.rowCount ||
      !(await bcrypt.compare(password, q.rows[0].password_hash))
    ) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    if (q.rows[0].status === 'blocked') {
      return res.status(403).json({
        error: 'Tu cuenta está bloqueada',
        reason: q.rows[0].ban_reason || null
      });
    }

    const user = publicUser(q.rows[0], true);
    res.json({ token: sign(user), user });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.get('/api/auth/me', activeAuth, async (req, res) => {
  res.json({ user: publicUser(req.currentUser, true) });
});

app.patch('/api/profile', activeAuth, async (req, res) => {
  try {
    const name = String(req.body.name ?? req.currentUser.name).trim();
    const email = String(req.body.email ?? req.currentUser.email).trim().toLowerCase();
    const phoneYape = String(
      req.body.phoneYape ?? req.body.phone_yape ?? req.currentUser.phone_yape ?? ''
    ).replace(/\D/g, '');
    const avatarUrl = String(
      req.body.avatarUrl ?? req.body.avatar_url ?? req.currentUser.avatar_url ?? ''
    ).trim();

    if (name.length < 2 || !email.includes('@') || !/^9\d{8}$/.test(phoneYape)) {
      return res.status(400).json({ error: 'Datos de perfil inválidos' });
    }

    // Por ahora guardamos URL de avatar. El upload binario lo conectaremos desde Android.
    if (avatarUrl && !/^https?:\/\//i.test(avatarUrl)) {
      return res.status(400).json({ error: 'avatarUrl inválida' });
    }

    const q = await pool.query(
      `UPDATE users
       SET name=$1,email=$2,phone_yape=$3,avatar_url=$4
       WHERE id=$5
       RETURNING *`,
      [name, email, phoneYape, avatarUrl || null, req.currentUser.id]
    );

    res.json({ user: publicUser(q.rows[0], true) });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(409).json({ error: 'Correo o teléfono Yape ya registrado' });
    }
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});


app.post('/api/profile/avatar', activeAuth, async (req, res) => {
  try {
    if (!CLOUDFLARE_ACCOUNT_ID || !CLOUDFLARE_API_TOKEN) {
      return res.status(500).json({
        error: 'Cloudflare Images no está configurado'
      });
    }

    const imageBase64 = String(req.body.imageBase64 || '');

    const match = imageBase64.match(
      /^data:(image\/(?:jpeg|jpg|png|webp));base64,(.+)$/i
    );

    if (!match) {
      return res.status(400).json({
        error: 'Formato de imagen inválido'
      });
    }

    const mime =
      match[1].toLowerCase() === 'image/jpg'
        ? 'image/jpeg'
        : match[1];

    const bytes = Buffer.from(match[2], 'base64');

    if (!bytes.length || bytes.length > 5 * 1024 * 1024) {
      return res.status(400).json({
        error: 'La imagen debe pesar menos de 5 MB'
      });
    }

    const form = new FormData();

    form.append(
      'file',
      new Blob([bytes], { type: mime }),
      `avatar-${req.currentUser.id}-${Date.now()}.jpg`
    );

    form.append(
      'metadata',
      JSON.stringify({
        userId: req.currentUser.id,
        username: req.currentUser.username,
        kind: 'avatar'
      })
    );

    const cfResponse = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/images/v1`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`
        },
        body: form
      }
    );

    const data = await cfResponse.json();

    if (!cfResponse.ok || data?.success === false) {
      console.error(
        'Cloudflare Images error:',
        JSON.stringify(data)
      );

      return res.status(502).json({
        error: 'No se pudo subir la foto de perfil'
      });
    }

    const avatarUrl =
      Array.isArray(data?.result?.variants) &&
      data.result.variants.length
        ? data.result.variants[0]
        : null;

    if (!avatarUrl) {
      return res.status(502).json({
        error: 'Cloudflare no devolvió una URL de imagen'
      });
    }

    const q = await pool.query(
      `UPDATE users
       SET avatar_url=$1
       WHERE id=$2
       RETURNING *`,
      [avatarUrl, req.currentUser.id]
    );

    return res.json({
      user: publicUser(q.rows[0], true)
    });
  } catch (e) {
    console.error('avatar upload error', e);

    return res.status(500).json({
      error: 'No se pudo actualizar la foto de perfil'
    });
  }
});

app.get('/api/chat/history', activeAuth, async (_req, res) => {
  const q = await pool.query(
    `SELECT cm.id,cm.user_id,cm.username,cm.message,cm.created_at,u.avatar_url
     FROM chat_messages cm
     JOIN users u ON u.id=cm.user_id
     WHERE cm.deleted_at IS NULL
     ORDER BY cm.id DESC LIMIT 100`
  );
  res.json({ messages: q.rows.reverse() });
});

// Lista de usuarios para panel de moderación.
app.get('/api/mod/users', activeAuth, moderatorOnly, async (_req, res) => {
  const q = await pool.query(
    `SELECT id,name,username,role,avatar_url,status,muted_until,created_at
     FROM users ORDER BY id DESC LIMIT 500`
  );
  res.json({ users: q.rows });
});

app.post('/api/mod/users/:id/mute', activeAuth, moderatorOnly, async (req, res) => {
  const targetId = Number(req.params.id);
  const minutes = Math.max(1, Math.min(Number(req.body.minutes || 10), 43200));

  const target = await pool.query('SELECT * FROM users WHERE id=$1', [targetId]);
  if (!target.rowCount) return res.status(404).json({ error: 'Usuario no existe' });
  if (target.rows[0].role === 'admin' && req.currentUser.role !== 'admin') {
    return res.status(403).json({ error: 'No puedes moderar a un administrador' });
  }

  const q = await pool.query(
    `UPDATE users
     SET muted_until=NOW() + ($1 * INTERVAL '1 minute')
     WHERE id=$2 RETURNING *`,
    [minutes, targetId]
  );

  res.json({ ok: true, user: publicUser(q.rows[0]) });
});

app.post('/api/mod/users/:id/unmute', activeAuth, moderatorOnly, async (req, res) => {
  const q = await pool.query(
    'UPDATE users SET muted_until=NULL WHERE id=$1 RETURNING *',
    [Number(req.params.id)]
  );
  if (!q.rowCount) return res.status(404).json({ error: 'Usuario no existe' });
  res.json({ ok: true, user: publicUser(q.rows[0]) });
});

app.post('/api/mod/users/:id/block', activeAuth, moderatorOnly, async (req, res) => {
  const targetId = Number(req.params.id);
  const reason = String(req.body.reason || 'Incumplimiento de las normas').trim().slice(0, 250);

  if (targetId === Number(req.currentUser.id)) {
    return res.status(400).json({ error: 'No puedes bloquear tu propia cuenta' });
  }

  const target = await pool.query('SELECT * FROM users WHERE id=$1', [targetId]);
  if (!target.rowCount) return res.status(404).json({ error: 'Usuario no existe' });
  if (target.rows[0].role === 'admin' && req.currentUser.role !== 'admin') {
    return res.status(403).json({ error: 'No puedes bloquear a un administrador' });
  }

  await pool.query(
    `UPDATE users SET status='blocked',ban_reason=$1 WHERE id=$2`,
    [reason, targetId]
  );

  disconnectUser(targetId, 'Cuenta bloqueada');
  res.json({ ok: true });
});

app.post('/api/mod/users/:id/unblock', activeAuth, moderatorOnly, async (req, res) => {
  const q = await pool.query(
    `UPDATE users SET status='active',ban_reason=NULL WHERE id=$1 RETURNING *`,
    [Number(req.params.id)]
  );
  if (!q.rowCount) return res.status(404).json({ error: 'Usuario no existe' });
  res.json({ ok: true, user: publicUser(q.rows[0]) });
});

app.delete('/api/mod/messages/:id', activeAuth, moderatorOnly, async (req, res) => {
  const q = await pool.query(
    `UPDATE chat_messages
     SET deleted_at=NOW(),deleted_by=$1
     WHERE id=$2 AND deleted_at IS NULL
     RETURNING id`,
    [req.currentUser.id, Number(req.params.id)]
  );

  if (!q.rowCount) return res.status(404).json({ error: 'Mensaje no existe' });

  broadcast({ type: 'message_deleted', id: Number(req.params.id) });
  res.json({ ok: true });
});

app.get('/api/mod/blocked-words', activeAuth, moderatorOnly, async (_req, res) => {
  const q = await pool.query('SELECT id,word FROM blocked_words ORDER BY word');
  res.json({ words: q.rows });
});

app.post('/api/mod/blocked-words', activeAuth, moderatorOnly, async (req, res) => {
  const word = String(req.body.word || '').trim().toLowerCase().slice(0, 80);
  if (word.length < 2) return res.status(400).json({ error: 'Palabra inválida' });

  const q = await pool.query(
    `INSERT INTO blocked_words(word) VALUES($1)
     ON CONFLICT(word) DO UPDATE SET word=EXCLUDED.word
     RETURNING *`,
    [word]
  );
  res.json({ word: q.rows[0] });
});

app.delete('/api/mod/blocked-words/:id', activeAuth, moderatorOnly, async (req, res) => {
  await pool.query('DELETE FROM blocked_words WHERE id=$1', [Number(req.params.id)]);
  res.json({ ok: true });
});

// Solo admin puede dar/quitar rol de moderador.
app.post('/api/admin/users/:id/role', activeAuth, async (req, res) => {
  if (req.currentUser.role !== 'admin') {
    return res.status(403).json({ error: 'Solo administrador' });
  }

  const role = String(req.body.role || '');
  if (!['user', 'moderator'].includes(role)) {
    return res.status(400).json({ error: 'Rol inválido' });
  }

  const q = await pool.query(
    'UPDATE users SET role=$1 WHERE id=$2 RETURNING *',
    [role, Number(req.params.id)]
  );
  if (!q.rowCount) return res.status(404).json({ error: 'Usuario no existe' });
  res.json({ ok: true, user: publicUser(q.rows[0]) });
});

wss.on('connection', (ws, request, user) => {
  ws.userId = Number(user.id);
  ws.username = user.username;

  ws.send(JSON.stringify({
    type: 'system',
    username: 'LudoActivo',
    message: 'Conectado al chat en vivo ✅',
    created_at: new Date().toISOString()
  }));

  ws.on('message', async data => {
    try {
      const state = await requireActiveUser(ws.userId);
      if (!state.ok) {
        ws.send(JSON.stringify({ type: 'forced_logout', reason: state.error }));
        return ws.close(4003, state.error);
      }

      const dbUser = state.user;

      if (dbUser.muted_until && new Date(dbUser.muted_until) > new Date()) {
        return ws.send(JSON.stringify({
          type: 'muted',
          message: 'Estás silenciado temporalmente.',
          mutedUntil: dbUser.muted_until
        }));
      }

      const body = JSON.parse(data.toString());
      let message = String(body.message || '').trim().slice(0, 500);
      if (!message) return;

      message = await filterBadWords(message);

      const q = await pool.query(
        `INSERT INTO chat_messages(user_id,username,message)
         VALUES($1,$2,$3)
         RETURNING id,user_id,username,message,created_at`,
        [dbUser.id, dbUser.username, message]
      );

      const payload = {
        type: 'message',
        ...q.rows[0],
        avatar_url: dbUser.avatar_url || null
      };

      broadcast(payload);
    } catch (e) {
      console.error('chat error', e);
    }
  });
});

server.on('upgrade', async (request, socket, head) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host}`);

    if (url.pathname !== '/ws/chat') return socket.destroy();

    const token = url.searchParams.get('token');
    const decoded = jwt.verify(token, JWT_SECRET);

    const state = await requireActiveUser(decoded.sub);
    if (!state.ok) return socket.destroy();

    const user = {
      id: state.user.id,
      username: state.user.username,
      role: state.user.role
    };

    wss.handleUpgrade(request, socket, head, ws =>
      wss.emit('connection', ws, request, user)
    );
  } catch {
    socket.destroy();
  }
});

server.listen(
  PORT,
  '0.0.0.0',
  () => console.log(`Ludo Activo backend en puerto ${PORT}`)
);
