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

app.use(cors());
app.use(express.json({ limit: '64kb' }));

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

function publicUser(row) {
  return {
    id: row.id,
    name: row.name,
    username: row.username,
    email: row.email,
    role: row.role
  };
}

function auth(req, res, next) {
  const raw = req.headers.authorization || '';
  const token = raw.startsWith('Bearer ')
    ? raw.slice(7)
    : '';

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({
      error: 'No autorizado'
    });
  }
}

app.get('/health', (_, res) =>
  res.json({
    ok: true,
    service: 'Ludo Activo',
    version: '0.3.2'
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

    // Cloudflare puede devolver el video del Live Input como
    // "live-inprogress" mientras transmite o "ready" cuando ya
    // existe un HLS reproducible. Aceptamos ambos siempre que
    // readyToStream no sea false y exista UID/HLS.
    const activeVideo =
      videos.find(video => {
        const state = String(video?.status?.state || '').toLowerCase();
        const playable = Boolean(video?.uid) &&
          Boolean(
            video?.playback?.hls ||
            video?.readyToStream === true
          );

        return playable &&
          video?.readyToStream !== false &&
          (state === 'live-inprogress' || state === 'ready');
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
    const name =
      String(req.body.name || '').trim();

    const username =
      String(req.body.username || '')
        .trim()
        .toLowerCase();

    const email =
      String(req.body.email || '')
        .trim()
        .toLowerCase();

    const password =
      String(req.body.password || '');

    if (
      name.length < 2 ||
      !/^[a-z0-9_.-]{3,40}$/.test(username) ||
      !email.includes('@') ||
      password.length < 6
    ) {
      return res.status(400).json({
        error: 'Datos inválidos'
      });
    }

    const hash =
      await bcrypt.hash(password, 12);

    const q = await pool.query(
      'INSERT INTO users(name,username,email,password_hash) VALUES($1,$2,$3,$4) RETURNING *',
      [name, username, email, hash]
    );

    const user =
      publicUser(q.rows[0]);

    res.status(201).json({
      token: sign(user),
      user
    });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(409).json({
        error: 'Usuario o correo ya registrado'
      });
    }

    console.error(e);

    res.status(500).json({
      error: 'Error del servidor'
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const login =
      String(req.body.login || '')
        .trim()
        .toLowerCase();

    const password =
      String(req.body.password || '');

    const q = await pool.query(
      'SELECT * FROM users WHERE username=$1 OR email=$1 LIMIT 1',
      [login]
    );

    if (
      !q.rowCount ||
      !(await bcrypt.compare(
        password,
        q.rows[0].password_hash
      ))
    ) {
      return res.status(401).json({
        error: 'Credenciales incorrectas'
      });
    }

    const user =
      publicUser(q.rows[0]);

    res.json({
      token: sign(user),
      user
    });
  } catch (e) {
    console.error(e);

    res.status(500).json({
      error: 'Error del servidor'
    });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  const q = await pool.query(
    'SELECT * FROM users WHERE id=$1',
    [Number(req.user.sub)]
  );

  if (!q.rowCount) {
    return res.status(404).json({
      error: 'Usuario no existe'
    });
  }

  res.json({
    user: publicUser(q.rows[0])
  });
});

app.get('/api/chat/history', auth, async (_req, res) => {
  const q = await pool.query(
    'SELECT id,user_id,username,message,created_at FROM chat_messages ORDER BY id DESC LIMIT 100'
  );

  res.json({
    messages: q.rows.reverse()
  });
});

wss.on('connection', (ws, request, user) => {
  ws.send(
    JSON.stringify({
      username: 'LudoActivo',
      message: 'Conectado al chat en vivo ✅',
      created_at: new Date().toISOString()
    })
  );

  ws.on('message', async data => {
    try {
      const body =
        JSON.parse(data.toString());

      const message =
        String(body.message || '')
          .trim()
          .slice(0, 500);

      if (!message) return;

      const q = await pool.query(
        'INSERT INTO chat_messages(user_id,username,message) VALUES($1,$2,$3) RETURNING id,user_id,username,message,created_at',
        [
          Number(user.sub),
          user.username,
          message
        ]
      );

      const payload =
        JSON.stringify(q.rows[0]);

      for (const client of wss.clients) {
        if (client.readyState === 1) {
          client.send(payload);
        }
      }
    } catch (e) {
      console.error(
        'chat error',
        e
      );
    }
  });
});

server.on('upgrade', (request, socket, head) => {
  try {
    const url =
      new URL(
        request.url,
        `http://${request.headers.host}`
      );

    if (url.pathname !== '/ws/chat') {
      return socket.destroy();
    }

    const token =
      url.searchParams.get('token');

    const user =
      jwt.verify(
        token,
        JWT_SECRET
      );

    wss.handleUpgrade(
      request,
      socket,
      head,
      ws =>
        wss.emit(
          'connection',
          ws,
          request,
          user
        )
    );
  } catch {
    socket.destroy();
  }
});

server.listen(
  PORT,
  '0.0.0.0',
  () =>
    console.log(
      `Ludo Activo backend en puerto ${PORT}`
    )
);
