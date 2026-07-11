const express = require('express');
const axios = require('axios');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { pool, migrate } = require('./db');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const REDIRECT_URI =
  process.env.REDIRECT_URI || 'https://clippilot-tokens.onrender.com/callback';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-secret-change-me';
if (!process.env.JWT_SECRET) {
  console.warn('⚠️  JWT_SECRET is not set. Set it in Render → Environment for production use.');
}
const COOKIE_NAME = 'clippilot_token';

// In-memory maps for in-flight OAuth exchanges only (never persisted).
const pendingRequests = {};
const tokenResults = {};

function randomState() {
  return Math.random().toString(36).substring(2) + Date.now();
}

function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
}

function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 30 * 24 * 60 * 60 * 1000
  });
}

function requireAuth(req, res, next) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ error: 'Not logged in' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Session expired, please log in again' });
  }
}

function successPage(channelHandler) {
  return '<html><body style="font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;background:#f0fff0"><div style="text-align:center;padding:40px;background:white;border-radius:12px"><div style="font-size:60px">&#9989;</div><h2 style="color:#16a34a">Token Generated!</h2><p><b>Channel:</b> ' + channelHandler + '</p><p style="color:gray;font-size:13px">This tab will close automatically...</p></div><script>setTimeout(function(){window.close()},3000)</script></body></html>';
}

function errorPage(msg) {
  return '<html><body style="font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;background:#fff0f0"><div style="text-align:center;padding:40px;background:white;border-radius:12px;max-width:600px"><div style="font-size:60px">&#10060;</div><h2 style="color:#dc2626">Something went wrong</h2><pre style="white-space:pre-wrap;text-align:left;font-size:12px;color:#666">' + msg + '</pre></div></body></html>';
}

/* ------------------------------------------------------------------ */
/*  Auth                                                               */
/* ------------------------------------------------------------------ */

app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const hash = await bcrypt.hash(String(password), 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
      [String(email).trim().toLowerCase(), hash]
    );
    const user = result.rows[0];
    setAuthCookie(res, signToken(user));
    res.json({ email: user.email });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'An account with this email already exists' });
    console.error(err);
    res.status(500).json({ error: 'Could not create account' });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [String(email).trim().toLowerCase()]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });
    const match = await bcrypt.compare(String(password), user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid email or password' });
    setAuthCookie(res, signToken(user));
    res.json({ email: user.email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
});

app.get('/auth/me', requireAuth, (req, res) => {
  res.json({ email: req.user.email });
});

/* ------------------------------------------------------------------ */
/*  Gmail Accounts (scoped to the logged-in user)                      */
/* ------------------------------------------------------------------ */

app.post('/gmail', requireAuth, async (req, res) => {
  const { gmail, client_id, client_secret } = req.body || {};
  if (!gmail || !client_id || !client_secret) {
    return res.status(400).json({ error: 'gmail, client_id and client_secret are required' });
  }
  try {
    const result = await pool.query(
      'INSERT INTO gmails (gmail, client_id, client_secret, user_id) VALUES ($1, $2, $3, $4) RETURNING id, gmail, created_at',
      [String(gmail).trim(), String(client_id).trim(), String(client_secret).trim(), req.user.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'This Gmail account is already saved' });
    console.error(err);
    res.status(500).json({ error: 'Could not save Gmail account' });
  }
});

app.get('/gmail', requireAuth, async (req, res) => {
  const result = await pool.query(
    'SELECT id, gmail, created_at FROM gmails WHERE user_id = $1 ORDER BY created_at DESC',
    [req.user.id]
  );
  res.json(result.rows);
});

app.get('/gmail/:id', requireAuth, async (req, res) => {
  const gmailResult = await pool.query(
    'SELECT id, gmail, created_at FROM gmails WHERE id = $1 AND user_id = $2',
    [req.params.id, req.user.id]
  );
  const row = gmailResult.rows[0];
  if (!row) return res.status(404).json({ error: 'Gmail account not found' });
  const channelsResult = await pool.query(
    'SELECT id, gmail_id, channel_handler, refresh_token, created_at FROM channels WHERE gmail_id = $1 ORDER BY created_at DESC',
    [req.params.id]
  );
  res.json({ ...row, channels: channelsResult.rows });
});

app.delete('/gmail/:id', requireAuth, async (req, res) => {
  const owned = await pool.query('SELECT id FROM gmails WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
  if (!owned.rows[0]) return res.status(404).json({ error: 'Gmail account not found' });
  await pool.query('DELETE FROM gmails WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

/* ------------------------------------------------------------------ */
/*  Channels + OAuth (token generation)                                */
/* ------------------------------------------------------------------ */

app.post('/channel', requireAuth, async (req, res) => {
  const { gmail_id, channel_handler } = req.body || {};
  if (!gmail_id || !channel_handler) {
    return res.status(400).json({ error: 'gmail_id and channel_handler are required' });
  }
  const gmailResult = await pool.query('SELECT * FROM gmails WHERE id = $1 AND user_id = $2', [gmail_id, req.user.id]);
  const gmailRow = gmailResult.rows[0];
  if (!gmailRow) return res.status(404).json({ error: 'Gmail account not found' });

  const state = randomState();
  pendingRequests[state] = {
    gmail_id: gmailRow.id,
    client_id: gmailRow.client_id,
    client_secret: gmailRow.client_secret,
    channel_handler: String(channel_handler).trim()
  };

  const authUrl =
    'https://accounts.google.com/o/oauth2/v2/auth?client_id=' + encodeURIComponent(gmailRow.client_id) +
    '&redirect_uri=' + encodeURIComponent(REDIRECT_URI) +
    '&response_type=code' +
    '&scope=' + encodeURIComponent(
      'openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/youtube https://www.googleapis.com/auth/youtube.upload'
    ) +
    '&access_type=offline&prompt=consent&state=' + state;

  res.json({ authUrl, state });
});

app.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.send(errorPage('Error: ' + error));
  if (!code || !state || !pendingRequests[state]) return res.send(errorPage('Invalid or expired request. Please try generating the token again.'));

  const { gmail_id, client_id, client_secret, channel_handler } = pendingRequests[state];
  delete pendingRequests[state];

  try {
    const tokenRes = await axios.post(
      'https://oauth2.googleapis.com/token',
      'code=' + encodeURIComponent(code) +
        '&client_id=' + encodeURIComponent(client_id) +
        '&client_secret=' + encodeURIComponent(client_secret) +
        '&redirect_uri=' + encodeURIComponent(REDIRECT_URI) +
        '&grant_type=authorization_code',
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const refresh_token = tokenRes.data.refresh_token;
    if (!refresh_token) {
      tokenResults[state] = { done: false, error: 'No refresh token returned. Revoke app access at myaccount.google.com/permissions and try again.' };
      return res.send(errorPage('No refresh token received.<br/>Go to myaccount.google.com/permissions, revoke this app, then try again.'));
    }

    const insertResult = await pool.query(
      'INSERT INTO channels (gmail_id, channel_handler, refresh_token) VALUES ($1, $2, $3) RETURNING id',
      [gmail_id, channel_handler, refresh_token]
    );

    tokenResults[state] = {
      done: true,
      refresh_token,
      channel_id: insertResult.rows[0].id,
      channel_handler,
      gmail_id
    };

    res.send(successPage(channel_handler));
  } catch (err) {
    const msg = err.response && err.response.data ? JSON.stringify(err.response.data) : err.message;
    tokenResults[state] = { done: false, error: msg };
    res.send(errorPage(msg));
  }
});

app.get('/token-status', (req, res) => {
  const state = req.query.state;
  if (!state || !tokenResults[state]) return res.json({ done: false });
  const result = tokenResults[state];
  delete tokenResults[state];
  res.json(result);
});

app.get('/channels', requireAuth, async (req, res) => {
  const { gmail_id } = req.query;
  if (gmail_id) {
    const owned = await pool.query('SELECT id FROM gmails WHERE id = $1 AND user_id = $2', [gmail_id, req.user.id]);
    if (!owned.rows[0]) return res.status(404).json({ error: 'Gmail account not found' });
    const result = await pool.query(
      'SELECT id, gmail_id, channel_handler, refresh_token, created_at FROM channels WHERE gmail_id = $1 ORDER BY created_at DESC',
      [gmail_id]
    );
    return res.json(result.rows);
  }
  const result = await pool.query(
    `SELECT c.id, c.gmail_id, c.channel_handler, c.refresh_token, c.created_at
     FROM channels c JOIN gmails g ON g.id = c.gmail_id
     WHERE g.user_id = $1 ORDER BY c.created_at DESC`,
    [req.user.id]
  );
  res.json(result.rows);
});

app.delete('/channel/:id', requireAuth, async (req, res) => {
  const owned = await pool.query(
    `SELECT c.id FROM channels c JOIN gmails g ON g.id = c.gmail_id WHERE c.id = $1 AND g.user_id = $2`,
    [req.params.id, req.user.id]
  );
  if (!owned.rows[0]) return res.status(404).json({ error: 'Channel not found' });
  await pool.query('DELETE FROM channels WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

/* ------------------------------------------------------------------ */
/*  Search (scoped to the logged-in user)                              */
/* ------------------------------------------------------------------ */

app.get('/search', requireAuth, async (req, res) => {
  const q = '%' + String(req.query.q || '').trim() + '%';
  const result = await pool.query(
    `SELECT c.id, c.gmail_id, c.channel_handler, c.refresh_token, c.created_at, g.gmail
     FROM channels c
     JOIN gmails g ON g.id = c.gmail_id
     WHERE g.user_id = $1 AND (c.channel_handler ILIKE $2 OR g.gmail ILIKE $2)
     ORDER BY c.created_at DESC`,
    [req.user.id, q]
  );
  res.json(result.rows);
});

app.get('/health', (req, res) => res.json({ ok: true }));

migrate()
  .then(() => {
    const PORT = process.env.PORT || 3721;

    app.listen(PORT, () => {
    console.log(`ClipPilot Token Manager running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('❌ Failed to connect to the database:', err.message);
    process.exit(1);
  });
