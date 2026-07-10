const express = require('express');
const axios = require('axios');
const path = require('path');
const db = require('./db');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const REDIRECT_URI =
  process.env.REDIRECT_URI || 'https://clippilot-tokens.onrender.com/callback';

// In-memory maps for in-flight OAuth exchanges (never touch the database
// until the token exchange actually succeeds).
const pendingRequests = {};
const tokenResults = {};

function randomState() {
  return Math.random().toString(36).substring(2) + Date.now();
}

function successPage(channelHandler) {
  return '<html><body style="font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;background:#f0fff0"><div style="text-align:center;padding:40px;background:white;border-radius:12px"><div style="font-size:60px">&#9989;</div><h2 style="color:#16a34a">Token Generated!</h2><p><b>Channel:</b> ' + channelHandler + '</p><p style="color:gray;font-size:13px">This tab will close automatically...</p></div><script>setTimeout(function(){window.close()},3000)</script></body></html>';
}

function errorPage(msg) {
  return '<html><body style="font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;background:#fff0f0"><div style="text-align:center;padding:40px;background:white;border-radius:12px;max-width:600px"><div style="font-size:60px">&#10060;</div><h2 style="color:#dc2626">Something went wrong</h2><pre style="white-space:pre-wrap;text-align:left;font-size:12px;color:#666">' + msg + '</pre></div></body></html>';
}

/* ------------------------------------------------------------------ */
/*  Gmail Accounts                                                     */
/* ------------------------------------------------------------------ */

app.post('/gmail', (req, res) => {
  const { gmail, client_id, client_secret } = req.body || {};
  if (!gmail || !client_id || !client_secret) {
    return res.status(400).json({ error: 'gmail, client_id and client_secret are required' });
  }
  try {
    const stmt = db.prepare('INSERT INTO gmails (gmail, client_id, client_secret) VALUES (?, ?, ?)');
    const info = stmt.run(String(gmail).trim(), String(client_id).trim(), String(client_secret).trim());
    const row = db.prepare('SELECT id, gmail, created_at FROM gmails WHERE id = ?').get(info.lastInsertRowid);
    res.json(row);
  } catch (err) {
    if (err.message && err.message.indexOf('UNIQUE') !== -1) {
      return res.status(409).json({ error: 'This Gmail account is already saved' });
    }
    res.status(500).json({ error: 'Could not save Gmail account' });
  }
});

app.get('/gmail', (req, res) => {
  const rows = db.prepare('SELECT id, gmail, created_at FROM gmails ORDER BY created_at DESC').all();
  res.json(rows);
});

app.get('/gmail/:id', (req, res) => {
  const row = db.prepare('SELECT id, gmail, created_at FROM gmails WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Gmail account not found' });
  const channels = db
    .prepare('SELECT id, gmail_id, channel_handler, refresh_token, created_at FROM channels WHERE gmail_id = ? ORDER BY created_at DESC')
    .all(req.params.id);
  res.json({ ...row, channels });
});

app.delete('/gmail/:id', (req, res) => {
  db.prepare('DELETE FROM channels WHERE gmail_id = ?').run(req.params.id);
  const info = db.prepare('DELETE FROM gmails WHERE id = ?').run(req.params.id);
  res.json({ ok: true, deleted: info.changes });
});

/* ------------------------------------------------------------------ */
/*  Channels + OAuth (token generation)                                */
/* ------------------------------------------------------------------ */

app.post('/channel', (req, res) => {
  const { gmail_id, channel_handler } = req.body || {};
  if (!gmail_id || !channel_handler) {
    return res.status(400).json({ error: 'gmail_id and channel_handler are required' });
  }
  const gmailRow = db.prepare('SELECT * FROM gmails WHERE id = ?').get(gmail_id);
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
    '&response_type=code&scope=' + encodeURIComponent('https://www.googleapis.com/auth/youtube.upload') +
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

    const stmt = db.prepare('INSERT INTO channels (gmail_id, channel_handler, refresh_token) VALUES (?, ?, ?)');
    const info = stmt.run(gmail_id, channel_handler, refresh_token);

    tokenResults[state] = {
      done: true,
      refresh_token,
      channel_id: info.lastInsertRowid,
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

app.get('/channels', (req, res) => {
  const { gmail_id } = req.query;
  const rows = gmail_id
    ? db.prepare('SELECT id, gmail_id, channel_handler, refresh_token, created_at FROM channels WHERE gmail_id = ? ORDER BY created_at DESC').all(gmail_id)
    : db.prepare('SELECT id, gmail_id, channel_handler, refresh_token, created_at FROM channels ORDER BY created_at DESC').all();
  res.json(rows);
});

app.delete('/channel/:id', (req, res) => {
  const info = db.prepare('DELETE FROM channels WHERE id = ?').run(req.params.id);
  res.json({ ok: true, deleted: info.changes });
});

/* ------------------------------------------------------------------ */
/*  Search                                                             */
/* ------------------------------------------------------------------ */

app.get('/search', (req, res) => {
  const q = '%' + String(req.query.q || '').trim() + '%';
  const rows = db
    .prepare(
      `SELECT c.id, c.gmail_id, c.channel_handler, c.refresh_token, c.created_at, g.gmail
       FROM channels c
       JOIN gmails g ON g.id = c.gmail_id
       WHERE c.channel_handler LIKE ? OR g.gmail LIKE ?
       ORDER BY c.created_at DESC`
    )
    .all(q, q);
  res.json(rows);
});

app.get('/health', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3721;

app.listen(PORT, () => {
  console.log(`ClipPilot Token Manager running on port ${PORT}`);
});
