const express = require('express');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const db = require('./db');
const captcha = require('./captcha');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-me';
const IP_SALT = process.env.IP_SALT || crypto.randomBytes(16).toString('hex');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(cookieParser());
app.use('/static', express.static(path.join(__dirname, 'public')));
app.set('trust proxy', 1);

function ipHash(req) {
  return crypto.createHash('sha256').update(IP_SALT + (req.ip || '')).digest('hex');
}

function isBanned(req) {
  return !!db.prepare('SELECT 1 FROM bans WHERE ip_hash = ?').get(ipHash(req));
}

function isAdmin(req) {
  return req.cookies.admin === ADMIN_PASSWORD;
}

const writeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Rate limit exceeded. Slow down.',
});

const voteLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use((req, res, next) => {
  res.locals.isAdmin = isAdmin(req);
  next();
});

function clean(s, max = 10000) {
  if (typeof s !== 'string') return '';
  return s.slice(0, max);
}

function validSubName(name) {
  return /^[a-z0-9_]{2,24}$/.test(name);
}

app.get('/', (req, res) => {
  const posts = db.prepare(`
    SELECT p.*, (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id AND c.removed = 0) AS comment_count
    FROM posts p
    WHERE p.removed = 0
    ORDER BY p.created_at DESC
    LIMIT 50
  `).all();
  const subs = db.prepare('SELECT name FROM subs ORDER BY name LIMIT 100').all();
  res.render('index', { posts, subs, title: 'ghost' });
});

app.get('/g/:sub', (req, res) => {
  const sub = db.prepare('SELECT * FROM subs WHERE name = ?').get(req.params.sub);
  if (!sub) return res.status(404).render('error', { message: 'No such ghost.', title: '404' });
  const posts = db.prepare(`
    SELECT p.*, (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id AND c.removed = 0) AS comment_count
    FROM posts p
    WHERE p.sub = ? AND p.removed = 0
    ORDER BY p.created_at DESC
    LIMIT 100
  `).all(sub.name);
  res.render('sub', { sub, posts, title: 'g/' + sub.name });
});

app.get('/g/:sub/:id', (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id = ? AND sub = ?').get(req.params.id, req.params.sub);
  if (!post) return res.status(404).render('error', { message: 'Post not found.', title: '404' });
  const comments = db.prepare(`
    SELECT * FROM comments WHERE post_id = ? ORDER BY created_at ASC
  `).all(post.id);
  const challenge = captcha.issue();
  res.render('post', { post, comments, challenge, title: post.title });
});

app.get('/submit', (req, res) => {
  const subName = req.query.sub || '';
  const subs = db.prepare('SELECT name FROM subs ORDER BY name').all();
  const challenge = captcha.issue();
  res.render('submit', { subs, subName, challenge, error: null, title: 'submit' });
});

app.get('/new-ghost', (req, res) => {
  const challenge = captcha.issue();
  res.render('create-sub', { challenge, error: null, title: 'new ghost' });
});

app.post('/new-ghost', writeLimiter, (req, res) => {
  if (isBanned(req)) return res.status(403).render('error', { message: 'Banned.', title: '403' });
  const name = clean(req.body.name, 32).toLowerCase().trim();
  const description = clean(req.body.description, 500);

  const v = captcha.verify({
    token: req.body.captcha_token,
    answer: req.body.captcha_answer,
    powNonce: req.body.pow_nonce,
    honeypot: req.body.website,
    usedTokens: captcha.usedTokens,
  });
  if (!v.ok) {
    const challenge = captcha.issue();
    return res.status(400).render('create-sub', { challenge, error: v.reason, title: 'new ghost' });
  }

  if (!validSubName(name)) {
    const challenge = captcha.issue();
    return res.status(400).render('create-sub', { challenge, error: 'Name must be 2–24 chars: a-z, 0-9, _', title: 'new ghost' });
  }
  const exists = db.prepare('SELECT 1 FROM subs WHERE name = ?').get(name);
  if (exists) {
    const challenge = captcha.issue();
    return res.status(400).render('create-sub', { challenge, error: 'That ghost already exists.', title: 'new ghost' });
  }

  db.prepare('INSERT INTO subs (name, description, created_at) VALUES (?, ?, ?)')
    .run(name, description, Date.now());
  res.redirect('/g/' + name);
});

app.post('/submit', writeLimiter, (req, res) => {
  if (isBanned(req)) return res.status(403).render('error', { message: 'Banned.', title: '403' });
  const sub = clean(req.body.sub, 32).toLowerCase().trim();
  const title = clean(req.body.title, 300).trim();
  const body = clean(req.body.body, 20000);
  const url = clean(req.body.url, 2000).trim();

  const subs = db.prepare('SELECT name FROM subs ORDER BY name').all();

  const v = captcha.verify({
    token: req.body.captcha_token,
    answer: req.body.captcha_answer,
    powNonce: req.body.pow_nonce,
    honeypot: req.body.website,
    usedTokens: captcha.usedTokens,
  });
  if (!v.ok) {
    const challenge = captcha.issue();
    return res.status(400).render('submit', { subs, subName: sub, challenge, error: v.reason, title: 'submit' });
  }

  const subRow = db.prepare('SELECT name FROM subs WHERE name = ?').get(sub);
  if (!subRow) {
    const challenge = captcha.issue();
    return res.status(400).render('submit', { subs, subName: sub, challenge, error: 'Pick an existing ghost.', title: 'submit' });
  }
  if (!title) {
    const challenge = captcha.issue();
    return res.status(400).render('submit', { subs, subName: sub, challenge, error: 'Title required.', title: 'submit' });
  }
  if (url && !/^https?:\/\//i.test(url)) {
    const challenge = captcha.issue();
    return res.status(400).render('submit', { subs, subName: sub, challenge, error: 'URL must start with http(s)://', title: 'submit' });
  }

  const result = db.prepare(`
    INSERT INTO posts (sub, title, body, url, created_at, ip_hash)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(sub, title, body, url || null, Date.now(), ipHash(req));

  res.redirect(`/g/${sub}/${result.lastInsertRowid}`);
});

app.post('/g/:sub/:id/comment', writeLimiter, (req, res) => {
  if (isBanned(req)) return res.status(403).render('error', { message: 'Banned.', title: '403' });
  const post = db.prepare('SELECT * FROM posts WHERE id = ? AND sub = ?').get(req.params.id, req.params.sub);
  if (!post) return res.status(404).render('error', { message: 'Post not found.', title: '404' });

  const body = clean(req.body.body, 10000).trim();
  const parentId = req.body.parent_id ? parseInt(req.body.parent_id, 10) : null;

  const v = captcha.verify({
    token: req.body.captcha_token,
    answer: req.body.captcha_answer,
    powNonce: req.body.pow_nonce,
    honeypot: req.body.website,
    usedTokens: captcha.usedTokens,
  });
  if (!v.ok || !body) {
    return res.redirect(`/g/${post.sub}/${post.id}?err=${encodeURIComponent(v.ok ? 'empty comment' : v.reason)}`);
  }

  if (parentId) {
    const parent = db.prepare('SELECT id FROM comments WHERE id = ? AND post_id = ?').get(parentId, post.id);
    if (!parent) return res.redirect(`/g/${post.sub}/${post.id}`);
  }

  db.prepare(`
    INSERT INTO comments (post_id, parent_id, body, created_at, ip_hash)
    VALUES (?, ?, ?, ?, ?)
  `).run(post.id, parentId || null, body, Date.now(), ipHash(req));

  res.redirect(`/g/${post.sub}/${post.id}`);
});

app.post('/vote', voteLimiter, (req, res) => {
  if (isBanned(req)) return res.status(403).send('banned');
  const kind = req.body.kind === 'comment' ? 'comment' : 'post';
  const targetId = parseInt(req.body.target_id, 10);
  const value = parseInt(req.body.value, 10);
  if (!Number.isFinite(targetId) || ![-1, 0, 1].includes(value)) return res.status(400).send('bad');

  const voter = ipHash(req);
  const existing = db.prepare('SELECT value FROM votes WHERE ip_hash = ? AND kind = ? AND target_id = ?').get(voter, kind, targetId);
  const prev = existing ? existing.value : 0;
  const delta = value - prev;

  const tx = db.transaction(() => {
    if (value === 0) {
      db.prepare('DELETE FROM votes WHERE ip_hash = ? AND kind = ? AND target_id = ?').run(voter, kind, targetId);
    } else if (existing) {
      db.prepare('UPDATE votes SET value = ? WHERE ip_hash = ? AND kind = ? AND target_id = ?').run(value, voter, kind, targetId);
    } else {
      db.prepare('INSERT INTO votes (ip_hash, kind, target_id, value) VALUES (?, ?, ?, ?)').run(voter, kind, targetId, value);
    }
    const table = kind === 'comment' ? 'comments' : 'posts';
    db.prepare(`UPDATE ${table} SET score = score + ? WHERE id = ?`).run(delta, targetId);
  });
  tx();

  const table = kind === 'comment' ? 'comments' : 'posts';
  const row = db.prepare(`SELECT score FROM ${table} WHERE id = ?`).get(targetId);
  res.json({ score: row ? row.score : 0, value });
});

app.get('/admin', (req, res) => {
  if (!isAdmin(req)) return res.render('admin-login', { error: null, title: 'admin' });
  const posts = db.prepare('SELECT * FROM posts ORDER BY created_at DESC LIMIT 100').all();
  const comments = db.prepare('SELECT * FROM comments ORDER BY created_at DESC LIMIT 100').all();
  const bans = db.prepare('SELECT * FROM bans ORDER BY created_at DESC LIMIT 100').all();
  res.render('admin', { posts, comments, bans, title: 'admin' });
});

app.post('/admin/login', (req, res) => {
  if (req.body.password === ADMIN_PASSWORD) {
    res.cookie('admin', ADMIN_PASSWORD, { httpOnly: true, sameSite: 'strict' });
    return res.redirect('/admin');
  }
  res.status(401).render('admin-login', { error: 'wrong password', title: 'admin' });
});

app.post('/admin/logout', (req, res) => {
  res.clearCookie('admin');
  res.redirect('/');
});

app.post('/admin/remove', (req, res) => {
  if (!isAdmin(req)) return res.status(403).send('forbidden');
  const kind = req.body.kind === 'comment' ? 'comments' : 'posts';
  const id = parseInt(req.body.id, 10);
  db.prepare(`UPDATE ${kind} SET removed = 1 WHERE id = ?`).run(id);
  res.redirect('/admin');
});

app.post('/admin/restore', (req, res) => {
  if (!isAdmin(req)) return res.status(403).send('forbidden');
  const kind = req.body.kind === 'comment' ? 'comments' : 'posts';
  const id = parseInt(req.body.id, 10);
  db.prepare(`UPDATE ${kind} SET removed = 0 WHERE id = ?`).run(id);
  res.redirect('/admin');
});

app.post('/admin/ban', (req, res) => {
  if (!isAdmin(req)) return res.status(403).send('forbidden');
  const kind = req.body.kind === 'comment' ? 'comments' : 'posts';
  const id = parseInt(req.body.id, 10);
  const row = db.prepare(`SELECT ip_hash FROM ${kind} WHERE id = ?`).get(id);
  if (row) {
    db.prepare('INSERT OR IGNORE INTO bans (ip_hash, reason, created_at) VALUES (?, ?, ?)')
      .run(row.ip_hash, clean(req.body.reason, 200), Date.now());
  }
  res.redirect('/admin');
});

app.post('/admin/unban', (req, res) => {
  if (!isAdmin(req)) return res.status(403).send('forbidden');
  db.prepare('DELETE FROM bans WHERE ip_hash = ?').run(clean(req.body.ip_hash, 128));
  res.redirect('/admin');
});

app.use((req, res) => {
  res.status(404).render('error', { message: 'Not found.', title: '404' });
});

app.listen(PORT, () => {
  console.log(`ghost running on http://localhost:${PORT}`);
  console.log(`admin password: ${ADMIN_PASSWORD === 'change-me' ? 'change-me (set ADMIN_PASSWORD env var!)' : '[set]'}`);
});
