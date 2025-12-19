
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const { customAlphabet } = require('nanoid');
const Database = require('better-sqlite3');
const stringify = require('csv-stringify').stringify;
const crypto = require('crypto');
const session = require('express-session');

// Optional: set this in production (e.g., sim.company.com) to show an HTTPS share link
const PROD_DOMAIN = process.env.PROD_DOMAIN || null;


const app = express();
// If you deploy behind a reverse proxy (Nginx/Cloudflare/ALB), this helps Express respect forwarded headers.
app.set('trust proxy', true);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Sessions (admin auth)
app.use(session({
  name: 'phishsim.sid',
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    // secure: true, // enable behind HTTPS
    maxAge: 1000 * 60 * 60 * 8 // 8 hours
  }
}));

// DB init
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
const dbPath = path.join(dataDir, 'phish.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS campaigns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id INTEGER NOT NULL,
  name TEXT,
  email TEXT,
  token TEXT UNIQUE NOT NULL,
  clicked_at TEXT,
  name_submitted_at TEXT,
  submitted_name TEXT,
  credential_attempt_at TEXT,
  attempted_username TEXT,
  password_hash TEXT,
  password_length INTEGER,
  created_at TEXT NOT NULL,
  FOREIGN KEY(campaign_id) REFERENCES campaigns(id)
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id INTEGER,
  target_id INTEGER,
  event_type TEXT NOT NULL, -- clicked | name_submitted | credential_attempt
  details TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(campaign_id) REFERENCES campaigns(id),
  FOREIGN KEY(target_id) REFERENCES targets(id)
);
`);
// Settings helpers
function normalizeHostInput(v) {
  if (!v) return null;
  let s = String(v).trim();
  if (!s) return null;
  // remove protocol if user pasted full URL
  s = s.replace(/^https?:\/\//i, '');
  // remove trailing path/query
  s = s.split('/')[0];
  return s || null;
}

function getSetting(key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}

function setSetting(key, value) {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .run(key, value);
}


const nowISO = () => new Date().toISOString();
const nanoid = customAlphabet('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 22);

// --- Admin auth helpers ---
function hashSecret(secret) {
  const salt = crypto.randomBytes(16).toString('hex');
  const h = crypto.createHash('sha256').update(salt + '|' + secret).digest('hex');
  return `${salt}:${h}`;
}

function verifySecret(secret, stored) {
  if (!stored || typeof stored !== 'string' || !stored.includes(':')) return false;
  const [salt, h] = stored.split(':');
  const cand = crypto.createHash('sha256').update(salt + '|' + secret).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(cand, 'hex'));
  } catch {
    return false;
  }
}

function hasAdmin() {
  const row = db.prepare('SELECT id FROM admin_users LIMIT 1').get();
  return !!row;
}

function requireAdmin(req, res, next) {
  // First-run: force admin setup (do not block public simulation routes)
  if (!hasAdmin()) return res.redirect('/setup');
  if (req.session && req.session.adminUser) return next();
  return res.redirect('/admin/login');
}

function hashPassword(pw) {
  // Store non-recoverable salted hash + length only
  const salt = crypto.randomBytes(16).toString('hex');
  const h = crypto.createHash('sha256').update(salt + '|' + pw).digest('hex');
  return `${salt}:${h}`;
}

// Layout helper
app.locals.layout = function(view, data) {
  this.__layout = view;
  this.__layoutData = data || {};
}
app.use((req, res, next) => {
  // Simple flash
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;

  // Expose admin to views
  res.locals.adminUser = (req.session && req.session.adminUser) ? req.session.adminUser : null;
  res.locals.hasAdmin = hasAdmin();

  const _render = res.render.bind(res);
  res.render = (view, data={}) => {
    _render(view, {
      ...data,
      layout: function(viewName, locals) {
        res.locals.__layout = viewName;
        res.locals.__layoutData = locals || {};
      }
    }, (err, html) => {
      if (err) { return res.status(500).send(String(err)); }
      if (res.locals.__layout) {
        app.render(res.locals.__layout, {...res.locals.__layoutData, body: html, flash: res.locals.flash }, (e2, finalHtml) => {
          if (e2) return res.status(500).send(String(e2));
          res.send(finalHtml);
        });
      } else {
        res.send(html);
      }
    });
  };
  next();
});

// --- Admin routes ---
// First-run setup wizard (creates the first admin account)
app.get('/setup', (req, res) => {
  if (hasAdmin()) return res.redirect('/admin/login');
  res.render('admin_setup', { title: 'Initial Setup' });
});

app.post('/setup', (req, res) => {
  if (hasAdmin()) return res.redirect('/admin/login');

  const username = String(req.body.username || 'admin').trim() || 'admin';
  const pw = String(req.body.password || '');
  const confirm = String(req.body.confirm_password || '');

  if (username.length < 3) {
    req.session.flash = 'Username must be at least 3 characters.';
    return res.redirect('/setup');
  }
  if (!pw || pw.length < 8) {
    req.session.flash = 'Password must be at least 8 characters.';
    return res.redirect('/setup');
  }
  if (pw !== confirm) {
    req.session.flash = 'Password and confirm password do not match.';
    return res.redirect('/setup');
  }

  const ts = nowISO();
  try {
    db.prepare('INSERT INTO admin_users (username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)')
      .run(username, hashSecret(pw), ts, ts);
  } catch (e) {
    req.session.flash = 'That username already exists. Choose another.';
    return res.redirect('/setup');
  }

  req.session.flash = 'Admin created. Please log in.';
  return res.redirect('/admin/login');
});

app.get('/admin/login', (req, res) => {
  if (!hasAdmin()) return res.redirect('/setup');
  // Already logged in
  if (req.session && req.session.adminUser) return res.redirect('/');
  res.render('admin_login', { title: 'Admin Login' });
});

app.post('/admin/login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const row = db.prepare('SELECT username, password_hash FROM admin_users WHERE username = ?').get(username);
  if (!row || !verifySecret(password, row.password_hash)) {
    req.session.flash = 'Invalid username or password';
    return res.redirect('/admin/login');
  }
  req.session.adminUser = { username: row.username };
  res.redirect('/');
});

app.post('/admin/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/admin/login'));
});

app.get('/admin/settings', requireAdmin, (req, res) => {
  const linkSettings = {
    testHost: getSetting('test_host') || req.get('host') || 'localhost:3000',
    prodDomain: getSetting('prod_domain') || PROD_DOMAIN || ''
  };
  res.render('admin_settings', { title: 'Admin Settings', linkSettings });
});


app.post('/admin/settings/links', requireAdmin, (req, res) => {
  const testHost = normalizeHostInput(req.body.test_host);
  const prodDomain = normalizeHostInput(req.body.prod_domain);

  // Always keep a usable default for test
  setSetting('test_host', testHost || (req.get('host') || 'localhost:3000'));

  // prod domain can be blank
  if (prodDomain) setSetting('prod_domain', prodDomain);
  else db.prepare('DELETE FROM settings WHERE key = ?').run('prod_domain');

  req.session.flash = 'Link settings updated.';
  return res.redirect('/admin/settings');
});

app.post('/admin/settings/password', requireAdmin, (req, res) => {
  const current = String(req.body.current_password || '');
  const nextPw = String(req.body.new_password || '');
  const confirm = String(req.body.confirm_password || '');
  if (!nextPw || nextPw.length < 8) {
    req.session.flash = 'New password must be at least 8 characters.';
    return res.redirect('/admin/settings');
  }
  if (nextPw !== confirm) {
    req.session.flash = 'New password and confirm password do not match.';
    return res.redirect('/admin/settings');
  }

  const uname = req.session.adminUser.username;
  const row = db.prepare('SELECT password_hash FROM admin_users WHERE username = ?').get(uname);
  if (!row || !verifySecret(current, row.password_hash)) {
    req.session.flash = 'Current password is incorrect.';
    return res.redirect('/admin/settings');
  }

  db.prepare('UPDATE admin_users SET password_hash = ?, updated_at = ? WHERE username = ?')
    .run(hashSecret(nextPw), nowISO(), uname);
  req.session.flash = 'Password updated.';
  res.redirect('/admin/settings');
});

// Dashboard
app.get('/', requireAdmin, (req, res) => {
  const stats = {
    campaigns: db.prepare('SELECT COUNT(*) AS c FROM campaigns').get().c,
    targets: db.prepare('SELECT COUNT(*) AS c FROM targets').get().c,
    clicks: db.prepare('SELECT COUNT(*) AS c FROM events WHERE event_type = ?').get('clicked').c
  };
  const recent = db.prepare(`
    SELECT e.*, t.name AS target_name, t.email AS target_email, c.name AS campaign_name
    FROM events e
    LEFT JOIN targets t ON t.id = e.target_id
    LEFT JOIN campaigns c ON c.id = e.campaign_id
    ORDER BY e.created_at DESC
    LIMIT 25
  `).all();
  res.render('index', { stats, recent });
});

// Campaigns
app.get('/campaigns', requireAdmin, (req, res) => {
  const campaigns = db.prepare(`
    SELECT c.*,
      (SELECT COUNT(*) FROM targets t WHERE t.campaign_id = c.id) AS targets,
      (SELECT COUNT(*) FROM events e WHERE e.campaign_id = c.id AND e.event_type = 'clicked') AS clicks,
      (SELECT COUNT(*) FROM events e WHERE e.campaign_id = c.id AND e.event_type = 'name_submitted') AS names,
      (SELECT COUNT(*) FROM events e WHERE e.campaign_id = c.id AND e.event_type = 'credential_attempt') AS creds
    FROM campaigns c ORDER BY c.id DESC
  `).all();
  res.render('campaigns', { campaigns });
});

app.post('/campaigns', requireAdmin, (req, res) => {
  const name = String(req.body.name || '').trim();
  if (!name) return res.redirect('/campaigns');
  const info = db.prepare('INSERT INTO campaigns (name, created_at) VALUES (?, ?)').run(name, nowISO());
  const id = Number(info.lastInsertRowid);
  // After creation, take the admin directly to the campaign detail/edit page
  res.redirect('/campaigns/' + id);
});

app.post('/campaigns/:id/delete', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const exists = db.prepare('SELECT id FROM campaigns WHERE id = ?').get(id);
  if (!exists) return res.redirect('/campaigns');

  // delete children first
  db.prepare('DELETE FROM events WHERE campaign_id = ?').run(id);
  db.prepare('DELETE FROM targets WHERE campaign_id = ?').run(id);
  db.prepare('DELETE FROM campaigns WHERE id = ?').run(id);

  req.session.flash = 'Campaign deleted.';
  res.redirect('/campaigns');
});

app.get('/campaigns/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const campaign = db.prepare('SELECT * FROM campaigns WHERE id = ?').get(id);
  if (!campaign) return res.status(404).send('Not found');
  const targets = db.prepare('SELECT * FROM targets WHERE campaign_id = ? ORDER BY id DESC').all(id);
  const shareToken = (targets && targets[0] && targets[0].token) ? targets[0].token : 'YOUR_TARGET_TOKEN';
  const effectiveTestHost = getSetting('test_host') || req.get('host') || 'localhost:3000';
  const effectiveProdDomain = getSetting('prod_domain') || PROD_DOMAIN || null;
  const httpBase = `http://${effectiveTestHost}`;
  const httpsBase = effectiveProdDomain ? `https://${effectiveProdDomain}` : null;

  res.render('campaign_detail', {
    campaign,
    targets,
    shareToken,
    httpBase,
    httpsBase
  });
});

app.post('/campaigns/:id/targets', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const campaign = db.prepare('SELECT * FROM campaigns WHERE id = ?').get(id);
  if (!campaign) return res.status(404).send('Not found');

  const bulk = String(req.body.emails || '').trim();
  if (bulk) {
    const lines = bulk
      .split(/\r?\n/)
      .map(s => s.trim())
      .filter(Boolean);

    const insert = db.prepare(`INSERT INTO targets (campaign_id, name, email, token, created_at) VALUES (?, ?, ?, ?, ?)`);
    const tx = db.transaction((rows) => {
      for (const email of rows) {
        insert.run(id, null, email, nanoid(), nowISO());
      }
    });
    tx(lines);
    return res.redirect('/campaigns/' + id + '#targets');
  }

  // Single target (optional fields)
  const name = String(req.body.name || '').trim() || null;
  const email = String(req.body.email || '').trim() || null;
  const token = nanoid();
  db.prepare(`INSERT INTO targets (campaign_id, name, email, token, created_at) VALUES (?, ?, ?, ?, ?)`)
    .run(id, name, email, token, nowISO());

  res.redirect('/campaigns/' + id + '#targets');
});

// Landing link: track click
app.get('/l/:token', (req, res) => {
  const token = String(req.params.token);
  const t = db.prepare('SELECT * FROM targets WHERE token = ?').get(token);
  if (!t) return res.status(404).send('Invalid link');
  if (!t.clicked_at) {
    db.prepare('UPDATE targets SET clicked_at = ? WHERE id = ?').run(nowISO(), t.id);
    db.prepare('INSERT INTO events (campaign_id, target_id, event_type, details, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(t.campaign_id, t.id, 'clicked', 'Landing viewed', nowISO());
  }
  res.render('landing', { token });
});

// Landing: submit name

app.post('/l/:token', (req, res) => {
  const token = String(req.params.token);
  const t = db.prepare('SELECT * FROM targets WHERE token = ?').get(token);
  if (!t) return res.status(404).send('Invalid link');
  const name = String(req.body.name || '').trim();
  if (name) {
    db.prepare('UPDATE targets SET submitted_name = ?, name_submitted_at = ? WHERE id = ?').run(name, nowISO(), t.id);
    db.prepare('INSERT INTO events (campaign_id, target_id, event_type, details, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(t.campaign_id, t.id, 'name_submitted', 'Name: ' + name, nowISO());
  }
  res.redirect('/login?token=' + token);
});

// Fake login: GET
app.get('/login', (req, res) => {
  const token = String(req.query.token || '');
  const t = db.prepare('SELECT * FROM targets WHERE token = ?').get(token);
  if (!t) return res.status(404).send('Invalid token');
  res.render('login', { token });
});

// Fake login: POST (record attempt only; store username + salted hash + length)
app.post('/login', (req, res) => {
  const token = String(req.body.token || '');
  const t = db.prepare('SELECT * FROM targets WHERE token = ?').get(token);
  if (!t) return res.status(404).send('Invalid token');

  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const phash = hashPassword(password);
  const plen = password.length;

  db.prepare('UPDATE targets SET credential_attempt_at = ?, attempted_username = ?, password_hash = ?, password_length = ? WHERE id = ?')
    .run(nowISO(), username || null, phash, plen, t.id);
  db.prepare('INSERT INTO events (campaign_id, target_id, event_type, details, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(t.campaign_id, t.id, 'credential_attempt', `user=${username}; len=${plen}`, nowISO());

  res.redirect('/post-login-done');
});


app.get('/post-login-done', (req, res) => {
  res.send(`
  <html><head><meta charset="utf-8"><script src="https://cdn.tailwindcss.com"></script></head>
  <body class="bg-gray-50">
    <div class="mx-auto max-w-xl bg-white mt-20 p-6 rounded-2xl shadow text-center">
      <h1 class="text-xl font-semibold mb-2">Thank you</h1>
      <p class="text-sm text-gray-700">You will get voucher shortly.</p>
      <a href="/" class="inline-block mt-4 px-4 py-2 rounded-xl bg-black text-white">OK</a>
    </div>
  </body></html>
  `);

});

// CSV exports
function sendCSV(res, rows, headers) {
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="export.csv"');
  stringify(rows, { header: true, columns: headers }).pipe(res);
}

app.get('/export/all.csv', requireAdmin, (req, res) => {
  if (!(req.session && req.session.adminUser)) return res.redirect('/admin/login');
  const rows = db.prepare(`
    SELECT e.created_at, e.event_type, e.details, c.name AS campaign, t.name AS target_name, t.email AS target_email
    FROM events e
    LEFT JOIN campaigns c ON c.id = e.campaign_id
    LEFT JOIN targets t ON t.id = e.target_id
    ORDER BY e.created_at DESC
  `).all();
  sendCSV(res, rows, ['created_at','event_type','details','campaign','target_name','target_email']);
});

app.get('/export/clicks.csv', requireAdmin, (req, res) => {
  if (!(req.session && req.session.adminUser)) return res.redirect('/admin/login');
  const rows = db.prepare(`
    SELECT t.clicked_at AS created_at, 'clicked' AS event_type, c.name AS campaign, t.name AS target_name, t.email AS target_email
    FROM targets t JOIN campaigns c ON c.id = t.campaign_id
    WHERE t.clicked_at IS NOT NULL ORDER BY t.clicked_at DESC
  `).all();
  sendCSV(res, rows, ['created_at','event_type','campaign','target_name','target_email']);
});

app.get('/export/names.csv', requireAdmin, (req, res) => {
  if (!(req.session && req.session.adminUser)) return res.redirect('/admin/login');
  const rows = db.prepare(`
    SELECT t.name_submitted_at AS created_at, 'name_submitted' AS event_type, t.submitted_name, c.name AS campaign, t.name AS target_name, t.email AS target_email
    FROM targets t JOIN campaigns c ON c.id = t.campaign_id
    WHERE t.name_submitted_at IS NOT NULL ORDER BY t.name_submitted_at DESC
  `).all();
  sendCSV(res, rows, ['created_at','event_type','submitted_name','campaign','target_name','target_email']);
});

app.get('/export/creds.csv', requireAdmin, (req, res) => {
  if (!(req.session && req.session.adminUser)) return res.redirect('/admin/login');
  const rows = db.prepare(`
    SELECT t.credential_attempt_at AS created_at, 'credential_attempt' AS event_type, t.attempted_username, t.password_length, c.name AS campaign, t.name AS target_name, t.email AS target_email
    FROM targets t JOIN campaigns c ON c.id = t.campaign_id
    WHERE t.credential_attempt_at IS NOT NULL ORDER BY t.credential_attempt_at DESC
  `).all();
  sendCSV(res, rows, ['created_at','event_type','attempted_username','password_length','campaign','target_name','target_email']);
});

app.get('/export/campaign/:id.csv', requireAdmin, (req, res) => {
  if (!(req.session && req.session.adminUser)) return res.redirect('/admin/login');
  const id = Number(req.params.id);
  const rows = db.prepare(`
    SELECT e.created_at, e.event_type, e.details, c.name AS campaign, t.name AS target_name, t.email AS target_email
    FROM events e
    LEFT JOIN campaigns c ON c.id = e.campaign_id
    LEFT JOIN targets t ON t.id = e.target_id
    WHERE e.campaign_id = ?
    ORDER BY e.created_at DESC
  `).all(id);
  sendCSV(res, rows, ['created_at','event_type','details','campaign','target_name','target_email']);
});

// --- Analytics API (for dashboard charts) ---
app.get('/api/stats/overview', requireAdmin, (req, res) => {
  try {
    const totals = {
      campaigns: db.prepare('SELECT COUNT(*) AS n FROM campaigns').get().n,
      targets: db.prepare('SELECT COUNT(*) AS n FROM targets').get().n,
      clicks: db.prepare("SELECT COUNT(*) AS n FROM events WHERE event_type='clicked'").get().n,
      names: db.prepare("SELECT COUNT(*) AS n FROM events WHERE event_type='name_submitted'").get().n,
      creds: db.prepare("SELECT COUNT(*) AS n FROM events WHERE event_type='credential_attempt'").get().n,
    };

    const funnel = db.prepare(`
      SELECT
        (SELECT COUNT(*) FROM targets) AS targets,
        (SELECT COUNT(*) FROM targets WHERE clicked_at IS NOT NULL) AS clicked,
        (SELECT COUNT(*) FROM targets WHERE name_submitted_at IS NOT NULL) AS name_submitted,
        (SELECT COUNT(*) FROM targets WHERE credential_attempt_at IS NOT NULL) AS credential_attempt
    `).get();

    const rows = db.prepare(`
      SELECT c.id, c.name, c.created_at,
        (SELECT COUNT(*) FROM targets t WHERE t.campaign_id = c.id) AS targets,
        (SELECT COUNT(*) FROM events e WHERE e.campaign_id = c.id AND e.event_type = 'clicked') AS clicks,
        (SELECT COUNT(*) FROM events e WHERE e.campaign_id = c.id AND e.event_type = 'name_submitted') AS names,
        (SELECT COUNT(*) FROM events e WHERE e.campaign_id = c.id AND e.event_type = 'credential_attempt') AS creds
      FROM campaigns c
      ORDER BY c.id DESC
      LIMIT 50;
    `).all();

    const byCampaign = rows.map(r => {
      const targets = Number(r.targets || 0);
      const clicks = Number(r.clicks || 0);
      const names = Number(r.names || 0);
      const creds = Number(r.creds || 0);
      const pct = (n, d) => (d > 0 ? Math.round((n / d) * 1000) / 10 : 0); // 1 decimal
      return {
        id: r.id,
        name: r.name,
        created_at: r.created_at,
        targets,
        clicks,
        names,
        creds,
        click_rate: pct(clicks, targets),
        name_submit_rate: pct(names, targets),
        credential_rate: pct(creds, targets),
      };
    });

    res.json({ totals, funnel, byCampaign });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to build overview stats' });
  }
});

app.get('/api/stats/campaign/:id', requireAdmin, (req, res) => {
  try {
    const id = Number(req.params.id);
    const campaign = db.prepare('SELECT * FROM campaigns WHERE id = ?').get(id);
    if (!campaign) return res.status(404).json({ error: 'Not found' });

    const funnel = db.prepare(`
      SELECT
        (SELECT COUNT(*) FROM targets WHERE campaign_id = ?) AS targets,
        (SELECT COUNT(*) FROM targets WHERE campaign_id = ? AND clicked_at IS NOT NULL) AS clicked,
        (SELECT COUNT(*) FROM targets WHERE campaign_id = ? AND name_submitted_at IS NOT NULL) AS name_submitted,
        (SELECT COUNT(*) FROM targets WHERE campaign_id = ? AND credential_attempt_at IS NOT NULL) AS credential_attempt
    `).get(id, id, id, id);

    const recent = db.prepare(`
      SELECT e.event_type, e.created_at, t.email, t.name
      FROM events e
      LEFT JOIN targets t ON t.id = e.target_id
      WHERE e.campaign_id = ?
      ORDER BY e.id DESC
      LIMIT 30;
    `).all(id);

    res.json({ campaign, funnel, recent });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to build campaign stats' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('PhishSim running on http://localhost:' + PORT);
});
