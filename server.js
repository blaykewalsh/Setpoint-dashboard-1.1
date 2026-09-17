const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const CALORIENINJAS_API_KEY = process.env.CALORIENINJAS_API_KEY;

// ---------------------------------------------------------------------------
// Tiny file-based "database". This is a personal/small-group project, so a
// couple of JSON files under DATA_DIR is enough, no separate database server
// to run. Mount DATA_DIR as a persistent volume in Coolify so accounts and
// logged data survive redeploys.
// ---------------------------------------------------------------------------
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const USERDATA_DIR = path.join(DATA_DIR, 'userdata');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

fs.mkdirSync(USERDATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '{}');

function safeKey(u) {
  return u.trim().toLowerCase().replace(/[^a-z0-9_.-]/g, '_');
}
function readJSON(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { return fallback; }
}
function writeJSON(file, obj) {
  fs.writeFileSync(file, JSON.stringify(obj));
}
function userDataFile(key) {
  return path.join(USERDATA_DIR, key + '.json');
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not signed in.' });
  try {
    req.userKey = jwt.verify(token, JWT_SECRET).sub;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Your session expired, please log in again.' });
  }
}

app.post('/api/auth/signup', (req, res) => {
  if (!JWT_SECRET) return res.status(500).json({ error: 'Server is missing JWT_SECRET. Set it in your Coolify environment variables and redeploy.' });

  const username = (req.body && req.body.username || '').toString().trim();
  const password = (req.body && req.body.password || '').toString().trim();
  const consent = !!(req.body && req.body.consent);
  if (!username || !password) return res.status(400).json({ error: 'Enter a username and password.' });
  if (!consent) return res.status(400).json({ error: "You must confirm you're 16 or older and agree to the Privacy Policy & Terms." });

  const users = readJSON(USERS_FILE, {});
  const key = safeKey(username);
  if (users[key]) return res.status(409).json({ error: 'That username is already taken.' });

  users[key] = { username, passwordHash: bcrypt.hashSync(password, 10), consentedAt: new Date().toISOString() };
  writeJSON(USERS_FILE, users);
  writeJSON(userDataFile(key), {});

  const token = jwt.sign({ sub: key }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username });
});

app.post('/api/auth/login', (req, res) => {
  if (!JWT_SECRET) return res.status(500).json({ error: 'Server is missing JWT_SECRET. Set it in your Coolify environment variables and redeploy.' });

  const username = (req.body && req.body.username || '').toString().trim();
  const password = (req.body && req.body.password || '').toString().trim();
  if (!username || !password) return res.status(400).json({ error: 'Enter your username and password.' });

  const users = readJSON(USERS_FILE, {});
  const key = safeKey(username);
  const user = users[key];
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }

  const token = jwt.sign({ sub: key }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: user.username });
});

// ---------------------------------------------------------------------------
// User data (planner, stats, diet, sports - the same blob the frontend keeps)
// ---------------------------------------------------------------------------
app.get('/api/data', requireAuth, (req, res) => {
  res.json(readJSON(userDataFile(req.userKey), {}));
});

app.put('/api/data', requireAuth, (req, res) => {
  if (!req.body || typeof req.body !== 'object') return res.status(400).json({ error: 'Invalid data.' });
  writeJSON(userDataFile(req.userKey), req.body);
  res.json({ ok: true });
});

// Permanently deletes the account's login AND all of its app data, not just
// the login. This is the real "forget me" button, not reversible.
app.delete('/api/account', requireAuth, (req, res) => {
  const users = readJSON(USERS_FILE, {});
  delete users[req.userKey];
  writeJSON(USERS_FILE, users);

  const file = userDataFile(req.userKey);
  if (fs.existsSync(file)) fs.unlinkSync(file);

  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// AI Nutritionist - uses CalorieNinjas' free natural-language nutrition API
// (get a free API key at https://calorieninjas.com/api) instead of a paid
// LLM call, since this task is just food-to-nutrition lookup, not reasoning.
// ---------------------------------------------------------------------------
app.post('/api/estimate-food', async (req, res) => {
  if (!CALORIENINJAS_API_KEY) {
    return res.status(500).json({ error: 'Server is missing CALORIENINJAS_API_KEY. Set it in your Coolify environment variables and redeploy.' });
  }

  const description = (req.body && req.body.description || '').toString().trim();
  if (!description) return res.status(400).json({ error: 'Missing food description.' });

  try {
    const response = await fetch('https://api.calorieninjas.com/v1/nutrition?query=' + encodeURIComponent(description), {
      headers: { 'X-Api-Key': CALORIENINJAS_API_KEY }
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error('CalorieNinjas API error:', response.status, errText);
      return res.status(502).json({ error: 'The AI Nutritionist could not be reached right now.' });
    }

    const json = await response.json();
    const items = json.items || [];
    if (!items.length) {
      // Nothing recognized - still return a zeroed entry so the log doesn't
      // silently fail, the person can edit/delete it if the estimate is off.
      return res.json({ name: description, cals: 0, p: 0, c: 0, f: 0 });
    }

    const totals = items.reduce((acc, item) => ({
      cals: acc.cals + (Number(item.calories) || 0),
      p: acc.p + (Number(item.protein_g) || 0),
      c: acc.c + (Number(item.carbohydrates_total_g) || 0),
      f: acc.f + (Number(item.fat_total_g) || 0)
    }), { cals: 0, p: 0, c: 0, f: 0 });

    const name = items.length === 1 ? items[0].name : items.map(i => i.name).join(', ');

    res.json({
      name: name || description,
      cals: Math.round(totals.cals),
      p: Math.round(totals.p),
      c: Math.round(totals.c),
      f: Math.round(totals.f)
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Unexpected error estimating that food.' });
  }
});

// ---------------------------------------------------------------------------
// Ranked - compares PRs across every account using estimated one-rep max
// (Epley formula), so different rep ranges compare fairly against each other.
// ---------------------------------------------------------------------------
function epley1RM(weight, reps) {
  const r = Math.max(1, Math.min(15, reps));
  return weight * (1 + r / 30);
}
function allUserFiles() {
  return fs.readdirSync(USERDATA_DIR).filter(f => f.endsWith('.json'));
}

app.get('/api/leaderboard/exercises', requireAuth, (req, res) => {
  const seen = new Map(); // lowercase -> original casing
  for (const file of allUserFiles()) {
    const d = readJSON(path.join(USERDATA_DIR, file), {});
    const prs = (d.stats && d.stats.prs) || [];
    for (const pr of prs) {
      if (!pr.exercise) continue;
      const key = pr.exercise.trim().toLowerCase();
      if (key && !seen.has(key)) seen.set(key, pr.exercise.trim());
    }
  }
  res.json([...seen.values()].sort((a, b) => a.localeCompare(b)));
});

app.get('/api/leaderboard', requireAuth, (req, res) => {
  const exercise = (req.query.exercise || '').toString().trim().toLowerCase();
  if (!exercise) return res.status(400).json({ error: 'Missing exercise.' });

  const users = readJSON(USERS_FILE, {});
  const rows = [];

  for (const file of allUserFiles()) {
    const key = file.replace(/\.json$/, '');
    const user = users[key];
    if (!user) continue;
    const d = readJSON(path.join(USERDATA_DIR, file), {});
    const prs = ((d.stats && d.stats.prs) || []).filter(pr => (pr.exercise || '').trim().toLowerCase() === exercise);
    if (!prs.length) continue;

    let best = null;
    for (const pr of prs) {
      const est = epley1RM(Number(pr.weight) || 0, Number(pr.reps) || 1);
      if (!best || est > best.est) best = { est, weight: pr.weight, reps: pr.reps };
    }
    rows.push({
      username: user.username,
      best1RM: Math.round(best.est * 10) / 10,
      sourceWeight: best.weight,
      sourceReps: best.reps
    });
  }

  rows.sort((a, b) => b.best1RM - a.best1RM);
  res.json(rows);
});

// If a request hits /api/* but matches nothing above, respond with JSON
// (not Express's default HTML 404 page) so the frontend's error message is
// meaningful instead of "Request failed" with no context. Seeing this after
// a deploy usually means the container is still running an older build.
app.all('/api/*', (req, res) => {
  res.status(404).json({ error: 'API route not found: ' + req.method + ' ' + req.path + '. The server may be running an older build.' });
});

// Anything else falls back to the dashboard (single-page app).
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Setpoint running on port ${PORT}`);
});
