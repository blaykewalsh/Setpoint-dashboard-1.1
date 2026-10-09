const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || '';
const SERVER_STARTED_AT = Date.now();

// ---------------------------------------------------------------------------
// Tiny file-based "database". This is a personal/small-group project, so a
// couple of JSON files under DATA_DIR is enough, no separate database server
// to run. Mount DATA_DIR as a persistent volume in Coolify so accounts and
// logged data survive redeploys.
// ---------------------------------------------------------------------------
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const USERDATA_DIR = path.join(DATA_DIR, 'userdata');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const DAU_FILE = path.join(DATA_DIR, 'dau.json');
if (!fs.existsSync(DAU_FILE)) fs.writeFileSync(DAU_FILE, '{}');
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');
if (!fs.existsSync(PRODUCTS_FILE)) fs.writeFileSync(PRODUCTS_FILE, '[]');
const ANNOUNCEMENT_FILE = path.join(DATA_DIR, 'announcement.json');
const NUTRITION_LOG_FILE = path.join(DATA_DIR, 'nutrition_logs.json');

fs.mkdirSync(USERDATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '{}');
if (!fs.existsSync(ANNOUNCEMENT_FILE)) fs.writeFileSync(ANNOUNCEMENT_FILE, 'null');
if (!fs.existsSync(NUTRITION_LOG_FILE)) fs.writeFileSync(NUTRITION_LOG_FILE, '[]');

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
function recordActiveUser(key){
  const today = new Date().toISOString().slice(0,10);
  const dau = readJSON(DAU_FILE, {});
  if (!dau[today]) dau[today] = [];
  if (!dau[today].includes(key)) dau[today].push(key);
  // keep the file from growing forever
  const dates = Object.keys(dau).sort();
  if (dates.length > 60) delete dau[dates[0]];
  writeJSON(DAU_FILE, dau);
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not signed in.' });
  try {
    req.userKey = jwt.verify(token, JWT_SECRET).sub;
    recordActiveUser(req.userKey);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Your session expired, please log in again.' });
  }
}

// Whoever's username matches ADMIN_USERNAME (set in Coolify's environment
// variables) is the admin, decided server-side and enforced on every admin
// route, never just by hiding a button on the frontend.
function isAdminKey(key) {
  return !!ADMIN_USERNAME && key === safeKey(ADMIN_USERNAME);
}
function requireAdmin(req, res, next) {
  if (!isAdminKey(req.userKey)) return res.status(403).json({ error: 'Not authorized.' });
  next();
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
function cleanEmail(v){ const e = (v || '').toString().trim().toLowerCase(); return (e.length <= 254 && EMAIL_RE.test(e)) ? e : null; }

app.post('/api/auth/signup', (req, res) => {
  if (!JWT_SECRET) return res.status(500).json({ error: 'Server is missing JWT_SECRET. Set it in your Coolify environment variables and redeploy.' });

  const username = (req.body && req.body.username || '').toString().trim();
  const password = (req.body && req.body.password || '').toString().trim();
  const consent = !!(req.body && req.body.consent);
  if (!username || !password) return res.status(400).json({ error: 'Enter a username and password.' });
  if (!consent) return res.status(400).json({ error: "You must confirm you're 16 or older and agree to the Privacy Policy & Terms." });
  const email = cleanEmail(req.body && req.body.email);
  if (!email) return res.status(400).json({ error: 'Enter a valid email address.' });

  const users = readJSON(USERS_FILE, {});
  const key = safeKey(username);
  if (users[key]) return res.status(409).json({ error: 'That username is already taken.' });

  users[key] = { username, email, passwordHash: bcrypt.hashSync(password, 10), consentedAt: new Date().toISOString(), createdAt: new Date().toISOString() };
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

app.get('/api/me', requireAuth, (req, res) => {
  const users = readJSON(USERS_FILE, {});
  const user = users[req.userKey];
  if (!user) return res.status(404).json({ error: 'Account not found.' });
  res.json({ username: user.username, isAdmin: isAdminKey(req.userKey), email: user.email || null });
});

app.put('/api/account/email', requireAuth, (req, res) => {
  const email = cleanEmail(req.body && req.body.email);
  if (!email) return res.status(400).json({ error: 'Enter a valid email address.' });
  const users = readJSON(USERS_FILE, {});
  const user = users[req.userKey];
  if (!user) return res.status(404).json({ error: 'Account not found.' });
  user.email = email;
  writeJSON(USERS_FILE, users);
  res.json({ email });
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
// Removes a deleted account's posts (and their media), comments, and likes.
function purgeSocialFor(key) {
  try {
    const posts = readJSON(POSTS_FILE, []);
    const next = [];
    for (const p of posts) {
      if (p.userKey === key) { removeMedia(p.media && p.media.file); continue; }
      p.likes = (p.likes || []).filter(k => k !== key);
      p.comments = (p.comments || []).filter(c => c.userKey !== key);
      p.reports = (p.reports || []).filter(k => k !== key);
      next.push(p);
    }
    writeJSON(POSTS_FILE, next);
  } catch (e) { /* best effort */ }
}
app.delete('/api/account', requireAuth, (req, res) => {
  const users = readJSON(USERS_FILE, {});
  delete users[req.userKey];
  writeJSON(USERS_FILE, users);

  const file = userDataFile(req.userKey);
  if (fs.existsSync(file)) fs.unlinkSync(file);

  purgeSocialFor(req.userKey);

  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// AI Nutritionist - a small, self-contained food database and parser. No
// external API, no API key, nothing that can go down or get rate-limited.
// Trade-off: it only recognizes foods in FOOD_DB below, rather than
// understanding literally anything the way a real API or LLM would. It's
// deliberately easy to extend, just add more entries to the list.
// ---------------------------------------------------------------------------
const FOOD_DB = [
  // Proteins
  { keywords: ['egg'], label: 'Egg', cals: 78, p: 6, c: 0.6, f: 5 },
  { keywords: ['bacon', 'rasher'], label: 'Bacon (rasher)', cals: 43, p: 3, c: 0.1, f: 3.3 },
  { keywords: ['chicken strips', 'chicken nuggets', 'chicken tenders', 'fried chicken', 'southern fried chicken'], label: 'Fried chicken strips (100g)', cals: 250, p: 19, c: 14, f: 14 },
  { keywords: ['chicken breast', 'chicken'], label: 'Chicken breast (100g)', cals: 165, p: 31, c: 0, f: 3.6 },
  { keywords: ['chicken thigh'], label: 'Chicken thigh (100g)', cals: 209, p: 26, c: 0, f: 10.9 },
  { keywords: ['turkey'], label: 'Turkey breast (100g)', cals: 135, p: 30, c: 0, f: 1 },
  { keywords: ['beef mince', 'mince', 'ground beef'], label: 'Beef mince (100g)', cals: 250, p: 26, c: 0, f: 17 },
  { keywords: ['ribs', 'rib'], label: 'Ribs (100g)', cals: 290, p: 22, c: 0, f: 22 },
  { keywords: ['steak', 'beef'], label: 'Steak (100g)', cals: 271, p: 25, c: 0, f: 19 },
  { keywords: ['salmon'], label: 'Salmon fillet (100g)', cals: 208, p: 20, c: 0, f: 13 },
  { keywords: ['tuna'], label: 'Tuna (1 can, ~145g)', cals: 191, p: 42, c: 0, f: 1.4 },
  { keywords: ['cod', 'white fish'], label: 'Cod fillet (100g)', cals: 105, p: 23, c: 0, f: 0.9 },
  { keywords: ['sausage'], label: 'Sausage', cals: 250, p: 12, c: 4, f: 21 },
  { keywords: ['ham'], label: 'Ham (slice)', cals: 46, p: 6.5, c: 0.6, f: 1.9 },
  { keywords: ['tofu'], label: 'Tofu (100g)', cals: 76, p: 8, c: 1.9, f: 4.8 },
  { keywords: ['prawn', 'shrimp'], label: 'Prawns (100g)', cals: 99, p: 24, c: 0.2, f: 0.3 },
  { keywords: ['pork chop', 'pork'], label: 'Pork chop (100g)', cals: 231, p: 25, c: 0, f: 14 },
  { keywords: ['protein shake', 'whey', 'protein powder'], label: 'Protein shake', cals: 150, p: 25, c: 5, f: 2 },
  { keywords: ['protein bar'], label: 'Protein bar', cals: 210, p: 20, c: 22, f: 7 },

  // Carbs / grains
  { keywords: ['toast', 'bread', 'slice of bread', 'sandwich'], label: 'Bread (slice, ~30g)', cals: 79, p: 2.7, c: 14, f: 1 },
  { keywords: ['hot dog bun', 'hotdog bun', 'hot dog roll'], label: 'Hot dog bun', cals: 120, p: 3.5, c: 22, f: 2 },
  { keywords: ['bagel'], label: 'Bagel', cals: 245, p: 9, c: 48, f: 1.5 },
  { keywords: ['rice'], label: 'Rice, cooked (1 cup, ~158g)', cals: 205, p: 4.3, c: 45, f: 0.4 },
  { keywords: ['pasta'], label: 'Pasta, cooked (1 cup, ~140g)', cals: 221, p: 8, c: 43, f: 1.3 },
  { keywords: ['noodles'], label: 'Noodles, cooked (1 cup, ~160g)', cals: 190, p: 7, c: 40, f: 1 },
  { keywords: ['potato waffle'], label: 'Potato waffle', cals: 100, p: 1.5, c: 13, f: 5 },
  { keywords: ['potato wedges', 'wedge', 'potato'], label: 'Potato, baked (medium, ~170g)', cals: 161, p: 4.3, c: 37, f: 0.2 },
  { keywords: ['hash brown', 'tater tot'], label: 'Hash brown', cals: 150, p: 2, c: 16, f: 9 },
  { keywords: ['meatball'], label: 'Meatballs (100g)', cals: 230, p: 14, c: 8, f: 16 },
  { keywords: ['sweet potato'], label: 'Sweet potato, baked (medium, ~130g)', cals: 112, p: 2, c: 26, f: 0.1 },
  { keywords: ['chips', 'fries'], label: 'Chips/fries (portion)', cals: 365, p: 4, c: 48, f: 17 },
  { keywords: ['oats', 'porridge'], label: 'Oats, dry (1/2 cup, ~40g)', cals: 150, p: 5, c: 27, f: 2.5 },
  { keywords: ['cereal bar'], label: 'Cereal bar', cals: 100, p: 1.5, c: 18, f: 3 },
  { keywords: ['chocolate cereal', 'cereal'], label: 'Cereal (1 bowl, ~40g)', cals: 150, p: 3, c: 32, f: 1.5 },
  { keywords: ['flapjack'], label: 'Flapjack (1 bar, ~70g)', cals: 300, p: 4, c: 38, f: 15 },
  { keywords: ['quinoa'], label: 'Quinoa, cooked (1 cup, ~185g)', cals: 222, p: 8, c: 39, f: 3.6 },
  { keywords: ['tortilla', 'wrap'], label: 'Tortilla wrap', cals: 130, p: 3.5, c: 22, f: 3 },
  { keywords: ['crackers', 'rice cake'], label: 'Rice cakes (2)', cals: 70, p: 1.5, c: 15, f: 0.5 },
  { keywords: ['stuffing'], label: 'Stuffing (100g)', cals: 180, p: 4, c: 22, f: 8 },

  // Dairy
  { keywords: ['milk'], label: 'Milk (1 cup, ~245ml)', cals: 122, p: 8, c: 12, f: 5 },
  { keywords: ['cheese', 'cheddar'], label: 'Cheese (slice, ~28g)', cals: 113, p: 7, c: 0.4, f: 9 },
  { keywords: ['yogurt', 'yoghurt'], label: 'Yogurt (1 cup, ~245g)', cals: 150, p: 8.5, c: 17, f: 8 },
  { keywords: ['greek yogurt', 'greek yoghurt'], label: 'Greek yogurt (170g pot)', cals: 100, p: 17, c: 6, f: 0.7 },
  { keywords: ['cottage cheese'], label: 'Cottage cheese (100g)', cals: 98, p: 11, c: 3.4, f: 4.3 },
  { keywords: ['butter'], label: 'Butter (1 tbsp)', cals: 102, p: 0.1, c: 0, f: 11.5 },
  { keywords: ['cream cheese'], label: 'Cream cheese (1 tbsp)', cals: 51, p: 0.9, c: 0.8, f: 5.1 },
  { keywords: ['mayonnaise', 'mayo'], label: 'Mayonnaise (1 tbsp)', cals: 94, p: 0.1, c: 0.1, f: 10.3 },
  { keywords: ['ketchup'], label: 'Ketchup (1 tbsp)', cals: 17, p: 0.2, c: 4.5, f: 0 },

  // Fruits
  { keywords: ['banana'], label: 'Banana', cals: 105, p: 1.3, c: 27, f: 0.4 },
  { keywords: ['apple'], label: 'Apple', cals: 95, p: 0.5, c: 25, f: 0.3 },
  { keywords: ['orange'], label: 'Orange', cals: 62, p: 1.2, c: 15, f: 0.2 },
  { keywords: ['strawberr'], label: 'Strawberries (1 cup)', cals: 49, p: 1, c: 12, f: 0.5 },
  { keywords: ['blueberr'], label: 'Blueberries (1 cup)', cals: 84, p: 1.1, c: 21, f: 0.5 },
  { keywords: ['grape'], label: 'Grapes (1 cup)', cals: 104, p: 1.1, c: 27, f: 0.2 },
  { keywords: ['avocado'], label: 'Avocado (half)', cals: 160, p: 2, c: 8.5, f: 15 },
  { keywords: ['pineapple'], label: 'Pineapple (1 cup)', cals: 82, p: 0.9, c: 22, f: 0.2 },
  { keywords: ['mango'], label: 'Mango (1 cup)', cals: 99, p: 1.4, c: 25, f: 0.6 },
  { keywords: ['pear'], label: 'Pear', cals: 101, p: 0.6, c: 27, f: 0.2 },
  { keywords: ['raisin'], label: 'Raisins (1/4 cup)', cals: 123, p: 1.3, c: 33, f: 0.2 },

  // Vegetables
  { keywords: ['broccoli'], label: 'Broccoli (1 cup)', cals: 55, p: 3.7, c: 11, f: 0.6 },
  { keywords: ['cauliflower'], label: 'Cauliflower (1 cup)', cals: 25, p: 2, c: 5, f: 0.3 },
  { keywords: ['coleslaw'], label: 'Coleslaw (100g)', cals: 150, p: 1, c: 8, f: 13 },
  { keywords: ['spinach'], label: 'Spinach (1 cup raw)', cals: 7, p: 0.9, c: 1.1, f: 0.1 },
  { keywords: ['kale'], label: 'Kale (1 cup)', cals: 33, p: 2.9, c: 6, f: 0.5 },
  { keywords: ['carrot'], label: 'Carrot', cals: 25, p: 0.6, c: 6, f: 0.1 },
  { keywords: ['tomato'], label: 'Tomato', cals: 22, p: 1.1, c: 4.8, f: 0.2 },
  { keywords: ['cucumber'], label: 'Cucumber (1 cup)', cals: 16, p: 0.7, c: 3.8, f: 0.1 },
  { keywords: ['lettuce', 'salad leaves', 'mixed leaves'], label: 'Lettuce/salad leaves (1 cup)', cals: 8, p: 0.6, c: 1.5, f: 0.1 },
  { keywords: ['onion'], label: 'Onion', cals: 44, p: 1.2, c: 10, f: 0.1 },
  { keywords: ['pepper', 'bell pepper'], label: 'Bell pepper', cals: 24, p: 1, c: 6, f: 0.2 },
  { keywords: ['mushroom'], label: 'Mushrooms (1 cup)', cals: 21, p: 3, c: 3, f: 0.3 },
  { keywords: ['peas'], label: 'Peas (1 cup)', cals: 118, p: 8, c: 21, f: 0.6 },
  { keywords: ['sweetcorn', 'corn'], label: 'Sweetcorn (1 cup)', cals: 132, p: 5, c: 29, f: 1.8 },
  { keywords: ['green bean'], label: 'Green beans (1 cup)', cals: 31, p: 1.8, c: 7, f: 0.1 },
  { keywords: ['asparagus'], label: 'Asparagus (1 cup)', cals: 27, p: 3, c: 5, f: 0.2 },
  { keywords: ['courgette', 'zucchini'], label: 'Courgette (1 cup)', cals: 20, p: 1.5, c: 4, f: 0.4 },
  { keywords: ['vegetables', 'mixed veg', 'veg'], label: 'Mixed vegetables (1 cup, ~150g)', cals: 50, p: 2, c: 10, f: 0.3 },

  // Legumes
  { keywords: ['baked bean'], label: 'Baked beans (1 cup, ~250g)', cals: 150, p: 7, c: 26, f: 0.6 },
  { keywords: ['kidney bean', 'beans'], label: 'Kidney beans (1 cup, ~180g)', cals: 225, p: 15, c: 40, f: 0.9 },
  { keywords: ['chickpea'], label: 'Chickpeas (1 cup, ~164g)', cals: 269, p: 15, c: 45, f: 4.3 },
  { keywords: ['lentil'], label: 'Lentils, cooked (1 cup, ~198g)', cals: 230, p: 18, c: 40, f: 0.8 },

  // Nuts / fats
  { keywords: ['almond'], label: 'Almonds (handful, ~28g)', cals: 164, p: 6, c: 6, f: 14 },
  { keywords: ['peanut butter'], label: 'Peanut butter (1 tbsp)', cals: 94, p: 4, c: 3, f: 8 },
  { keywords: ['olive oil'], label: 'Olive oil (1 tbsp)', cals: 119, p: 0, c: 0, f: 13.5 },
  { keywords: ['walnut'], label: 'Walnuts (28g)', cals: 185, p: 4.3, c: 3.9, f: 18.5 },
  { keywords: ['cashew'], label: 'Cashews (28g)', cals: 157, p: 5.2, c: 8.6, f: 12.4 },
  { keywords: ['peanut'], label: 'Peanuts (28g)', cals: 161, p: 7.3, c: 4.6, f: 14 },
  { keywords: ['tahini'], label: 'Tahini (1 tbsp)', cals: 89, p: 2.6, c: 3.2, f: 8 },

  // Snacks / drinks
  { keywords: ['chocolate cookie', 'chocolate biscuit'], label: 'Chocolate biscuit', cals: 130, p: 1.5, c: 17, f: 6.5 },
  { keywords: ['chocolate'], label: 'Chocolate bar (~45g)', cals: 240, p: 3, c: 27, f: 13 },
  { keywords: ['crisps', 'chips (bag)'], label: 'Crisps (1 bag, ~30g)', cals: 160, p: 2, c: 15, f: 10 },
  { keywords: ['biscuit', 'cookie'], label: 'Biscuit', cals: 78, p: 1, c: 10, f: 3.7 },
  { keywords: ['honey'], label: 'Honey (1 tbsp)', cals: 64, p: 0.1, c: 17, f: 0 },
  { keywords: ['jam'], label: 'Jam (1 tbsp)', cals: 56, p: 0.1, c: 14, f: 0 },
  { keywords: ['fizzy drink', 'soft drink', 'soda', 'cola', 'lemonade'], label: 'Fizzy drink (330ml can)', cals: 140, p: 0, c: 35, f: 0 },

  // Combo dishes - these already represent a whole assembled meal, so when
  // one of these matches, it's used on its own rather than summed with
  // other keywords found in the same segment (e.g. "chicken burger" should
  // count as one burger, not a burger plus a separate chicken breast).
  { keywords: ['pizza'], label: 'Pizza (1 slice)', cals: 285, p: 12, c: 36, f: 10, combo: true },
  { keywords: ['burger'], label: 'Burger', cals: 500, p: 25, c: 40, f: 27, combo: true },
  { keywords: ['curry'], label: 'Curry (1 serving)', cals: 450, p: 25, c: 30, f: 25, combo: true },
  { keywords: ['soup'], label: 'Soup (1 bowl)', cals: 170, p: 7, c: 20, f: 6, combo: true },
  { keywords: ['smoothie'], label: 'Smoothie (1 cup)', cals: 190, p: 4, c: 40, f: 2, combo: true }
];

const NUMBER_WORDS = { a:1, an:1, one:1, two:2, three:3, four:4, five:5, six:6, seven:7, eight:8, nine:9, ten:10, couple:2, few:3 };

// Pulls an explicit weight/volume out of what someone typed, e.g. "80g",
// "1000g", "350ml", "1kg". Treats ml roughly as grams, fine for this level
// of estimate.
function extractGrams(segment){
  const m = segment.match(/(\d+(\.\d+)?)\s*(kg|g|grams?|ml|millilitres?|l|litres?)\b/i);
  if (!m) return null;
  let val = parseFloat(m[1]);
  const unit = m[3].toLowerCase();
  if (unit === 'kg') val *= 1000;
  if (unit === 'l' || unit.startsWith('litre')) val *= 1000;
  return val;
}
// Pulls the gram/ml figure already baked into a FOOD_DB label, e.g.
// "Chicken breast (100g)" -> 100, "Greek yogurt (170g pot)" -> 170.
function baselineGrams(label){
  const m = label.match(/(\d+(\.\d+)?)\s*(g|ml)\b/i);
  return m ? parseFloat(m[1]) : null;
}

function matchFoodSegment(segment){
  let qty = 1;
  const qtyMatch = segment.match(/^(\d+(\.\d+)?|a|an|one|two|three|four|five|six|seven|eight|nine|ten|couple|few)\s+/);
  let rest = segment;
  if (qtyMatch) {
    const token = qtyMatch[1];
    qty = isNaN(Number(token)) ? (NUMBER_WORDS[token] || 1) : Number(token);
    rest = segment.slice(qtyMatch[0].length);
  }
  rest = rest.replace(/^(slices?|cups?|bowls?|pieces?|rashers?|cans?|scoops?|handfuls?|servings?|portions?)\s+of\s+/, '').trim();

  // Find every keyword match in the segment, longest keyword first, and
  // claim its character span so a shorter, more generic keyword (e.g. plain
  // "chicken") can't also match text already covered by a more specific one
  // (e.g. "chicken strips"). This is what lets a phrase like "egg beans"
  // recognize BOTH foods instead of only the one with the longer keyword.
  const allMatches = [];
  for (const food of FOOD_DB) {
    for (const kw of food.keywords) {
      const idx = rest.indexOf(kw);
      if (idx !== -1) allMatches.push({ food, start: idx, end: idx + kw.length, kwLen: kw.length });
    }
  }
  allMatches.sort((a, b) => b.kwLen - a.kwLen);

  const claimed = []; // [start, end] ranges already used
  const overlaps = (a, b) => a.start < b.end && b.start < a.end;
  const found = [];
  for (const m of allMatches) {
    if (claimed.some(c => overlaps(c, m))) continue;
    claimed.push(m);
    if (!found.some(f => f.food === m.food)) found.push(m.food);
  }
  if (!found.length) return null;

  // A combo dish (burger, pizza, curry...) already represents a whole
  // assembled meal on its own, use just that rather than summing it with
  // whatever else got matched in the same segment (avoids e.g. "chicken
  // burger" becoming a burger AND a separate raw chicken breast).
  const combo = found.find(f => f.combo);
  const items = combo ? [combo] : found;

  const statedGrams = extractGrams(segment);
  const labelParts = [];
  let cals = 0, p = 0, c = 0, f = 0;

  for (const food of items) {
    let multiplier = qty;
    let prefix = (qty > 1 && items.length === 1) ? qty + 'x ' : '';
    if (statedGrams) {
      const base = baselineGrams(food.label);
      if (base) {
        multiplier = statedGrams / base;
        prefix = items.length === 1 ? Math.round(statedGrams) + 'g ' : '';
      }
    }
    cals += food.cals * multiplier;
    p += food.p * multiplier;
    c += food.c * multiplier;
    f += food.f * multiplier;
    labelParts.push(prefix + food.label);
  }

  return { label: labelParts.join(' + '), cals, p, c, f };
}

function estimateFoodLocally(description){
  const text = description.toLowerCase();
  const segments = text.split(/,| and | with | plus |\+/).map(s => s.trim()).filter(Boolean);
  const matched = [];
  let anyUnmatched = false;
  for (const seg of segments) {
    const m = matchFoodSegment(seg);
    if (m) matched.push(m); else anyUnmatched = true;
  }
  if (!matched.length) return null;

  const totals = matched.reduce((acc, m) => ({
    cals: acc.cals + m.cals, p: acc.p + m.p, c: acc.c + m.c, f: acc.f + m.f
  }), { cals: 0, p: 0, c: 0, f: 0 });

  let name = matched.map(m => m.label).join(', ');
  if (anyUnmatched) name += ' (partial estimate)';

  return {
    name,
    cals: Math.round(totals.cals),
    p: Math.round(totals.p),
    c: Math.round(totals.c),
    f: Math.round(totals.f)
  };
}

function logNutritionAttempt(entry){
  const log = readJSON(NUTRITION_LOG_FILE, []);
  log.unshift({ ...entry, at: new Date().toISOString() });
  writeJSON(NUTRITION_LOG_FILE, log.slice(0, 300)); // keep it bounded
}

app.post('/api/estimate-food', (req, res) => {
  const description = (req.body && req.body.description || '').toString().trim();
  if (!description) return res.status(400).json({ error: 'Missing food description.' });

  const result = estimateFoodLocally(description);
  if (!result) {
    logNutritionAttempt({ description, success: false });
    return res.status(422).json({ error: "Couldn't recognize that food. Try naming it more simply, e.g. \"two eggs and toast\" or \"chicken and rice\"." });
  }
  logNutritionAttempt({ description, success: true, matched: result.name });
  res.json(result);
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
      if (!best || est > best.est) best = { est, weight: pr.weight, reps: pr.reps, date: pr.date };
    }
    rows.push({
      key,
      username: user.username,
      best1RM: Math.round(best.est * 10) / 10,
      sourceWeight: best.weight,
      sourceReps: best.reps,
      sourceDate: best.date
    });
  }

  rows.sort((a, b) => b.best1RM - a.best1RM);
  res.json(rows);
});

// Admin-only: remove one specific PR (e.g. an unrealistic entry) from
// whichever account logged it, identified by exercise+weight+reps+date
// rather than an index, since that's what the leaderboard already shows.
app.delete('/api/admin/pr', requireAuth, requireAdmin, (req, res) => {
  const { key, exercise, weight, reps, date } = req.body || {};
  if (!key || !exercise) return res.status(400).json({ error: 'Missing key or exercise.' });

  const file = userDataFile(key);
  const d = readJSON(file, {});
  if (!d.stats || !Array.isArray(d.stats.prs)) return res.status(404).json({ error: 'No PRs found for that account.' });

  const before = d.stats.prs.length;
  d.stats.prs = d.stats.prs.filter(pr =>
    !(pr.exercise === exercise && Number(pr.weight) === Number(weight) && Number(pr.reps) === Number(reps) && pr.date === date)
  );
  if (d.stats.prs.length === before) return res.status(404).json({ error: 'Matching PR not found.' });

  writeJSON(file, d);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Admin - only reachable by whichever account matches ADMIN_USERNAME. Gives
// a read-only overview of usage plus the ability to delete any account or
// reset its password (e.g. if someone's locked out and asks for help).
// ---------------------------------------------------------------------------
app.get('/api/admin/overview', requireAuth, requireAdmin, (req, res) => {
  const users = readJSON(USERS_FILE, {});
  const rows = [];
  let totalPRs = 0, totalBodyweight = 0, totalFoodToday = 0, usersWithDietPlan = 0;

  for (const key of Object.keys(users)) {
    const u = users[key];
    const d = readJSON(userDataFile(key), {});
    const prCount = ((d.stats && d.stats.prs) || []).length;
    const bwCount = ((d.stats && d.stats.bodyweight) || []).length;
    const hasDietPlan = !!(d.diet && d.diet.plan);
    const foodToday = ((d.diet && d.diet.dailyLog && d.diet.dailyLog.entries) || []).length;

    totalPRs += prCount;
    totalBodyweight += bwCount;
    totalFoodToday += foodToday;
    if (hasDietPlan) usersWithDietPlan++;

    rows.push({
      key,
      username: u.username,
      email: u.email || null,
      createdAt: u.createdAt || u.consentedAt || null,
      prCount,
      bwCount,
      hasDietPlan,
      sport: (d.sports && d.sports.selected) || null,
      isAdmin: isAdminKey(key)
    });
  }

  rows.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));

  res.json({
    totalUsers: rows.length,
    totalPRs,
    totalBodyweight,
    totalFoodToday,
    usersWithDietPlan,
    uptimeSeconds: Math.floor((Date.now() - SERVER_STARTED_AT) / 1000),
    users: rows
  });
});

// Same permanent deletion as the self-service one, just usable on any account.
app.delete('/api/admin/users/:key', requireAuth, requireAdmin, (req, res) => {
  const key = req.params.key;
  const users = readJSON(USERS_FILE, {});
  if (!users[key]) return res.status(404).json({ error: 'Account not found.' });

  delete users[key];
  writeJSON(USERS_FILE, users);

  const file = userDataFile(key);
  if (fs.existsSync(file)) fs.unlinkSync(file);
  purgeSocialFor(key);

  res.json({ ok: true });
});

app.put('/api/admin/users/:key/password', requireAuth, requireAdmin, (req, res) => {
  const key = req.params.key;
  const users = readJSON(USERS_FILE, {});
  if (!users[key]) return res.status(404).json({ error: 'Account not found.' });

  const newPassword = (req.body && req.body.newPassword || '').toString().trim();
  if (newPassword.length < 4) return res.status(400).json({ error: 'New password must be at least 4 characters.' });

  users[key].passwordHash = bcrypt.hashSync(newPassword, 10);
  writeJSON(USERS_FILE, users);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Announcements - one active announcement at a time. Each has its own
// createdAt, and a user's dismissal is tied to that exact createdAt, so
// posting a new announcement automatically shows it to everyone again,
// including people who dismissed a previous one.
// ---------------------------------------------------------------------------
app.get('/api/announcement', requireAuth, (req, res) => {
  const ann = readJSON(ANNOUNCEMENT_FILE, null);
  if (!ann) return res.json(null);
  if (new Date(ann.expiresAt).getTime() < Date.now()) return res.json(null);

  const users = readJSON(USERS_FILE, {});
  const user = users[req.userKey];
  const dismissed = !!(user && user.dismissedAnnouncementAt === ann.createdAt);
  if (dismissed) return res.json(null);

  res.json({ message: ann.message, createdAt: ann.createdAt });
});

app.post('/api/announcement/dismiss', requireAuth, (req, res) => {
  const ann = readJSON(ANNOUNCEMENT_FILE, null);
  const users = readJSON(USERS_FILE, {});
  if (ann && users[req.userKey]) {
    users[req.userKey].dismissedAnnouncementAt = ann.createdAt;
    writeJSON(USERS_FILE, users);
  }
  res.json({ ok: true });
});

app.post('/api/admin/announcement', requireAuth, requireAdmin, (req, res) => {
  const message = (req.body && req.body.message || '').toString().trim();
  const durationHours = Number(req.body && req.body.durationHours) || 24;
  if (!message) return res.status(400).json({ error: 'Announcement text is required.' });

  const now = Date.now();
  writeJSON(ANNOUNCEMENT_FILE, {
    message,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + durationHours * 3600 * 1000).toISOString()
  });
  res.json({ ok: true });
});

app.delete('/api/admin/announcement', requireAuth, requireAdmin, (req, res) => {
  writeJSON(ANNOUNCEMENT_FILE, null);
  res.json({ ok: true });
});

app.get('/api/admin/dau', requireAuth, requireAdmin, (req, res) => {
  const dau = readJSON(DAU_FILE, {});
  const days = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0,10);
    days.push({ date: key, count: (dau[key] || []).length });
  }
  res.json(days);
});

// ---------------------------------------------------------------------------
// Shop - admin-managed product tiles (brand promotions). Anyone signed in
// can view the list; only the admin can add, edit, or remove products.
// ---------------------------------------------------------------------------
app.get('/api/shop/products', requireAuth, (req, res) => {
  res.json(readJSON(PRODUCTS_FILE, []));
});

app.post('/api/admin/shop/products', requireAuth, requireAdmin, (req, res) => {
  const title = (req.body && req.body.title || '').toString().trim();
  const link = (req.body && req.body.link || '').toString().trim();
  const imageUrl = (req.body && req.body.imageUrl || '').toString().trim();
  const description = (req.body && req.body.description || '').toString().trim();
  if (!title || !link) return res.status(400).json({ error: 'Title and link are required.' });

  const products = readJSON(PRODUCTS_FILE, []);
  const product = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
    title, link, imageUrl, description,
    createdAt: new Date().toISOString()
  };
  products.push(product);
  writeJSON(PRODUCTS_FILE, products);
  res.json(product);
});

app.put('/api/admin/shop/products/:id', requireAuth, requireAdmin, (req, res) => {
  const products = readJSON(PRODUCTS_FILE, []);
  const idx = products.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Product not found.' });

  const title = (req.body && req.body.title || '').toString().trim();
  const link = (req.body && req.body.link || '').toString().trim();
  if (!title || !link) return res.status(400).json({ error: 'Title and link are required.' });

  products[idx] = {
    ...products[idx],
    title, link,
    imageUrl: (req.body.imageUrl || '').toString().trim(),
    description: (req.body.description || '').toString().trim()
  };
  writeJSON(PRODUCTS_FILE, products);
  res.json(products[idx]);
});

app.delete('/api/admin/shop/products/:id', requireAuth, requireAdmin, (req, res) => {
  const products = readJSON(PRODUCTS_FILE, []);
  const next = products.filter(p => p.id !== req.params.id);
  if (next.length === products.length) return res.status(404).json({ error: 'Product not found.' });
  writeJSON(PRODUCTS_FILE, next);
  res.json({ ok: true });
});

app.get('/api/admin/nutrition-logs', requireAuth, requireAdmin, (req, res) => {
  res.json(readJSON(NUTRITION_LOG_FILE, []));
});


// ---------------------------------------------------------------------------
// Social feed: global posts (photo or video + caption), likes, comments,
// admin pinning, and admin-run ads. No extra packages: uploads arrive as the
// raw request body, are checked by their real file signature (never trusting
// the filename or content-type header), and stored under DATA_DIR/uploads.
// Media URLs are unguessable random ids but not login-gated, because <img>
// and <video> tags can't send an Authorization header.
// ---------------------------------------------------------------------------
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });
const POSTS_FILE = path.join(DATA_DIR, 'social_posts.json');
const ADS_FILE = path.join(DATA_DIR, 'social_ads.json');
if (!fs.existsSync(POSTS_FILE)) fs.writeFileSync(POSTS_FILE, '[]');
if (!fs.existsSync(ADS_FILE)) fs.writeFileSync(ADS_FILE, '[]');
const MAX_UPLOAD_BYTES = 40 * 1024 * 1024;
const MAX_STORAGE_BYTES = (parseFloat(process.env.SOCIAL_MAX_GB) || 5) * 1024 * 1024 * 1024;
const MAX_POSTS_PER_DAY = 10;
const POST_LIFETIME_MS = 24 * 3600 * 1000;   // posts disappear after 24 hours, unless the admin pins them

// Deletes expired posts and their media files. Pinned posts stay up until unpinned,
// and the 24 hours restarts from the moment they are unpinned.
function purgeExpiredPosts() {
  try {
    const posts = readJSON(POSTS_FILE, []);
    const now = Date.now();
    const keep = [];
    for (const p of posts) {
      const base = p.pinned ? null : Math.max(new Date(p.createdAt).getTime(), p.unpinnedAt || 0);
      if (base !== null && now - base >= POST_LIFETIME_MS) { removeMedia(p.media && p.media.file); continue; }
      keep.push(p);
    }
    if (keep.length !== posts.length) writeJSON(POSTS_FILE, keep);
  } catch (e) { /* best effort */ }
}
setInterval(purgeExpiredPosts, 10 * 60 * 1000);
const crypto = require('crypto');

app.use('/uploads', express.static(UPLOADS_DIR, {
  index: false, dotfiles: 'ignore', maxAge: '7d',
  setHeaders: (res) => { res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox"); }
}));

function sniffMedia(buf) {
  if (buf.length < 16) return null;
  if (buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return { ext: 'jpg', kind: 'image' };
  if (buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))) return { ext: 'png', kind: 'image' };
  if (buf.slice(0, 4).toString('latin1') === 'GIF8') return { ext: 'gif', kind: 'image' };
  if (buf.slice(0, 4).toString('latin1') === 'RIFF' && buf.slice(8, 12).toString('latin1') === 'WEBP') return { ext: 'webp', kind: 'image' };
  if (buf.slice(4, 8).toString('latin1') === 'ftyp') return { ext: 'mp4', kind: 'video' };   // mp4 / mov / m4v
  if (buf.slice(0, 4).equals(Buffer.from([0x1A, 0x45, 0xDF, 0xA3]))) return { ext: 'webm', kind: 'video' };
  return null;
}
function uploadsSize() {
  let total = 0;
  try { for (const f of fs.readdirSync(UPLOADS_DIR)) total += fs.statSync(path.join(UPLOADS_DIR, f)).size; } catch (e) {}
  return total;
}
function removeMedia(file) {
  if (!file || !/^[a-f0-9]{24}\.[a-z0-9]{3,4}$/.test(file)) return;
  try { fs.unlinkSync(path.join(UPLOADS_DIR, file)); } catch (e) {}
}
// Validates + saves an upload body. Returns { file, kind } or sends an error and returns null.
function saveUpload(req, res) {
  const buf = req.body;
  if (!Buffer.isBuffer(buf) || !buf.length) { res.status(400).json({ error: 'Choose a photo or video first.' }); return null; }
  const info = sniffMedia(buf);
  if (!info) { res.status(400).json({ error: 'That file type isn\'t supported. Use a JPG, PNG, GIF, WebP, MP4, MOV or WebM.' }); return null; }
  if (uploadsSize() + buf.length > MAX_STORAGE_BYTES) { res.status(507).json({ error: 'The social feed is full right now. Please try again later.' }); return null; }
  const file = crypto.randomBytes(12).toString('hex') + '.' + info.ext;
  fs.writeFileSync(path.join(UPLOADS_DIR, file), buf);
  return { file, kind: info.kind };
}
const rawUpload = express.raw({ type: () => true, limit: MAX_UPLOAD_BYTES });
function hdrText(req, name, max) {
  try { return decodeURIComponent((req.get(name) || '').toString()).trim().slice(0, max); } catch (e) { return ''; }
}
function cleanText(v, max) { return (v || '').toString().replace(/\s+\n/g, '\n').trim().slice(0, max); }
function safeLink(v) {
  const l = (v || '').toString().trim();
  return /^https?:\/\/[^\s]+$/i.test(l) && l.length <= 600 ? l : null;
}

function viewPost(p, me) {
  return {
    id: p.id, username: p.username, isAdminAuthor: !!p.isAdminAuthor, caption: p.caption,
    media: p.media, createdAt: p.createdAt, pinned: !!p.pinned,
    expiresAt: p.pinned ? null : new Date(Math.max(new Date(p.createdAt).getTime(), p.unpinnedAt || 0) + POST_LIFETIME_MS).toISOString(),
    likeCount: p.likes.length, liked: p.likes.includes(me),
    mine: p.userKey === me,
    comments: p.comments.map(c => ({ id: c.id, username: c.username, text: c.text, createdAt: c.createdAt, mine: c.userKey === me }))
  };
}

app.get('/api/social/feed', requireAuth, (req, res) => {
  purgeExpiredPosts();
  const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
  const limit = 15;
  const posts = readJSON(POSTS_FILE, []);
  // pinned first (newest pin order = most recently pinned first), then newest posts
  const sorted = posts.slice().sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0) || (b.pinned ? (b.pinnedAt || 0) - (a.pinnedAt || 0) : new Date(b.createdAt) - new Date(a.createdAt)));
  const page = sorted.slice(offset, offset + limit).map(p => viewPost(p, req.userKey));
  const ads = readJSON(ADS_FILE, []).filter(a => a.active).map(a => ({ id: a.id, caption: a.caption, media: a.media, link: a.link }));
  res.json({ posts: page, hasMore: offset + limit < sorted.length, ads });
});

app.post('/api/social/posts', requireAuth, rawUpload, (req, res) => {
  const posts = readJSON(POSTS_FILE, []);
  const dayAgo = Date.now() - 24 * 3600 * 1000;
  if (!isAdminKey(req.userKey) && posts.filter(p => p.userKey === req.userKey && new Date(p.createdAt).getTime() > dayAgo).length >= MAX_POSTS_PER_DAY) {
    return res.status(429).json({ error: 'You\'ve hit the limit of ' + MAX_POSTS_PER_DAY + ' posts per day. Try again tomorrow.' });
  }
  const users = readJSON(USERS_FILE, {});
  const user = users[req.userKey];
  if (!user) return res.status(404).json({ error: 'Account not found.' });
  const caption = hdrText(req, 'x-caption', 500);
  const saved = saveUpload(req, res);
  if (!saved) return;
  const post = {
    id: crypto.randomBytes(8).toString('hex'), userKey: req.userKey, username: user.username,
    isAdminAuthor: isAdminKey(req.userKey), caption,
    media: { file: saved.file, kind: saved.kind }, createdAt: new Date().toISOString(),
    likes: [], comments: [], reports: [], pinned: false
  };
  posts.push(post);
  writeJSON(POSTS_FILE, posts);
  res.json(viewPost(post, req.userKey));
});

app.post('/api/social/posts/:id/like', requireAuth, (req, res) => {
  const posts = readJSON(POSTS_FILE, []);
  const p = posts.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Post not found.' });
  const i = p.likes.indexOf(req.userKey);
  if (i >= 0) p.likes.splice(i, 1); else p.likes.push(req.userKey);
  writeJSON(POSTS_FILE, posts);
  res.json({ liked: i < 0, likeCount: p.likes.length });
});

app.post('/api/social/posts/:id/comments', requireAuth, (req, res) => {
  const text = cleanText(req.body && req.body.text, 300);
  if (!text) return res.status(400).json({ error: 'Write a comment first.' });
  const posts = readJSON(POSTS_FILE, []);
  const p = posts.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Post not found.' });
  if (p.comments.length >= 300) return res.status(400).json({ error: 'This post has hit its comment limit.' });
  const user = readJSON(USERS_FILE, {})[req.userKey];
  const c = { id: crypto.randomBytes(6).toString('hex'), userKey: req.userKey, username: user ? user.username : 'unknown', text, createdAt: new Date().toISOString() };
  p.comments.push(c);
  writeJSON(POSTS_FILE, posts);
  res.json({ id: c.id, username: c.username, text: c.text, createdAt: c.createdAt, mine: true });
});

app.delete('/api/social/posts/:id/comments/:cid', requireAuth, (req, res) => {
  const posts = readJSON(POSTS_FILE, []);
  const p = posts.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Post not found.' });
  const c = p.comments.find(x => x.id === req.params.cid);
  if (!c) return res.status(404).json({ error: 'Comment not found.' });
  if (c.userKey !== req.userKey && !isAdminKey(req.userKey)) return res.status(403).json({ error: 'Not allowed.' });
  p.comments = p.comments.filter(x => x.id !== c.id);
  writeJSON(POSTS_FILE, posts);
  res.json({ ok: true });
});

app.post('/api/social/posts/:id/report', requireAuth, (req, res) => {
  const posts = readJSON(POSTS_FILE, []);
  const p = posts.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Post not found.' });
  if (!p.reports) p.reports = [];
  if (!p.reports.includes(req.userKey)) p.reports.push(req.userKey);
  writeJSON(POSTS_FILE, posts);
  res.json({ ok: true });
});

app.delete('/api/social/posts/:id', requireAuth, (req, res) => {
  const posts = readJSON(POSTS_FILE, []);
  const p = posts.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Post not found.' });
  if (p.userKey !== req.userKey && !isAdminKey(req.userKey)) return res.status(403).json({ error: 'Not allowed.' });
  removeMedia(p.media && p.media.file);
  writeJSON(POSTS_FILE, posts.filter(x => x.id !== p.id));
  res.json({ ok: true });
});

app.put('/api/admin/social/posts/:id/pin', requireAuth, requireAdmin, (req, res) => {
  const posts = readJSON(POSTS_FILE, []);
  const p = posts.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Post not found.' });
  p.pinned = !!(req.body && req.body.pinned);
  p.pinnedAt = p.pinned ? Date.now() : 0;
  if (!p.pinned) p.unpinnedAt = Date.now();
  writeJSON(POSTS_FILE, posts);
  res.json({ pinned: p.pinned });
});

app.get('/api/admin/social/reports', requireAuth, requireAdmin, (req, res) => {
  purgeExpiredPosts();
  const posts = readJSON(POSTS_FILE, []);
  res.json({
    storageMB: Math.round(uploadsSize() / 1048576), storageCapMB: Math.round(MAX_STORAGE_BYTES / 1048576), totalPosts: posts.length,
    reported: posts.filter(p => (p.reports || []).length).sort((a, b) => b.reports.length - a.reports.length)
      .map(p => ({ id: p.id, username: p.username, caption: p.caption, media: p.media, reports: p.reports.length }))
  });
});

// ---- Ads (admin creates; everyone sees them in the feed, clicks go to the admin's link) ----
app.get('/api/admin/social/ads', requireAuth, requireAdmin, (req, res) => {
  res.json(readJSON(ADS_FILE, []));
});
app.post('/api/admin/social/ads', requireAuth, requireAdmin, rawUpload, (req, res) => {
  const link = safeLink(hdrText(req, 'x-link', 600));
  if (!link) return res.status(400).json({ error: 'Enter a valid link starting with http:// or https://' });
  const caption = hdrText(req, 'x-caption', 300);
  const saved = saveUpload(req, res);
  if (!saved) return;
  const ads = readJSON(ADS_FILE, []);
  const ad = { id: crypto.randomBytes(6).toString('hex'), caption, link, media: { file: saved.file, kind: saved.kind }, active: true, clicks: 0, createdAt: new Date().toISOString() };
  ads.push(ad);
  writeJSON(ADS_FILE, ads);
  res.json(ad);
});
app.put('/api/admin/social/ads/:id', requireAuth, requireAdmin, (req, res) => {
  const ads = readJSON(ADS_FILE, []);
  const ad = ads.find(a => a.id === req.params.id);
  if (!ad) return res.status(404).json({ error: 'Ad not found.' });
  if (req.body && typeof req.body.active === 'boolean') ad.active = req.body.active;
  writeJSON(ADS_FILE, ads);
  res.json(ad);
});
app.delete('/api/admin/social/ads/:id', requireAuth, requireAdmin, (req, res) => {
  const ads = readJSON(ADS_FILE, []);
  const ad = ads.find(a => a.id === req.params.id);
  if (ad) removeMedia(ad.media && ad.media.file);
  writeJSON(ADS_FILE, ads.filter(a => a.id !== req.params.id));
  res.json({ ok: true });
});
app.post('/api/social/ads/:id/click', requireAuth, (req, res) => {
  const ads = readJSON(ADS_FILE, []);
  const ad = ads.find(a => a.id === req.params.id);
  if (ad) { ad.clicks = (ad.clicks || 0) + 1; writeJSON(ADS_FILE, ads); }
  res.json({ ok: true });
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
