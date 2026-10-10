// Food database + parser behind the AI Nutritionist (no external services).
const DISHES = require('./dishes');

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
  { keywords: ['baked bean', 'beans'], label: 'Baked beans (1 cup, ~250g)', cals: 150, p: 7, c: 26, f: 0.6 },
  { keywords: ['kidney bean', 'black bean'], label: 'Kidney beans (1 cup, ~180g)', cals: 225, p: 15, c: 40, f: 0.9 },
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
DISHES.forEach(d => FOOD_DB.push(d));

const NUMBER_WORDS = { a:1, an:1, one:1, two:2, three:3, four:4, five:5, six:6, seven:7, eight:8, nine:9, ten:10, couple:2, few:3 };

// Pulls an explicit weight/volume out of what someone typed, e.g. "80g",
// "1000g", "350ml", "1kg". Treats ml roughly as grams.
function extractGrams(segment){
  const m = segment.match(/(\d+(\.\d+)?)\s*(kg|g|grams?|ml|millilitres?|l|litres?)\b/i);
  if (!m) return null;
  let val = parseFloat(m[1]);
  const unit = m[3].toLowerCase();
  if (unit === 'kg') val *= 1000;
  if (unit === 'l' || unit.startsWith('litre')) val *= 1000;
  return val;
}
// "Chicken breast (100g)" -> 100, "Greek yogurt (170g pot)" -> 170.
function baselineGrams(label){
  const m = label.match(/(\d+(\.\d+)?)\s*(g|ml)\b/i);
  return m ? parseFloat(m[1]) : null;
}

// ---- keyword matching: whole words only (so "tea" can't match inside "steak"
// or "ale" inside "kale"), allowing a plural ending on the keyword.
const esc = k => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const KW_RE = new Map();
function kwRegex(kw){
  let r = KW_RE.get(kw);
  if (!r) { r = new RegExp('(^|[^a-z])(' + esc(kw) + ')(?:s|es)?(?![a-z])', 'i'); KW_RE.set(kw, r); }
  return r;
}
function findKeyword(text, kw){
  const m = kwRegex(kw).exec(text);
  if (!m) return null;
  const start = m.index + m[1].length;
  return { start, end: start + m[2].length };
}

// ---- typo tolerance: if a segment matches nothing, fix words that are one or
// two letters off a known single-word keyword ("speghetti" -> "spaghetti").
const VOCAB = new Set();
FOOD_DB.forEach(f => f.keywords.forEach(k => k.split(' ').forEach(w => { if (w.length >= 5 && /^[a-z]+$/.test(w)) VOCAB.add(w); })));
function editDistance(a, b, max){
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let cur = [i], best = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      best = Math.min(best, cur[j]);
    }
    if (best > max) return max + 1;
    for (let j = 0; j <= b.length; j++) prev[j] = cur[j];
  }
  return prev[b.length];
}
function fixTypos(segment){
  return segment.replace(/[a-z]{5,}/g, w => {
    if (VOCAB.has(w) || VOCAB.has(w.replace(/(es|s)$/, ''))) return w;
    const max = w.length >= 8 ? 2 : 1;
    let best = null, bestD = max + 1;
    for (const v of VOCAB) {
      const d = editDistance(w, v, max);
      if (d < bestD) { bestD = d; best = v; }
    }
    return best && bestD <= max ? best : w;
  });
}

// Dish names containing " and " / " with " are protected so they aren't split
// into two foods, e.g. "fish and chips", "spaghetti with meatballs".
const PROTECTED = (DISHES.PROTECTED || []).slice().sort((a, b) => b.length - a.length);
function protectPhrases(text){
  let out = text;
  for (const p of PROTECTED) {
    const re = new RegExp('(^|[^a-z])(' + esc(p) + ')(?![a-z])', 'gi');
    out = out.replace(re, (m, pre, phrase) => pre + phrase.replace(/ /g, '_'));
  }
  return out;
}

function matchOnce(rest){
  const allMatches = [];
  for (const food of FOOD_DB) {
    for (const kw of food.keywords) {
      const hit = findKeyword(rest, kw);
      if (hit) allMatches.push({ food, start: hit.start, end: hit.end, kwLen: kw.length });
    }
  }
  // Longest keyword first; a claimed span can't be reused by a shorter keyword.
  allMatches.sort((a, b) => b.kwLen - a.kwLen);
  const claimed = [];
  const overlaps = (a, b) => a.start < b.end && b.start < a.end;
  const found = [];
  for (const m of allMatches) {
    if (claimed.some(c => overlaps(c, m))) continue;
    claimed.push(m);
    if (!found.some(f => f.food === m.food)) found.push(m.food);
  }
  return found;
}

function matchFoodSegment(rawSegment){
  const segment = rawSegment.replace(/_/g, ' ').replace(/\s+/g, ' ').trim();
  let qty = 1;
  const qtyMatch = segment.match(/^(\d+(\.\d+)?|a|an|one|two|three|four|five|six|seven|eight|nine|ten|couple|few)\s+/);
  let rest = segment;
  if (qtyMatch) {
    const token = qtyMatch[1];
    qty = isNaN(Number(token)) ? (NUMBER_WORDS[token] || 1) : Number(token);
    rest = segment.slice(qtyMatch[0].length);
  }
  rest = rest.replace(/^(slices?|cups?|bowls?|plates?|pieces?|rashers?|cans?|scoops?|handfuls?|servings?|portions?|pints?)\s+of\s+/, '').trim();

  let found = matchOnce(rest);
  if (!found.length) { found = matchOnce(fixTypos(rest)); }
  if (!found.length) return null;

  // A combo dish already represents a whole plate: use just that rather than
  // also adding its ingredients ("chicken burger" is not burger + chicken).
  const combo = found.find(f => f.combo);
  const items = combo ? [combo] : found;

  const statedGrams = extractGrams(segment);
  const labelParts = [];
  let cals = 0, p = 0, c = 0, f = 0;

  for (const food of items) {
    let multiplier = qty;
    let prefix = (qty !== 1 && items.length === 1) ? qty + 'x ' : '';
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

// Returns { name, cals, p, c, f, unmatched: [segments we couldn't place] } or
// null when nothing matched (unmatched is then the whole input).
function estimateFoodLocally(description){
  const text = protectPhrases(description.toLowerCase());
  const segments = text.split(/,|\band\b| with |\bplus\b|\+|&|\n/).map(s => s.trim()).filter(Boolean);
  const matched = [];
  const unmatched = [];
  for (const seg of segments) {
    const m = matchFoodSegment(seg);
    if (m) matched.push(m); else unmatched.push(seg.replace(/_/g, ' '));
  }
  if (!matched.length) return { name: null, unmatched };

  const totals = matched.reduce((acc, m) => ({
    cals: acc.cals + m.cals, p: acc.p + m.p, c: acc.c + m.c, f: acc.f + m.f
  }), { cals: 0, p: 0, c: 0, f: 0 });

  return {
    name: matched.map(m => m.label).join(', '),
    cals: Math.round(totals.cals), p: Math.round(totals.p), c: Math.round(totals.c), f: Math.round(totals.f),
    unmatched
  };
}

module.exports = { estimateFoodLocally, FOOD_DB, extractGrams };
