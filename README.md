# Setpoint - deploying on Coolify

This folder is the dashboard plus a small Express backend. The backend does
two things:

1. Holds shared accounts in a tiny file-based database, so anyone can log
   into the same account from any device or browser, not just the one they
   signed up on.
2. Proxies the AI Nutritionist to a **free** nutrition API (CalorieNinjas)
   instead of a paid LLM call, so logging food doesn't cost you anything
   per request.

The dashboard still works exactly the same when opened inside Claude - it
detects that automatically and uses Claude's own account storage and API
access there instead of any of this.

## What's in here

- `public/index.html` - the dashboard (same file as the Claude artifact)
- `server.js` - serves the dashboard, handles accounts/login, and proxies
  `POST /api/estimate-food` to CalorieNinjas
- `package.json`, `Dockerfile` - so Coolify can build and run it
- `.env.example` - shows the environment variables it needs
- `data/` (created automatically) - `users.json` plus one JSON file per user
  under `data/userdata/`, this is the whole "database"

## Before you deploy

1. **Get a free CalorieNinjas API key** at https://calorieninjas.com/api.
   No credit card needed. This powers the AI Nutritionist's food lookups.
2. **Generate a JWT secret**, a random string used to sign login sessions:
   ```
   openssl rand -hex 32
   ```
   (Any long random string works if you don't have `openssl` handy.)

## Deploy on Coolify

1. Push this folder to a Git repo Coolify can reach.
2. In Coolify, create a new **Application** from that repo, build pack
   **Dockerfile**, exposed port **3000**.
3. Under **Environment Variables**, add:
   - `JWT_SECRET` = the random string from above (mark as secret)
   - `CALORIENINJAS_API_KEY` = your key from calorieninjas.com
4. **Add a persistent volume** mounted at `/app/data`. This is what keeps
   accounts and logged data across redeploys, without it, every deploy
   wipes all accounts. In Coolify this is usually under the app's
   **Storage** or **Volumes** tab.
5. Deploy. Visit the domain Coolify gives the app, accounts, and the AI
   Nutritionist should now both work for anyone visiting it, from any
   device.

## A couple of things worth knowing

- **The Privacy Policy & Terms text is a reasonable starting point, not a
  legal review.** It covers what data is collected, the third parties
  involved (CalorieNinjas, and Anthropic when used inside Claude), account
  deletion, and a "not medical/professional advice" disclaimer for the
  workout, diet, and drill content. It's written in plain language on
  purpose. Before this goes properly public, it's worth a cheap one-off
  read-through from an actual solicitor, especially since UK GDPR applies
  once you're collecting other people's data, even for a small side
  project. Search-replace the placeholder-ish bits (there's no named
  operator or contact email in there yet) with your own details.
- **Signup now requires ticking a consent box** (16+, agrees to the policy)
  before an account can be created. The backend rejects signups without it
  too, so it can't be bypassed by skipping the frontend.
- **Delete account is a real, permanent deletion.** It removes the login
  from `users.json` and deletes that user's entire data file, not just a
  "deactivate" flag. There's no undo, by design.
- **Ranked is only available once this is live on Coolify.** It compares PRs
  across every account, which needs the shared account system this backend
  provides. It won't show anything meaningful in Claude's own preview, where
  each person's storage is private to their own Claude account.
- **Passwords are hashed** (bcrypt) before they're stored, never saved in
  plain text. Login sessions use signed tokens (JWT) that expire after 30
  days.
- **This is a simple file-based store, not a full production database.**
  It's genuinely fine at the scale of a personal project or a small group of
  friends. If this grows into something with real concurrent users, moving
  `users.json` and the per-user data files into a proper database (Postgres,
  etc.) is the natural next step, the API shape (`/api/auth/*`, `/api/data`)
  wouldn't need to change, just what's behind it.
- **Rate limiting still isn't built in.** CalorieNinjas' free tier has its
  own request limits, so if this gets busy, it's worth adding basic rate
  limiting to `/api/estimate-food` (e.g. the `express-rate-limit` package)
  so one person can't use up everyone else's free quota.
