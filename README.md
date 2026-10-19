# WAYANIME

PC-only Node + Express site with username/password login (Discord optional).

## Run locally
    npm install
    npm start        # http://localhost:3000

## Deploy (GitHub + Render)
1. Push this folder to a GitHub repo.
2. On render.com: New > Blueprint (or Web Service) > pick the repo.
3. Set DATABASE_URL (free Postgres from Neon or Supabase) so accounts and cards survive redeploys.
4. SESSION_SECRET is generated automatically by render.yaml.
5. Optional: BASE_URL = your https site URL (needed only for Discord login).

GitHub Pages cannot run this project: it needs a Node server.
