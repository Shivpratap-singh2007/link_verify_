# LINK VERIFY AI — Deployment Guide

## 1. Local Development (Without Docker)

### Backend
```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate | Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

## 2. Docker Compose (PostgreSQL + FastAPI + Nginx Frontend)
1. Copy `.env.example` to `.env` and set strong secrets (`LOCAL_JWT_SECRET`, optional threat-intel keys, or Supabase credentials).
2. Run:
   ```bash
   docker compose up --build
   ```
3. Frontend serves on `http://localhost:3000`, Backend API on `http://localhost:8000`, PostgreSQL on `localhost:5432`.

## 3. Supabase Database & Auth Setup
1. Create a Supabase project.
2. Run `database/schema.sql` followed by `database/rls_policies.sql` in the Supabase SQL Editor.
3. Enable the `auth.users` FK and `on_auth_user_created` trigger in `database/rls_policies.sql`.
4. Configure backend environment variables:
   - `DATABASE_URL` (Supabase Postgres connection string)
   - `SUPABASE_URL`
   - `SUPABASE_ANON_KEY`
   - `SUPABASE_JWT_SECRET`
5. Configure frontend environment variables:
   - `VITE_SUPABASE_URL`
   - `VITE_SUPABASE_ANON_KEY`
   - `VITE_API_BASE_URL`

## 4. Cloud Deployment

### Frontend on Vercel
- Root directory: `frontend`
- Build command: `npm run build`
- Output directory: `dist`
- Environment variables: `VITE_API_BASE_URL`, `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`
- Note: Never set backend API keys (`VIRUSTOTAL_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, etc.) in Vercel frontend environment variables.

### Backend on Render or Railway
- Root directory: `backend` (or deploy using `backend/Dockerfile`)
- Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- Environment variables: `DATABASE_URL`, `CORS_ORIGINS`, `SUPABASE_URL`, `SUPABASE_JWT_SECRET`, `LOCAL_JWT_SECRET`, and optional backend-only threat intelligence API keys.

