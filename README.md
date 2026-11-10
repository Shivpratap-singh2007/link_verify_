# LINK VERIFY AI

**Tagline:** *A Smarter First Check Before You Click.*

LINK VERIFY AI is a full-stack cybersecurity platform for static suspicious URL detection, phishing indicator analysis, machine learning classification, and threat intelligence aggregation.

---

## Key Features

- **Zero-Execution Static URL Analysis Engine:** Extracts 25 lexical, structural, and domain features (`url_length`, `domain_length`, `num_dots`, `num_hyphens`, `num_subdomains`, `num_digits`, `has_ip_address`, `suspicious_keyword_count`, `path_length`, `num_special_chars`, `has_at_symbol`, `is_https`, `has_punycode_idn`, `has_suspicious_tld`, `unusual_encoding_count`, entropy, userinfo deception, and brand impersonation) without ever visiting or executing submitted links.
- **Machine Learning Classification:** Reproducible training & evaluation pipeline (`ml-training/`) trained on the Hannousse & Yahiouche (2021) public phishing URL benchmark dataset (`11,427` deduplicated URLs), comparing Majority Baseline, Logistic Regression, Random Forest, and XGBoost.
- **Explainable Risk Scoring (`0–100`):** Separates ML model confidence from the aggregated risk score (`LOW` 0–24, `MEDIUM` 25–49, `HIGH` 50–74, `CRITICAL` 75–100) and never treats a single weak signal (such as plain HTTP or URL length alone) as proof of maliciousness.
- **Threat Intelligence Integration:** Backend-only adapters for Google Safe Browsing, VirusTotal, PhishTank, and URLhaus with TTL caching, timeouts, rate-limit handling, and honest `"Threat intelligence service not configured."` reporting when API keys are absent.
- **Security Controls:** Strict SSRF validation blocking loopback, private IP ranges, link-local ranges, cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`), DNS rebinding, and unsafe redirects; sliding-window rate limiting; JWT authentication; and PostgreSQL / Supabase Row Level Security.
- **Full-Stack SaaS Interface:** React 19 + TypeScript + Tailwind CSS + Recharts + TanStack Query + Zod with 7 complete pages (Landing, URL Scanner, Scan Results, Authenticated Dashboard, Scan History, Authentication/Profile, About) and dark/light theme support.

---

## Project Structure

```text
link_verify_/
├── frontend/                  # React 19 + Vite + TypeScript + Tailwind CSS
├── backend/                   # FastAPI + SQLAlchemy 2.0 + Pydantic v2 + ML inference
├── ml-training/               # Dataset ingestion, preprocessing, training & evaluation
├── database/                  # PostgreSQL DDL (schema.sql) & Supabase RLS (rls_policies.sql)
├── docs/                      # Architecture and deployment documentation
├── docker-compose.yml         # PostgreSQL + FastAPI + Nginx Frontend
├── .env.example               # Environment configuration template
└── README.md
```

---

## Quick Start (Local Development)

### 1. Environment Setup
Copy `.env.example` to `.env` and fill in optional keys as needed. In local development without Supabase keys, the backend automatically uses SQLite (`link_verify_local.db`) and local PBKDF2 + HS256 JWT authentication.

### 2. Backend Setup
```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate | Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
API documentation is served at `http://localhost:8000/docs`.

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173`. Vite proxies `/api/*` requests directly to `http://localhost:8000`.

### 4. Retrain ML Model (Optional — Pre-trained Artifact Included)
```bash
backend/.venv/Scripts/python.exe ml-training/training/fetch_dataset.py
backend/.venv/Scripts/python.exe ml-training/training/train.py
backend/.venv/Scripts/python.exe ml-training/evaluation/evaluate.py
```

---

## Running Tests & Build Checks

### Backend Tests (`pytest`)
```bash
backend/.venv/Scripts/python.exe -m pytest backend/tests -v
```

### Frontend Tests & Production Build
```bash
cd frontend
npm test
npm run build
```

---

## Docker & Cloud Deployment
See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for Docker Compose (`docker compose up --build`), Supabase PostgreSQL + RLS setup, Vercel frontend deployment, and Render/Railway backend deployment.

