# LINK VERIFY AI — System Architecture

## Overview
LINK VERIFY AI is a full-stack cybersecurity platform for static URL risk analysis, machine learning phishing classification, and multi-provider threat intelligence aggregation.

## Key Architectural Principles
1. **Zero-Execution Static Inspection:** Submitted URLs are never visited, rendered, or executed by the backend server. All lexical and structural features are computed deterministically from the URL string.
2. **Defense-in-Depth SSRF Protection:** Any outbound HTTP request made by the backend (exclusively to configured threat intelligence APIs) passes through [`validate_fetch_target`](file:///backend/app/security/ssrf.py), blocking loopback, private RFC1918/ULA IP ranges, link-local ranges, cloud metadata endpoints, DNS rebinding targets, and unsafe redirects.
3. **Transparent Multi-Source Risk Aggregation:** Overall risk scores (`0–100`) combine heuristic signals, ML phishing probabilities, and external threat intelligence matches with explicit source attributions. Model confidence (`0.50–1.00`) is reported independently from the risk score.
4. **Dual-Mode Authentication & User Data Isolation:** Supports Supabase Auth JWT verification in cloud deployments and local PBKDF2 + HS256 JWT authentication in standalone Docker/local environments. PostgreSQL Row Level Security policies enforce user ownership at the database layer alongside FastAPI ownership checks.

## Component Layout
- `frontend/`: React 19 + TypeScript + Vite + Tailwind CSS + Recharts + TanStack Query + Zod SPA.
- `backend/`: FastAPI + SQLAlchemy 2.0 + Pydantic v2 REST API, security controls, URL analysis modules, and Joblib ML inference.
- `ml-training/`: Reproducible dataset download, validation, deduplication, leakage-free feature engineering, model comparison (Logistic Regression, Random Forest, XGBoost), and evaluation scripts.
- `database/`: PostgreSQL DDL (`schema.sql`) and Supabase RLS policies (`rls_policies.sql`).

