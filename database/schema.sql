-- ==============================================================================
-- LINK VERIFY AI — PostgreSQL & Supabase Database Schema
-- ==============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ------------------------------------------------------------------------------
-- TABLE: profiles
-- Stores application user profile metadata.
-- In Supabase deployments, `id` references `auth.users(id)` via trigger/FK.
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    password_hash TEXT NULL, -- Only populated when local JWT fallback auth is active; NULL for Supabase Auth
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT profiles_email_length CHECK (char_length(email) BETWEEN 3 AND 320)
);

CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles (email);

-- ------------------------------------------------------------------------------
-- TABLE: scans
-- Stores submitted URL scan summaries owned by a user (or NULL for anonymous scans
-- if anonymous persistence is explicitly enabled; user history only queries user_id).
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    original_url TEXT NOT NULL,
    normalized_domain TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    model_confidence DOUBLE PRECISION NULL CHECK (model_confidence IS NULL OR (model_confidence >= 0.0 AND model_confidence <= 1.0)),
    verdict TEXT NOT NULL,
    scan_status TEXT NOT NULL DEFAULT 'completed' CHECK (scan_status IN ('pending', 'completed', 'failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT scans_original_url_length CHECK (char_length(original_url) BETWEEN 1 AND 2048),
    CONSTRAINT scans_domain_length CHECK (char_length(normalized_domain) BETWEEN 1 AND 255)
);

CREATE INDEX IF NOT EXISTS idx_scans_user_created ON public.scans (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON public.scans (risk_level);
CREATE INDEX IF NOT EXISTS idx_scans_normalized_domain ON public.scans (normalized_domain);

-- ------------------------------------------------------------------------------
-- TABLE: scan_features
-- Stores extracted URL structural/lexical features and risk contributions.
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.scan_features (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    feature_name TEXT NOT NULL,
    feature_value TEXT NOT NULL,
    risk_contribution DOUBLE PRECISION NOT NULL DEFAULT 0.0
);

CREATE INDEX IF NOT EXISTS idx_scan_features_scan_id ON public.scan_features (scan_id);

-- ------------------------------------------------------------------------------
-- TABLE: threat_intelligence
-- Stores external threat intelligence lookup statuses and sanitized summaries.
-- Never store API secrets inside `details`.
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.threat_intelligence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    detection_status TEXT NOT NULL CHECK (
        detection_status IN ('clean', 'malicious', 'suspicious', 'not_configured', 'unavailable', 'rate_limited', 'error')
    ),
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_scan_id ON public.threat_intelligence (scan_id);
CREATE INDEX IF NOT EXISTS idx_threat_intel_provider ON public.threat_intelligence (provider);

-- ------------------------------------------------------------------------------
-- TABLE: scan_reports
-- Stores full explainable report JSONB payload (signals, recommendations, timings).
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.scan_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL UNIQUE REFERENCES public.scans(id) ON DELETE CASCADE,
    report_data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_reports_scan_id ON public.scan_reports (scan_id);

