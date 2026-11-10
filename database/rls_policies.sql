-- ==============================================================================
-- LINK VERIFY AI — Supabase Row Level Security (RLS) & Auth Sync
-- Apply after `schema.sql` in your Supabase SQL Editor.
-- ==============================================================================

-- Optionally link public.profiles.id to auth.users(id) on Supabase:
-- ALTER TABLE public.profiles
--   ADD CONSTRAINT profiles_auth_user_fk
--   FOREIGN KEY (id) REFERENCES auth.users(id) ON DELETE CASCADE;

-- Automatically provision a profile row whenever a new user registers via Supabase Auth
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    INSERT INTO public.profiles (id, email, display_name)
    VALUES (
        NEW.id,
        COALESCE(NEW.email, ''),
        COALESCE(NEW.raw_user_meta_data ->> 'display_name', split_part(COALESCE(NEW.email, ''), '@', 1))
    )
    ON CONFLICT (id) DO UPDATE
    SET email = EXCLUDED.email,
        updated_at = NOW();
    RETURN NEW;
END;
$$;

-- Trigger on auth.users (uncomment when running inside Supabase):
-- DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
-- CREATE TRIGGER on_auth_user_created
--     AFTER INSERT ON auth.users
--     FOR EACH ROW
--     EXECUTE FUNCTION public.handle_new_user();

-- Enable Row Level Security on all user-facing tables
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_features ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_intelligence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_reports ENABLE ROW LEVEL SECURITY;

-- Profiles: Users can only view and update their own profile
DROP POLICY IF EXISTS "Users can view own profile" ON public.profiles;
CREATE POLICY "Users can view own profile"
    ON public.profiles FOR SELECT
    USING (auth.uid() = id);

DROP POLICY IF EXISTS "Users can update own profile" ON public.profiles;
CREATE POLICY "Users can update own profile"
    ON public.profiles FOR UPDATE
    USING (auth.uid() = id)
    WITH CHECK (auth.uid() = id);

-- Scans: Users can only select, insert, and delete their own scans
DROP POLICY IF EXISTS "Users can view own scans" ON public.scans;
CREATE POLICY "Users can view own scans"
    ON public.scans FOR SELECT
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can insert own scans" ON public.scans;
CREATE POLICY "Users can insert own scans"
    ON public.scans FOR INSERT
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can delete own scans" ON public.scans;
CREATE POLICY "Users can delete own scans"
    ON public.scans FOR DELETE
    USING (auth.uid() = user_id);

-- Scan features: Accessible only when the parent scan belongs to auth.uid()
DROP POLICY IF EXISTS "Users can view own scan features" ON public.scan_features;
CREATE POLICY "Users can view own scan features"
    ON public.scan_features FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM public.scans s
            WHERE s.id = scan_features.scan_id
              AND s.user_id = auth.uid()
        )
    );

DROP POLICY IF EXISTS "Users can insert own scan features" ON public.scan_features;
CREATE POLICY "Users can insert own scan features"
    ON public.scan_features FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM public.scans s
            WHERE s.id = scan_features.scan_id
              AND s.user_id = auth.uid()
        )
    );

-- Threat intelligence records: Accessible only via parent scan ownership
DROP POLICY IF EXISTS "Users can view own threat intel" ON public.threat_intelligence;
CREATE POLICY "Users can view own threat intel"
    ON public.threat_intelligence FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM public.scans s
            WHERE s.id = threat_intelligence.scan_id
              AND s.user_id = auth.uid()
        )
    );

DROP POLICY IF EXISTS "Users can insert own threat intel" ON public.threat_intelligence;
CREATE POLICY "Users can insert own threat intel"
    ON public.threat_intelligence FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM public.scans s
            WHERE s.id = threat_intelligence.scan_id
              AND s.user_id = auth.uid()
        )
    );

-- Scan reports: Accessible only via parent scan ownership
DROP POLICY IF EXISTS "Users can view own scan reports" ON public.scan_reports;
CREATE POLICY "Users can view own scan reports"
    ON public.scan_reports FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM public.scans s
            WHERE s.id = scan_reports.scan_id
              AND s.user_id = auth.uid()
        )
    );

DROP POLICY IF EXISTS "Users can insert own scan reports" ON public.scan_reports;
CREATE POLICY "Users can insert own scan reports"
    ON public.scan_reports FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM public.scans s
            WHERE s.id = scan_reports.scan_id
              AND s.user_id = auth.uid()
        )
    );

