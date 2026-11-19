/*
# Phone login requests + receipts storage bucket

1. New Tables
- `phone_login_requests`: one row per phone-number login attempt.
  - `id` (uuid, primary key, auto-generated)
  - `phone` (text, not null) — Sudanese local format 0XXXXXXXXX, enforced by CHECK
  - `code` (text, not null) — 6-digit code, enforced by CHECK
  - `status` (text, default 'pending') — one of pending / approved / rejected / used
  - `created_at` (timestamp, not null, default now())
  - `expires_at` (timestamp, not null, default now() + 15 minutes)
  - `reviewed_at`, `reviewed_by` (who handled the request)
2. Indexes
- `phone_login_requests_phone_idx` on (phone, created_at DESC)
- `phone_login_requests_status_idx` on (status, created_at DESC)
3. Security
- Enable RLS on `phone_login_requests`; revoke all from anon/authenticated.
- Grant SELECT to authenticated (owners only, via is_owner() policy).
- Grant ALL to service_role (server-side code manages this table).
- New SECURITY DEFINER function `review_phone_login(p_request_id, p_approve)`:
  owners approve/reject a still-pending, unexpired request; executable by
  authenticated only, revoked from PUBLIC/anon.
4. Storage
- Create private bucket `receipts` (non-public) for uploaded payment receipt images.
- Storage policies: authenticated users may upload/read/delete only their own
  files (folder named by their user id); owners may read everything.
*/

CREATE TABLE IF NOT EXISTS public.phone_login_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  phone text NOT NULL CHECK (phone ~ '^0[0-9]{9}$'),
  code text NOT NULL CHECK (code ~ '^[0-9]{6}$'),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','used')),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT now() + interval '15 minutes',
  reviewed_at timestamptz,
  reviewed_by uuid
);
CREATE INDEX IF NOT EXISTS phone_login_requests_phone_idx ON public.phone_login_requests (phone, created_at DESC);
CREATE INDEX IF NOT EXISTS phone_login_requests_status_idx ON public.phone_login_requests (status, created_at DESC);

ALTER TABLE public.phone_login_requests ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.phone_login_requests FROM anon, authenticated;
GRANT SELECT ON public.phone_login_requests TO authenticated;
GRANT ALL ON public.phone_login_requests TO service_role;

DROP POLICY IF EXISTS "Owners read phone login requests" ON public.phone_login_requests;
CREATE POLICY "Owners read phone login requests" ON public.phone_login_requests
  FOR SELECT TO authenticated USING (public.is_owner());

CREATE OR REPLACE FUNCTION public.review_phone_login(p_request_id uuid, p_approve boolean)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO ''
AS $$
BEGIN
  IF NOT public.is_owner() THEN
    RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
  END IF;
  UPDATE public.phone_login_requests
     SET status = CASE WHEN p_approve THEN 'approved' ELSE 'rejected' END,
         reviewed_at = now(),
         reviewed_by = auth.uid()
   WHERE id = p_request_id AND status = 'pending' AND expires_at > now();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'request not pending' USING ERRCODE = 'P0002';
  END IF;
END;
$$;
REVOKE ALL ON FUNCTION public.review_phone_login(uuid, boolean) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.review_phone_login(uuid, boolean) TO authenticated;

INSERT INTO storage.buckets (id, name, public)
VALUES ('receipts', 'receipts', false)
ON CONFLICT (id) DO NOTHING;

DROP POLICY IF EXISTS "authenticated upload own receipt" ON storage.objects;
CREATE POLICY "authenticated upload own receipt" ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'receipts' AND (storage.foldername(name))[1] = auth.uid()::text);

DROP POLICY IF EXISTS "authenticated read own receipt" ON storage.objects;
CREATE POLICY "authenticated read own receipt" ON storage.objects
  FOR SELECT TO authenticated
  USING (bucket_id = 'receipts' AND (storage.foldername(name))[1] = auth.uid()::text);

DROP POLICY IF EXISTS "authenticated delete own receipt" ON storage.objects;
CREATE POLICY "authenticated delete own receipt" ON storage.objects
  FOR DELETE TO authenticated
  USING (bucket_id = 'receipts' AND (storage.foldername(name))[1] = auth.uid()::text);

DROP POLICY IF EXISTS "owner read all receipts" ON storage.objects;
CREATE POLICY "owner read all receipts" ON storage.objects
  FOR SELECT TO authenticated
  USING (bucket_id = 'receipts' AND public.is_owner());