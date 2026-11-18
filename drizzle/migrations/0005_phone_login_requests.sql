CREATE TABLE public.phone_login_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  phone text NOT NULL CHECK (phone ~ '^0[0-9]{9}$'),
  code text NOT NULL CHECK (code ~ '^[0-9]{6}$'),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','used')),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT now() + interval '15 minutes',
  reviewed_at timestamptz,
  reviewed_by uuid
);
CREATE INDEX phone_login_requests_phone_idx ON public.phone_login_requests (phone, created_at DESC);
CREATE INDEX phone_login_requests_status_idx ON public.phone_login_requests (status, created_at DESC);

ALTER TABLE public.phone_login_requests ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.phone_login_requests FROM anon, authenticated;
GRANT SELECT ON public.phone_login_requests TO authenticated;
GRANT ALL ON public.phone_login_requests TO service_role;

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