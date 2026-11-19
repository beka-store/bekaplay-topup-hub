/*
# Owner email allowlist

1. Plain-English summary
   Adds a private list of admin emails. When someone signs up with a confirmed
   email on that list, the database automatically grants them the "owner"
   (admin) role — no manual role insert needed.

2. New tables
   - `owner_email_allowlist`: lowercase admin emails.

3. Functions & triggers
   - `grant_owner_from_allowlist()`: on new/updated auth users, grants 'owner'
     when the confirmed email is on the list.
   - `apply_owner_allowlist_to_existing()`: when an email is added to the list,
     grants 'owner' to any existing confirmed account with that email.

4. Security
   - RLS enabled; no policies — only the service role and the SECURITY DEFINER
     triggers can touch the table. Clients can never grant themselves owner.
*/

CREATE TABLE IF NOT EXISTS public.owner_email_allowlist (
  email text PRIMARY KEY CHECK (email = lower(email)),
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT ALL ON public.owner_email_allowlist TO service_role;
ALTER TABLE public.owner_email_allowlist ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.grant_owner_from_allowlist()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF NEW.email IS NOT NULL
     AND NEW.email_confirmed_at IS NOT NULL
     AND EXISTS (SELECT 1 FROM public.owner_email_allowlist a WHERE a.email = lower(NEW.email))
     AND NOT EXISTS (SELECT 1 FROM public.user_roles r WHERE r.user_id = NEW.id AND r.role = 'owner')
  THEN
    INSERT INTO public.user_roles (user_id, role) VALUES (NEW.id, 'owner');
  END IF;
  RETURN NEW;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.grant_owner_from_allowlist() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS on_auth_user_owner_allowlist ON auth.users;
CREATE TRIGGER on_auth_user_owner_allowlist
AFTER INSERT OR UPDATE OF email_confirmed_at, email ON auth.users
FOR EACH ROW EXECUTE FUNCTION public.grant_owner_from_allowlist();

CREATE OR REPLACE FUNCTION public.apply_owner_allowlist_to_existing()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.user_roles (user_id, role)
  SELECT u.id, 'owner'
  FROM auth.users u
  WHERE lower(u.email) = NEW.email
    AND u.email_confirmed_at IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM public.user_roles r WHERE r.user_id = u.id AND r.role = 'owner');
  RETURN NEW;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.apply_owner_allowlist_to_existing() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS owner_allowlist_apply_existing ON public.owner_email_allowlist;
CREATE TRIGGER owner_allowlist_apply_existing
AFTER INSERT ON public.owner_email_allowlist
FOR EACH ROW EXECUTE FUNCTION public.apply_owner_allowlist_to_existing();