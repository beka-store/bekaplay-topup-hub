CREATE TABLE public.reviews (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id uuid UNIQUE REFERENCES public.orders(id) ON DELETE SET NULL,
  user_id uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  customer_name text NOT NULL CHECK (char_length(btrim(customer_name)) BETWEEN 2 AND 40),
  game_id text REFERENCES public.games(id) ON DELETE SET NULL,
  rating smallint NOT NULL CHECK (rating BETWEEN 1 AND 5),
  comment text NOT NULL CHECK (char_length(btrim(comment)) BETWEEN 3 AND 400),
  source text NOT NULL DEFAULT 'customer' CHECK (source IN ('customer', 'owner')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  created_at timestamptz NOT NULL DEFAULT now(),
  reviewed_at timestamptz
);

CREATE INDEX reviews_status_created_idx ON public.reviews (status, created_at DESC);

GRANT SELECT (id, customer_name, game_id, rating, comment, source, status, created_at) ON public.reviews TO anon;
GRANT SELECT ON public.reviews TO authenticated;
GRANT INSERT, UPDATE, DELETE ON public.reviews TO authenticated;
GRANT ALL ON public.reviews TO service_role;

ALTER TABLE public.reviews ENABLE ROW LEVEL SECURITY;

CREATE POLICY public_read_approved_reviews ON public.reviews
  FOR SELECT TO anon, authenticated USING (status = 'approved');
CREATE POLICY read_own_reviews ON public.reviews
  FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY owner_read_all_reviews ON public.reviews
  FOR SELECT TO authenticated USING (public.is_owner());
CREATE POLICY owner_insert_reviews ON public.reviews
  FOR INSERT TO authenticated WITH CHECK (public.is_owner() AND source = 'owner');
CREATE POLICY owner_update_reviews ON public.reviews
  FOR UPDATE TO authenticated USING (public.is_owner()) WITH CHECK (public.is_owner());
CREATE POLICY owner_delete_reviews ON public.reviews
  FOR DELETE TO authenticated USING (public.is_owner());

-- Customers review their own completed orders through this function only.
CREATE OR REPLACE FUNCTION public.submit_review(p_order_id uuid, p_rating integer, p_comment text)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_order public.orders%ROWTYPE;
  v_name text;
  v_id uuid;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'NOT_SIGNED_IN'; END IF;
  SELECT * INTO v_order FROM public.orders WHERE id = p_order_id;
  IF NOT FOUND OR v_order.user_id IS DISTINCT FROM v_uid THEN RAISE EXCEPTION 'ORDER_NOT_FOUND'; END IF;
  IF v_order.status NOT IN ('completed', 'confirmed') THEN RAISE EXCEPTION 'ORDER_NOT_COMPLETED'; END IF;
  IF EXISTS (SELECT 1 FROM public.reviews WHERE order_id = p_order_id) THEN RAISE EXCEPTION 'ALREADY_REVIEWED'; END IF;

  SELECT COALESCE(NULLIF(btrim(v_order.customer_name), ''), NULLIF(btrim(p.name), ''), 'عميل بيكا ستور')
    INTO v_name FROM public.profiles p WHERE p.id = v_uid;
  v_name := left(COALESCE(v_name, 'عميل بيكا ستور'), 40);

  INSERT INTO public.reviews (order_id, user_id, customer_name, game_id, rating, comment, source, status)
  VALUES (p_order_id, v_uid, v_name, v_order.game_id, p_rating, btrim(p_comment), 'customer', 'pending')
  RETURNING id INTO v_id;
  RETURN v_id;
END;
$$;

REVOKE ALL ON FUNCTION public.submit_review(uuid, integer, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.submit_review(uuid, integer, text) TO authenticated;