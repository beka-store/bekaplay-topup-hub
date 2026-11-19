/*
# Customer reviews

1. Plain-English summary
   Lets customers leave a rating and comment on a completed order, shown on the
   home page only after the store owner publishes them.

2. New tables
   - `reviews`
     - `order_id`: the completed order being reviewed (unique — one review per order).
     - `customer_name`: display name (2-40 chars).
     - `rating`: 1-5 stars.
     - `comment`: 3-400 chars.
     - `source`: 'customer' (submitted by the buyer) or 'owner' (written by the admin).
     - `status`: 'pending' until the owner approves; 'approved' shows publicly; 'rejected' never shows.

3. Functions
   - `submit_review(p_order_id, p_rating, p_comment)`: SECURITY DEFINER RPC —
     only the order's own signed-in customer, order must be completed, one
     review per order, always starts as 'pending'.

4. Security
   - RLS enabled. Anyone (anon included) can read only approved reviews;
     customers see their own pending review; owners see and manage everything.
   - anon gets SELECT on the display columns only, so unpublished statuses can
     never leak.
*/

CREATE TABLE IF NOT EXISTS public.reviews (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id uuid NOT NULL REFERENCES public.orders(id) ON DELETE CASCADE,
  customer_name text NOT NULL CHECK (char_length(trim(customer_name)) BETWEEN 2 AND 40),
  rating integer NOT NULL CHECK (rating BETWEEN 1 AND 5),
  comment text NOT NULL CHECK (char_length(trim(comment)) BETWEEN 3 AND 400),
  source text NOT NULL DEFAULT 'customer' CHECK (source IN ('customer', 'owner')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS reviews_order_id_key ON public.reviews (order_id);
CREATE INDEX IF NOT EXISTS reviews_status_created_idx ON public.reviews (status, created_at DESC);

ALTER TABLE public.reviews ENABLE ROW LEVEL SECURITY;

GRANT SELECT (id, order_id, customer_name, rating, comment, source, created_at) ON public.reviews TO anon;
GRANT SELECT, INSERT ON public.reviews TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.reviews TO service_role;

DROP POLICY IF EXISTS "public_read_approved_reviews" ON public.reviews;
CREATE POLICY "public_read_approved_reviews" ON public.reviews
  FOR SELECT TO anon, authenticated USING (status = 'approved');

DROP POLICY IF EXISTS "customer_read_own_reviews" ON public.reviews;
CREATE POLICY "customer_read_own_reviews" ON public.reviews
  FOR SELECT TO authenticated
  USING (auth.uid() IN (
    SELECT o.user_id FROM public.orders o WHERE o.id = order_id
  ));

DROP POLICY IF EXISTS "owner_all_reviews" ON public.reviews;
CREATE POLICY "owner_all_reviews" ON public.reviews
  FOR SELECT TO authenticated USING (public.is_owner());
CREATE POLICY "owner_insert_reviews" ON public.reviews
  FOR INSERT TO authenticated WITH CHECK (public.is_owner());
CREATE POLICY "owner_update_reviews" ON public.reviews
  FOR UPDATE TO authenticated USING (public.is_owner()) WITH CHECK (public.is_owner());
CREATE POLICY "owner_delete_reviews" ON public.reviews
  FOR DELETE TO authenticated USING (public.is_owner());

CREATE OR REPLACE FUNCTION public.submit_review(p_order_id uuid, p_rating integer, p_comment text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_order public.orders%ROWTYPE;
  v_id uuid;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'NOT_SIGNED_IN' USING ERRCODE = '42501'; END IF;
  SELECT * INTO v_order FROM public.orders WHERE id = p_order_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'NOT_FOUND'; END IF;
  IF v_order.user_id IS NULL OR v_order.user_id <> v_uid THEN
    RAISE EXCEPTION 'NOT_YOUR_ORDER' USING ERRCODE = '42501';
  END IF;
  IF v_order.status <> 'completed' THEN RAISE EXCEPTION 'ORDER_NOT_COMPLETED'; END IF;
  IF p_rating NOT BETWEEN 1 AND 5 THEN RAISE EXCEPTION 'INVALID_RATING'; END IF;
  IF char_length(trim(p_comment)) NOT BETWEEN 3 AND 400 THEN RAISE EXCEPTION 'INVALID_COMMENT'; END IF;

  INSERT INTO public.reviews (order_id, customer_name, rating, comment, source, status)
  VALUES (
    p_order_id,
    coalesce(v_order.customer_name, 'عميل'),
    p_rating,
    trim(p_comment),
    'customer',
    'pending'
  )
  RETURNING id INTO v_id;
  RETURN v_id;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.submit_review(uuid, integer, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.submit_review(uuid, integer, text) TO authenticated;