/*
# Wallet-paid orders

1. Plain-English summary
   Adds "wallet" as a payment method so signed-in customers can pay for orders
   directly from their stored balance, and hardens order review so a rejected
   wallet order refunds the customer.

2. Modified tables
   - `orders`: amount_sdg now has a DEFAULT 0 (the trigger always fills the real price).

3. New rows
   - `payment_methods`: a disabled 'wallet' row (shown to customers only when
     signed in with enough balance).

4. Functions & triggers
   - `set_order_amount()` rewritten: matches active packages only, and blocks
     direct inserts paid by wallet — wallet orders must go through the RPC so
     the balance is deducted atomically.
   - `place_wallet_order(...)`: SECURITY DEFINER RPC for signed-in customers;
     checks the balance, deducts it, and inserts the order in one atomic step.
   - `review_order(...)` rewritten: approving completes the order; rejecting a
     wallet order refunds the customer's balance.

5. Security
   - EXECUTE on `place_wallet_order` granted to authenticated only.
   - Money still never moves from the client — only these database functions.
*/

ALTER TABLE public.orders ALTER COLUMN amount_sdg SET DEFAULT 0;

INSERT INTO public.payment_methods (id, name_ar, account_label_ar, account_value, instructions_ar, sort_order, is_active)
VALUES ('wallet', 'رصيد المحفظة', 'المحفظة', '-', 'يتم الخصم من رصيد محفظتك مباشرة.', 0, false)
ON CONFLICT (id) DO NOTHING;

CREATE OR REPLACE FUNCTION public.set_order_amount()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
BEGIN
  SELECT p.price_sdg INTO NEW.amount_sdg
  FROM public.packages p
  WHERE p.id = NEW.package_id AND p.game_id = NEW.game_id AND p.is_active;
  IF NEW.amount_sdg IS NULL THEN
    RAISE EXCEPTION 'Package does not match the selected game';
  END IF;
  IF NEW.payment_method_id = 'wallet' AND coalesce(current_setting('app.wallet_order', true), '') <> 'on' THEN
    RAISE EXCEPTION 'WALLET_ORDER_VIA_RPC_ONLY';
  END IF;
  NEW.status := 'pending';
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.place_wallet_order(
  p_game_id text, p_package_id text, p_player_id text, p_whatsapp text, p_customer_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_price integer;
  v_id uuid;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'NOT_SIGNED_IN' USING ERRCODE = '42501'; END IF;
  SELECT price_sdg INTO v_price FROM public.packages
    WHERE id = p_package_id AND game_id = p_game_id AND is_active;
  IF v_price IS NULL THEN RAISE EXCEPTION 'Package does not match the selected game'; END IF;
  UPDATE public.profiles SET balance = balance - v_price
    WHERE id = v_uid AND balance >= v_price;
  IF NOT FOUND THEN RAISE EXCEPTION 'INSUFFICIENT_BALANCE'; END IF;
  PERFORM set_config('app.wallet_order', 'on', true);
  INSERT INTO public.orders (game_id, package_id, player_id, whatsapp, payment_method_id, customer_name, user_id)
  VALUES (p_game_id, p_package_id, p_player_id, p_whatsapp, 'wallet', NULLIF(p_customer_name, ''), v_uid)
  RETURNING id INTO v_id;
  PERFORM set_config('app.wallet_order', 'off', true);
  RETURN v_id;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.place_wallet_order(text, text, text, text, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.place_wallet_order(text, text, text, text, text) TO authenticated;

CREATE OR REPLACE FUNCTION public.review_order(p_order_id uuid, p_approve boolean)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_row public.orders%ROWTYPE;
BEGIN
  IF NOT public.is_owner() THEN
    RAISE EXCEPTION 'NOT_OWNER' USING ERRCODE = '42501';
  END IF;
  SELECT * INTO v_row FROM public.orders WHERE id = p_order_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'NOT_FOUND'; END IF;
  IF v_row.status <> 'pending' THEN RAISE EXCEPTION 'ALREADY_REVIEWED'; END IF;
  IF p_approve THEN
    UPDATE public.orders SET status = 'completed', reviewed_at = now() WHERE id = p_order_id;
  ELSE
    IF v_row.payment_method_id = 'wallet' AND v_row.user_id IS NOT NULL THEN
      UPDATE public.profiles SET balance = balance + v_row.amount_sdg WHERE id = v_row.user_id;
    END IF;
    UPDATE public.orders SET status = 'rejected', reviewed_at = now() WHERE id = p_order_id;
  END IF;
END;
$$;