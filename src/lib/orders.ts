import { supabase } from '@/lib/supabase';
import { uploadReceipt } from '@/lib/receipts';
import type { OrderStatus, StoreOrder } from '@/types';

export type { StoreOrder };
export { MAX_RECEIPT_BYTES, validateReceipt, uploadReceipt, fetchReceiptUrl } from '@/lib/receipts';

export interface OrderInput {
  customerName: string;
  gameId: string;
  packageId: string;
  playerId: string;
  whatsapp: string;
  paymentMethodId: string;
  payerAccount: string;
  receipt: File;
}

export interface SubmitOrderResult {
  receiptSaved: boolean;
}

export function normalizePlayerId(value: string): string {
  return value.trim();
}

export function normalizeWhatsapp(value: string): string {
  return value.replace(/[\s-]/g, '');
}

export function normalizePayerAccount(value: string): string {
  return value.replace(/[\s-]/g, '');
}

export function isValidPlayerId(value: string): boolean {
  return value.length >= 3 && value.length <= 50;
}

export function isValidWhatsapp(value: string): boolean {
  return /^\+?[0-9]{7,15}$/.test(value);
}

export function isValidPayerAccount(value: string): boolean {
  return /^\+?[0-9]{3,30}$/.test(value);
}

export async function submitOrder(input: OrderInput): Promise<SubmitOrderResult> {
  const receiptPath = await uploadReceipt(input.receipt);
  const customerName = input.customerName.trim();
  const payerAccount = normalizePayerAccount(input.payerAccount);

  const { error } = await supabase.from('orders').insert({
    customer_name: customerName.length >= 2 ? customerName : null,
    game_id: input.gameId,
    package_id: input.packageId,
    player_id: input.playerId,
    whatsapp: input.whatsapp,
    payment_method_id: input.paymentMethodId,
    payer_account: payerAccount.length >= 3 ? payerAccount : null,
    receipt_path: receiptPath,
  });
  if (error) throw new Error(error.message);

  return { receiptSaved: receiptPath !== null };
}

export const WALLET_METHOD_ID = 'wallet';

export interface WalletOrderInput {
  customerName: string;
  gameId: string;
  packageId: string;
  playerId: string;
  whatsapp: string;
}

/** Pays from the signed-in user's wallet; the database checks and deducts the balance. */
export async function submitWalletOrder(input: WalletOrderInput): Promise<void> {
  const { error } = await supabase.rpc('place_wallet_order', {
    p_game_id: input.gameId,
    p_package_id: input.packageId,
    p_player_id: input.playerId,
    p_whatsapp: input.whatsapp,
    p_customer_name: input.customerName.trim(),
  });
  if (error) throw new Error(error.message);
}

export async function reviewOrder(orderId: string, approve: boolean): Promise<void> {
  const { error } = await supabase.rpc('review_order', { p_order_id: orderId, p_approve: approve });
  if (error) throw error;
}

const ORDER_COLUMNS = `
  id, customer_name, whatsapp, player_id, amount_sdg, payer_account, receipt_path,
  status, created_at, reviewed_at, user_id,
  game:games(name_ar, name_en),
  package:packages(label_ar),
  payment_method:payment_methods(name_ar),
  user:profiles(name, phone, email)
`;

interface OrderRow {
  id: string;
  customer_name: string | null;
  whatsapp: string;
  player_id: string;
  amount_sdg: number;
  payer_account: string | null;
  receipt_path: string | null;
  status: string;
  created_at: string;
  reviewed_at: string | null;
  user_id: string | null;
  game: { name_ar: string; name_en: string } | null;
  package: { label_ar: string } | null;
  payment_method: { name_ar: string } | null;
  user: { name: string | null; phone: string | null; email: string | null } | null;
}

function toOrderStatus(value: string): OrderStatus {
  if (value === 'completed' || value === 'confirmed') return 'completed';
  if (value === 'rejected') return 'rejected';
  return 'pending';
}

function toStoreOrder(row: OrderRow): StoreOrder {
  return {
    id: row.id,
    customerName: row.customer_name,
    whatsapp: row.whatsapp,
    gameName: row.game?.name_ar ?? '—',
    gameEn: row.game?.name_en ?? '',
    packageLabel: row.package?.label_ar ?? '—',
    playerId: row.player_id,
    amount: row.amount_sdg,
    paymentName: row.payment_method?.name_ar ?? '—',
    payerAccount: row.payer_account,
    receiptPath: row.receipt_path,
    status: toOrderStatus(row.status),
    createdAt: row.created_at,
    reviewedAt: row.reviewed_at,
    userId: row.user_id,
    userName: row.user?.name ?? null,
    userPhone: row.user?.phone ?? null,
    userEmail: row.user?.email ?? null,
  };
}

/** Owners get every order; customers get only their own (enforced by the database). */
export async function fetchOrders(): Promise<StoreOrder[]> {
  const { data, error } = await supabase
    .from('orders')
    .select(ORDER_COLUMNS)
    .order('created_at', { ascending: false });
  if (error) throw new Error(error.message);
  return ((data ?? []) as unknown as OrderRow[]).map(toStoreOrder);
}

/** Only the signed-in customer's own orders, even when that customer is the owner. */
export async function fetchMyOrders(userId: string): Promise<StoreOrder[]> {
  const { data, error } = await supabase
    .from('orders')
    .select(ORDER_COLUMNS)
    .eq('user_id', userId)
    .order('created_at', { ascending: false });
  if (error) throw new Error(error.message);
  return ((data ?? []) as unknown as OrderRow[]).map(toStoreOrder);
}
