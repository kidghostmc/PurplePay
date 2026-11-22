import { createHash, createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

export class AppError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
export const digest = value => createHash('sha256').update(String(value)).digest('hex');
export function equal(a, b) { return timingSafeEqual(Buffer.from(digest(a)), Buffer.from(digest(b))); }
export function passwordHash(password) {
  const salt = randomBytes(16).toString('hex');
  return `${salt}:${scryptSync(password, salt, 64).toString('hex')}`;
}
export function passwordValid(password, hash) {
  if (!/^[a-f0-9]{32}:[a-f0-9]{128}$/.test(hash || '')) return false;
  const [salt, expected] = hash.split(':');
  return timingSafeEqual(scryptSync(password, salt, 64), Buffer.from(expected, 'hex'));
}
export function requireOrigin(req, origin) {
  if (!origin || req.headers.origin !== origin || req.headers['sec-fetch-site'] === 'cross-site') {
    throw new AppError(403, 'Origem não autorizada.');
  }
}
export function verifyWebhook(raw, signature, secret, now = Date.now()) {
  if (!secret || typeof signature !== 'string') return false;
  const match = /^t=(\d+),v1=([a-fA-F0-9]{64})$/.exec(signature);
  if (!match || Math.abs(now / 1000 - Number(match[1])) > 300) return false;
  const expected = createHmac('sha256', secret).update(`${match[1]}.`).update(raw).digest();
  return timingSafeEqual(expected, Buffer.from(match[2], 'hex'));
}
export function cents(value) {
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount < 0 || Math.abs(amount * 100 - Math.round(amount * 100)) > 0.00001) {
    throw new AppError(502, 'Valor inválido retornado pelo gateway.');
  }
  return Math.round(amount * 100);
}
export function validateCharge(body) {
  if (!Number.isSafeInteger(body.amountCents) || body.amountCents < 100 || body.amountCents > 100000000) {
    throw new AppError(400, 'Informe um valor entre R$ 1,00 e R$ 1.000.000,00, com até duas casas decimais.');
  }
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(body.requestId || '')) {
    throw new AppError(400, 'Identificador de cobrança inválido.');
  }
}
export function transactionData(data) {
  // The create endpoint wraps its response; the lookup endpoint documents a flat response.
  const transaction = data?.transaction ?? data?.data ?? data;
  if (!transaction || typeof transaction !== 'object') throw new AppError(502, 'Resposta inválida da NexusPag.');
  return transaction;
}
export function matchTransaction(order, transaction) {
  if (!transaction.id || transaction.external_id !== order.external_id || cents(transaction.amount) !== order.amount_cents ||
      (order.nexus_id && order.nexus_id !== transaction.id) || transaction.shop_id ||
      transaction.splits?.details?.length || transaction.splits_preview?.splits?.length) {
    throw new AppError(502, 'A cobrança retornada não corresponde ao pedido da PurplePay.');
  }
  if (!['pending', 'paid', 'expired', 'cancelled'].includes(transaction.status)) {
    throw new AppError(502, 'Status desconhecido da NexusPag.');
  }
  return transaction;
}
