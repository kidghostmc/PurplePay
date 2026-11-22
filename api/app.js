import { randomBytes } from 'node:crypto';
import { database, limit } from '../lib/db.js';
import { AppError, digest, equal, passwordHash, passwordValid, requireOrigin, verifyWebhook,
  validateCharge, transactionData, matchTransaction, cents } from '../lib/security.js';

export const config = { api: { bodyParser: false } };
const COOKIE = '__Host-purplepay';
const publicUser = row => ({ id: row.id, nome: row.nome, pct: Number(row.pct), tel: row.tel, user: row.username, active: row.active });
const identity = session => session.role === 'mod' ? 'admin' : `at:${session.aid}`;
function reply(res, status, data) { res.statusCode = status; res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.end(JSON.stringify(data)); }
function method(req, expected) { if (req.method !== expected) throw new AppError(405, 'Método não permitido.'); }
function origin() {
  const value = process.env.APP_ORIGIN;
  if (!value || new URL(value).origin !== value || !value.startsWith('https://')) {
    throw new AppError(503, 'O administrador precisa concluir a configuração do serviço.');
  }
  return value;
}
function gatewayReady() {
  origin();
  if (!process.env.NEXUS_API_KEY || !process.env.NEXUS_WEBHOOK_SECRET) {
    throw new AppError(503, 'O administrador precisa concluir a conexão com a NexusPag.');
  }
}
async function rawBody(req) {
  let length = 0; const chunks = [];
  for await (const chunk of req) {
    length += chunk.length;
    if (length > 65536) throw new AppError(413, 'Requisição muito grande.');
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}
function parse(raw) {
  try { return JSON.parse(raw.toString('utf8')); }
  catch { throw new AppError(400, 'JSON inválido.'); }
}
async function sessionFor(req, sql) {
  const cookie = String(req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(`${COOKIE}=`));
  const token = cookie?.slice(COOKIE.length + 1);
  if (!/^[a-f0-9]{64}$/.test(token || '')) throw new AppError(401, 'Entre para continuar.');
  const [session] = await sql`SELECT s.role, s.aid FROM pp_sessions s WHERE token_hash=${digest(token)} AND expires_at > now()
    AND (s.role='mod' OR EXISTS(SELECT 1 FROM pp_attendants a WHERE a.id=s.aid AND a.active=true))`;
  if (!session) throw new AppError(401, 'Sua sessão expirou. Entre novamente.');
  return { ...session, tokenHash: digest(token) };
}
function admin(session) { if (session.role !== 'mod') throw new AppError(403, 'Acesso restrito ao administrador.'); }
export async function nexus(path, options = {}) {
  gatewayReady();
  let response;
  try {
    response = await fetch(`https://nexuspag.com${path}`, {
      ...options, redirect: 'error', signal: AbortSignal.timeout(20000),
      headers: { 'x-api-key': process.env.NEXUS_API_KEY, 'Content-Type': 'application/json' }
    });
  } catch { throw new AppError(502, 'A NexusPag não respondeu. Tente consultar esta mesma cobrança novamente.'); }
  if (response.status === 404) throw new AppError(404, 'Cobrança ainda não localizada na NexusPag.');
  if (!response.ok) throw new AppError(response.status === 401 ? 503 : 502,
    response.status === 401 ? 'A credencial da NexusPag precisa ser revisada pelo administrador.' : 'Não foi possível concluir a solicitação à NexusPag. Tente novamente.');
  let data;
  try { data = await response.json(); } catch { throw new AppError(502, 'Resposta inválida da NexusPag.'); }
  return transactionData(data);
}
async function saveTransaction(sql, order, transaction) {
  matchTransaction(order, transaction);
  const fee = transaction.fee == null ? null : cents(transaction.fee);
  const net = transaction.net_amount == null ? null : cents(transaction.net_amount);
  const paidAt = transaction.status === 'paid' ? transaction.paid_at : null;
  if (transaction.status === 'paid' && (!paidAt || !Number.isFinite(Date.parse(paidAt)))) {
    throw new AppError(502, 'Confirmação de pagamento incompleta.');
  }
  const [updated] = await sql`UPDATE pp_orders SET nexus_id=${String(transaction.id)},
    status=CASE WHEN status='paid' THEN 'paid' ELSE ${transaction.status} END,
    paid_at=COALESCE(paid_at,${paidAt}), fee_cents=COALESCE(${fee},fee_cents), net_cents=COALESCE(${net},net_cents),
    pix_code=COALESCE(${transaction.pix_copia_cola || null},pix_code),
    qr_image=COALESCE(${transaction.qr_code_base64 || null},qr_image),
    expires_at=COALESCE(${transaction.expires_at || null},expires_at), last_checked_at=now()
    WHERE id=${order.id} RETURNING *`;
  return updated;
}
async function reconcile(sql, order) {
  const transaction = await nexus(`/api/pix/${encodeURIComponent(order.nexus_id || order.external_id)}`);
  return saveTransaction(sql, order, transaction);
}
function publicOrder(row) {
  return { id: row.id, status: row.status, amount: row.amount_cents / 100, pixCode: row.pix_code,
    qrImage: row.qr_image, expiresAt: row.expires_at, aid: row.aid, pct: Number(row.pct) };
}
async function loadOrder(sql, id, session) {
  if (!/^[a-f0-9-]{36}$/i.test(id || '')) throw new AppError(400, 'Cobrança inválida.');
  const [order] = await sql`SELECT * FROM pp_orders WHERE id=${id}`;
  if (!order || (session.role !== 'mod' && order.aid !== session.aid)) throw new AppError(404, 'Cobrança não encontrada.');
  return order;
}
async function login(req, res, sql, body) {
  const user = String(body.user || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (user.length > 80 || password.length > 256) throw new AppError(400, 'Credenciais inválidas.');
  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0];
  await limit(sql, `login-ip:${digest(ip)}`, 20, 900);
  await limit(sql, `login-user:${digest(user)}`, 10, 900);
  let role, aid = null;
  if (body.role === 'mod') {
    const expected = process.env.PURPLEPAY_ADMIN_PASSWORD;
    if (!expected || expected.length < 12) throw new AppError(503, 'O administrador precisa configurar uma senha de acesso com pelo menos 12 caracteres.');
    if (user !== 'admin' || !equal(password, expected)) throw new AppError(401, 'Usuário ou senha incorretos.');
    role = 'mod';
  } else if (body.role === 'at') {
    const [attendant] = await sql`SELECT * FROM pp_attendants WHERE username=${user} AND active=true`;
    // Always perform scrypt, including for unknown users.
    const hash = attendant?.password_hash || `00000000000000000000000000000000:${'0'.repeat(128)}`;
    if (!passwordValid(password, hash) || !attendant) throw new AppError(401, 'Usuário ou senha incorretos.');
    role = 'at'; aid = attendant.id;
  } else throw new AppError(400, 'Tipo de acesso inválido.');
  const token = randomBytes(32).toString('hex');
  await sql`INSERT INTO pp_sessions(token_hash,role,aid,expires_at) VALUES(${digest(token)},${role},${aid},now()+interval '12 hours')`;
  res.setHeader('Set-Cookie', `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=43200`);
  return { session: { role, aid } };
}
async function state(sql, session) {
  const [users, orders, settings, pending] = await sql.transaction([
    sql`SELECT id,nome,pct,tel,username,active FROM pp_attendants WHERE (${session.role}='mod' OR id=${session.aid}) ORDER BY id`,
    sql`SELECT id,aid,pct,amount_cents,paid_at,fee_cents,net_cents FROM pp_orders WHERE status='paid'
      AND (${session.role}='mod' OR aid=${session.aid}) ORDER BY paid_at DESC`,
    sql`SELECT meta FROM pp_settings WHERE id=1`,
    sql`SELECT id,status,amount_cents,aid,pct,expires_at FROM pp_orders WHERE status IN ('pending','creating')
      AND (${session.role}='mod' OR aid=${session.aid}) ORDER BY created_at DESC LIMIT 30`
  ], { isolationLevel: 'RepeatableRead', readOnly: true });
  return { session: { role: session.role, aid: session.aid }, attendants: users.map(publicUser),
    sales: orders.map(o => ({ id: o.id, aid: o.aid, pct: Number(o.pct), valor: o.amount_cents / 100,
      t: Date.parse(o.paid_at), fee: (o.fee_cents || 0) / 100, net: o.net_cents == null ? null : o.net_cents / 100 })),
    meta: settings[0].meta, pending: pending.map(publicOrder),
    gatewayConfigured: !!(process.env.NEXUS_API_KEY && process.env.NEXUS_WEBHOOK_SECRET) };
}
async function attendant(sql, session, body) {
  admin(session);
  if (body.disable) {
    if (!Number.isSafeInteger(body.id)) throw new AppError(400, 'Atendente inválido.');
    await sql.transaction([
      sql`UPDATE pp_attendants SET active=false WHERE id=${body.id}`,
      sql`DELETE FROM pp_sessions WHERE aid=${body.id}`
    ]);
    return { ok: true };
  }
  const nome = String(body.nome || '').trim(), user = String(body.user || '').trim().toLowerCase();
  const tel = String(body.tel || '').replace(/\D/g, ''), pct = Number(body.pct), password = String(body.password || '');
  if (nome.length < 2 || nome.length > 100 || !/^[a-z0-9._-]{3,40}$/.test(user) || user === 'admin' ||
      !/^[0-9]{10,11}$/.test(tel) || !Number.isFinite(pct) || pct <= 0 || pct > 100 || Math.abs(pct * 100 - Math.round(pct * 100)) > 0.00001) {
    throw new AppError(400, 'Confira nome, usuário, telefone e comissão do atendente.');
  }
  if ((!body.id || password) && (password.length < 12 || password.length > 256)) throw new AppError(400, 'Use uma senha entre 12 e 256 caracteres.');
  try {
    if (body.id) {
      if (!Number.isSafeInteger(body.id)) throw new AppError(400, 'Atendente inválido.');
      const [old] = await sql`SELECT * FROM pp_attendants WHERE id=${body.id} AND active=true`;
      if (!old) throw new AppError(404, 'Atendente não encontrado.');
      await sql.transaction([
        sql`UPDATE pp_attendants SET nome=${nome},pct=${pct},tel=${tel},username=${user},
          password_hash=${password ? passwordHash(password) : old.password_hash} WHERE id=${body.id}`,
        sql`DELETE FROM pp_sessions WHERE aid=${body.id}`
      ]);
    } else await sql`INSERT INTO pp_attendants(nome,pct,tel,username,password_hash) VALUES(${nome},${pct},${tel},${user},${passwordHash(password)})`;
  } catch (error) { if (error.code === '23505') throw new AppError(409, 'Esse usuário já está em uso.'); throw error; }
  return { ok: true };
}
async function createPix(sql, session, body) {
  gatewayReady(); validateCharge(body);
  await limit(sql, `pix:${identity(session)}`, 60, 600);
  const aid = session.role === 'at' ? session.aid : body.aid || null;
  if (aid !== null && !Number.isSafeInteger(aid)) throw new AppError(400, 'Atendente inválido.');
  let pct = 0;
  if (aid) {
    const [att] = await sql`SELECT pct FROM pp_attendants WHERE id=${aid} AND active=true`;
    if (!att) throw new AppError(400, 'Atendente não disponível.'); pct = Number(att.pct);
  }
  const externalId = `purplepay-${body.requestId}`;
  await sql`INSERT INTO pp_orders(id,external_id,creator,aid,pct,amount_cents)
    VALUES(${body.requestId},${externalId},${identity(session)},${aid},${pct},${body.amountCents}) ON CONFLICT(id) DO NOTHING`;
  const [order] = await sql`SELECT * FROM pp_orders WHERE id=${body.requestId}`;
  if (order.creator !== identity(session) || order.amount_cents !== body.amountCents || order.aid !== aid) {
    throw new AppError(409, 'Esse identificador já pertence a outra cobrança.');
  }
  if (order.nexus_id) return publicOrder(order);
  const tx = await nexus('/api/pix/create', { method: 'POST', body: JSON.stringify({
    amount: order.amount_cents / 100, description: 'PurplePay', external_id: order.external_id,
    webhook_url: `${origin()}/api/nexus/webhook`, expiration: 1800
  }) });
  return publicOrder(await saveTransaction(sql, order, tx));
}
async function webhook(req, res, raw, getDatabase) {
  method(req, 'POST');
  if (!process.env.NEXUS_WEBHOOK_SECRET) throw new AppError(503, 'Webhook ainda não configurado.');
  if (!verifyWebhook(raw, req.headers['x-webhook-signature'], process.env.NEXUS_WEBHOOK_SECRET)) {
    throw new AppError(401, 'Assinatura inválida.');
  }
  const body = parse(raw);
  if (body.event !== 'payment.confirmed') return reply(res, 200, { received: true, ignored: true });
  if (body.status !== 'paid' || typeof body.external_id !== 'string' || !body.external_id.startsWith('purplepay-')) {
    return reply(res, 200, { received: true, ignored: true });
  }
  const sql = await getDatabase();
  const [order] = await sql`SELECT * FROM pp_orders WHERE external_id=${body.external_id}`;
  if (!order) return reply(res, 200, { received: true, ignored: true });
  if (order.status !== 'paid') {
    // Confirm against the provider API even after validating the webhook signature.
    let updated;
    try { updated = await reconcile(sql, order); }
    catch (error) {
      if (error.status === 404) throw new AppError(503, 'Aguardando disponibilidade da cobrança para confirmação.');
      throw error;
    }
    if (updated.status !== 'paid') throw new AppError(503, 'Pagamento ainda não confirmado na consulta.');
  }
  return reply(res, 200, { received: true });
}
export function createHandler({ getDatabase = database } = {}) {
return async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  const url = new URL(req.url, 'https://purplepay.invalid');
  const action = url.pathname === '/api/nexus/webhook' ? 'webhook' : url.searchParams.get('action');
  try {
    if (action === 'health') {
      method(req, 'GET');
      return reply(res, 200, { ok: true, configured: !!(process.env.DATABASE_URL && process.env.APP_ORIGIN &&
        process.env.NEXUS_API_KEY && process.env.NEXUS_WEBHOOK_SECRET && process.env.PURPLEPAY_ADMIN_PASSWORD?.length >= 12) });
    }
    if (!['webhook','login','logout','state','attendant','settings','pix','status'].includes(action)) throw new AppError(404, 'Recurso não encontrado.');
    const raw = req.method === 'POST' ? await rawBody(req) : Buffer.alloc(0);
    if (action === 'webhook') return await webhook(req, res, raw, getDatabase);
    if (req.method === 'POST') {
      requireOrigin(req, origin());
      if (!String(req.headers['content-type'] || '').startsWith('application/json')) throw new AppError(415, 'Envie JSON.');
    }
    const sql = await getDatabase();
    const body = req.method === 'POST' ? parse(raw) : {};
    if (action === 'login') { method(req, 'POST'); return reply(res, 200, await login(req, res, sql, body)); }
    const session = await sessionFor(req, sql);
    if (action === 'logout') {
      method(req, 'POST'); await sql`DELETE FROM pp_sessions WHERE token_hash=${session.tokenHash}`;
      res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
      return reply(res, 200, { ok: true });
    }
    if (action === 'state') { method(req, 'GET'); return reply(res, 200, await state(sql, session)); }
    if (action === 'attendant') { method(req, 'POST'); return reply(res, 200, await attendant(sql, session, body)); }
    if (action === 'settings') {
      method(req, 'POST'); admin(session);
      if (!Number.isSafeInteger(body.meta) || body.meta < 1 || body.meta > 1000000000) throw new AppError(400, 'Meta inválida.');
      await sql`UPDATE pp_settings SET meta=${body.meta} WHERE id=1`; return reply(res, 200, { ok: true });
    }
    if (action === 'pix') { method(req, 'POST'); return reply(res, 200, await createPix(sql, session, body)); }
    if (action === 'status') {
      method(req, 'GET'); gatewayReady();
      let order = await loadOrder(sql, url.searchParams.get('id'), session);
      if (order.status !== 'paid' && (!order.last_checked_at || Date.now() - Date.parse(order.last_checked_at) > 8000)) {
        try { order = await reconcile(sql, order); }
        catch (error) { if (error.status !== 404 || order.status !== 'creating') throw error; }
      }
      return reply(res, 200, publicOrder(order));
    }
  } catch (error) {
    // Never log bodies, provider responses, credentials, or database connection strings.
    if (!(error instanceof AppError)) console.error('PurplePay request failed', { action, code: String(error.code || 'INTERNAL').slice(0,40) });
    return reply(res, error.status || 503, { error: error instanceof AppError ? error.message : 'Serviço temporariamente indisponível. Tente novamente.' });
  }
}
}
export default createHandler();
