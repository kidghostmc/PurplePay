import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { createHmac, randomUUID } from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import { initializeDatabase } from '../lib/db.js';
import { createHandler } from '../api/app.js';
import { verifyWebhook, passwordHash, passwordValid, validateCharge } from '../lib/security.js';

test('webhook signature binds the raw body and timestamp', () => {
  const now = Date.now(), t = Math.floor(now / 1000), raw = Buffer.from('{ "amount": 50 }'), secret = 'test-only-webhook';
  const signature = `t=${t},v1=${createHmac('sha256', secret).update(`${t}.`).update(raw).digest('hex')}`;
  assert.equal(verifyWebhook(raw, signature, secret, now), true);
  assert.equal(verifyWebhook(Buffer.from('{"amount":50}'), signature, secret, now), false);
  assert.equal(verifyWebhook(raw, signature, secret, now + 301000), false);
  assert.equal(verifyWebhook(raw, `t=${t},v1=zz`, secret, now), false);
  assert.equal(verifyWebhook(raw, undefined, secret, now), false);
});
test('passwords are salted and charge amounts require integer cents', () => {
  const hash = passwordHash('test-only-password');
  assert.equal(passwordValid('test-only-password', hash), true);
  assert.equal(passwordValid('wrong', hash), false);
  assert.notEqual(hash, passwordHash('test-only-password'));
  for (const amountCents of [0, -100, 99, 100.5, '5000', 100000001]) {
    assert.throws(() => validateCharge({ requestId: randomUUID(), amountCents }));
  }
});

test('authenticated Pix lifecycle, idempotency, isolation and verified payment', async t => {
  const db = new PGlite();
  t.after(() => db.close());
  const sql = (parts, ...params) => {
    const text = parts.reduce((s, part, i) => s + (i ? `$${i}` : '') + part, '');
    return { text, params, then(resolve, reject) { return db.query(text, params).then(r => r.rows).then(resolve, reject); } };
  };
  sql.transaction = queries => db.transaction(async tx => {
    const result = [];
    for (const q of queries) result.push((await tx.query(q.text, q.params)).rows);
    return result;
  });
  await initializeDatabase(sql);
  process.env.APP_ORIGIN = 'https://purplepay-snowy.vercel.app';
  process.env.PURPLEPAY_ADMIN_PASSWORD = 'test-only-admin-password';
  process.env.NEXUS_API_KEY = 'test-only-api-key';
  process.env.NEXUS_WEBHOOK_SECRET = 'test-only-secret';
  const handler = createHandler({ getDatabase: async () => sql });
  async function request(action, body, cookie, extra = {}) {
    const raw = body === undefined ? '' : typeof body === 'string' ? body : JSON.stringify(body);
    const req = Readable.from(raw ? [Buffer.from(raw)] : []);
    req.url = `/api/app?action=${action}`;
    req.method = raw ? 'POST' : 'GET';
    req.headers = { origin: process.env.APP_ORIGIN, 'content-type': 'application/json', 'x-forwarded-for': '127.0.0.1', cookie, ...extra };
    const res = { headers: {}, setHeader(k,v) { this.headers[k.toLowerCase()] = v; }, end(value) { this.body = JSON.parse(value); } };
    await handler(req, res);
    return { ...res, cookie: res.headers['set-cookie']?.split(';')[0] };
  }
  assert.equal((await request('state')).statusCode, 401);
  assert.equal((await request('login', { user: 'admin', password: '123', role: 'mod' })).statusCode, 401);
  assert.equal((await request('login', {}, undefined, { origin: 'https://attacker.invalid' })).statusCode, 403);
  const login = await request('login', { user: 'admin', password: process.env.PURPLEPAY_ADMIN_PASSWORD, role: 'mod' });
  assert.equal(login.statusCode, 200);
  assert.match(login.headers['set-cookie'], /HttpOnly; Secure; SameSite=Strict/);
  const adminCookie = login.cookie;
  const createAtt = await request('attendant', { nome: 'Atendente teste', user: 'atendente', password: 'test-only-attendant', tel: '11999999999', pct: 10 }, adminCookie);
  assert.equal(createAtt.statusCode, 200);
  const atLogin = await request('login', { user: 'atendente', password: 'test-only-attendant', role: 'at' });
  assert.equal(atLogin.statusCode, 200);
  const atCookie = atLogin.cookie;
  const snapshot = await request('state', undefined, adminCookie);
  assert.equal(snapshot.body.attendants.length, 1);
  assert.equal('password_hash' in snapshot.body.attendants[0], false);
  assert.equal((await request('settings', { meta: 10 }, atCookie)).statusCode, 403);
  const upstream = new Map(); let creates = 0;
  const originalFetch = global.fetch;
  t.after(() => { global.fetch = originalFetch; });
  global.fetch = async (url, options) => {
    assert.equal(new URL(url).origin, 'https://nexuspag.com');
    assert.equal(options.headers['x-api-key'], 'test-only-api-key');
    if (options.method === 'POST') {
      creates++; const b = JSON.parse(options.body);
      assert.equal(b.split, undefined); assert.equal(b.splits, undefined); assert.equal(b.shop_id, undefined);
      assert.equal(b.webhook_url, 'https://purplepay-snowy.vercel.app/api/nexus/webhook');
      const tx = upstream.get(b.external_id) || { id: randomUUID(), external_id: b.external_id, amount: b.amount, status: 'pending',
        pix_copia_cola: '000201-test-only', qr_code_base64: 'data:image/png;base64,AAAA', expires_at: new Date(Date.now()+1800000).toISOString() };
      upstream.set(b.external_id, tx); upstream.set(tx.id, tx);
      return new Response(JSON.stringify({ success: true, transaction: tx }), { status: 201 });
    }
    const tx = upstream.get(decodeURIComponent(new URL(url).pathname.split('/').pop()));
    return new Response(JSON.stringify(tx || {}), { status: tx ? 200 : 404 });
  };
  const id = randomUUID(), payload = { requestId: id, amountCents: 5000, aid: null };
  assert.equal((await request('pix', payload)).statusCode, 401);
  const generated = await request('pix', payload, adminCookie);
  assert.equal(generated.statusCode, 200);
  assert.equal(generated.body.status, 'pending');
  assert.equal((await request('pix', payload, adminCookie)).body.id, id);
  assert.equal(creates, 1);
  assert.equal((await request('pix', { ...payload, amountCents: 6000 }, adminCookie)).statusCode, 409);
  assert.equal((await request(`status&id=${id}`, undefined, atCookie)).statusCode, 404);
  const atId = randomUUID();
  const atCharge = await request('pix', { requestId: atId, amountCents: 2000, aid: null }, atCookie);
  assert.equal(atCharge.body.aid, atLogin.body.session.aid, 'server forces attendant identity');
  assert.equal(atCharge.body.pct, 10);
  const tx = upstream.get('purplepay-'+id);
  const webhookBody = JSON.stringify({ event: 'payment.confirmed', status: 'paid', transaction_id: tx.id, external_id: tx.external_id, amount: tx.amount });
  const timestamp = Math.floor(Date.now()/1000);
  const signature = `t=${timestamp},v1=${createHmac('sha256',process.env.NEXUS_WEBHOOK_SECRET).update(`${timestamp}.${webhookBody}`).digest('hex')}`;
  assert.equal((await request('webhook', webhookBody)).statusCode, 401);
  assert.equal((await request('webhook', webhookBody, undefined, { 'x-webhook-signature': signature })).statusCode, 503, 'signed event alone cannot mark unpaid upstream charge paid');
  tx.status = 'paid'; tx.paid_at = new Date().toISOString(); tx.fee = 2.5; tx.net_amount = 47.5;
  tx.amount = 60;
  assert.equal((await request('webhook', webhookBody, undefined, { 'x-webhook-signature': signature })).statusCode, 502);
  assert.equal((await request('state', undefined, adminCookie)).body.sales.length, 0);
  tx.amount = 50;
  for (let n=0;n<2;n++) assert.equal((await request('webhook', webhookBody, undefined, { 'x-webhook-signature': signature })).statusCode, 200);
  const paid = await request('state', undefined, adminCookie);
  assert.equal(paid.body.sales.length, 1);
  assert.equal(paid.body.sales[0].valor, 50);
  assert.equal(paid.body.sales[0].net, 47.5);
  assert.equal((await request('state', undefined, atCookie)).body.sales.length, 0);
  assert.equal((await request('logout', {}, adminCookie)).statusCode, 200);
  assert.equal((await request('state', undefined, adminCookie)).statusCode, 401);
});
