/* بک‌اند کامل بازارچه آیدی — Vercel Serverless + Upstash Redis + بات سروش‌پلاس */
const crypto = require('crypto');
const E = process.env;
const TOKEN = (E.BOT_TOKEN || '').trim();
/* سروش‌پلاس برای امضای initData فقط بخش بعد از «:» توکن را به‌کار می‌برد */
const SIGN_KEY = TOKEN.includes(':') ? TOKEN.split(':').pop() : TOKEN;
/* توکن باتِ دوم (اختیاری) فقط برای تأیید امضا: BOT_TOKEN_2 */
const KEYS = [...new Set([SIGN_KEY, TOKEN, ...String(E.BOT_TOKEN_2 || '').split(',').map(x => x.trim()).filter(Boolean).flatMap(t => [t.split(':').pop(), t])])];
const SECRET = E.WEBHOOK_SECRET || '';
const ADMIN = String(E.ADMIN_ID || '');
const CARD = E.CARD || 'شماره کارت تنظیم نشده';
const BOTU = (E.BOT_USERNAME || '').replace(/^@/, '');
const FEE = Number(E.FEE_PERCENT || 5);
const LOCK = Number(E.LOCK_HOURS || 24) * 3600;
const PAYWAIT = 2 * 3600;
const RURL = E.UPSTASH_REDIS_REST_URL || E.KV_REST_API_URL;
const RTOK = E.UPSTASH_REDIS_REST_TOKEN || E.KV_REST_API_TOKEN;

const now = () => Math.floor(Date.now() / 1000);
const err = (status, message, code) => Object.assign(new Error(message), { status, code });
const fa = n => Number(n).toLocaleString('fa-IR');

/* ---------- Redis (REST) ---------- */
async function R(...cmd) {
  const r = await fetch(RURL, { method: 'POST', headers: { Authorization: 'Bearer ' + RTOK }, body: JSON.stringify(cmd) });
  const j = await r.json();
  if (j.error) throw new Error('Redis: ' + j.error);
  return j.result;
}
const getj = async k => { const v = await R('GET', k); return v ? JSON.parse(v) : null; };
const setj = (k, v, ex) => (ex ? R('SET', k, JSON.stringify(v), 'EX', ex) : R('SET', k, JSON.stringify(v)));
async function mget(keys) {
  if (!keys.length) return [];
  const r = await R('MGET', ...keys);
  return r.map(x => (x ? JSON.parse(x) : null));
}
const allListings = async () => (await mget((await R('SMEMBERS', 'lsts')).map(i => 'lst:' + i))).filter(Boolean);
const allDeals = async () => (await mget((await R('SMEMBERS', 'deals')).map(i => 'deal:' + i))).filter(Boolean);

/* ---------- بات سروش‌پلاس ---------- */
async function tg(method, p) {
  try {
    const r = await fetch(`https://api.splus.ir/bot${TOKEN}/${method}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(p)
    });
    return await r.json();
  } catch (e) { return null; }
}
const say = (id, text) => (id ? tg('sendMessage', { chat_id: id, text }) : null);
const tellAdmin = text => say(ADMIN, text);

/* بررسی امضا؛ چند شکل مختلف نوشتن JSON کاربر (slash و یونی‌کد) هم امتحان می‌شود */
function userForms(u) {
  const out = [u];
  try {
    const base = JSON.stringify(JSON.parse(u));
    const esc = x => x.replace(/[\u0080-\uffff]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
    const sl = x => x.replace(/\//g, '\\/');
    out.push(base, sl(base), esc(base), esc(sl(base)), u.replace(/\\\//g, '/'), esc(u), sl(u));
  } catch (e) {}
  return [...new Set(out)];
}
function sigOk(entries, hash) {
  const ui = entries.findIndex(e => e[0] === 'user');
  const forms = ui >= 0 ? userForms(entries[ui][1]) : [null];
  for (const f of forms) {
    const ents = entries.map(e => [e[0], e[0] === 'user' && f !== null ? f : e[1]]);
    const dcs = ents.sort((x, y) => (x[0] < y[0] ? -1 : 1)).map(([k, v]) => k + '=' + v).join('\n');
    for (const k of KEYS) {
      const sec = crypto.createHmac('sha256', 'WebAppData').update(k).digest();
      const h = crypto.createHmac('sha256', sec).update(dcs).digest('hex');
      if (h.length === hash.length && crypto.timingSafeEqual(Buffer.from(h), Buffer.from(hash))) return true;
    }
  }
  return false;
}

/* ---------- احراز هویت ----------
   راه ۱: initData امضاشدهٔ سروش‌پلاس (اگر معتبر بود)
   راه ۲: نشست (session) که با ارسال کد به بات ساخته شده؛ به امضای سروش‌پلاس وابسته نیست */
const sha = x => crypto.createHash('sha256').update(String(x)).digest('hex');
const SESS_TTL = 30 * 86400;
const CODE_ABC = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const newLoginCode = () => Array.from({ length: 8 }, () => CODE_ABC[crypto.randomInt(CODE_ABC.length)]).join('');

function initAuth(req) {
  const init = req.headers['x-init'] || '';
  if (!init) return null;
  try {
    const p = new URLSearchParams(init);
    const hash = p.get('hash');
    let ok = false;
    if (hash) {
      p.delete('hash');
      ok = sigOk([...p.entries()], hash);
    }
    if (!ok && E.TRUST_INITDATA !== '1') return null;   /* TRUST_INITDATA فقط برای تست */
    const u = p.get('user') ? JSON.parse(p.get('user')) : null;
    if (!u || !u.id) return null;
    return { id: String(u.id), username: String(u.username || '').toLowerCase() };
  } catch (e) { return null; }
}
async function sessAuth(req) {
  const sid = String(req.headers['x-sess'] || '');
  if (!/^[a-f0-9]{48}$/.test(sid)) return null;
  const r = await getj('sess:' + sha(sid));
  return r && r.id ? { id: String(r.id), username: String(r.username || '').toLowerCase() } : null;
}
async function auth(req) {
  const u = initAuth(req) || (await sessAuth(req));
  if (!u) throw err(401, 'برای ورود، کد را برای بات بفرستید', 'login');
  return u;
}

/* ---------- کمکی‌ها ---------- */
async function relist(d) {
  const l = await getj('lst:' + d.lid);
  if (l && l.status === 'reserved') { l.status = 'active'; await setj('lst:' + l.id, l); }
}
async function removeListing(lid) { await R('SREM', 'lsts', String(lid)); await R('DEL', 'lst:' + lid); }
async function saveDeal(d, patch) { Object.assign(d, patch, { upd: now() }); await setj('deal:' + d.id, d); }
const payoutOf = p => p - Math.round((p * FEE) / 100);

async function toDue(d, why) {
  await saveDeal(d, { status: 'due' });
  await tellAdmin(`💰 معامله #${d.id} آمادهٔ واریز به فروشنده است (${why})\nآیدی: @${d.uname}\nمبلغ واریزی: ${fa(payoutOf(d.price))} تومان\nفروشنده: ${d.seller}\nپس از واریز دستی بفرستید: /paid ${d.id}`);
  await say(d.sellerChat, `✅ معامله #${d.id} تأیید شد. مبلغ ${fa(payoutOf(d.price))} تومان به‌زودی واریز می‌شود.`);
}

async function sweep() {
  const ds = await allDeals();
  for (const d of ds) {
    if (d.status === 'wait_pay' && now() - d.ts > PAYWAIT) {
      await saveDeal(d, { status: 'cancel' }); await relist(d);
      await say(d.buyerChat, `⏱ معامله #${d.id} به دلیل عدم پرداخت لغو شد.`);
    } else if (d.status === 'handed' && d.lockEnd && now() >= d.lockEnd) {
      await toDue(d, 'پایان قفل زمانی');
    }
  }
}

/* ---------- مسیریابی ---------- */
module.exports = async (req, res) => {
  try {
    if (!TOKEN || !RURL || !RTOK) throw err(500, 'تنظیمات سرور ناقص است (BOT_TOKEN یا Redis)');
    const u = new URL(req.url, 'http://x');
    const parts = u.pathname.replace(/^\/api\/?/, '').split('/').filter(Boolean);
    const out = await route(req, parts);
    res.status(200).json(out ?? { ok: true });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.status ? e.message : 'خطای داخلی سرور: ' + e.message, code: e.code });
  }
};

async function route(req, parts) {
  const [a, b, c] = parts, M = req.method, body = req.body || {};
  if (a === 'webhook') return webhook(req, b);
  if (a === 'setup') {
    if (!SECRET || b !== SECRET) throw err(403, 'forbidden');
    const url = `https://${req.headers.host}/api/webhook/${SECRET}`;
    return { url, result: await tg('setWebhook', { url }) };
  }
  if (a === 'ping') return { version: 'v7-login', hasToken: !!TOKEN, hasSecret: !!SECRET, hasAdmin: !!ADMIN, hasRedis: !!(RURL && RTOK) };
  if (a === 'cron') { await sweep(); return { ok: true }; }

  /* --- ورود با کد داخل چت بات (بدون نیاز به امضای initData) --- */
  if (a === 'login' && b === 'start' && M === 'POST') {
    const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'x';
    const n = await R('INCR', 'rl:' + ip);
    if (n === 1) await R('EXPIRE', 'rl:' + ip, 60);
    if (n > 12) throw err(429, 'تعداد درخواست زیاد است؛ کمی بعد تلاش کنید');
    const code = newLoginCode(), sid = crypto.randomBytes(24).toString('hex');
    await setj('lgc:' + code, { h: sha(sid) }, 600);
    return { code, sid, ttl: 600, bot: BOTU };
  }
  if (a === 'login' && b === 'status' && M === 'GET') {
    const sid = String(req.headers['x-sess'] || '');
    if (!/^[a-f0-9]{48}$/.test(sid)) return { state: 'wait' };
    return { state: (await getj('sess:' + sha(sid))) ? 'ok' : 'wait' };
  }

  const user = await auth(req);

  /* --- لیست آگهی‌ها --- */
  if (a === 'listings' && M === 'GET') {
    await sweep();
    const ls = await allListings();
    const act = ls.filter(l => l.status === 'active').sort((x, y) => y.ts - x.ts);
    const sold = ls.filter(l => l.status === 'sold').sort((x, y) => (y.soldTs || 0) - (x.soldTs || 0));
    const done = await mget(act.map(l => 'done:' + l.seller));
    return {
      stats: { active: act.length, sold: sold.length, volume: sold.reduce((s, l) => s + l.price, 0) },
      items: act.map((l, i) => ({ id: l.id, uname: l.uname, price: l.price, descr: l.descr, done: done[i] || 0, mine: l.seller === user.id })),
      sold: sold.slice(0, 30).map(l => ({ uname: l.uname, price: l.price }))
    };
  }

  /* --- ثبت آگهی: شروع تأیید مالکیت --- */
  if (a === 'verify' && b === 'start' && M === 'POST') {
    const uname = String(body.uname || '').trim().replace(/^@/, '').toLowerCase();
    const price = parseInt(body.price, 10);
    if (!/^[a-z][a-z0-9_]{2,31}$/.test(uname)) throw err(400, 'آیدی معتبر نیست');
    if (!price || price < 1000 || price > 1e10) throw err(400, 'قیمت معتبر نیست (حداقل ۱٬۰۰۰ تومان)');
    const ex = (await allListings()).find(l => l.uname === uname && l.status !== 'sold');
    if (ex) throw err(409, 'این آیدی قبلاً آگهی شده است');
    const code = String(1000 + crypto.randomInt(9000));
    await setj('ver:' + user.id, { uname, price, descr: String(body.descr || '').slice(0, 300), code, exp: now() + 600, state: 'wait' }, 1200);
    return { code, ttl: 600, bot: BOTU };
  }
  if (a === 'verify' && b === 'status' && M === 'GET') {
    const v = await getj('ver:' + user.id);
    if (!v) return { state: 'expired' };
    if (v.state === 'wait' && now() > v.exp) return { state: 'expired' };
    return { state: v.state, why: v.why };
  }

  /* --- معاملات --- */
  if (a === 'deals' && !b && M === 'GET') {
    await sweep();
    const ds = (await allDeals()).filter(d => d.buyer === user.id || d.seller === user.id).sort((x, y) => y.ts - x.ts);
    return { items: ds.map(d => ({ id: d.id, uname: d.uname, price: d.price, status: d.status, role: d.buyer === user.id ? 'buyer' : 'seller' })) };
  }
  if (a === 'deals' && !b && M === 'POST') {
    const lid = String(body.lid || '');
    const got = await R('SET', 'lock:' + lid, '1', 'NX', 'EX', 10);
    if (!got) throw err(409, 'در حال پردازش است، چند ثانیه بعد تلاش کنید');
    const l = await getj('lst:' + lid);
    if (!l || l.status !== 'active') throw err(409, 'این آیدی دیگر موجود نیست');
    if (l.seller === user.id) throw err(400, 'آگهی خودتان را نمی‌توانید بخرید');
    const id = await R('INCR', 'seq');
    const d = { id, lid: l.id, uname: l.uname, price: l.price, buyer: user.id, buyerChat: user.id, seller: l.seller, sellerChat: l.sellerChat, status: 'wait_pay', ts: now() };
    l.status = 'reserved';
    await setj('lst:' + l.id, l); await setj('deal:' + id, d); await R('SADD', 'deals', String(id));
    await say(l.sellerChat, `🛒 برای آیدی @${l.uname} خریدار پیدا شد (معامله #${id}). پس از تأیید پرداخت، خبر می‌دهیم.`);
    return { id };
  }
  if (a === 'deals' && b) {
    await sweep();
    const d = await getj('deal:' + b);
    if (!d) throw err(404, 'معامله پیدا نشد');
    const isB = d.buyer === user.id, isS = d.seller === user.id;
    if (!isB && !isS) throw err(403, 'دسترسی ندارید');
    if (c === 'act' && M === 'POST') {
      const x = body.act;
      if (x === 'cancel' && isB && d.status === 'wait_pay') { await saveDeal(d, { status: 'cancel' }); await relist(d); }
      else if (x === 'handed' && isS && d.status === 'paid') {
        await saveDeal(d, { status: 'handed', lockEnd: now() + LOCK });
        await say(d.buyerChat, `📦 فروشنده آیدی @${d.uname} را تحویل داد. تا ${fa(LOCK / 3600)} ساعت فرصت دارید داخل برنامک تأیید یا شکایت کنید.`);
        await tellAdmin(`ℹ️ معامله #${d.id}: فروشنده تحویل داد (قفل ${fa(LOCK / 3600)} ساعته).`);
      }
      else if (x === 'confirm' && isB && d.status === 'handed') await toDue(d, 'تأیید خریدار');
      else if (x === 'dispute' && isB && d.status === 'handed') {
        await saveDeal(d, { status: 'dispute' });
        await tellAdmin(`⚠️ شکایت در معامله #${d.id} (@${d.uname}, ${fa(d.price)} تومان)\nخریدار: ${d.buyer}\nفروشنده: ${d.seller}\nبعد از بررسی: /release ${d.id} (واریز به فروشنده) یا /refund ${d.id} (بازگشت پول خریدار)`);
        await say(d.sellerChat, `⚠️ خریدار برای معامله #${d.id} شکایت ثبت کرد؛ پشتیبانی بررسی می‌کند.`);
      }
      else throw err(400, 'این عملیات در وضعیت فعلی مجاز نیست');
      return { ok: true };
    }
    const lock = d.status === 'handed' ? Math.max(0, (d.lockEnd || 0) - now()) : 0;
    return { id: d.id, status: d.status, role: isB ? 'buyer' : 'seller', uname: d.uname, price: d.price, card: CARD, lock, payout: payoutOf(d.price) };
  }
  throw err(404, 'مسیر پیدا نشد');
}

/* ---------- وب‌هوک بات ---------- */
async function webhook(req, key) {
  if (!SECRET || key !== SECRET) throw err(403, 'forbidden');
  const m = (req.body || {}).message;
  if (!m || !m.from) return { ok: true };
  const fid = String(m.from.id), chat = (m.chat && m.chat.id) || m.from.id;
  const uname = String(m.from.username || '').toLowerCase();
  const text = String(m.text || '').trim();

  /* دستورهای ادمین */
  if (ADMIN && fid === ADMIN && text.startsWith('/') && !text.startsWith('/start')) {
    const [cmd, arg] = text.split(/\s+/);
    if (cmd === '/list') {
      const ds = (await allDeals()).filter(d => ['receipt', 'dispute', 'due'].includes(d.status));
      await say(chat, ds.length ? ds.map(d => `#${d.id} @${d.uname} ${fa(d.price)} — ${d.status}`).join('\n') : 'مورد بازی نیست.');
      return { ok: true };
    }
    const d = await getj('deal:' + arg);
    if (!d) { await say(chat, 'معامله پیدا نشد. مثال: ' + cmd + ' 12'); return { ok: true }; }
    if (cmd === '/ok' && ['receipt', 'wait_pay'].includes(d.status)) {
      await saveDeal(d, { status: 'paid' });
      await say(d.buyerChat, `✅ پرداخت معامله #${d.id} تأیید شد. منتظر تحویل آیدی از فروشنده باشید.`);
      await say(d.sellerChat, `✅ پرداخت خریدار برای @${d.uname} تأیید شد. آیدی را تحویل دهید و در برنامک «آیدی را تحویل دادم» را بزنید.`);
      await say(chat, 'انجام شد.');
    } else if (cmd === '/no' && ['receipt', 'wait_pay'].includes(d.status)) {
      await saveDeal(d, { status: 'cancel' }); await relist(d);
      await say(d.buyerChat, `❌ رسید معامله #${d.id} تأیید نشد و معامله لغو شد.`);
      await say(chat, 'لغو شد.');
    } else if (cmd === '/release' && ['dispute', 'handed'].includes(d.status)) {
      await toDue(d, 'تصمیم ادمین'); await say(chat, 'به وضعیت واریز رفت.');
    } else if (cmd === '/refund' && ['dispute', 'handed', 'paid'].includes(d.status)) {
      const was = d.status;
      await saveDeal(d, { status: 'cancel' });
      if (was === 'paid') await relist(d); else await removeListing(d.lid);
      await say(d.buyerChat, `↩️ معامله #${d.id} لغو شد و پول شما برگردانده می‌شود.`);
      await say(chat, `لغو شد. مبلغ ${fa(d.price)} تومان را دستی به خریدار برگردانید.`);
    } else if (cmd === '/paid' && d.status === 'due') {
      await saveDeal(d, { status: 'done' });
      const l = await getj('lst:' + d.lid);
      if (l) { l.status = 'sold'; l.soldTs = now(); await setj('lst:' + l.id, l); }
      await R('INCR', 'done:' + d.seller);
      await say(d.sellerChat, `💸 مبلغ معامله #${d.id} واریز شد. ممنون!`);
      await say(chat, 'ثبت شد.');
    } else await say(chat, `این دستور برای وضعیت فعلی (${d.status}) مجاز نیست.`);
    return { ok: true };
  }

  /* /start */
  if (text.startsWith('/start')) {
    await say(chat, `سلام 👋\nبرای خرید و فروش آیدی، دکمهٔ منوی بات را بزنید.\nاگر در حال ثبت آگهی هستید، کد ۴ رقمی را همین‌جا بفرستید.\n\nشناسهٔ عددی شما: ${fid}`);
    return { ok: true };
  }

  /* کد ورود به برنامک (۸ حرف/عدد) */
  if (/^[A-HJ-NP-Z2-9]{8}$/.test(text.toUpperCase())) {
    const c = text.toUpperCase(), L = await getj('lgc:' + c);
    if (!L) { await say(chat, 'این کد ورود معتبر نیست یا منقضی شده. از برنامک دوباره «کد ورود» بگیرید.'); return { ok: true }; }
    await setj('sess:' + L.h, { id: fid, username: uname }, SESS_TTL);
    await R('DEL', 'lgc:' + c);
    await say(chat, '✅ وارد شدید. به برنامک برگردید.\nاگر خودتان این کد را درخواست نکرده‌اید، هرگز آن را برای کسی نفرستید.');
    return { ok: true };
  }

  /* کد ۴ رقمی تأیید مالکیت */
  if (/^\d{4}$/.test(text)) {
    const v = await getj('ver:' + fid);
    if (!v || v.state !== 'wait' || now() > v.exp) { await say(chat, 'کد فعالی برای شما نیست. از برنامک دوباره «ثبت آگهی» بزنید.'); return { ok: true }; }
    if (text !== v.code) { await say(chat, '❌ کد اشتباه است.'); return { ok: true }; }
    if (!uname) { v.state = 'fail'; v.why = 'اکانت شما آیدی (username) ندارد'; await setj('ver:' + fid, v, 600); await say(chat, '❌ ' + v.why); return { ok: true }; }
    if (uname !== v.uname) {
      v.state = 'fail'; v.why = `آیدی این اکانت (@${uname}) با آیدی آگهی (@${v.uname}) یکی نیست`;
      await setj('ver:' + fid, v, 600); await say(chat, '❌ ' + v.why); return { ok: true };
    }
    const id = await R('INCR', 'seq');
    await setj('lst:' + id, { id, uname: v.uname, price: v.price, descr: v.descr, seller: fid, sellerChat: chat, status: 'active', ts: now() });
    await R('SADD', 'lsts', String(id));
    v.state = 'ok'; await setj('ver:' + fid, v, 600);
    await say(chat, `✅ مالکیت @${v.uname} تأیید و آگهی ثبت شد.`);
    return { ok: true };
  }

  /* رسید پرداخت (عکس یا فایل) */
  if (m.photo || m.document) {
    const ds = (await allDeals()).filter(d => d.buyer === fid && d.status === 'wait_pay').sort((x, y) => y.ts - x.ts);
    if (!ds.length) { await say(chat, 'معامله‌ای در انتظار پرداخت ندارید.'); return { ok: true }; }
    const d = ds[0];
    await saveDeal(d, { status: 'receipt' });
    if (ADMIN) {
      await tg('forwardMessage', { chat_id: ADMIN, from_chat_id: chat, message_id: m.message_id });
      await tellAdmin(`🧾 رسید معامله #${d.id}\nآیدی: @${d.uname}\nمبلغ: ${fa(d.price)} تومان\nتأیید: /ok ${d.id}\nرد: /no ${d.id}`);
    }
    await say(chat, `🧾 رسید معامله #${d.id} دریافت شد و در انتظار تأیید است.`);
    return { ok: true };
  }

  await say(chat, 'برای استفاده از بازارچه دکمهٔ منوی بات را بزنید.');
  return { ok: true };
}
