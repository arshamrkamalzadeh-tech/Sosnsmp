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
const say = (id, text, kb) => (id ? tg('sendMessage', kb ? { chat_id: id, text, reply_markup: { inline_keyboard: kb } } : { chat_id: id, text }) : null);

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
  /* شناسهٔ کاربر باید با شناسهٔ او در چت بات یکی باشد؛ پس به‌طور پیش‌فرض فقط نشست ورود با کد معتبر است */
  const u = (E.USE_INITDATA === '1' ? initAuth(req) : null) || (await sessAuth(req));
  if (!u) throw err(401, 'برای ورود، کد را برای بات بفرستید', 'login');
  return u;
}

/* ---------- کمکی‌ها ---------- */
const btn = (t, d) => [{ text: t, callback_data: d }];
const STL = { wait_pay: 'در انتظار پرداخت', receipt: 'رسید ارسال شد؛ در انتظار تأیید', paid: 'پرداخت تأیید شد؛ منتظر تحویل', handed: 'تحویل شد؛ قفل زمانی', dispute: 'در بررسی پشتیبانی', due: 'در حال واریز', done: 'تکمیل شد', cancel: 'لغو شد' };

async function relist(d) {
  const l = await getj('lst:' + d.lid);
  if (l && l.status === 'reserved') { l.status = 'active'; await setj('lst:' + l.id, l); }
}
async function removeListing(lid) { await R('SREM', 'lsts', String(lid)); await R('DEL', 'lst:' + lid); }
async function saveDeal(d, patch) { Object.assign(d, patch, { upd: now() }); await setj('deal:' + d.id, d); }
const payoutOf = p => p - Math.round((p * FEE) / 100);

async function toDue(d, why) {
  await saveDeal(d, { status: 'due' });
  await say(ADMIN, `💰 معامله #${d.id} آمادهٔ واریز به فروشنده است (${why})\nآیدی: @${d.uname}\nمبلغ واریزی: ${fa(payoutOf(d.price))} تومان\nفروشنده: ${d.seller}\nپس از واریز دستی، دکمهٔ زیر را بزنید.`, [btn('💸 واریز شد', 'a:paid:' + d.id)]);
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

/* قفل کوتاه برای جلوگیری از دوبار کلیک هم‌زمان؛ معاملهٔ تازه را برمی‌گرداند */
async function lockDeal(id) {
  if (!(await R('SET', 'alock:' + id, '1', 'NX', 'EX', 5))) throw err(409, 'در حال پردازش است؛ چند ثانیه بعد تلاش کنید');
  const d = await getj('deal:' + id);
  if (!d) throw err(404, 'معامله پیدا نشد');
  return d;
}

/* ---------- عملیات کاربر روی معامله (مشترک بین برنامک و بات) ---------- */
async function dealAct(id, uid, x) {
  const d = await lockDeal(id);
  try { return await dealActInner(d, uid, x); } finally { await R('DEL', 'alock:' + d.id).catch(() => {}); }
}
async function dealActInner(d, uid, x) {
  const isB = d.buyer === uid, isS = d.seller === uid;
  if (!isB && !isS) throw err(403, 'دسترسی ندارید');
  if (x === 'cancel' && isB && d.status === 'wait_pay') {
    await saveDeal(d, { status: 'cancel' }); await relist(d);
    await say(d.buyerChat, `معامله #${d.id} لغو شد.`);
  } else if (x === 'handed' && isS && d.status === 'paid') {
    await saveDeal(d, { status: 'handed', lockEnd: now() + LOCK });
    await say(d.buyerChat, `📦 فروشنده آیدی @${d.uname} را تحویل داد.\nتا ${fa(LOCK / 3600)} ساعت فرصت دارید تأیید یا شکایت کنید:`,
      [btn('✅ همه‌چیز درست است', 'x:confirm:' + d.id), btn('⚠️ شکایت دارم', 'x:dispute:' + d.id)]);
    await say(ADMIN, `ℹ️ معامله #${d.id}: فروشنده تحویل داد (قفل ${fa(LOCK / 3600)} ساعته).`);
  } else if (x === 'confirm' && isB && d.status === 'handed') {
    await toDue(d, 'تأیید خریدار');
  } else if (x === 'dispute' && isB && d.status === 'handed') {
    await saveDeal(d, { status: 'dispute' });
    await say(ADMIN, `⚠️ شکایت در معامله #${d.id} (@${d.uname}، ${fa(d.price)} تومان)\nخریدار: ${d.buyer}\nفروشنده: ${d.seller}\nپس از بررسی تصمیم بگیرید:`,
      [btn('💸 واریز به فروشنده', 'a:release:' + d.id), btn('↩️ بازگشت پول خریدار', 'a:refund:' + d.id)]);
    await say(d.sellerChat, `⚠️ خریدار برای معامله #${d.id} شکایت ثبت کرد؛ پشتیبانی بررسی می‌کند.`);
  } else throw err(400, 'این عملیات در وضعیت فعلی مجاز نیست');
}

/* ---------- عملیات ادمین (فقط با دکمه) ---------- */
async function adminAct(x, id) {
  const d = await lockDeal(id);
  try { return await adminActInner(x, d); } finally { await R('DEL', 'alock:' + d.id).catch(() => {}); }
}
async function adminActInner(x, d) {
  if (x === 'ok' && ['receipt', 'wait_pay'].includes(d.status)) {
    await saveDeal(d, { status: 'paid' });
    await say(d.buyerChat, `✅ پرداخت معامله #${d.id} تأیید شد. منتظر تحویل آیدی از فروشنده باشید.`);
    await say(d.sellerChat, `✅ پرداخت خریدار برای @${d.uname} تأیید شد.\nآیدی را تحویل دهید و بعد دکمهٔ زیر را بزنید:`, [btn('📦 تحویل دادم', 'x:handed:' + d.id)]);
    return `معامله #${d.id}: پرداخت تأیید شد.`;
  }
  if (x === 'no' && ['receipt', 'wait_pay'].includes(d.status)) {
    await saveDeal(d, { status: 'cancel' }); await relist(d);
    await say(d.buyerChat, `❌ رسید معامله #${d.id} تأیید نشد و معامله لغو شد.`);
    return `معامله #${d.id}: لغو شد.`;
  }
  if (x === 'release' && ['dispute', 'handed'].includes(d.status)) { await toDue(d, 'تصمیم ادمین'); return `معامله #${d.id}: به وضعیت واریز رفت.`; }
  if (x === 'refund' && ['dispute', 'handed', 'paid'].includes(d.status)) {
    const was = d.status;
    await saveDeal(d, { status: 'cancel' });
    if (was === 'paid') await relist(d); else await removeListing(d.lid);
    await say(d.buyerChat, `↩️ معامله #${d.id} لغو شد و پول شما برگردانده می‌شود.`);
    return `معامله #${d.id} لغو شد. مبلغ ${fa(d.price)} تومان را دستی به خریدار برگردانید.`;
  }
  if (x === 'paid' && d.status === 'due') {
    await saveDeal(d, { status: 'done' });
    const l = await getj('lst:' + d.lid);
    if (l) { l.status = 'sold'; l.soldTs = now(); await setj('lst:' + l.id, l); }
    await R('INCR', 'done:' + d.seller);
    await say(d.sellerChat, `💸 مبلغ معامله #${d.id} واریز شد. ممنون!`);
    await say(d.buyerChat, `معامله #${d.id} با موفقیت بسته شد.`);
    return `معامله #${d.id}: ثبت شد.`;
  }
  return `این عمل برای وضعیت فعلی معامله #${d.id} (${STL[d.status] || d.status}) مجاز نیست.`;
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
  if (a === 'webhook') {
    try { return await webhook(req, b); }
    catch (e) { if (e.status === 403) throw e; console.error('webhook error:', e && e.message); return { ok: true }; }
  }
  if (a === 'info') {
    if (!SECRET || b !== SECRET) throw err(403, 'forbidden');
    return await tg('getWebhookInfo', {});
  }
  if (a === 'setup') {
    if (!SECRET || b !== SECRET) throw err(403, 'forbidden');
    const url = `https://${req.headers.host}/api/webhook/${SECRET}`;
    return { url, result: await tg('setWebhook', { url, allowed_updates: ['message', 'callback_query'] }) };
  }
  if (a === 'ping') return { version: 'v9-buttons', hasToken: !!TOKEN, hasSecret: !!SECRET, hasAdmin: !!ADMIN, hasRedis: !!(RURL && RTOK) };
  if (a === 'cron') {
    await sweep();
    /* خودترمیمی: هر روز وب‌هوک بات دوباره ثبت می‌شود */
    if (SECRET) { const host = E.PUBLIC_HOST || req.headers.host; await tg('setWebhook', { url: `https://${host}/api/webhook/${SECRET}`, allowed_updates: ['message', 'callback_query'] }); }
    return { ok: true };
  }

  /* --- ورود با کد داخل چت بات --- */
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
      me: { username: user.username },
      stats: { active: act.length, sold: sold.length, volume: sold.reduce((s, l) => s + l.price, 0) },
      items: act.map((l, i) => ({ id: l.id, uname: l.uname, price: l.price, descr: l.descr, done: done[i] || 0, mine: l.seller === user.id })),
      sold: sold.slice(0, 30).map(l => ({ uname: l.uname, price: l.price }))
    };
  }

  /* --- ثبت آگهی: مالکیت = آیدیِ اکانتی که با آن (از طریق بات) وارد شده‌اید --- */
  if (a === 'listings' && M === 'POST') {
    const uname = String(body.uname || '').trim().replace(/^@/, '').toLowerCase();
    const price = parseInt(body.price, 10);
    if (!/^[a-z][a-z0-9_]{2,31}$/.test(uname)) throw err(400, 'آیدی معتبر نیست (فقط حروف انگلیسی، عدد و _ ؛ حداقل ۳ کاراکتر و شروع با حرف)');
    if (!price || price < 1000 || price > 1e10) throw err(400, 'قیمت معتبر نیست (حداقل ۱٬۰۰۰ تومان)');
    if (!user.username) throw err(400, 'اکانت شما آیدی (username) ندارد. ابتدا در تنظیمات سروش‌پلاس یک آیدی بگذارید و دوباره وارد شوید.');
    if (uname !== user.username) throw err(403, `فقط آیدی همین اکانت (@${user.username}) را می‌توانید آگهی کنید. برای فروش آیدی اکانت دیگر، با همان اکانت وارد شوید.`);
    const ex = (await allListings()).find(l => l.uname === uname && l.status !== 'sold');
    if (ex) throw err(409, 'این آیدی قبلاً آگهی شده است');
    const id = await R('INCR', 'seq');
    await setj('lst:' + id, { id, uname, price, descr: String(body.descr || '').slice(0, 300), seller: user.id, sellerChat: user.id, status: 'active', ts: now() });
    await R('SADD', 'lsts', String(id));
    return { ok: true, id };
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
    const d = { id, lid: l.id, uname: l.uname, price: l.price, buyer: user.id, buyerChat: user.id, seller: l.seller, sellerChat: l.sellerChat || l.seller, status: 'wait_pay', ts: now() };
    l.status = 'reserved';
    await setj('lst:' + l.id, l); await setj('deal:' + id, d); await R('SADD', 'deals', String(id));
    await say(d.sellerChat, `🛒 برای آیدی @${l.uname} خریدار پیدا شد (معامله #${id}). پس از تأیید پرداخت، خبر می‌دهیم.`);
    await say(d.buyerChat, `🧾 معامله #${id} برای @${l.uname}\nمبلغ: ${fa(l.price)} تومان\nکارت‌به‌کارت کنید به:\n${CARD}\n\nبعد از پرداخت، «عکس رسید» را همین‌جا برای بات بفرستید. (مهلت پرداخت ۲ ساعت)`, [btn('❌ لغو معامله', 'x:cancel:' + id)]);
    return { id };
  }
  if (a === 'deals' && b) {
    await sweep();
    if (c === 'act' && M === 'POST') { await dealAct(b, user.id, body.act); return { ok: true }; }
    const d = await getj('deal:' + b);
    if (!d) throw err(404, 'معامله پیدا نشد');
    const isB = d.buyer === user.id, isS = d.seller === user.id;
    if (!isB && !isS) throw err(403, 'دسترسی ندارید');
    const lock = d.status === 'handed' ? Math.max(0, (d.lockEnd || 0) - now()) : 0;
    return { id: d.id, status: d.status, role: isB ? 'buyer' : 'seller', uname: d.uname, price: d.price, card: CARD, lock, payout: payoutOf(d.price) };
  }
  throw err(404, 'مسیر پیدا نشد');
}

/* ---------- بات: منوها (همه‌چیز با دکمه) ---------- */
function mainKb(fid) {
  const kb = [btn('🧾 معاملات من', 'm:deals'), btn('📖 راهنما', 'm:help')];
  if (ADMIN && fid === ADMIN) kb.push(btn('🛠 موارد باز (ادمین)', 'a:list'));
  return kb;
}
const HELP = 'راهنما:\n• برنامک را از دکمهٔ منوی همین بات (کنار جعبهٔ پیام) باز کنید.\n• بار اول، کد ورودی که برنامک نشان می‌دهد را همین‌جا بفرستید.\n• خرید: آگهی را انتخاب کنید، مبلغ را کارت‌به‌کارت کنید و عکس رسید را اینجا بفرستید.\n• فروش: «آگهی فروش» را در برنامک بزنید؛ آیدی باید مال همین اکانت باشد.\n• تحویل، تأیید و شکایت همه با دکمه‌هایی که همین‌جا می‌آید انجام می‌شود.';

async function showMenu(chat, fid, text) {
  await say(chat, text || 'منوی بازارچه امن آیدی:\nبرای دیدن آگهی‌ها، دکمهٔ منوی بات را بزنید تا برنامک باز شود.', mainKb(fid).map(x => x));
}
async function showMyDeals(chat, fid) {
  const ds = (await allDeals()).filter(d => d.buyer === fid || d.seller === fid).sort((x, y) => y.ts - x.ts).slice(0, 8);
  if (!ds.length) return say(chat, 'هنوز معامله‌ای ندارید.', [btn('⬅️ منو', 'm:home')]);
  const kb = [];
  const lines = ds.map(d => {
    const isB = d.buyer === fid;
    if (isB && d.status === 'wait_pay') kb.push(btn(`❌ لغو #${d.id}`, 'x:cancel:' + d.id));
    if (isB && d.status === 'handed') kb.push(btn(`✅ تأیید #${d.id}`, 'x:confirm:' + d.id), btn(`⚠️ شکایت #${d.id}`, 'x:dispute:' + d.id));
    if (!isB && d.status === 'paid') kb.push(btn(`📦 تحویل دادم #${d.id}`, 'x:handed:' + d.id));
    return `#${d.id} @${d.uname} — ${fa(d.price)} تومان — ${isB ? 'خرید' : 'فروش'} — ${STL[d.status] || d.status}`;
  });
  kb.push(btn('⬅️ منو', 'm:home'));
  return say(chat, lines.join('\n'), kb);
}
async function showAdminList(chat) {
  const ds = (await allDeals()).filter(d => ['receipt', 'dispute', 'due', 'wait_pay'].includes(d.status)).sort((x, y) => y.ts - x.ts).slice(0, 10);
  if (!ds.length) return say(chat, 'مورد بازی نیست.', [btn('⬅️ منو', 'm:home')]);
  for (const d of ds) {
    const kb = d.status === 'receipt' || d.status === 'wait_pay' ? [btn('✅ تأیید پرداخت', 'a:ok:' + d.id), btn('❌ رد', 'a:no:' + d.id)]
      : d.status === 'dispute' ? [btn('💸 واریز به فروشنده', 'a:release:' + d.id), btn('↩️ بازگشت پول', 'a:refund:' + d.id)]
      : [btn('💸 واریز شد', 'a:paid:' + d.id)];
    await say(chat, `#${d.id} @${d.uname} — ${fa(d.price)} تومان — ${STL[d.status]}\nخریدار: ${d.buyer}  فروشنده: ${d.seller}`, kb);
  }
}

/* ---------- وب‌هوک بات ---------- */
async function webhook(req, key) {
  if (!SECRET || key !== SECRET) throw err(403, 'forbidden');
  const body = req.body || {};
  if (body.callback_query) return onCallback(body.callback_query);
  const m = body.message;
  if (!m || !m.from) return { ok: true };
  const fid = String(m.from.id), chat = (m.chat && m.chat.id) || m.from.id;
  const uname = String(m.from.username || '').toLowerCase();
  const text = String(m.text || '').trim();

  if (text.startsWith('/start') || text === '/menu') {
    await showMenu(chat, fid, 'به بازارچه امن آیدی خوش آمدید 👋\nبرای خرید و فروش، دکمهٔ منوی بات را بزنید تا برنامک باز شود.\nهمهٔ کارها از همین دکمه‌های پایین هم قابل انجام است.');
    return { ok: true };
  }

  /* کد ورود به برنامک (۸ حرف/عدد) */
  if (/^[A-HJ-NP-Z2-9]{8}$/.test(text.toUpperCase())) {
    const c = text.toUpperCase(), L = await getj('lgc:' + c);
    if (!L) { await say(chat, 'این کد ورود معتبر نیست یا منقضی شده. از برنامک دوباره کد بگیرید.'); return { ok: true }; }
    await setj('sess:' + L.h, { id: fid, username: uname }, SESS_TTL);
    await R('DEL', 'lgc:' + c);
    await say(chat, '✅ وارد شدید. به برنامک برگردید.\nاگر خودتان این کد را درخواست نکرده‌اید، هرگز آن را برای کسی نفرستید.', [btn('🧾 معاملات من', 'm:deals')]);
    return { ok: true };
  }

  /* رسید پرداخت (عکس یا فایل) */
  if (m.photo || m.document) {
    const ds = (await allDeals()).filter(d => d.buyer === fid && d.status === 'wait_pay').sort((x, y) => y.ts - x.ts);
    if (!ds.length) { await say(chat, 'معامله‌ای در انتظار پرداخت ندارید.', [btn('🧾 معاملات من', 'm:deals')]); return { ok: true }; }
    const d = ds[0];
    await saveDeal(d, { status: 'receipt' });
    if (ADMIN) {
      await tg('forwardMessage', { chat_id: ADMIN, from_chat_id: chat, message_id: m.message_id });
      await say(ADMIN, `🧾 رسید معامله #${d.id}\nآیدی: @${d.uname}\nمبلغ: ${fa(d.price)} تومان\nخریدار: ${d.buyer}`, [btn('✅ تأیید پرداخت', 'a:ok:' + d.id), btn('❌ رد', 'a:no:' + d.id)]);
    }
    await say(chat, `🧾 رسید معامله #${d.id} دریافت شد و در انتظار تأیید است.`);
    return { ok: true };
  }

  await showMenu(chat, fid, 'برای ادامه از دکمه‌های زیر یا دکمهٔ منوی بات استفاده کنید.');
  return { ok: true };
}

async function onCallback(cb) {
  const fid = String(cb.from.id), data = String(cb.data || '');
  const chat = (cb.message && cb.message.chat && cb.message.chat.id) || cb.from.id;
  const mid = cb.message && cb.message.message_id;
  await tg('answerCallbackQuery', { callback_query_id: cb.id });
  const [ns, act, id] = data.split(':');
  const clear = () => (mid ? tg('editMessageReplyMarkup', { chat_id: chat, message_id: mid, reply_markup: { inline_keyboard: [] } }) : null);
  try {
    if (ns === 'm') {
      if (act === 'deals') await showMyDeals(chat, fid);
      else if (act === 'help') await say(chat, HELP, [btn('⬅️ منو', 'm:home')]);
      else await showMenu(chat, fid);
    } else if (ns === 'x') {
      await dealAct(id, fid, act);
      await clear();
      await say(chat, '✅ انجام شد.');
    } else if (ns === 'a') {
      if (!ADMIN || fid !== ADMIN) return { ok: true };
      if (act === 'list') await showAdminList(chat);
      else { const msg = await adminAct(act, id); await clear(); await say(chat, msg); }
    }
  } catch (e) {
    await say(chat, '⚠️ ' + (e.status ? e.message : 'خطای موقت؛ دوباره تلاش کنید'));
  }
  return { ok: true };
}
