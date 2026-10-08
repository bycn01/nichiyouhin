// 日用品こうかん帳（サーバー側）
// /api/ で始まるアクセスだけをここで処理し、それ以外は public フォルダの画面を返す。
// データは Cloudflare D1（データベース）に保存し、家族みんなで同じ一覧を見る。
//
// 使えるのは家族だけ：合言葉（秘密の設定 PASSPHRASE）を入れた端末に、署名付きの Cookie を渡す。
// 署名の鍵は秘密の設定 AUTH_SECRET。

const DATE = /^\d{4}-\d{2}-\d{2}$/;
const MAX_FAILS = 5;
const LOCK_MINUTES = 10;
const COOKIE = 'nk';
const CATS = ['bath', 'kitchen', 'clean', 'home', 'bed', 'kids', 'other'];
const MAX_HISTORY = 20;
let ready = false;

class UserError extends Error {}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(request);

    try {
      if (!ready) {
        await setup(env.DB);
        ready = true;
      }
      const route = request.method + ' ' + url.pathname;

      if (route === 'POST /api/login') return await login(request, env);
      if (!(await loggedIn(request, env))) return json({ error: '合言葉を入れてください', needLogin: true }, 401);

      switch (route) {
        case 'GET /api/items':
          return json(await getItems(env.DB));
        case 'POST /api/item':
          await saveItem(env.DB, await body(request));
          return json(await getItems(env.DB));
        case 'POST /api/item/done': {
          // 今日交換した：前回の日付を履歴に残して、使い始めた日を今日にする
          const b = await body(request);
          const row = await env.DB.prepare('SELECT start, history, done_by FROM items WHERE id = ?').bind(String(b.id || '')).first();
          if (!row) throw new UserError('この日用品は、ほかの人が消したようです');
          const today = todayJst();
          const history = parseHistory(row.history);
          if (row.start !== today) history.push({ date: row.start, by: row.done_by || '' });
          await env.DB.prepare('UPDATE items SET start = ?, history = ?, done_by = ?, updated_by = ?, updated_at = ? WHERE id = ?')
            .bind(today, JSON.stringify(history.slice(-MAX_HISTORY)), name(b.me), name(b.me), nowJst(), String(b.id)).run();
          return json(await getItems(env.DB));
        }
        case 'POST /api/item/delete':
          await env.DB.prepare('DELETE FROM items WHERE id = ?').bind(String((await body(request)).id || '')).run();
          return json(await getItems(env.DB));
      }
      return json({ error: 'ページが見つかりません' }, 404);
    } catch (e) {
      if (e instanceof UserError) return json({ error: e.message }, 400);
      console.error(e);
      return json({ error: 'サーバーでエラーが起きました' }, 500);
    }
  },
};

// ---------- はじめの準備 ----------

async function setup(db) {
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS items (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, cat TEXT, interval INTEGER NOT NULL, start TEXT NOT NULL,
      memo TEXT, history TEXT, done_by TEXT, updated_by TEXT, updated_at TEXT)`),
    db.prepare('CREATE TABLE IF NOT EXISTS attempts (ip TEXT PRIMARY KEY, fails INTEGER, until INTEGER)'),
  ]);
}

// ---------- 合言葉 ----------

async function login(request, env) {
  if (!env.AUTH_SECRET || !env.PASSPHRASE) throw new Error('AUTH_SECRET か PASSPHRASE が設定されていません');
  const ip = request.headers.get('cf-connecting-ip') || 'local';
  const now = Date.now();
  const rec = await env.DB.prepare('SELECT fails, until FROM attempts WHERE ip = ?').bind(ip).first();
  if (rec && rec.until > now) {
    return json({ error: 'まちがいが続いたので、' + Math.ceil((rec.until - now) / 60000) + '分ほど待ってからやり直してください' }, 429);
  }

  // スペースの有無・全角半角・ひらがなカタカナのちがいは気にしない
  const norm = s => String(s || '').normalize('NFKC').replace(/\s/g, '')
    .replace(/[ァ-ヶ]/g, c => String.fromCharCode(c.charCodeAt(0) - 0x60)).toLowerCase();
  const b = await body(request);
  if (!(await same(env, norm(b.pass), norm(env.PASSPHRASE)))) {
    const fails = (rec ? rec.fails : 0) + 1;
    const until = fails >= MAX_FAILS ? now + LOCK_MINUTES * 60000 : 0;
    await env.DB.prepare('INSERT INTO attempts (ip, fails, until) VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE SET fails = excluded.fails, until = excluded.until')
      .bind(ip, until ? 0 : fails, until).run();
    return json({
      error: until ? 'まちがいが続いたので、' + LOCK_MINUTES + '分間ロックしました' : '合言葉がちがうようです（あと' + (MAX_FAILS - fails) + '回）',
    }, until ? 429 : 403);
  }

  await env.DB.prepare('DELETE FROM attempts WHERE ip = ?').bind(ip).run();
  const value = 'ok.' + now;
  const token = value + '.' + await sign(env, value);
  return json({ ok: true }, 200, {
    'set-cookie': COOKIE + '=' + token + '; Path=/; Max-Age=34560000; HttpOnly; Secure; SameSite=Lax',
  });
}

async function loggedIn(request, env) {
  if (!env.AUTH_SECRET) return false;
  const m = (request.headers.get('cookie') || '').match(new RegExp('(?:^|;\\s*)' + COOKIE + '=([^;]+)'));
  if (!m) return false;
  const parts = m[1].split('.');
  if (parts.length !== 3 || parts[0] !== 'ok') return false;
  return same(env, parts[2], await sign(env, parts[0] + '.' + parts[1]));
}

async function sign(env, text) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.AUTH_SECRET),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(text));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// 文字列を比べる（かかる時間で中身がばれないよう、署名どうしで比べる）
async function same(env, a, b) {
  const [x, y] = await Promise.all([sign(env, 'cmp:' + a), sign(env, 'cmp:' + b)]);
  return x === y;
}

// ---------- 日用品 ----------

async function getItems(db) {
  const { results } = await db.prepare('SELECT * FROM items').all();
  return {
    today: todayJst(),
    items: results.map(r => ({
      id: r.id, name: r.name, cat: r.cat || 'other', interval: r.interval, start: r.start,
      memo: r.memo || '', history: parseHistory(r.history), doneBy: r.done_by || '',
      updatedBy: r.updated_by || '', updatedAt: r.updated_at || '',
    })),
  };
}

// 送られてきた内容をたしかめて、保存できる形にそろえる
function clean(t) {
  const s = (v, max) => String(v == null ? '' : v).trim().slice(0, max);
  const e = {
    id: s(t.id, 64),
    name: s(t.name, 60),
    cat: CATS.includes(t.cat) ? t.cat : 'other',
    interval: Number(t.interval),
    start: s(t.start, 10),
    memo: s(t.memo, 1000),
    history: Array.isArray(t.history) ? t.history : [],
  };
  if (!e.name) throw new UserError('名前を入れてください');
  if (!Number.isInteger(e.interval) || e.interval < 1 || e.interval > 3650 * 3) throw new UserError('交換の目安が正しくありません');
  if (!DATE.test(e.start)) throw new UserError('使い始めた日が正しくありません');
  // 以前の形（日付だけの並び）にも対応する
  e.history = e.history
    .map(h => typeof h === 'string' ? { date: h, by: '' } : { date: s(h && h.date, 10), by: name(h && h.by) })
    .filter(h => DATE.test(h.date))
    .slice(-MAX_HISTORY);
  return e;
}

function insertStmt(db, e, me) {
  return db.prepare(`INSERT INTO items (id, name, cat, interval, start, memo, history, done_by, updated_by, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, '', ?, ?)`)
    .bind(crypto.randomUUID(), e.name, e.cat, e.interval, e.start, e.memo, JSON.stringify(e.history), me, nowJst());
}

async function saveItem(db, t) {
  const e = clean(t);
  const me = name(t.me);
  if (e.id) {
    const r = await db.prepare('UPDATE items SET name = ?, cat = ?, interval = ?, start = ?, memo = ?, updated_by = ?, updated_at = ? WHERE id = ?')
      .bind(e.name, e.cat, e.interval, e.start, e.memo, me, nowJst(), e.id).run();
    if (!r.meta.changes) throw new UserError('この日用品は、ほかの人が消したようです');
  } else {
    await insertStmt(db, e, me).run();
  }
}

function parseHistory(text) {
  try {
    const h = JSON.parse(text || '[]');
    return Array.isArray(h) ? h : [];
  } catch {
    return [];
  }
}

function name(v) {
  return String(v == null ? '' : v).trim().slice(0, 30);
}

function nowJst() {
  return new Date(Date.now() + 9 * 3600 * 1000).toISOString().slice(0, 16).replace('T', ' ');
}

function todayJst() {
  return new Date(Date.now() + 9 * 3600 * 1000).toISOString().slice(0, 10);
}

async function body(request) {
  try {
    return (await request.json()) || {};
  } catch {
    throw new UserError('送られたデータが読めませんでした');
  }
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extraHeaders },
  });
}
