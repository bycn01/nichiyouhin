// 小林家（家のあれこれの期限・期間を2人で共有するアプリ）サーバー側
// /api/ で始まるアクセスだけをここで処理し、それ以外は public フォルダの画面を返す。
// データは Cloudflare D1（データベース）に保存し、2人で同じ一覧を見る。
//
// 使えるのは家族だけ：合言葉（秘密の設定 PASSPHRASE）を入れた端末に、署名付きの Cookie を渡す。
// 署名の鍵は秘密の設定 AUTH_SECRET。
//
// 項目の種類（kind）
//   repeat … 交換・お手入れ。前回やった日（start）から interval 日ごと
//   once   … 期限日（due）。cycle か月ごとにくり返すこともできる（0 ならくり返さない）
//   period … 有効期限・保証。due まで有効（start は使い始めた日、なくてもよい）

const DATE = /^\d{4}-\d{2}-\d{2}$/;
const MAX_FAILS = 5;
const LOCK_MINUTES = 10;
const COOKIE = 'nk';
const KINDS = ['repeat', 'once', 'period'];
const CATS = ['bath', 'kitchen', 'clean', 'home', 'bed', 'car', 'docs', 'money', 'health', 'kids', 'food', 'other'];
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
        case 'POST /api/item/done':
          await markDone(env.DB, String((await body(request)).id || ''));
          return json(await getItems(env.DB));
        case 'POST /api/item/undo':
          // 完了にしたものを元に戻す
          await env.DB.prepare('UPDATE items SET done = 0, done_at = NULL, updated_at = ? WHERE id = ?')
            .bind(nowJst(), String((await body(request)).id || '')).run();
          return json(await getItems(env.DB));
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
  // 日用品だけだったころの表に、あとから増えた列を足す（今あるデータは「交換・お手入れ」になる）
  const { results } = await db.prepare('PRAGMA table_info(items)').all();
  const have = new Set(results.map(r => r.name));
  const add = [
    ['kind', "TEXT DEFAULT 'repeat'"], ['due', 'TEXT'], ['cycle', 'INTEGER DEFAULT 0'],
    ['notice', 'INTEGER'], ['done', 'INTEGER DEFAULT 0'], ['done_at', 'TEXT'],
  ].filter(([col]) => !have.has(col));
  if (add.length) await db.batch(add.map(([col, type]) => db.prepare(`ALTER TABLE items ADD COLUMN ${col} ${type}`)));
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

// ---------- 項目 ----------

async function getItems(db) {
  const { results } = await db.prepare('SELECT * FROM items').all();
  return {
    today: todayJst(),
    items: results.map(r => ({
      id: r.id, name: r.name, kind: KINDS.includes(r.kind) ? r.kind : 'repeat', cat: r.cat || 'other',
      interval: r.interval, start: r.start || '', due: r.due || '', cycle: r.cycle || 0,
      notice: r.notice == null ? null : r.notice, memo: r.memo || '',
      history: parseHistory(r.history).map(h => h.date).filter(Boolean),
      done: !!r.done, doneAt: r.done_at || '', updatedAt: r.updated_at || '',
    })),
  };
}

// 送られてきた内容をたしかめて、保存できる形にそろえる
function clean(t) {
  const s = (v, max) => String(v == null ? '' : v).trim().slice(0, max);
  const e = {
    id: s(t.id, 64),
    name: s(t.name, 60),
    kind: KINDS.includes(t.kind) ? t.kind : 'repeat',
    cat: CATS.includes(t.cat) ? t.cat : 'other',
    interval: 0,
    start: s(t.start, 10),
    due: s(t.due, 10),
    cycle: 0,
    notice: t.notice === null || t.notice === '' || t.notice === undefined ? null : Number(t.notice),
    memo: s(t.memo, 1000),
  };
  if (!e.name) throw new UserError('名前を入れてください');
  if (e.notice !== null && (!Number.isInteger(e.notice) || e.notice < 0 || e.notice > 3650)) throw new UserError('知らせ始める時期が正しくありません');

  if (e.kind === 'repeat') {
    e.interval = Number(t.interval);
    if (!Number.isInteger(e.interval) || e.interval < 1 || e.interval > 3650 * 3) throw new UserError('くり返しの目安が正しくありません');
    if (!DATE.test(e.start)) throw new UserError('前回やった日が正しくありません');
    e.due = '';
  } else {
    if (!DATE.test(e.due)) throw new UserError(e.kind === 'once' ? '期限日を入れてください' : '有効期限を入れてください');
    if (e.start && !DATE.test(e.start)) throw new UserError('使い始めた日が正しくありません');
    if (e.kind === 'once') {
      e.cycle = Number(t.cycle) || 0;
      if (!Number.isInteger(e.cycle) || e.cycle < 0 || e.cycle > 240) throw new UserError('くり返しが正しくありません');
      e.start = '';
    }
  }
  return e;
}

async function saveItem(db, t) {
  const e = clean(t);
  if (e.id) {
    const r = await db.prepare(`UPDATE items SET name = ?, kind = ?, cat = ?, interval = ?, start = ?, due = ?, cycle = ?,
        notice = ?, memo = ?, updated_at = ? WHERE id = ?`)
      .bind(e.name, e.kind, e.cat, e.interval, e.start, e.due, e.cycle, e.notice, e.memo, nowJst(), e.id).run();
    if (!r.meta.changes) throw new UserError('この項目は、もう一人が消したようです');
  } else {
    await db.prepare(`INSERT INTO items (id, name, kind, cat, interval, start, due, cycle, notice, memo, history, done, done_by, updated_by, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', 0, '', '', ?)`)
      .bind(crypto.randomUUID(), e.name, e.kind, e.cat, e.interval, e.start, e.due, e.cycle, e.notice, e.memo, nowJst()).run();
  }
}

// 「やった」「完了」を押したとき
//   交換・お手入れ … 前回やった日を今日にする
//   くり返す期限日 … 次の期限日へ進める（今日より後になるまで）
//   それ以外       … 完了にして、一覧の下の「完了したもの」へ
async function markDone(db, id) {
  const row = await db.prepare('SELECT * FROM items WHERE id = ?').bind(id).first();
  if (!row) throw new UserError('この項目は、もう一人が消したようです');
  const today = todayJst();
  const history = parseHistory(row.history);
  const kind = KINDS.includes(row.kind) ? row.kind : 'repeat';

  if (kind === 'repeat') {
    if (row.start !== today) history.push({ date: row.start });
    await db.prepare('UPDATE items SET start = ?, history = ?, updated_at = ? WHERE id = ?')
      .bind(today, JSON.stringify(history.slice(-MAX_HISTORY)), nowJst(), id).run();
  } else if (kind === 'once' && row.cycle > 0) {
    history.push({ date: row.due });
    let next = addMonths(row.due, row.cycle);
    while (next <= today) next = addMonths(next, row.cycle);
    await db.prepare('UPDATE items SET due = ?, history = ?, updated_at = ? WHERE id = ?')
      .bind(next, JSON.stringify(history.slice(-MAX_HISTORY)), nowJst(), id).run();
  } else {
    await db.prepare('UPDATE items SET done = 1, done_at = ?, updated_at = ? WHERE id = ?')
      .bind(today, nowJst(), id).run();
  }
}

// 「2027-01-31 の1か月後」のように、月末は月末にそろえる
function addMonths(date, n) {
  const [y, m, d] = date.split('-').map(Number);
  const total = y * 12 + (m - 1) + n;
  const ny = Math.floor(total / 12), nm = total % 12;
  const last = new Date(Date.UTC(ny, nm + 1, 0)).getUTCDate();
  return `${ny}-${String(nm + 1).padStart(2, '0')}-${String(Math.min(d, last)).padStart(2, '0')}`;
}

function parseHistory(text) {
  try {
    const h = JSON.parse(text || '[]');
    return Array.isArray(h) ? h.map(x => typeof x === 'string' ? { date: x } : x) : [];
  } catch {
    return [];
  }
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
