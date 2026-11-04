// Runs the real Store against node:sqlite (a stand-in for the Durable Object's SqlStorage).
import { DatabaseSync } from 'node:sqlite';
import { initSchema, isLegacy, migrateLegacy, parseQuery, Store } from '../src/store.ts';
import { sqliteAuthState } from '../src/auth-state.ts';
import { limitsOf, verdict } from '../src/limits.ts';
import { createAccount, KEY_STRETCH, newToken, openAccount, rewrap, tokenId, unwrapForToken, Vault, wrapForToken } from '../src/vault.ts';

// ---------- a SqlStorage lookalike ----------

function makeSql() {
  const db = new DatabaseSync(':memory:');
  const fromDb = (rows: any[]) => rows.map((r) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, v instanceof Uint8Array ? v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength) : v])));
  const toDb = (args: any[]) => args.map((a) => (a instanceof ArrayBuffer ? new Uint8Array(a) : a));
  const cursor = (rows: any[], written = 0) => ({ toArray: () => rows, one: () => rows[0], rowsWritten: written, [Symbol.iterator]: () => rows[Symbol.iterator]() });
  const sql: any = {
    exec(q: string, ...args: any[]) {
      if (args.length === 0 && q.trim().split(';').filter((x) => x.trim()).length > 1) { db.exec(q); return cursor([]); }
      const stmt = db.prepare(q);
      if (/^\s*(select|with|pragma)/i.test(q)) return cursor(fromDb(stmt.all(...toDb(args)) as any[]));
      return cursor([], Number(stmt.run(...toDb(args)).changes));
    },
  };
  return { db, sql: sql as SqlStorage };
}

let failed = 0;
const check = (name: string, ok: boolean, detail?: unknown) => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${ok ? '' : ' -> ' + JSON.stringify(detail)}`); if (!ok) failed++; };
const throws = (f: () => unknown) => { try { f(); return false; } catch { return true; } };

// ---------- the vault ----------

const FAST = 1000; // iterations: the real count is for production, tests just need the logic
const acct = await createAccount('correct horse battery', FAST);
check('right password opens the account', (await openAccount('correct horse battery', acct.record))?.equals(acct.dek) === true);
check('wrong password does not', (await openAccount('wrong horse battery', acct.record)) === null);
check('the record holds neither the key nor the password', !JSON.stringify(acct.record).includes(acct.dek.toString('base64')) && !JSON.stringify(acct.record).includes('horse'));
const moved = await rewrap('correct horse battery', 'a brand new password', acct.record);
check('changing the password keeps the same key', (await openAccount('a brand new password', moved!))?.equals(acct.dek) === true);
check('and the old password stops working', (await openAccount('correct horse battery', moved!)) === null);
check('changing needs the old password', (await rewrap('nope nope nope', 'x', acct.record)) === null);

// a key from the login service: already random, so it isn't stretched, and the same key opens the same account
const loginKey = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
const keyed = await createAccount(loginKey, KEY_STRETCH);
check('a login-service key opens its account', (await openAccount(loginKey, keyed.record))?.equals(keyed.dek) === true);
check('another key does not', (await openAccount(loginKey.slice(1) + 'A', keyed.record)) === null);
check('the key is not in the record', !JSON.stringify(keyed.record).includes(loginKey));

const vault = new Vault(acct.dek);
const other = new Vault((await createAccount('someone else entirely', FAST)).dek);
const sealed = vault.seal({ hello: 'world' }, 'x');
check('seal then open round-trips', vault.open<any>(sealed, 'x').hello === 'world');
check('ciphertext differs every time', Buffer.compare(Buffer.from(sealed), Buffer.from(vault.seal({ hello: 'world' }, 'x'))) !== 0);
check('another key cannot open it', throws(() => other.open(sealed, 'x')));
check('a blob cannot be passed off as another kind', throws(() => vault.open(sealed, 'y')));
const tampered = new Uint8Array(sealed.slice(0)); tampered[tampered.length - 20] ^= 1;
check('tampering is detected', throws(() => vault.open(tampered, 'x')));
check('pseudonyms are stable', vault.pid('jid', 'a@s.whatsapp.net') === vault.pid('jid', 'a@s.whatsapp.net'));
check('pseudonyms differ by value, kind and key', vault.pid('jid', 'a') !== vault.pid('jid', 'b') && vault.pid('jid', 'a') !== vault.pid('auth', 'a') && vault.pid('jid', 'a') !== other.pid('jid', 'a'));
const tk = newToken();
const wrapped = wrapForToken(tk.token, acct.dek);
check('a token unwraps the key it carries', unwrapForToken(tk.token, wrapped)?.equals(acct.dek) === true);
check('a different token does not', unwrapForToken(newToken().token, wrapped) === null);
check('the stored id is not the token', tokenId(tk.token) !== tk.token && tk.id === tokenId(tk.token));

// ---------- the store ----------

const { db, sql } = makeSql();
initSchema(sql);
const store = new Store(sql, (fn) => fn(), vault);

const GILAD = '972524219320@s.whatsapp.net', STRANGER1 = '972500000001@s.whatsapp.net', STRANGER2 = '972500000002@s.whatsapp.net';
const M = (id: string, chat: string, ts: number, body: string, fromMe = false, extra: any = {}) =>
  ({ key: { id, remoteJid: chat, fromMe, ...extra.key }, messageTimestamp: ts, message: { conversation: body }, pushName: extra.pushName }) as any;

const added = store.ingestMessages([
  M('a1', GILAD, 100, 'hi'), M('a2', GILAD, 200, 'shalom, got a minute?'),
  M('b1', STRANGER1, 150, 'wrong number, sorry'),
  M('c1', STRANGER2, 160, 'hello', true), M('c2', STRANGER2, 170, 'hey there'),
]);
check('ingest counts new messages', added === 5, added);
check('a repeat delivery adds nothing', store.ingestMessages([M('a1', GILAD, 100, 'hi')]) === 0);

// WhatsApp's masked placeholder must not count as a name
store.upsertContacts([{ id: GILAD, name: '+972∙∙∙∙∙∙∙20' }]);
store.upsertChatNames([{ id: STRANGER1, name: '+972∙∙∙∙∙∙∙01' }]);
store.setCustomNames([{ jid: GILAD, name: 'Gilad Shoham' }]);

check('Gilad shows his saved name, not the placeholder', (store.listChats('Gilad', 5) as any[]).length === 1, store.listChats(undefined, 10));
check('searching by his name resolves the chat', (store.resolveChat('gilad') as any[])[0]?.jid === GILAD);
check('chats come back most recent first', (store.listChats(undefined, 10) as any[])[0].jid === GILAD);

const un = store.unnamedChats(10) as any[];
check('unnamed chats lists the strangers, not Gilad', un.length === 2 && !un.some((r) => r.jid === GILAD), un.map((r) => r.jid));
check('busiest unnamed chat comes first', un[0]?.jid === STRANGER2, un.map((r) => r.messages));
check('last thing THEY said, not me', un[0]?.last_theirs === 'hey there', un[0]);
check('unnamed count', store.unnamedCount() === 2);

const r1 = store.setCustomNames([{ jid: STRANGER2, name: 'Dana Levi' }, { jid: '972599999999@s.whatsapp.net', name: 'Nobody Yet' }]);
check('save reports saved and which have chats', r1.saved === 2 && r1.withChat === 1, r1);
check('named chat leaves the unnamed list', store.unnamedCount() === 1);
check('new name shows in chat list', (store.listChats('Dana', 5) as any[]).length === 1);
const msgs = store.getMessages({ chat: STRANGER2, limit: 5 }) as any[];
check('sender name used in messages', msgs.some((m) => m.sender === 'Dana Levi') && msgs.some((m) => m.sender === 'Me'), msgs.map((m) => m.sender));
check('messages read oldest first', msgs[0].body === 'hello' && msgs[1].body === 'hey there', msgs.map((m) => m.body));
const r2 = store.setCustomNames([{ jid: STRANGER2, name: '' }]);
check('empty name removes it', r2.removed === 1 && store.unnamedCount() === 2, r2);

store.ingestMessages([M('g1', '1203@g.us', 300, 'lunch at noon', false, { key: { participant: GILAD } })]);
const gm = store.getMessages({ chat: '1203@g.us', limit: 5 }) as any[];
check('group message sender resolves to custom name', gm[0]?.sender === 'Gilad Shoham', gm);
store.ingestMessages([M('g2', '1203@g.us', 310, 'who is this', false, { key: { participant: '972511111111@s.whatsapp.net' }, pushName: 'Pushy' })]);
check('a sender with only a push name shows it', (store.getMessages({ chat: '1203@g.us', limit: 5 }) as any[]).some((m) => m.sender === 'Pushy'));
store.ingestMessages([M('g3', '1203@g.us', 320, 'and this', false, { key: { participant: '972522222222@s.whatsapp.net' } })]);
check('a sender with nothing shows their number', (store.getMessages({ chat: '1203@g.us', limit: 5 }) as any[]).some((m) => m.sender === '+972522222222'));

// push names fill a nameless chat
store.ingestMessages([M('p1', '972533333333@s.whatsapp.net', 400, 'hi it is me', false, { pushName: 'Tali' })]);
check('a push name names a chat', (store.listChats('Tali', 5) as any[]).length === 1 && store.unnamedCount() === 2);

// edits and deletes
const edit = (id: string, chat: string, text: string) => ({ key: { id: 'e' + id, remoteJid: chat, fromMe: false }, messageTimestamp: 500, message: { protocolMessage: { key: { id }, editedMessage: { conversation: text } } } }) as any;
store.ingestMessages([edit('a2', GILAD, 'shalom, got two minutes?')]);
check('an edit replaces the text', (store.getMessages({ chat: GILAD, limit: 5 }) as any[]).some((m) => m.body === 'shalom, got two minutes?'));
store.ingestMessages([{ key: { id: 'd1', remoteJid: GILAD, fromMe: false }, messageTimestamp: 510, message: { protocolMessage: { key: { id: 'a1' }, type: 0 } } } as any]);
check('a delete leaves a marker', (store.getMessages({ chat: GILAD, limit: 5 }) as any[]).some((m) => m.body === '[deleted]' && m.type === 'deleted'));

// lid -> phone number folding
const LID = '99887766@lid', LIDPN = '972544444444@s.whatsapp.net';
store.ingestMessages([M('l1', LID, 600, 'sent from a lid')]);
check('a lid chat is its own chat at first', (store.listChats(undefined, 50) as any[]).some((c) => c.jid === LID));
store.addAlias(LID, LIDPN);
const folded = store.listChats(undefined, 50) as any[];
check('learning the number folds the lid chat into it', !folded.some((c) => c.jid === LID) && folded.some((c) => c.jid === LIDPN), folded.map((c) => c.jid));
check('and its messages follow', (store.getMessages({ chat: LIDPN, limit: 5 }) as any[])[0]?.body === 'sent from a lid');
store.ingestMessages([M('l2', LID, 610, 'later, still on the lid')]);
check('later lid messages land on the number', (store.getMessages({ chat: LIDPN, limit: 5 }) as any[]).length === 2);

// ---------- reactions ----------
{
  const { sql: rsql } = makeSql();
  initSchema(rsql);
  const rs = new Store(rsql, (fn) => fn(), vault);
  const DANA = '972555555555@s.whatsapp.net', GROUP = '9999@g.us';
  const R = (id: string, chat: string, ts: number, target: string, text: string, fromMe = false, extra: any = {}) =>
    ({ key: { id, remoteJid: chat, fromMe, ...extra.key }, messageTimestamp: ts, message: { reactionMessage: { key: { id: target }, text, senderTimestampMs: ts * 1000 } }, pushName: extra.pushName }) as any;
  const body = (chat: string) => (rs.getMessages({ chat, limit: 20 }) as any[]).map((m) => `${m.sender}: ${m.body}`);

  rs.ingestMessages([M('q1', DANA, 100, 'are we still on for 8?', false, { pushName: 'Dana' })]);
  check('my reaction counts as a new message', rs.ingestMessages([R('x1', DANA, 200, 'q1', '🙏', true)]) === 1);
  check('a reaction shows as my reply, quoting the message', body(DANA).at(-1) === 'Me: [reacted 🙏 to "are we still on for 8?"]', body(DANA));
  rs.ingestMessages([R('x2', DANA, 210, 'q1', '❤️', true)]);
  check('changing it replaces the old one', body(DANA).length === 2 && body(DANA).at(-1)!.includes('❤️'), body(DANA));
  rs.ingestMessages([R('x0', DANA, 150, 'q1', '👍', true)]);
  check('an older update arriving late is ignored', body(DANA).at(-1)!.includes('❤️'), body(DANA));
  rs.ingestMessages([R('x3', DANA, 220, 'q1', '', true)]);
  check('taking it back removes it', body(DANA).length === 1, body(DANA));
  rs.ingestMessages([R('x4', DANA, 230, 'q1', '😂', false, { pushName: 'Dana' })]);
  check('their reaction is theirs', body(DANA).at(-1) === 'Dana: [reacted 😂 to "are we still on for 8?"]', body(DANA));

  // a reaction and its message in the same batch, in the wrong order
  rs.ingestMessages([R('y1', GROUP, 310, 'g9', '👍', false, { key: { participant: DANA }, pushName: 'Dana' }), M('g9', GROUP, 300, 'pizza tonight', false, { key: { participant: GILAD } })]);
  check('a group reaction quotes a message from the same batch', body(GROUP).at(-1) === 'Dana: [reacted 👍 to "pizza tonight"]', body(GROUP));
  // history sync puts reactions on the message itself
  rs.ingestMessages([{ ...M('g8', GROUP, 320, 'who is in'), key: { id: 'g8', remoteJid: GROUP, fromMe: false, participant: GILAD }, reactions: [{ key: { fromMe: true }, text: '✋', senderTimestampMs: 330000 }] } as any]);
  check('reactions carried on a history message are kept', body(GROUP).at(-1) === 'Me: [reacted ✋ to "who is in"]', body(GROUP));
  check('reactions are searchable', (rs.search({ queries: ['pizza'], limit: 10 }).hits[0]).length === 2);
}

// ---------- media ----------
{
  const { sql: msql } = makeSql();
  initSchema(msql);
  const ms = new Store(msql, (fn) => fn(), vault);
  const ANA = '5511999990000@s.whatsapp.net';
  const KEY = new Uint8Array(32).fill(7);
  const IMG = (id: string, ts: number, extra: any = {}) =>
    ({ key: { id, remoteJid: ANA, fromMe: false }, messageTimestamp: ts, message: { imageMessage: { caption: 'the receipt', mimetype: 'image/jpeg', mediaKey: KEY, directPath: '/v/t62/abc', fileLength: 1234, ...extra } } }) as any;

  ms.ingestMessages([IMG('i1', 100)]);
  const ref = ms.media(ANA, 'i1');
  check('an image keeps what it takes to download it', ref?.k === 'image' && ref.path === '/v/t62/abc' && ref.key === Buffer.from(KEY).toString('base64') && ref.mime === 'image/jpeg' && ref.len === 1234, ref);
  check('and the message key, for asking the phone to re-upload', ref?.rk.remoteJid === ANA && ref.rk.fromMe === false, ref?.rk);
  check('reading flags it as media', (ms.getMessages({ chat: ANA, limit: 5 }) as any[])[0].media === true);
  check('text has no media', (ms.ingestMessages([M('t1', ANA, 110, 'thanks')]), ms.media(ANA, 't1')) === null);

  // a message stored before media was kept gets it filled in on a repeat delivery
  ms.ingestMessages([IMG('i2', 120, { mediaKey: undefined })]);
  check('no key, no media', ms.media(ANA, 'i2') === null);
  ms.ingestMessages([IMG('i2', 120)]);
  check('a repeat delivery fills it in', ms.media(ANA, 'i2')?.path === '/v/t62/abc');
  ms.setMediaLocation(ANA, 'i2', { path: '/v/new' });
  check('a re-upload moves it', ms.media(ANA, 'i2')?.path === '/v/new' && ms.media(ANA, 'i2')?.key === Buffer.from(KEY).toString('base64'));

  // WhatsApp's format: HKDF(mediaKey) -> iv, AES-CBC key, HMAC key; file = ciphertext + first 10 bytes of HMAC(iv || ciphertext)
  const { downloadMedia } = await import('../src/media.ts');
  const plain = new TextEncoder().encode('a tiny jpeg, honestly');
  const base = await crypto.subtle.importKey('raw', KEY, 'HKDF', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('WhatsApp Image Keys') }, base, 112 * 8));
  const iv = bits.slice(0, 16);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, await crypto.subtle.importKey('raw', bits.slice(16, 48), 'AES-CBC', false, ['encrypt']), plain));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', await crypto.subtle.importKey('raw', bits.slice(48, 80), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']), new Uint8Array([...iv, ...ct]))).slice(0, 10);
  const file = new Uint8Array([...ct, ...mac]);
  const realFetch = globalThis.fetch;
  let asked = '';
  globalThis.fetch = (async (u: string) => { asked = u; return u.endsWith('/gone') ? new Response('', { status: 410 }) : new Response(file); }) as any;
  const got = await downloadMedia({ k: 'image', key: ref!.key, path: '/v/t62/abc' }, 1e6);
  check('downloads from the CDN path', asked === 'https://mmg.whatsapp.net/v/t62/abc', asked);
  check('and decrypts', got.ok && new TextDecoder().decode(got.bytes) === 'a tiny jpeg, honestly', got);
  const tampered = file.slice(); tampered[0] ^= 1;
  globalThis.fetch = (async () => new Response(tampered)) as any;
  const bad = await downloadMedia({ k: 'image', key: ref!.key, path: '/x' }, 1e6);
  check('a tampered file fails the integrity check', !bad.ok && !bad.expired);
  globalThis.fetch = (async () => new Response('', { status: 410 })) as any;
  const gone = await downloadMedia({ k: 'image', key: ref!.key, path: '/gone' }, 1e6);
  check('a 410 means expired', !gone.ok && gone.expired);
  check('too big is refused before downloading', !(await downloadMedia({ k: 'image', key: ref!.key, path: '/x', len: 2e6 }, 1e6)).ok);
  globalThis.fetch = realFetch;
}

// ---------- unanswered ----------
{
  const { sql: usql } = makeSql();
  initSchema(usql);
  const us = new Store(usql, (fn) => fn(), vault);
  const A = '5511900000001@s.whatsapp.net', B = '5511900000002@s.whatsapp.net', C = '5511900000003@s.whatsapp.net', D = '5511900000004@s.whatsapp.net', G = '1234@g.us';
  const R = (id: string, chat: string, ts: number, target: string, text: string, fromMe: boolean) =>
    ({ key: { id, remoteJid: chat, fromMe }, messageTimestamp: ts, message: { reactionMessage: { key: { id: target }, text, senderTimestampMs: ts * 1000 } } }) as any;
  us.ingestMessages([
    M('a1', A, 100, 'oi', true), M('a2', A, 200, 'tudo bem?'), M('a3', A, 210, 'me liga'),          // waiting: 2
    M('b1', B, 100, 'pode ser amanha?'), M('b2', B, 150, 'pode sim', true),                         // answered
    M('c1', C, 100, 'mandei o arquivo'), R('c2', C, 120, 'c1', '👍', true),                          // my reaction answers
    M('d1', D, 100, 'valeu', true), R('d2', D, 130, 'd1', '❤️', false),                              // their reaction is not a message
    M('g1', G, 300, 'alguem?', false, { key: { participant: A } }),                                 // groups are left out
  ]);
  const un = us.unanswered({ limit: 10 });
  check('only direct chats where they spoke last', JSON.stringify(un.map((r) => r.jid)) === JSON.stringify([A]), un);
  check('counts what is waiting, since the first of it', un[0]?.waiting === 2 && un[0].since === 200 && un[0].last === 'me liga', un[0]);
  check('since filters by last activity', us.unanswered({ since: 250, limit: 10 }).length === 0);
  us.ingestMessages([M('a4', A, 220, 'respondi', true)]);
  check('a reply clears it', us.unanswered({ limit: 10 }).length === 0);
}

// ---------- search ----------

const ts0 = 1000;
store.ingestMessages([
  M('s1', GILAD, ts0 + 1, 'The flights are booked for Thursday'),
  M('s2', GILAD, ts0 + 2, 'Lease signed, deposit paid'),
  M('s3', STRANGER1, ts0 + 3, 'Café on Thursday? the flight lands late'),
  M('s4', STRANGER2, ts0 + 4, 'שלום, מה שלומך? נתראה ביום חמישי'),
  M('s5', GILAD, ts0 + 5, 'release notes attached'),
]);
const one = store.search({ queries: ['flights'], limit: 10 }).hits[0];
check('word search finds it', one.length === 1 && one[0].id === 's1', one.map((h) => h.id));
check('hits carry chat, sender and time', one[0].chat === GILAD && one[0].chat_name === 'Gilad Shoham' && one[0].sender === 'Gilad Shoham' && one[0].ts === ts0 + 1, one[0]);
check('words match whole, so lease is not release', store.search({ queries: ['lease'], limit: 10 }).hits[0].map((h) => h.id).join() === 's2');
check('case and accents are ignored', store.search({ queries: ['CAFE'], limit: 10 }).hits[0].length === 1);
check('several words must all appear', store.search({ queries: ['thursday flight'], limit: 10 }).hits[0].map((h) => h.id).join() === 's3');
check('a quoted phrase must appear in order', store.search({ queries: ['"booked for thursday"'], limit: 10 }).hits[0].length === 1 && store.search({ queries: ['"thursday booked"'], limit: 10 }).hits[0].length === 0);
check('a trailing star matches word starts', store.search({ queries: ['flight*'], limit: 10 }).hits[0].length === 2);
check('Hebrew works', store.search({ queries: ['שלומך'], limit: 10 }).hits[0].map((h) => h.id).join() === 's4');
check('results are newest first', store.search({ queries: ['thursday'], limit: 10 }).hits[0].map((h) => h.id).join() === 's3,s1');
check('a chat can be searched alone', store.search({ queries: ['thursday'], chat: GILAD, limit: 10 }).hits[0].map((h) => h.id).join() === 's1');
check('dates narrow the scan', store.search({ queries: ['thursday'], since: ts0 + 2, limit: 10 }).hits[0].map((h) => h.id).join() === 's3');

const batch = store.search({ queries: ['flights', 'lease', 'nothing here', 'שלום'], limit: 10 });
check('a batch answers every query in order', batch.hits.map((h) => h.map((x) => x.id).join()).join('|') === 's1|s2||s4', batch.hits.map((h) => h.length));
const total = store.counts().messages;
check('a batch decrypts each message once, not once per query', batch.scanned <= total, { scanned: batch.scanned, total });
const early = store.search({ queries: ['thursday'], limit: 1 });
check('it stops as soon as every query is full', early.scanned < total && early.hits[0].length === 1, early.scanned);
check('a query of only punctuation matches nothing', store.search({ queries: ['!!!'], limit: 5 }).hits[0].length === 0);
check('query parsing', JSON.stringify(parseQuery('a "b c" d*')) === JSON.stringify([{ tokens: ['a'], prefix: false }, { tokens: ['b', 'c'], prefix: false }, { tokens: ['d'], prefix: true }]));

// ---------- nothing readable at rest ----------

const allBytes = () => {
  let out = '';
  for (const { name } of db.prepare(`SELECT name FROM sqlite_master WHERE type='table'`).all() as any[]) {
    for (const row of db.prepare(`SELECT * FROM ${name}`).all() as any[]) {
      for (const v of Object.values(row)) out += (v instanceof Uint8Array ? Buffer.from(v).toString('latin1') + Buffer.from(v).toString('utf8') + Buffer.from(v).toString('hex') : String(v)) + '\n';
    }
  }
  return out;
};
const raw = allBytes();
check('(control) the dump covers real content: plaintext columns are in it', raw.includes('text') && raw.length > 5000, raw.length);
const leaks = ['shalom', 'two minutes', 'Gilad', 'Shoham', 'Dana', 'Tali', 'Pushy', 'lunch', '972524219320', '972500000001', '9725', 'lid', 'flights', 'שלום', 'Thursday'];
const leaked = leaks.filter((s) => raw.includes(s));
check('no message, name or number is readable in the database', leaked.length === 0, leaked);
check('the data key is not in the database either', !raw.includes(acct.dek.toString('base64')) && !raw.includes(acct.dek.toString('hex')));

// a different key sees only noise
const stranger = new Store(sql, (fn) => fn(), other);
check('another key cannot read the chats', throws(() => stranger.listChats(undefined, 10)));
check('another key cannot search', throws(() => stranger.search({ queries: ['flights'], limit: 5 })));

// ---------- auth state ----------

const authDb = makeSql();
initSchema(authDb.sql);
const flags: boolean[] = [];
const auth = sqliteAuthState(authDb.sql, vault, (p) => flags.push(p));
await auth.state.keys.set({ session: { '972501234567.0': { secret: 'abc' } as any }, 'pre-key': { '7': { private: Buffer.from('p'), public: Buffer.from('q') } as any } });
await auth.saveCreds();
check('keys round-trip', ((await auth.state.keys.get('session', ['972501234567.0']))['972501234567.0'] as any)?.secret === 'abc');
const authRaw = (authDb.db.prepare(`SELECT k, data FROM auth`).all() as any[]).map((r) => r.k + Buffer.from(r.data).toString('latin1')).join();
check('session keys do not give away who they are for', !authRaw.includes('972501234567') && !authRaw.includes('session') && !authRaw.includes('abc'));
const auth2 = sqliteAuthState(authDb.sql, vault);
check('creds survive a reload', Object.keys(auth2.state.creds).length > 3 && (auth2.state.creds as any).noiseKey != null);
check('reporting unpaired when there is no link', flags[0] === false);
auth.clear();
check('clear wipes the keys', (authDb.db.prepare(`SELECT COUNT(*) n FROM auth`).get() as any).n === 0);

// ---------- upgrading a plaintext database ----------

const old = makeSql();
old.db.exec(`
  CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT);
  INSERT INTO meta VALUES ('google_refresh','secret-token'),('last_pull','123');
  CREATE TABLE messages (id TEXT NOT NULL, chat TEXT NOT NULL, ts INTEGER NOT NULL, from_me INTEGER NOT NULL, sender TEXT, push_name TEXT, type TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY (chat, id));
  CREATE INDEX messages_chat_ts ON messages (chat, ts);
  CREATE INDEX messages_ts ON messages (ts);
  CREATE TABLE chats (jid TEXT PRIMARY KEY, name TEXT, is_group INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE contacts (jid TEXT PRIMARY KEY, name TEXT, notify TEXT);
  CREATE TABLE google_contacts (jid TEXT PRIMARY KEY, name TEXT NOT NULL);
  CREATE TABLE alias (lid TEXT PRIMARY KEY, pn TEXT NOT NULL);
  CREATE TABLE auth (k TEXT PRIMARY KEY, v TEXT NOT NULL);
  INSERT INTO chats VALUES ('${GILAD}', NULL, 0), ('${STRANGER2}', NULL, 0), ('1203@g.us', 'Lunch crew', 1);
  INSERT INTO messages VALUES ('a1','${GILAD}',100,0,'${GILAD}',NULL,'text','hi there'),
    ('a2','${GILAD}',200,1,'me',NULL,'text','plaintext secret about the lease'),
    ('c1','${STRANGER2}',160,0,'${STRANGER2}','Dana P','text','hey'),
    ('g1','1203@g.us',300,0,'${GILAD}',NULL,'text','lunch at noon');
  INSERT INTO contacts VALUES ('${GILAD}', '+972∙∙∙∙∙∙∙20', 'Gil');
  INSERT INTO google_contacts VALUES ('${GILAD}', 'Gilad Shoham');
  INSERT INTO alias VALUES ('55@lid', '${STRANGER2}');
  INSERT INTO auth VALUES ('creds', '{"me":{"id":"972500000000:1@s.whatsapp.net"}}'), ('session-972501234567.0', '{"x":1}');
`);
initSchema(old.sql);
const dumpOf = (d: DatabaseSync) => { let o = ''; for (const { name } of d.prepare(`SELECT name FROM sqlite_master WHERE type='table'`).all() as any[]) for (const row of d.prepare(`SELECT * FROM ${name}`).all() as any[]) for (const v of Object.values(row)) o += (v instanceof Uint8Array ? Buffer.from(v).toString('latin1') : String(v)) + '\n'; return o; };
check('(control) the leak detector does find plaintext in an unmigrated database', ['plaintext secret', 'Gilad', 'session-'].every((x) => dumpOf(old.db).includes(x)));
check('an old plaintext database is detected and left alone', isLegacy(old.sql) && !!(old.db.prepare(`SELECT 1 FROM sqlite_master WHERE name='messages' AND sql LIKE '%body%'`).get()));
check('the stored Google credential is deleted', !old.db.prepare(`SELECT 1 FROM meta WHERE k='google_refresh'`).get());
migrateLegacy(old.sql, vault, (fn) => fn());
check('after migrating it is no longer legacy', !isLegacy(old.sql));
check('no legacy tables are left', !old.db.prepare(`SELECT 1 FROM sqlite_master WHERE name LIKE 'legacy_%' OR name='google_contacts' OR name LIKE '%fts%'`).get());
const up = new Store(old.sql, (fn) => fn(), vault);
check('messages survive', (up.getMessages({ chat: GILAD, limit: 5 }) as any[]).map((m) => m.body).join('|') === 'hi there|plaintext secret about the lease');
check('old Google names are custom names now', (up.listChats('Gilad', 5) as any[]).length === 1);
check('push names survive', (up.listChats('Dana', 5) as any[]).length === 1);
check('group names and senders survive', (up.listChats('Lunch', 5) as any[]).length === 1 && (up.getMessages({ chat: '1203@g.us', limit: 5 }) as any[])[0].sender === 'Gilad Shoham');
check('search works on migrated data', up.search({ queries: ['lease'], limit: 5 }).hits[0].length === 1);
check('aliases survive', (up as any).aliases().get('55@lid') === STRANGER2);
check('auth moved across, sealed', (old.db.prepare(`SELECT COUNT(*) n FROM auth`).get() as any).n === 2 && sqliteAuthState(old.sql, vault).isPaired());
check('other meta kept', (old.db.prepare(`SELECT v FROM meta WHERE k='last_pull'`).get() as any)?.v === '123');
const oldRaw = dumpOf(old.db);
check('nothing readable is left after migrating', !['plaintext secret', 'Gilad', 'Dana', '9725242', 'session-', 'noon'].some((s) => oldRaw.includes(s)), ['plaintext secret', 'Gilad', 'Dana', '9725242', 'session-', 'noon'].filter((s) => oldRaw.includes(s)));

// ---------- size limits ----------

const MB = 1024 * 1024;
const many = { OWNER_PASSWORD: undefined, SIGNUP_LIMIT: '100', OPEN_SIGNUP: 'true' } as any;
check('many-user mode has default caps', limitsOf(many).messages === 250_000 && limitsOf(many).bytes === 300 * MB, limitsOf(many));
check('single-user mode has none', limitsOf({ OWNER_PASSWORD: 'x'.repeat(12) } as any).messages === 0 && limitsOf({ OWNER_PASSWORD: 'x'.repeat(12) } as any).bytes === 0);
check('settings override the defaults', limitsOf({ ...many, MAX_MESSAGES: '1000', MAX_DB_MB: '5' }).messages === 1000 && limitsOf({ ...many, MAX_MESSAGES: '1000', MAX_DB_MB: '5' }).bytes === 5 * MB);
check('0 turns a cap off', limitsOf({ ...many, MAX_MESSAGES: '0', MAX_DB_MB: '0' }).messages === 0);
check('nonsense falls back to the default', limitsOf({ ...many, MAX_MESSAGES: 'lots' }).messages === 250_000);
const lim = { messages: 1000, bytes: 10 * MB };
check('under the caps is fine', verdict({ messages: 1000, bytes: 10 * MB }, lim, true) === null);
check('too many messages while linking is turned away', verdict({ messages: 1001, bytes: 1 }, lim, true) === 'reject');
check('too much data while linking is turned away', verdict({ messages: 1, bytes: 10 * MB + 1 }, lim, true) === 'reject');
check('an account that outgrows its cap later just pauses', verdict({ messages: 5000, bytes: 1 }, lim, false) === 'pause');
check('no caps never rejects', verdict({ messages: 9e9, bytes: 9e12 }, { messages: 0, bytes: 0 }, true) === null);

// ---------- phone parsing ----------

const { toJid } = await import('../src/phone.ts');
const cases: [string, string | undefined, string | null][] = [
  ['+972 52-421-9320', undefined, '972524219320@s.whatsapp.net'], ['052-421-9320', '972', '972524219320@s.whatsapp.net'],
  ['052-421-9320', undefined, null], ['00972524219320', undefined, '972524219320@s.whatsapp.net'],
  ['524219320', '972', '972524219320@s.whatsapp.net'], ['972524219320@s.whatsapp.net', undefined, '972524219320@s.whatsapp.net'],
  ['abc', '972', null], ['+1 (818) 917-7834', '972', '18189177834@s.whatsapp.net'],
];
for (const [i, cc, want] of cases) check(`toJid(${JSON.stringify(i)}, ${cc})`, toJid(i, cc) === want, toJid(i, cc));

console.log(failed ? `\n${failed} FAILED` : '\nall passed');
process.exit(failed ? 1 : 0);
