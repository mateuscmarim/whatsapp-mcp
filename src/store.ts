/**
 * Message store: schema, ingest from Baileys events, and the queries the MCP tools use.
 *
 * Everything sensitive is sealed with the user's Vault before it reaches SQLite. What stays readable is
 * only what the database needs to do its job: timestamps, who-sent-it as an opaque id, and message types.
 * Phone numbers and chat ids are replaced by pseudonyms (Vault.pid), so SQL can still group and join on them,
 * and the real values live inside sealed blobs. Names are therefore resolved here, in memory, from a decrypted
 * snapshot of the small tables, and search decrypts and scans (see search()).
 */
import { getContentType, normalizeMessageContent, jidNormalizedUser } from '@whiskeysockets/baileys';
import type { proto } from '@whiskeysockets/baileys';
import type { Vault } from './vault.js';

// What each kind of blob is bound to, so one can't be swapped for another.
const MSG = 'm', CHAT = 'c', CONTACT = 'k', NAME = 'n', ALIAS = 'l';

interface MsgBlob { b: string; p?: string; s?: string; m?: MediaRef; t?: string } // body, push name, sender jid, media, transcript
interface ChatRec { jid: string; name?: string | null; group: 0 | 1; push?: string; pushTs?: number }
interface ContactRec { jid: string; name?: string | null; notify?: string | null }

export type MediaKind = 'image' | 'video' | 'audio' | 'document' | 'sticker';
/**
 * What it takes to fetch a message's media later: where it sits on WhatsApp's CDN and the key it is encrypted
 * with, plus the original message key, which asking the phone to upload it again needs once the CDN copy expires.
 */
export interface MediaRef {
  k: MediaKind; key: string; path?: string; url?: string; mime?: string; len?: number; name?: string;
  rk: { remoteJid: string; fromMe: boolean; participant?: string };
}

const TABLES = ['messages', 'chats', 'contacts', 'custom_names', 'alias', 'auth'] as const;

function createTables(sql: SqlStorage) {
  sql.exec(`
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT NOT NULL, chat TEXT NOT NULL, ts INTEGER NOT NULL, from_me INTEGER NOT NULL,
      sender TEXT, type TEXT NOT NULL, data BLOB NOT NULL,
      PRIMARY KEY (chat, id)
    );
    CREATE INDEX IF NOT EXISTS messages_chat_ts ON messages (chat, ts);
    CREATE INDEX IF NOT EXISTS messages_ts ON messages (ts);
    CREATE TABLE IF NOT EXISTS chats (cid TEXT PRIMARY KEY, data BLOB NOT NULL);
    CREATE TABLE IF NOT EXISTS contacts (cid TEXT PRIMARY KEY, data BLOB NOT NULL);
    CREATE TABLE IF NOT EXISTS custom_names (cid TEXT PRIMARY KEY, data BLOB NOT NULL);
    CREATE TABLE IF NOT EXISTS alias (cid TEXT PRIMARY KEY, data BLOB NOT NULL);
    CREATE TABLE IF NOT EXISTS auth (k TEXT PRIMARY KEY, data BLOB NOT NULL);
  `);
}

const tableExists = (sql: SqlStorage, name: string) => sql.exec(`SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?`, name).toArray().length > 0;

/** The first release stored everything in plaintext, with a `body` column. */
export function isLegacy(sql: SqlStorage): boolean {
  const row = sql.exec<{ sql: string }>(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'messages'`).toArray()[0];
  return Boolean(row && /\bbody\b/.test(row.sql));
}

/** Tables that need no key. A plaintext database from the first release is left alone until there is a key to encrypt it with. */
export function initSchema(sql: SqlStorage) {
  sql.exec(`
    CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
    CREATE TABLE IF NOT EXISTS account (k TEXT PRIMARY KEY, v TEXT NOT NULL);
  `);
  if (!isLegacy(sql)) createTables(sql);
  sql.exec(`DELETE FROM meta WHERE k LIKE 'google_%'`);
}

/** Encrypt a plaintext database in place, all or nothing. Needs the key, so it runs at the first sign-in after an upgrade. */
export function migrateLegacy(sql: SqlStorage, vault: Vault, tx: <T>(fn: () => T) => T) {
  tx(() => {
    sql.exec(`DROP TRIGGER IF EXISTS messages_ai; DROP TRIGGER IF EXISTS messages_ad; DROP TRIGGER IF EXISTS messages_au;`);
    sql.exec(`DROP TABLE IF EXISTS messages_fts`);
    sql.exec(`DROP INDEX IF EXISTS messages_chat_ts; DROP INDEX IF EXISTS messages_ts;`); // index names outlive a table rename
    for (const t of TABLES) if (tableExists(sql, t)) sql.exec(`ALTER TABLE ${t} RENAME TO legacy_${t}`);
    // an earlier version synced names from Google; those names are ordinary custom names now
    if (tableExists(sql, 'google_contacts') && !tableExists(sql, 'legacy_custom_names')) sql.exec(`ALTER TABLE google_contacts RENAME TO legacy_custom_names`);
    createTables(sql);

    const pid = (j: string) => vault.pid('jid', j);
    const lastPush = new Map<string, { p: string; ts: number }>();
    const chatJids = new Set<string>();
    for (let after = -1; ; ) {
      const rows = sql.exec<any>(
        `SELECT rowid AS rid, id, chat, ts, from_me, sender, push_name, type, body FROM legacy_messages WHERE rowid > ? ORDER BY rowid LIMIT 2000`, after,
      ).toArray();
      if (!rows.length) break;
      for (const r of rows) {
        const blob: MsgBlob = { b: r.body };
        if (r.push_name) blob.p = r.push_name;
        if (r.sender && r.sender !== 'me') blob.s = r.sender;
        sql.exec(
          `INSERT OR IGNORE INTO messages (id, chat, ts, from_me, sender, type, data) VALUES (?,?,?,?,?,?,?)`,
          r.id, pid(r.chat), r.ts, r.from_me, r.sender === 'me' ? 'me' : r.sender ? pid(r.sender) : null, r.type, vault.seal(blob, MSG),
        );
        chatJids.add(r.chat);
        if (!r.from_me && r.push_name && (lastPush.get(r.chat)?.ts ?? -1) <= r.ts) lastPush.set(r.chat, { p: r.push_name, ts: r.ts });
      }
      after = rows[rows.length - 1].rid;
    }

    const seen = new Set<string>();
    if (tableExists(sql, 'legacy_chats')) {
      for (const c of sql.exec<any>(`SELECT jid, name, is_group FROM legacy_chats`).toArray()) {
        seen.add(c.jid);
        const rec: ChatRec = { jid: c.jid, name: c.name, group: c.is_group ? 1 : 0 };
        const lp = lastPush.get(c.jid);
        if (lp) { rec.push = lp.p; rec.pushTs = lp.ts; }
        sql.exec(`INSERT OR REPLACE INTO chats (cid, data) VALUES (?, ?)`, pid(c.jid), vault.seal(rec, CHAT));
      }
    }
    for (const jid of chatJids) {
      if (seen.has(jid)) continue;
      const rec: ChatRec = { jid, group: jid.endsWith('@g.us') ? 1 : 0 };
      const lp = lastPush.get(jid);
      if (lp) { rec.push = lp.p; rec.pushTs = lp.ts; }
      sql.exec(`INSERT OR IGNORE INTO chats (cid, data) VALUES (?, ?)`, pid(jid), vault.seal(rec, CHAT));
    }
    if (tableExists(sql, 'legacy_contacts')) {
      for (const c of sql.exec<any>(`SELECT jid, name, notify FROM legacy_contacts`).toArray()) {
        sql.exec(`INSERT OR REPLACE INTO contacts (cid, data) VALUES (?, ?)`, pid(c.jid), vault.seal({ jid: c.jid, name: c.name, notify: c.notify } satisfies ContactRec, CONTACT));
      }
    }
    if (tableExists(sql, 'legacy_custom_names')) {
      for (const c of sql.exec<any>(`SELECT jid, name FROM legacy_custom_names`).toArray()) {
        sql.exec(`INSERT OR REPLACE INTO custom_names (cid, data) VALUES (?, ?)`, pid(c.jid), vault.seal({ jid: c.jid, name: c.name }, NAME));
      }
    }
    if (tableExists(sql, 'legacy_alias')) {
      for (const a of sql.exec<any>(`SELECT lid, pn FROM legacy_alias`).toArray()) {
        sql.exec(`INSERT OR REPLACE INTO alias (cid, data) VALUES (?, ?)`, pid(a.lid), vault.seal({ lid: a.lid, pn: a.pn }, ALIAS));
      }
    }
    if (tableExists(sql, 'legacy_auth')) {
      for (const a of sql.exec<any>(`SELECT k, v FROM legacy_auth`).toArray()) {
        sql.exec(`INSERT OR REPLACE INTO auth (k, data) VALUES (?, ?)`, vault.pid('auth', a.k), vault.seal(a.v, 'a'));
      }
    }
    for (const t of TABLES) sql.exec(`DROP TABLE IF EXISTS legacy_${t}`);
    sql.exec(`INSERT OR REPLACE INTO meta (k, v) VALUES ('schema', '2')`);
  });
}

// ---------- names ----------

/** WhatsApp names chats it has no contact for after the number, sometimes masked ("+972∙∙∙∙∙∙∙20"). That is a placeholder, not a name. */
const isPlaceholder = (name?: string | null) => !name || /∙/.test(name) || /^[\d\s+-]*$/.test(name);
const real = (x?: string | null) => (isPlaceholder(x) ? null : (x as string));
const num = (v: unknown) => Number((v as { toNumber?: () => number })?.toNumber?.() ?? v ?? 0);
const numberLabel = (jid: string) => (jid.endsWith('@s.whatsapp.net') ? `+${jid.replace('@s.whatsapp.net', '')}` : jid);

const b64 = (v: unknown) => (typeof v === 'string' ? v : v instanceof Uint8Array ? Buffer.from(v).toString('base64') : undefined);

type MediaContent = { mediaKey?: unknown; directPath?: string | null; url?: string | null; mimetype?: string | null; fileLength?: unknown; fileName?: string | null };
const mediaOf = (k: MediaKind, c?: MediaContent | null): Omit<MediaRef, 'rk'> | undefined => {
  const key = b64(c?.mediaKey);
  if (!c || !key || !(c.directPath || c.url)) return undefined;
  const ref: Omit<MediaRef, 'rk'> = { k, key };
  if (c.directPath) ref.path = c.directPath;
  if (c.url) ref.url = c.url;
  if (c.mimetype) ref.mime = c.mimetype;
  if (num(c.fileLength)) ref.len = num(c.fileLength);
  if (c.fileName) ref.name = c.fileName;
  return ref;
};

/** What a message says, in text. Media becomes a short label so search and reading still make sense. */
export function describe(msg: proto.IWebMessageInfo): { type: string; body: string; media?: Omit<MediaRef, 'rk'> } | null {
  const m = normalizeMessageContent(msg.message);
  if (!m) return null;
  const type = getContentType(m);
  if (!type) return null;
  const cap = (s?: string | null) => (s ? ` ${s}` : '');
  switch (type) {
    case 'conversation':
      return { type: 'text', body: m.conversation ?? '' };
    case 'extendedTextMessage':
      return { type: 'text', body: m.extendedTextMessage?.text ?? '' };
    case 'imageMessage':
      return { type: 'image', body: `[image]${cap(m.imageMessage?.caption)}`, media: mediaOf('image', m.imageMessage) };
    case 'videoMessage':
      return { type: 'video', body: `[video]${cap(m.videoMessage?.caption)}`, media: mediaOf('video', m.videoMessage) };
    case 'audioMessage': {
      const s = num(m.audioMessage?.seconds);
      return { type: 'audio', body: `[${m.audioMessage?.ptt ? 'voice note' : 'audio'}${s ? ` ${s}s` : ''}]`, media: mediaOf('audio', m.audioMessage) };
    }
    case 'documentMessage':
      return { type: 'document', body: `[document: ${m.documentMessage?.fileName ?? 'file'}]${cap(m.documentMessage?.caption)}`, media: mediaOf('document', m.documentMessage) };
    case 'documentWithCaptionMessage':
      return { type: 'document', body: `[document]` };
    case 'stickerMessage':
      return { type: 'sticker', body: '[sticker]', media: mediaOf('sticker', m.stickerMessage) };
    case 'locationMessage':
    case 'liveLocationMessage':
      return { type: 'location', body: `[location${m.locationMessage?.name ? `: ${m.locationMessage.name}` : ''}]` };
    case 'contactMessage':
      return { type: 'contact', body: `[contact: ${m.contactMessage?.displayName ?? ''}]` };
    case 'pollCreationMessage':
    case 'pollCreationMessageV2':
    case 'pollCreationMessageV3':
      return { type: 'poll', body: `[poll: ${(m as any)[type]?.name ?? ''}]` };
    default:
      return null; // reactions, protocol, key distribution and other plumbing
  }
}

// ---------- search ----------

const fold = (s: string) => s.normalize('NFKD').replace(/\p{M}/gu, '').toLowerCase();
const words = (s: string) => fold(s).match(/[\p{L}\p{N}]+/gu) ?? [];

/** One search term: a word, or a quoted phrase. A trailing * on a word matches any word that starts with it. */
interface Term { tokens: string[]; prefix: boolean }

/** Plain words are AND-ed; "quoted phrases" must appear in order; word* is a prefix. Every word is matched whole, case and accents aside. */
export function parseQuery(q: string): Term[] {
  const out: Term[] = [];
  for (const raw of q.match(/"[^"]*"|\S+/g) ?? []) {
    const quoted = raw.startsWith('"');
    const prefix = !quoted && raw.endsWith('*');
    const tokens = words(quoted ? raw.replace(/"/g, '') : raw);
    if (tokens.length) out.push({ tokens, prefix });
  }
  return out;
}

function hasTerm(have: string[], t: Term): boolean {
  const n = t.tokens.length;
  outer: for (let i = 0; i + n <= have.length; i++) {
    for (let j = 0; j < n; j++) {
      const ok = j === n - 1 && t.prefix ? have[i + j].startsWith(t.tokens[j]) : have[i + j] === t.tokens[j];
      if (!ok) continue outer;
    }
    return true;
  }
  return false;
}

/** Does this text satisfy every term? The cheap substring check runs first so most messages never get tokenized. */
function matches(text: string, terms: Term[]): boolean {
  const flat = fold(text);
  if (!terms.every((t) => t.tokens.every((tok) => flat.includes(tok)))) return false;
  const have = flat.match(/[\p{L}\p{N}]+/gu) ?? [];
  return terms.every((t) => hasTerm(have, t));
}

export interface SearchHit { id: string; chat: string; chat_name: string; ts: number; sender: string; body: string; media: boolean }

// ---------- the store ----------

interface Snapshot { chats: Map<string, ChatRec>; contacts: Map<string, ContactRec>; customs: Map<string, string> }

export class Store {
  private snap: Snapshot | null = null;
  private stats: Map<string, { n: number; last: number }> | null = null;
  private aliasMap: Map<string, string> | null = null;

  constructor(private sql: SqlStorage, private tx: <T>(fn: () => T) => T, private vault: Vault) {}

  private pj = (jid: string) => this.vault.pid('jid', jid);
  private dirty() { this.snap = null; this.stats = null; }
  /** Forget what was cached, after something outside the store changed the tables. */
  reset() { this.dirty(); this.aliasMap = null; }

  // ----- reading the small tables -----

  private snapshot(): Snapshot {
    if (this.snap) return this.snap;
    const all = <T>(table: string, aad: string) => new Map(this.sql.exec<{ cid: string; data: ArrayBuffer }>(`SELECT cid, data FROM ${table}`).toArray().map((r) => [r.cid, this.vault.open<T>(r.data, aad)] as const));
    const customs = new Map<string, string>();
    for (const [cid, r] of all<{ jid: string; name: string }>('custom_names', NAME)) customs.set(cid, r.name);
    return (this.snap = { chats: all<ChatRec>('chats', CHAT), contacts: all<ContactRec>('contacts', CONTACT), customs });
  }

  private chatStats() {
    if (this.stats) return this.stats;
    const m = new Map<string, { n: number; last: number }>();
    for (const r of this.sql.exec<{ chat: string; n: number; last: number }>(`SELECT chat, COUNT(*) AS n, MAX(ts) AS last FROM messages GROUP BY chat`).toArray()) m.set(r.chat, { n: r.n, last: r.last });
    return (this.stats = m);
  }

  private aliases(): Map<string, string> {
    if (this.aliasMap) return this.aliasMap;
    const m = new Map<string, string>();
    for (const r of this.sql.exec<{ data: ArrayBuffer }>(`SELECT data FROM alias`).toArray()) {
      const a = this.vault.open<{ lid: string; pn: string }>(r.data, ALIAS);
      m.set(a.lid, a.pn);
    }
    return (this.aliasMap = m);
  }

  /** The best name we have for a chat or person, and whether it is only the number. */
  private nameOf(jid: string, s: Snapshot): { name: string; numberOnly: boolean } {
    const id = this.pj(jid), ch = s.chats.get(id), ct = s.contacts.get(id);
    const name = real(ch?.name) ?? real(ct?.name) ?? s.customs.get(id) ?? real(ct?.notify) ?? ch?.push ?? null;
    return name ? { name, numberOnly: false } : { name: numberLabel(jid), numberOnly: true };
  }

  private senderLabel(row: { from_me: number; sender: string | null }, blob: MsgBlob, s: Snapshot): string {
    if (row.from_me) return 'Me';
    const ct = row.sender ? s.contacts.get(row.sender) : undefined;
    const fallback = blob.s ? `+${blob.s.replace('@s.whatsapp.net', '').replace('@lid', '')}` : 'unknown';
    return real(ct?.name) ?? (row.sender ? s.customs.get(row.sender) : undefined) ?? real(ct?.notify) ?? blob.p ?? fallback;
  }

  // ----- writing -----

  private norm(jid?: string | null, alt?: string | null): string | null {
    if (!jid) return null;
    if (jid.endsWith('@lid')) {
      if (alt && !alt.endsWith('@lid')) {
        this.addAlias(jid, alt);
        return jidNormalizedUser(alt);
      }
      const pn = this.aliases().get(jidNormalizedUser(jid));
      if (pn) return pn;
    }
    return jidNormalizedUser(jid);
  }

  private getChat(jid: string): ChatRec | null {
    const r = this.sql.exec<{ data: ArrayBuffer }>(`SELECT data FROM chats WHERE cid = ?`, this.pj(jid)).toArray()[0];
    return r ? this.vault.open<ChatRec>(r.data, CHAT) : null;
  }
  private putChat(rec: ChatRec) {
    this.sql.exec(`INSERT OR REPLACE INTO chats (cid, data) VALUES (?, ?)`, this.pj(rec.jid), this.vault.seal(rec, CHAT));
  }

  addAlias(lid: string, pn: string) {
    lid = jidNormalizedUser(lid);
    pn = jidNormalizedUser(pn);
    const L = this.pj(lid), P = this.pj(pn);
    this.sql.exec(`INSERT OR REPLACE INTO alias (cid, data) VALUES (?, ?)`, L, this.vault.seal({ lid, pn }, ALIAS));
    this.aliases().set(lid, pn);
    // fold anything already stored under the lid into the phone-number jid
    for (const r of this.sql.exec<{ chat: string; id: string; data: ArrayBuffer }>(`SELECT chat, id, data FROM messages WHERE sender = ?`, L).toArray()) {
      const blob = this.vault.open<MsgBlob>(r.data, MSG);
      blob.s = pn;
      this.sql.exec(`UPDATE messages SET sender = ?, data = ? WHERE chat = ? AND id = ?`, P, this.vault.seal(blob, MSG), r.chat, r.id);
    }
    this.sql.exec(`UPDATE OR IGNORE messages SET chat = ? WHERE chat = ?`, P, L);
    this.sql.exec(`DELETE FROM messages WHERE chat = ?`, L);
    const old = this.getChat(lid);
    if (old) {
      if (!this.getChat(pn)) this.putChat({ ...old, jid: pn, group: 0 });
      this.sql.exec(`DELETE FROM chats WHERE cid = ?`, L);
    }
    this.dirty();
  }

  private editBody(chat: string, id: string, body: string, type?: string) {
    const cid = this.pj(chat);
    const r = this.sql.exec<{ data: ArrayBuffer }>(`SELECT data FROM messages WHERE chat = ? AND id = ?`, cid, id).toArray()[0];
    if (!r) return;
    const blob = this.vault.open<MsgBlob>(r.data, MSG);
    blob.b = body;
    this.sql.exec(`UPDATE messages SET data = ?${type ? ', type = ?' : ''} WHERE chat = ? AND id = ?`, ...[this.vault.seal(blob, MSG), ...(type ? [type] : []), cid, id]);
  }

  /**
   * A reaction is stored as its own line in the chat, at the time it was made, so an agent reading the latest
   * messages sees it as the reply it often is. One per person per message: a new emoji replaces the old one,
   * and an empty one (taking it back) removes it.
   */
  private react(chat: string, r: { target: string; fromMe: boolean; senderJid: string | null; emoji: string; ts: number; push?: string | null }): number {
    const cid = this.pj(chat);
    const sender = r.fromMe ? 'me' : r.senderJid ? this.pj(r.senderJid) : null;
    const id = `react:${r.target}:${sender ?? '?'}`;
    const old = this.sql.exec<{ ts: number }>(`SELECT ts FROM messages WHERE chat = ? AND id = ?`, cid, id).toArray()[0];
    if (old && old.ts > r.ts) return 0; // an older update arriving late
    if (!r.emoji) {
      if (old) this.sql.exec(`DELETE FROM messages WHERE chat = ? AND id = ?`, cid, id);
      return 0;
    }
    const t = this.sql.exec<{ data: ArrayBuffer }>(`SELECT data FROM messages WHERE chat = ? AND id = ?`, cid, r.target).toArray()[0];
    const said = t ? this.vault.open<MsgBlob>(t.data, MSG).b : null;
    const quote = said ? ` to "${said.length > 80 ? said.slice(0, 80).trimEnd() + '…' : said}"` : ' to a message';
    const blob: MsgBlob = { b: `[reacted ${r.emoji}${quote}]` };
    if (r.push) blob.p = r.push;
    if (!r.fromMe && r.senderJid) blob.s = r.senderJid;
    this.sql.exec(
      `INSERT OR REPLACE INTO messages (id, chat, ts, from_me, sender, type, data) VALUES (?,?,?,?,?,?,?)`,
      id, cid, r.ts, r.fromMe ? 1 : 0, sender, 'reaction', this.vault.seal(blob, MSG),
    );
    return old ? 0 : 1;
  }

  /** Inserts new messages and applies edits/deletes and reactions. Returns how many were new. */
  ingestMessages(msgs: proto.IWebMessageInfo[]): number {
    let added = 0;
    const chatsSeen = new Map<string, { group: 0 | 1; push?: { p: string; ts: number } }>();
    // reactions wait until the batch's messages are in, so they can quote the message they react to
    const reactions: { chat: string; r: Parameters<Store['react']>[1] }[] = [];
    this.tx(() => {
      for (const msg of msgs) {
        const key = msg.key;
        if (!key?.id || !key.remoteJid || key.remoteJid === 'status@broadcast') continue;
        const chat = this.norm(key.remoteJid, (key as any).remoteJidAlt);
        if (!chat) continue;
        const isGroupChat = chat.endsWith('@g.us');
        const who = (k: proto.IMessageKey | null | undefined, participant?: string | null) =>
          k?.fromMe ? null : isGroupChat ? this.norm(k?.participant ?? participant, (k as any)?.participantAlt) : chat;
        // history sync can carry reactions on the message itself
        for (const x of msg.reactions ?? []) {
          reactions.push({ chat, r: { target: key.id, fromMe: !!x.key?.fromMe, senderJid: who(x.key), emoji: x.text ?? '', ts: Math.floor(num(x.senderTimestampMs) / 1000) || num(msg.messageTimestamp) } });
        }
        const rm = normalizeMessageContent(msg.message)?.reactionMessage;
        if (rm?.key?.id) {
          reactions.push({ chat, r: { target: rm.key.id, fromMe: !!key.fromMe, senderJid: who(key, msg.participant), emoji: rm.text ?? '', ts: Math.floor(num(rm.senderTimestampMs) / 1000) || num(msg.messageTimestamp), push: msg.pushName } });
          if (!chatsSeen.has(chat)) chatsSeen.set(chat, { group: isGroupChat ? 1 : 0 });
          continue;
        }
        const proto_ = msg.message?.protocolMessage;
        if (proto_?.key?.id) {
          if (proto_.editedMessage) {
            const body = proto_.editedMessage.conversation ?? proto_.editedMessage.extendedTextMessage?.text;
            if (body) this.editBody(chat, proto_.key.id, body);
          } else if (proto_.type === 0) {
            this.editBody(chat, proto_.key.id, '[deleted]', 'deleted');
          }
          continue;
        }
        const d = describe(msg);
        if (!d) continue;
        const isGroup = chat.endsWith('@g.us');
        const senderJid = key.fromMe
          ? 'me'
          : isGroup
            ? this.norm(key.participant ?? msg.participant, (key as any).participantAlt)
            : chat;
        const cid = this.pj(chat);
        const sender = senderJid === 'me' ? 'me' : senderJid ? this.pj(senderJid) : null;
        const ts = num(msg.messageTimestamp);
        const media: MediaRef | undefined = d.media && {
          ...d.media,
          rk: { remoteJid: key.remoteJid, fromMe: !!key.fromMe, ...(key.participant ? { participant: key.participant } : {}) },
        };

        const existing = this.sql.exec<{ sender: string | null; data: ArrayBuffer }>(`SELECT sender, data FROM messages WHERE chat = ? AND id = ?`, cid, key.id).toArray()[0];
        if (!existing) {
          const blob: MsgBlob = { b: d.body };
          if (msg.pushName) blob.p = msg.pushName;
          if (senderJid && senderJid !== 'me') blob.s = senderJid;
          if (media) blob.m = media;
          this.sql.exec(
            `INSERT INTO messages (id, chat, ts, from_me, sender, type, data) VALUES (?,?,?,?,?,?,?)`,
            key.id, cid, ts, key.fromMe ? 1 : 0, sender, d.type, this.vault.seal(blob, MSG),
          );
          added++;
        } else if (existing.sender == null || msg.pushName || media) {
          // a repeat delivery can still fill in who sent it, their push name, or (stored before media was kept) the media
          const blob = this.vault.open<MsgBlob>(existing.data, MSG);
          const fillPush = !blob.p && msg.pushName;
          const fillSender = existing.sender == null && sender;
          const fillMedia = !blob.m && media;
          if (fillPush || fillSender || fillMedia) {
            if (fillPush) blob.p = msg.pushName!;
            if (fillMedia) blob.m = media;
            if (fillSender && senderJid && senderJid !== 'me') blob.s = senderJid;
            this.sql.exec(`UPDATE messages SET sender = COALESCE(sender, ?), data = ? WHERE chat = ? AND id = ?`, sender, this.vault.seal(blob, MSG), cid, key.id);
          }
        }

        const seen = chatsSeen.get(chat) ?? { group: isGroup ? 1 : 0 };
        if (!key.fromMe && msg.pushName && (seen.push?.ts ?? -1) <= ts) seen.push = { p: msg.pushName, ts };
        chatsSeen.set(chat, seen);
      }
      for (const { chat, r } of reactions) added += this.react(chat, r);
      // one write per chat for the batch, not one per message
      for (const [jid, seen] of chatsSeen) {
        const old = this.getChat(jid);
        const rec: ChatRec = old ?? { jid, group: seen.group };
        let changed = !old;
        if (seen.push && seen.push.ts >= (rec.pushTs ?? -1)) { rec.push = seen.push.p; rec.pushTs = seen.push.ts; changed = true; }
        if (changed) this.putChat(rec);
      }
    });
    this.dirty();
    return added;
  }

  upsertContacts(contacts: { id?: string | null; lid?: string | null; phoneNumber?: string | null; name?: string | null; notify?: string | null; verifiedName?: string | null }[]) {
    this.tx(() => {
      for (const c of contacts) {
        if (!c.id) continue;
        const pn = c.id.endsWith('@lid') ? c.phoneNumber : c.id;
        const lid = c.id.endsWith('@lid') ? c.id : c.lid;
        if (lid && pn) this.addAlias(lid, pn);
        const jid = jidNormalizedUser(pn || c.id);
        const cid = this.pj(jid);
        const old = this.sql.exec<{ data: ArrayBuffer }>(`SELECT data FROM contacts WHERE cid = ?`, cid).toArray()[0];
        const prev = old ? this.vault.open<ContactRec>(old.data, CONTACT) : null;
        const name = isPlaceholder(c.name) ? null : c.name;
        const notify = isPlaceholder(c.notify ?? c.verifiedName) ? null : (c.notify ?? c.verifiedName);
        const rec: ContactRec = { jid, name: name ?? prev?.name ?? null, notify: notify ?? prev?.notify ?? null };
        this.sql.exec(`INSERT OR REPLACE INTO contacts (cid, data) VALUES (?, ?)`, cid, this.vault.seal(rec, CONTACT));
      }
    });
    this.dirty();
  }

  upsertChatNames(chats: { id?: string | null; name?: string | null; subject?: string | null }[]) {
    this.tx(() => {
      for (const c of chats) {
        const name = c.name ?? c.subject;
        if (!c.id || !name || isPlaceholder(name)) continue;
        const jid = this.norm(c.id) ?? c.id;
        const rec = this.getChat(jid) ?? { jid, group: jid.endsWith('@g.us') ? 1 : 0 } as ChatRec;
        rec.name = name;
        this.putChat(rec);
      }
    });
    this.dirty();
  }

  /**
   * Save names for numbers. An empty name removes a saved one. Keyed by jid, so a name sticks to the
   * phone number and shows up in every chat and group that person is in.
   */
  setCustomNames(rows: { jid: string; name: string }[]) {
    let saved = 0, removed = 0, withChat = 0;
    this.tx(() => {
      for (const r of rows) {
        const cid = this.pj(r.jid);
        if (r.name) {
          this.sql.exec(`INSERT OR REPLACE INTO custom_names (cid, data) VALUES (?, ?)`, cid, this.vault.seal({ jid: r.jid, name: r.name }, NAME));
          saved++;
        } else {
          removed += this.sql.exec(`DELETE FROM custom_names WHERE cid = ?`, cid).rowsWritten > 0 ? 1 : 0;
        }
        if (this.sql.exec(`SELECT 1 FROM messages WHERE chat = ? LIMIT 1`, cid).toArray().length) withChat++;
      }
    });
    this.dirty();
    return { saved, removed, withChat };
  }

  setMeta(k: string, v: string) {
    this.sql.exec(`INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)`, k, v);
  }
  getMeta(k: string): string | null {
    return this.sql.exec<{ v: string }>(`SELECT v FROM meta WHERE k = ?`, k).toArray()[0]?.v ?? null;
  }

  counts() {
    const one = (q: string) => this.sql.exec<{ n: number }>(q).toArray()[0].n;
    return { messages: one(`SELECT COUNT(*) n FROM messages`), chats: one(`SELECT COUNT(DISTINCT chat) n FROM messages`) };
  }

  // ----- queries -----

  /** Chats that have messages, with their names and activity. */
  private chatRows() {
    const s = this.snapshot();
    const rows: { jid: string; name: string; numberOnly: boolean; is_group: number; messages: number; last_ts: number }[] = [];
    for (const [cid, st] of this.chatStats()) {
      const rec = s.chats.get(cid);
      if (!rec) continue;
      const { name, numberOnly } = this.nameOf(rec.jid, s);
      rows.push({ jid: rec.jid, name, numberOnly, is_group: rec.group, messages: st.n, last_ts: st.last });
    }
    return rows;
  }

  /** One-to-one chats that are still only a phone number: no WhatsApp name, no saved name, no display name. */
  unnamedChats(limit: number) {
    const rows = this.chatRows().filter((r) => !r.is_group && r.numberOnly).sort((a, b) => b.messages - a.messages || b.last_ts - a.last_ts).slice(0, limit);
    return rows.map((r) => {
      const theirs = this.sql.exec<{ data: ArrayBuffer }>(`SELECT data FROM messages WHERE chat = ? AND from_me = 0 ORDER BY ts DESC LIMIT 1`, this.pj(r.jid)).toArray()[0];
      return { jid: r.jid, name: r.name, messages: r.messages, last_ts: r.last_ts, last_theirs: theirs ? this.vault.open<MsgBlob>(theirs.data, MSG).b : null };
    });
  }
  unnamedCount(): number {
    return this.chatRows().filter((r) => !r.is_group && r.numberOnly).length;
  }

  /** Resolve a chat reference (jid, or name/number fragment) to jids. */
  resolveChat(ref: string): { jid: string; name: string }[] {
    if (ref.includes('@')) return [{ jid: ref, name: this.chatName(ref) }];
    const q = ref.toLowerCase();
    return this.chatRows()
      .filter((r) => r.name.toLowerCase().includes(q) || r.jid.toLowerCase().includes(q))
      .sort((a, b) => b.last_ts - a.last_ts).slice(0, 10)
      .map((r) => ({ jid: r.jid, name: r.name }));
  }

  chatName(jid: string): string {
    return this.nameOf(jid, this.snapshot()).name;
  }

  listChats(query: string | undefined, limit: number) {
    const q = query?.toLowerCase();
    return this.chatRows()
      .filter((r) => !q || r.name.toLowerCase().includes(q) || r.jid.toLowerCase().includes(q))
      .sort((a, b) => b.last_ts - a.last_ts).slice(0, limit)
      .map(({ jid, name, is_group, messages, last_ts }) => ({ jid, name, is_group, messages, last_ts }));
  }

  getMessages(opts: { chat: string; before?: number; after?: number; limit: number; newestFirst?: boolean }) {
    const where = [`chat = ?`];
    const args: (string | number)[] = [this.pj(opts.chat)];
    if (opts.before) { where.push(`ts < ?`); args.push(opts.before); }
    if (opts.after) { where.push(`ts > ?`); args.push(opts.after); }
    // newest N, shown oldest-first, unless an `after` cursor asks to page forward
    const order = opts.after && !opts.before ? 'ASC' : 'DESC';
    const s = this.snapshot();
    const rows = this.sql
      .exec<{ id: string; ts: number; from_me: number; sender: string | null; type: string; data: ArrayBuffer }>(
        `SELECT id, ts, from_me, sender, type, data FROM messages WHERE ${where.join(' AND ')} ORDER BY ts ${order} LIMIT ?`,
        ...args, opts.limit,
      )
      .toArray()
      .map((r) => {
        const blob = this.vault.open<MsgBlob>(r.data, MSG);
        return { id: r.id, ts: r.ts, sender: this.senderLabel(r, blob, s), type: r.type, body: blob.b, media: Boolean(blob.m) };
      });
    return order === 'DESC' ? rows.reverse() : rows;
  }

  /**
   * Find messages for several queries in one pass, newest first. There is no index to search: the messages are
   * sealed, so this streams them out of SQLite, decrypts each one and tests it against every query still looking.
   * Decrypting is the expensive part and it happens once per message however many queries ride along, so
   * agents should batch. It stops as soon as every query has `limit` hits.
   */
  search(opts: { queries: string[]; chat?: string; since?: number; until?: number; limit: number }): { hits: SearchHit[][]; scanned: number } {
    const wants = opts.queries.map((q) => ({ terms: parseQuery(q), hits: [] as SearchHit[] }));
    const live = new Set(wants.filter((w) => w.terms.length));
    if (!live.size) return { hits: wants.map(() => []), scanned: 0 };
    const where: string[] = [];
    const args: (string | number)[] = [];
    if (opts.chat) { where.push(`chat = ?`); args.push(this.pj(opts.chat)); }
    if (opts.since) { where.push(`ts >= ?`); args.push(opts.since); }
    if (opts.until) { where.push(`ts <= ?`); args.push(opts.until); }
    const s = this.snapshot();
    const jidOf = new Map<string, string>();
    for (const [cid, rec] of s.chats) jidOf.set(cid, rec.jid);
    const cursor = this.sql.exec<{ id: string; chat: string; ts: number; from_me: number; sender: string | null; data: ArrayBuffer }>(
      `SELECT id, chat, ts, from_me, sender, data FROM messages ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY ts DESC`, ...args,
    );
    let scanned = 0;
    for (const row of cursor) {
      scanned++;
      const blob = this.vault.open<MsgBlob>(row.data, MSG);
      for (const w of live) {
        if (!matches(blob.b, w.terms)) continue;
        const jid = jidOf.get(row.chat) ?? row.chat;
        w.hits.push({ id: row.id, chat: jid, chat_name: this.nameOf(jid, s).name, ts: row.ts, sender: this.senderLabel(row, blob, s), body: blob.b, media: Boolean(blob.m) });
        if (w.hits.length >= opts.limit) live.delete(w);
      }
      if (!live.size) break;
    }
    return { hits: wants.map((w) => w.hits), scanned };
  }

  /** The media reference stored with a message, if it has one. */
  media(chat: string, id: string): MediaRef | null {
    const r = this.sql.exec<{ data: ArrayBuffer }>(`SELECT data FROM messages WHERE chat = ? AND id = ?`, this.pj(chat), id).toArray()[0];
    return r ? (this.vault.open<MsgBlob>(r.data, MSG).m ?? null) : null;
  }

  /** A voice note's saved transcript, if it has been transcribed. */
  transcript(chat: string, id: string): string | null {
    const r = this.sql.exec<{ data: ArrayBuffer }>(`SELECT data FROM messages WHERE chat = ? AND id = ?`, this.pj(chat), id).toArray()[0];
    return r ? (this.vault.open<MsgBlob>(r.data, MSG).t ?? null) : null;
  }

  /** Keep a transcript with the message and in its text, after the label, so reading and search see it. */
  setTranscript(chat: string, id: string, transcript: string) {
    const cid = this.pj(chat);
    const r = this.sql.exec<{ data: ArrayBuffer }>(`SELECT data FROM messages WHERE chat = ? AND id = ?`, cid, id).toArray()[0];
    if (!r) return;
    const blob = this.vault.open<MsgBlob>(r.data, MSG);
    const label = blob.t ? blob.b.slice(0, blob.b.length - ` (transcript) ${blob.t}`.length) : blob.b;
    blob.t = transcript;
    blob.b = `${label} (transcript) ${transcript}`;
    this.sql.exec(`UPDATE messages SET data = ? WHERE chat = ? AND id = ?`, this.vault.seal(blob, MSG), cid, id);
  }

  /** Where the phone re-uploaded a message's media to. */
  setMediaLocation(chat: string, id: string, loc: { path?: string; url?: string }) {
    const cid = this.pj(chat);
    const r = this.sql.exec<{ data: ArrayBuffer }>(`SELECT data FROM messages WHERE chat = ? AND id = ?`, cid, id).toArray()[0];
    if (!r) return;
    const blob = this.vault.open<MsgBlob>(r.data, MSG);
    if (!blob.m) return;
    blob.m = { ...blob.m, ...loc };
    this.sql.exec(`UPDATE messages SET data = ? WHERE chat = ? AND id = ?`, this.vault.seal(blob, MSG), cid, id);
  }

  /**
   * One-to-one chats where the other person spoke last: nothing from me after their latest message. A reaction of
   * mine counts as an answer; theirs doesn't count as a new message. Groups, channels and broadcasts are left out.
   */
  unanswered(opts: { since?: number; limit: number }) {
    const s = this.snapshot();
    const latest = this.sql.exec<{ chat: string; from_me: number }>(
      `SELECT m.chat, m.from_me FROM messages m
       JOIN (SELECT chat, MAX(ts) AS t FROM messages WHERE type != 'reaction' OR from_me = 1 GROUP BY chat) l ON m.chat = l.chat AND m.ts = l.t
       WHERE (m.type != 'reaction' OR m.from_me = 1) ${opts.since ? 'AND l.t >= ?' : ''}`,
      ...(opts.since ? [opts.since] : []),
    ).toArray();
    const answered = new Set(latest.filter((r) => r.from_me).map((r) => r.chat));
    const out: { jid: string; name: string; waiting: number; since: number; last_ts: number; last: string }[] = [];
    for (const cid of new Set(latest.map((r) => r.chat))) {
      if (answered.has(cid)) continue;
      const rec = s.chats.get(cid);
      if (!rec || rec.group || !/@(s\.whatsapp\.net|lid)$/.test(rec.jid)) continue;
      const theirs = this.sql.exec<{ ts: number; data: ArrayBuffer }>(
        `SELECT ts, data FROM messages WHERE chat = ? AND from_me = 0 AND type != 'reaction'
         AND ts > COALESCE((SELECT MAX(ts) FROM messages WHERE chat = ? AND from_me = 1), 0) ORDER BY ts`, cid, cid,
      ).toArray();
      if (!theirs.length) continue;
      const lastRow = theirs[theirs.length - 1];
      out.push({
        jid: rec.jid, name: this.nameOf(rec.jid, s).name, waiting: theirs.length, since: theirs[0].ts, last_ts: lastRow.ts,
        last: this.vault.open<MsgBlob>(lastRow.data, MSG).b,
      });
    }
    return out.sort((a, b) => b.last_ts - a.last_ts).slice(0, opts.limit);
  }
}
