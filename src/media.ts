/**
 * Media download: fetch a message's encrypted file from WhatsApp's CDN and decrypt it with the key stored
 * alongside the message. Nothing is downloaded until an agent asks for it, and nothing downloaded is kept.
 *
 * The format is WhatsApp's: HKDF-SHA256 expands the 32-byte media key (salt zero, info by media type) into
 * an IV, an AES-256-CBC key and an HMAC-SHA256 key. The file is the ciphertext followed by the first 10 bytes
 * of HMAC(iv || ciphertext). Done with WebCrypto so it runs the same on Workers and under local workerd.
 */
import type { MediaKind, MediaRef } from './store.js';

const INFO: Record<MediaKind, string> = {
  image: 'WhatsApp Image Keys',
  sticker: 'WhatsApp Image Keys',
  video: 'WhatsApp Video Keys',
  audio: 'WhatsApp Audio Keys',
  document: 'WhatsApp Document Keys',
};
const CDN = 'https://mmg.whatsapp.net';
const MAC_LEN = 10;

export type Download =
  | { ok: true; bytes: Uint8Array }
  | { ok: false; expired: boolean; error: string };

async function keys(mediaKey: Uint8Array, kind: MediaKind) {
  const base = await crypto.subtle.importKey('raw', mediaKey, 'HKDF', false, ['deriveBits']);
  const bits = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode(INFO[kind]) }, base, 112 * 8),
  );
  return { iv: bits.slice(0, 16), cipherKey: bits.slice(16, 48), macKey: bits.slice(48, 80) };
}

/** Fetch and decrypt. `expired` means the CDN no longer has it, and asking the phone to upload it again may help. */
export async function downloadMedia(ref: Pick<MediaRef, 'k' | 'key' | 'path' | 'url' | 'len'>, maxBytes: number): Promise<Download> {
  if (ref.len && ref.len > maxBytes) return { ok: false, expired: false, error: `file is ${mb(ref.len)}, over the ${mb(maxBytes)} limit` };
  const url = ref.path ? `${CDN}${ref.path}` : ref.url;
  if (!url) return { ok: false, expired: true, error: 'no download location stored' };
  const res = await fetch(url, { headers: { Origin: 'https://web.whatsapp.com' } });
  if (res.status === 404 || res.status === 410) return { ok: false, expired: true, error: `WhatsApp's copy has expired (${res.status})` };
  if (!res.ok) return { ok: false, expired: false, error: `download failed (${res.status})` };
  const declared = Number(res.headers.get('content-length') ?? 0);
  if (declared > maxBytes + MAC_LEN + 16) return { ok: false, expired: false, error: `file is ${mb(declared)}, over the ${mb(maxBytes)} limit` };
  const file = new Uint8Array(await res.arrayBuffer());
  if (file.length <= MAC_LEN) return { ok: false, expired: false, error: 'download was empty' };

  const { iv, cipherKey, macKey } = await keys(Buffer.from(ref.key, 'base64'), ref.k);
  const body = file.subarray(0, file.length - MAC_LEN);
  const mac = new Uint8Array(
    await crypto.subtle.sign('HMAC', await crypto.subtle.importKey('raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']), concat(iv, body)),
  ).subarray(0, MAC_LEN);
  if (!equal(mac, file.subarray(file.length - MAC_LEN))) return { ok: false, expired: false, error: 'file failed its integrity check' };
  try {
    const aes = await crypto.subtle.importKey('raw', cipherKey, 'AES-CBC', false, ['decrypt']);
    return { ok: true, bytes: new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, aes, body)) };
  } catch {
    return { ok: false, expired: false, error: 'could not decrypt the file' };
  }
}

const mb = (n: number) => `${(n / 1024 / 1024).toFixed(1)} MB`;
const concat = (a: Uint8Array, b: Uint8Array) => {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
};
const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
