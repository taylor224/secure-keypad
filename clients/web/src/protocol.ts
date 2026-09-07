/**
 * secure-keypad client protocol (v1) — pure functions, no DOM.
 *
 * Mirrors spec/PROTOCOL.md: X25519 key agreement, HKDF-SHA256 key schedule, ChaCha20-Poly1305 AEAD,
 * Ed25519 response signature, the inner frame, and the padded input batch.
 */
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { extract, expand } from "@noble/hashes/hkdf.js";
import { concatBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";

export const PROTOCOL_VERSION = 1;
export const RECORD_SIZE = 8;

export type KeypadType = "qwerty" | "number";
export type Platform = "ios" | "android" | "web";
export type Style = "ios" | "material";
export type Role =
  | "char"
  | "space"
  | "shift"
  | "backspace"
  | "mode_abc"
  | "mode_sym1"
  | "mode_sym2"
  | "done"
  | "blank";
export type Mode = "lower" | "upper" | "sym1" | "sym2" | "number";

export interface KeyRect {
  /** [x, y, w, h] in device pixels, relative to the keypad surface. */
  r: [number, number, number, number];
  role: Role;
  /** Sprite cell index; only for role "char". Never identifies a character. */
  t?: number;
}

export interface Layer {
  /** (gen << 3) | mode */
  id: number;
  mode: Mode;
  keys: KeyRect[];
}

export interface SpriteInfo {
  w: number;
  h: number;
  cols: number;
  count: number;
}

export interface LayoutSet {
  v: number;
  type: KeypadType;
  style: Style;
  w: number;
  h: number;
  gen: number;
  maxLen: number;
  exp: number;
  layouts: Layer[];
  tile: SpriteInfo;
  popup: SpriteInfo;
}

export interface Viewport {
  w: number;
  dpr: number;
  platform: Platform;
  style?: Style;
}

export interface SessionResponse {
  v: number;
  sid: string;
  kid: string;
  sp: string;
  sig: string;
  ct: string;
}

export interface RelayoutResponse {
  v: number;
  sid: string;
  gen: number;
  ct: string;
}

/** A recorded character tap. */
export interface Tap {
  layoutId: number;
  x: number;
  y: number;
}

export class ProtocolError extends Error {
  constructor(
    message: string,
    readonly kind: "BAD_SIGNATURE" | "BAD_MAC" | "BAD_RESPONSE" | "UNSUPPORTED" | "CONSUMED" | "TOO_LONG" | "CRYPTO",
  ) {
    super(message);
    this.name = "ProtocolError";
  }
}

// ---- encoding helpers ---------------------------------------------------------------------------

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function b64encode(bytes: Uint8Array, url = false): string {
  const alphabet = url ? B64URL : B64;
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += alphabet[(n >> 18) & 63] + alphabet[(n >> 12) & 63] + alphabet[(n >> 6) & 63] + alphabet[n & 63];
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i] << 16;
    out += alphabet[(n >> 18) & 63] + alphabet[(n >> 12) & 63] + (url ? "" : "==");
  } else if (rem === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += alphabet[(n >> 18) & 63] + alphabet[(n >> 12) & 63] + alphabet[(n >> 6) & 63] + (url ? "" : "=");
  }
  return out;
}

export function b64decode(s: string, url = false): Uint8Array {
  const alphabet = url ? B64URL : B64;
  const clean = url ? s : s.replace(/=+$/, "");
  if (!/^[A-Za-z0-9+/_-]*$/.test(clean) || clean.length % 4 === 1) throw new ProtocolError("bad base64", "BAD_RESPONSE");
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let buf = 0;
  let bits = 0;
  let o = 0;
  for (const ch of clean) {
    const v = alphabet.indexOf(ch);
    if (v < 0) throw new ProtocolError("bad base64 alphabet", "BAD_RESPONSE");
    buf = (buf << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (buf >> bits) & 255;
    }
  }
  return out.subarray(0, o);
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2) throw new Error("odd hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function u32be(v: number): Uint8Array {
  return new Uint8Array([(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]);
}

function readU32be(b: Uint8Array, off: number): number {
  return ((b[off] << 24) >>> 0) + (b[off + 1] << 16) + (b[off + 2] << 8) + b[off + 3];
}

export function nonce12(ctr: number): Uint8Array {
  const n = new Uint8Array(12);
  // 4 zero bytes || u64 big-endian counter (counters stay far below 2^53)
  n[8] = (ctr / 2 ** 24) & 255;
  n[9] = (ctr >>> 16) & 255;
  n[10] = (ctr >>> 8) & 255;
  n[11] = ctr & 255;
  return n;
}

/** Best-effort zeroing. JS engines may keep copies; the server-side wipe is the real guarantee. */
export function wipe(...arrays: (Uint8Array | undefined | null)[]): void {
  for (const a of arrays) a?.fill(0);
}

// ---- client session ------------------------------------------------------------------------------

export interface ClientKeys {
  sk: Uint8Array;
  pk: Uint8Array;
}

export function generateClientKeys(sk?: Uint8Array): ClientKeys {
  const secret = sk ? Uint8Array.from(sk) : randomBytes(32);
  return { sk: secret, pk: x25519.getPublicKey(secret) };
}

export interface SessionRequest {
  v: number;
  kp: string;
  type: KeypadType;
  viewport: Viewport;
  opts?: { maxLen?: number };
}

export function buildSessionRequest(keys: ClientKeys, type: KeypadType, viewport: Viewport, maxLen?: number): SessionRequest {
  const req: SessionRequest = { v: PROTOCOL_VERSION, kp: b64encode(keys.pk), type, viewport: { ...viewport } };
  if (maxLen) req.opts = { maxLen };
  return req;
}

export interface OpenSession {
  sid: Uint8Array;
  sidB64: string;
  kid: string;
  kS2c: Uint8Array;
  kC2s: Uint8Array;
  /** counter for the next server → client message (relayout) */
  s2cCtr: number;
  layout: LayoutSet;
  tiles: Uint8Array;
  popups: Uint8Array;
  consumed: boolean;
}

function deriveKeys(sk: Uint8Array, cPk: Uint8Array, sPk: Uint8Array, sid: Uint8Array): { kS2c: Uint8Array; kC2s: Uint8Array } {
  const ss = x25519.getSharedSecret(sk, sPk);
  if (ss.every((b) => b === 0)) throw new ProtocolError("low-order server key", "CRYPTO");
  const prk = extract(sha256, ss, concatBytes(utf8ToBytes("skp/v1"), sid));
  const kS2c = expand(sha256, prk, concatBytes(utf8ToBytes("s2c"), cPk, sPk), 32);
  const kC2s = expand(sha256, prk, concatBytes(utf8ToBytes("c2s"), cPk, sPk), 32);
  wipe(ss, prk);
  return { kS2c, kC2s };
}

function unframe(pt: Uint8Array): { json: string; tiles: Uint8Array; popups: Uint8Array } {
  let pos = 0;
  const parts: Uint8Array[] = [];
  for (let i = 0; i < 3; i++) {
    if (pos + 4 > pt.length) throw new ProtocolError("truncated frame", "BAD_RESPONSE");
    const n = readU32be(pt, pos);
    pos += 4;
    if (pos + n > pt.length) throw new ProtocolError("truncated frame", "BAD_RESPONSE");
    parts.push(pt.subarray(pos, pos + n));
    pos += n;
  }
  if (pos !== pt.length) throw new ProtocolError("trailing bytes", "BAD_RESPONSE");
  return { json: new TextDecoder().decode(parts[0]), tiles: Uint8Array.from(parts[1]), popups: Uint8Array.from(parts[2]) };
}

function parseLayout(json: string): LayoutSet {
  let l: LayoutSet;
  try {
    l = JSON.parse(json);
  } catch {
    throw new ProtocolError("inner json", "BAD_RESPONSE");
  }
  if (l.v !== PROTOCOL_VERSION || !Array.isArray(l.layouts) || !l.tile || !l.popup) throw new ProtocolError("inner schema", "BAD_RESPONSE");
  return l;
}

/**
 * Verifies and decrypts the server's session response. `serverPublicKey` (base64 Ed25519) is optional
 * but strongly recommended; without it a TLS-breaking attacker could substitute a known layout.
 * The client secret key is wiped on success.
 */
export function openSession(response: SessionResponse, keys: ClientKeys, serverPublicKey?: string | null): OpenSession {
  if (response.v !== PROTOCOL_VERSION) throw new ProtocolError("protocol version", "UNSUPPORTED");
  if (typeof response.sid !== "string" || typeof response.sp !== "string" || typeof response.ct !== "string" || typeof response.kid !== "string")
    throw new ProtocolError("response schema", "BAD_RESPONSE");
  const sid = b64decode(response.sid, true);
  const sPk = b64decode(response.sp);
  const ct = b64decode(response.ct);
  if (sid.length !== 16 || sPk.length !== 32 || response.kid.length !== 8) throw new ProtocolError("response fields", "BAD_RESPONSE");
  if (serverPublicKey) {
    const sig = b64decode(response.sig);
    const msg = concatBytes(utf8ToBytes("skp/v1/session"), utf8ToBytes(response.kid), sid, keys.pk, sPk, sha256(ct));
    let ok = false;
    try {
      ok = ed25519.verify(sig, msg, b64decode(serverPublicKey));
    } catch {
      ok = false;
    }
    if (!ok) throw new ProtocolError("server signature invalid", "BAD_SIGNATURE");
  }
  const { kS2c, kC2s } = deriveKeys(keys.sk, keys.pk, sPk, sid);
  wipe(keys.sk);
  let pt: Uint8Array;
  try {
    pt = chacha20poly1305(kS2c, nonce12(0), concatBytes(utf8ToBytes("skp/v1/session"), sid)).decrypt(ct);
  } catch {
    wipe(kS2c, kC2s);
    throw new ProtocolError("session ciphertext", "BAD_MAC");
  }
  const { json, tiles, popups } = unframe(pt);
  wipe(pt);
  return { sid, sidB64: response.sid, kid: response.kid, kS2c, kC2s, s2cCtr: 1, layout: parseLayout(json), tiles, popups, consumed: false };
}

export function buildRelayoutRequest(session: OpenSession, viewport: Viewport): { v: number; sid: string; viewport: Viewport } {
  return { v: PROTOCOL_VERSION, sid: session.sidB64, viewport: { ...viewport } };
}

/** Decrypts a relayout response and replaces the session's layout set (generation advances). */
export function openRelayout(session: OpenSession, response: RelayoutResponse): LayoutSet {
  if (session.consumed) throw new ProtocolError("session consumed", "CONSUMED");
  if (response.v !== PROTOCOL_VERSION || response.sid !== session.sidB64) throw new ProtocolError("relayout response", "BAD_RESPONSE");
  const ct = b64decode(response.ct);
  let pt: Uint8Array;
  try {
    pt = chacha20poly1305(session.kS2c, nonce12(session.s2cCtr), concatBytes(utf8ToBytes("skp/v1/relayout"), session.sid)).decrypt(ct);
  } catch {
    throw new ProtocolError("relayout ciphertext", "BAD_MAC");
  }
  session.s2cCtr += 1;
  const { json, tiles, popups } = unframe(pt);
  wipe(pt);
  const layout = parseLayout(json);
  if (layout.gen !== response.gen) throw new ProtocolError("relayout generation", "BAD_RESPONSE");
  wipe(session.tiles, session.popups);
  session.layout = layout;
  session.tiles = tiles;
  session.popups = popups;
  return layout;
}

export interface InputPayload {
  v: number;
  sid: string;
  ct: string;
}

/**
 * Encrypts the recorded character taps as the fixed-size batch of spec §7 and consumes the session
 * (keys and sprites are wiped). Returns the payload object the app sends to its own server.
 */
export function buildInputPayload(session: OpenSession, taps: Tap[], maxLen = session.layout.maxLen): InputPayload {
  if (session.consumed) throw new ProtocolError("session consumed", "CONSUMED");
  if (taps.length > maxLen) throw new ProtocolError("too many taps", "TOO_LONG");
  const batch = new Uint8Array(4 + RECORD_SIZE * maxLen);
  batch[0] = 1;
  batch[1] = 0;
  batch[2] = (taps.length >> 8) & 255;
  batch[3] = taps.length & 255;
  taps.forEach((t, i) => {
    const o = 4 + RECORD_SIZE * i;
    batch[o] = (i >> 8) & 255;
    batch[o + 1] = i & 255;
    batch[o + 2] = t.layoutId & 255;
    batch[o + 3] = 0;
    batch[o + 4] = (t.x >> 8) & 255;
    batch[o + 5] = t.x & 255;
    batch[o + 6] = (t.y >> 8) & 255;
    batch[o + 7] = t.y & 255;
  });
  const ct = chacha20poly1305(session.kC2s, nonce12(0), concatBytes(utf8ToBytes("skp/v1/input"), session.sid)).encrypt(batch);
  wipe(batch);
  consumeSession(session);
  return { v: PROTOCOL_VERSION, sid: session.sidB64, ct: b64encode(ct) };
}

/** Wipes key material and sprites. Safe to call more than once. */
export function consumeSession(session: OpenSession): void {
  wipe(session.kS2c, session.kC2s, session.tiles, session.popups);
  session.consumed = true;
}

// ---- geometry ------------------------------------------------------------------------------------

/** Nearest key by squared distance to the rect (spec §10); ties resolve to the first listed key. */
export function hitTest(layer: Layer, x: number, y: number): number {
  let best = -1;
  let bestD = Infinity;
  for (let i = 0; i < layer.keys.length; i++) {
    const [rx, ry, rw, rh] = layer.keys[i].r;
    const dx = Math.max(rx - x, 0, x - (rx + rw - 1));
    const dy = Math.max(ry - y, 0, y - (ry + rh - 1));
    const d = dx * dx + dy * dy;
    if (d < bestD) {
      bestD = d;
      best = i;
    }
  }
  return best;
}

export function findLayer(layout: LayoutSet, mode: Mode): Layer | undefined {
  return layout.layouts.find((l) => l.mode === mode);
}

export const MODE_BITS: Record<Mode, number> = { lower: 0, upper: 1, sym1: 2, sym2: 3, number: 4 };

export function layoutId(gen: number, mode: Mode): number {
  return (gen << 3) | MODE_BITS[mode];
}

export { u32be as _u32be };
