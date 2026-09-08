/**
 * @secure-keypad/server — Node.js server SDK.
 *
 * Wraps the native libskp binding with a session store so that an HTTP handler only has to forward
 * JSON: `createSession(req.body)` → response for the client, `decrypt(payload)` → the typed value.
 */
import { createRequire } from "node:module";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

// tsup's --shims provides import.meta.url in the CJS build, so one code path serves both formats.
const require_ = createRequire(import.meta.url);
// Resolve the package root whether we run from dist/ (built) or src/ (tests): both are one level below it.
const here = dirname(fileURLToPath(import.meta.url));
const native = require_("node-gyp-build")(dirname(here));

export const ERROR_NAMES: Record<number, string> = {
  [-1]: "NOMEM",
  [-2]: "INVALID_ARG",
  [-3]: "BAD_KEY",
  [-4]: "BAD_REQUEST",
  [-5]: "CRYPTO",
  [-6]: "EXPIRED",
  [-7]: "BAD_MAC",
  [-8]: "TAMPERED",
  [-9]: "CTX_MISMATCH",
  [-10]: "SID_MISMATCH",
  [-11]: "RENDER",
  [-12]: "IO",
  [-13]: "UNSUPPORTED",
  [-100]: "SESSION_NOT_FOUND",
};

export type SkpErrorKind =
  | "NOMEM"
  | "INVALID_ARG"
  | "BAD_KEY"
  | "BAD_REQUEST"
  | "CRYPTO"
  | "EXPIRED"
  | "BAD_MAC"
  | "TAMPERED"
  | "CTX_MISMATCH"
  | "SID_MISMATCH"
  | "RENDER"
  | "IO"
  | "UNSUPPORTED"
  | "SESSION_NOT_FOUND";

/** Error raised by the SDK. `kind` is stable; `message` is for logs only and never contains values. */
export class SkpError extends Error {
  readonly code: number;
  readonly kind: SkpErrorKind;
  constructor(code: number, message: string) {
    super(message);
    this.name = "SkpError";
    this.code = code;
    this.kind = (ERROR_NAMES[code] ?? "CRYPTO") as SkpErrorKind;
  }
}

function wrap<T>(fn: () => T): T {
  try {
    return fn();
  } catch (e: any) {
    if (e && typeof e.code === "number") throw new SkpError(e.code, e.message);
    throw e;
  }
}

/** Where sealed session blobs live between creation and decryption. Blobs are ciphertext. */
export interface SessionStore {
  put(sid: string, sealed: Uint8Array, ttlSec: number): Promise<void> | void;
  get(sid: string): Promise<Uint8Array | null | undefined> | Uint8Array | null | undefined;
  /** Atomically fetch and delete. */
  take(sid: string): Promise<Uint8Array | null | undefined> | Uint8Array | null | undefined;
  delete(sid: string): Promise<void> | void;
}

/** In-process store for single-instance deployments. */
export class MemoryStore implements SessionStore {
  private readonly map = new Map<string, { sealed: Uint8Array; expires: number }>();
  private sweepCounter = 0;

  put(sid: string, sealed: Uint8Array, ttlSec: number): void {
    this.map.set(sid, { sealed: Uint8Array.from(sealed), expires: Date.now() + ttlSec * 1000 });
    if (++this.sweepCounter % 256 === 0) this.sweep();
  }

  get(sid: string): Uint8Array | null {
    const e = this.map.get(sid);
    if (!e) return null;
    if (e.expires < Date.now()) {
      this.delete(sid);
      return null;
    }
    return e.sealed;
  }

  take(sid: string): Uint8Array | null {
    const v = this.get(sid);
    if (!v) return null;
    const copy = Uint8Array.from(v); // delete() zeroes the stored copy
    this.delete(sid);
    return copy;
  }

  delete(sid: string): void {
    const e = this.map.get(sid);
    if (e) e.sealed.fill(0);
    this.map.delete(sid);
  }

  get size(): number {
    return this.map.size;
  }

  sweep(): void {
    const now = Date.now();
    for (const [sid, e] of this.map) if (e.expires < now) this.delete(sid);
  }
}

/** The decrypted value. Call `wipe()` as soon as it has been used. */
export class Secret {
  #bytes: Buffer;
  #wiped = false;
  constructor(bytes: Buffer) {
    this.#bytes = bytes;
  }
  /** UTF-8 bytes, owned by this Secret. Do not keep references beyond `wipe()`. */
  get bytes(): Buffer {
    if (this.#wiped) throw new Error("secret has been wiped");
    return this.#bytes;
  }
  get length(): number {
    return this.#wiped ? 0 : this.#bytes.length;
  }
  get wiped(): boolean {
    return this.#wiped;
  }
  /** Decodes to a JS string. Strings cannot be wiped; prefer `bytes` when the consumer accepts them. */
  toString(): string {
    return this.bytes.toString("utf8");
  }
  /** Zeroes the buffer. Best effort: V8 may have made copies during earlier reads. */
  wipe(): void {
    if (!this.#wiped) {
      this.#bytes.fill(0);
      this.#wiped = true;
    }
  }
}

export interface ServerOptions {
  /** Path to a file holding the base64 or hex master key. */
  masterKeyPath?: string;
  /** The master key itself (base64/hex string or 32 raw bytes). */
  masterKey?: string | Uint8Array;
  /** Session store; defaults to an in-memory store. */
  store?: SessionStore;
  /** Default session lifetime in seconds (180). */
  defaultTtl?: number;
  /** Upper bound for maxLen (256). */
  maxLenCap?: number;
  fontIosPath?: string;
  fontMaterialPath?: string;
  /** TrueType file replacing the embedded Noto Sans KR subset used for Hangul labels. */
  fontFallbackPath?: string;
}

/** Keyboard languages of the QWERTY keypad: "en" (Latin), "ko" (Korean 2-set, composed server-side). */
export type KeypadLanguage = "en" | "ko";

export interface CreateSessionOptions {
  /** Binding context (user id, login attempt id). Must be passed again to `decrypt`. */
  ctx?: string;
  /** "shuffle" (default) | "full" | "fixed" (native QWERTY / 2-set / phone-pad order; coordinates reveal characters) */
  layout?: "shuffle" | "full" | "fixed";
  /** Shuffled number pad blank cell: "fixed" (default) | "random"; ignored with layout "fixed" */
  blank?: "fixed" | "random";
  ttl?: number;
  maxLen?: number;
  /**
   * Languages of the QWERTY keypad in switch order (first is shown initially), e.g. ["en", "ko"] or ["ko"].
   * Unset: the client's request (`opts.langs`) is honoured, else the default ["en", "ko"]. Ignored for number pads.
   */
  languages?: KeypadLanguage[] | string;
}

export interface DecryptOptions {
  ctx?: string;
  /** Keep the session in the store after a successful decrypt (default false: single use). */
  keep?: boolean;
}

function toJson(v: object | string): string {
  return typeof v === "string" ? v : JSON.stringify(v);
}

export class SecureKeypadServer {
  private readonly native: any;
  readonly store: SessionStore;
  readonly publicKey: string;
  readonly keyId: string;

  constructor(options: ServerOptions) {
    if (!options || (!options.masterKeyPath && !options.masterKey)) {
      const env = process.env.SKP_MASTER_KEY;
      const envPath = process.env.SKP_MASTER_KEY_PATH;
      if (!env && !envPath) throw new SkpError(-2, "masterKeyPath or masterKey is required (or SKP_MASTER_KEY / SKP_MASTER_KEY_PATH)");
      options = { ...options, masterKey: env || undefined, masterKeyPath: env ? undefined : envPath };
    }
    this.store = options.store ?? new MemoryStore();
    this.native = wrap(
      () =>
        new native.Server({
          masterKeyPath: options.masterKeyPath,
          masterKey: options.masterKey instanceof Uint8Array ? Buffer.from(options.masterKey) : options.masterKey,
          defaultTtl: options.defaultTtl,
          maxLenCap: options.maxLenCap,
          fontIosPath: options.fontIosPath,
          fontMaterialPath: options.fontMaterialPath,
          fontFallbackPath: options.fontFallbackPath,
        }),
    );
    this.publicKey = this.native.publicKey();
    this.keyId = this.native.keyId();
  }

  /** Creates a session from the client's request JSON and stores the sealed state. Returns the response object. */
  async createSession(request: object | string, opts: CreateSessionOptions = {}): Promise<Record<string, unknown>> {
    const nativeOpts = { ...opts, languages: Array.isArray(opts.languages) ? opts.languages.join(",") : opts.languages };
    const { response, sealed } = wrap(() => this.native.createSession(toJson(request), nativeOpts));
    const info = wrap(() => this.native.sessionInfo(sealed));
    const ttl = Math.max(1, info.expires - Math.floor(Date.now() / 1000));
    await this.store.put(info.sid, sealed, ttl);
    return JSON.parse(response);
  }

  /** Re-renders the session for a new viewport; the stored blob is replaced. */
  async relayout(request: object | string): Promise<Record<string, unknown>> {
    const req = typeof request === "string" ? JSON.parse(request) : request;
    const sid = typeof req?.sid === "string" ? req.sid : null;
    if (!sid) throw new SkpError(-4, "relayout: sid missing");
    const sealed = await this.store.get(sid);
    if (!sealed) throw new SkpError(-100, "relayout: session not found");
    const out = wrap(() => this.native.relayout(Buffer.from(sealed), toJson(req)));
    const info = wrap(() => this.native.sessionInfo(out.sealed));
    await this.store.put(sid, out.sealed, Math.max(1, info.expires - Math.floor(Date.now() / 1000)));
    return JSON.parse(out.response);
  }

  /** Decrypts the client's payload. The session is removed from the store unless `keep` is set. */
  async decrypt(payload: object | string, opts: DecryptOptions = {}): Promise<Secret> {
    const p = typeof payload === "string" ? JSON.parse(payload) : payload;
    const sid = typeof p?.sid === "string" ? p.sid : null;
    if (!sid) throw new SkpError(-4, "decrypt: sid missing");
    const sealed = opts.keep ? await this.store.get(sid) : await this.store.take(sid);
    if (!sealed) throw new SkpError(-100, "decrypt: session not found (expired, already used, or unknown)");
    try {
      const bytes: Buffer = wrap(() => this.native.decrypt(Buffer.from(sealed), toJson(p), opts.ctx));
      return new Secret(bytes);
    } finally {
      if (!opts.keep) (sealed as Uint8Array).fill?.(0);
    }
  }

  /** Expiry (unix seconds) and sid of a sealed blob, for custom stores. */
  sessionInfo(sealed: Uint8Array): { expires: number; sid: string } {
    return wrap(() => this.native.sessionInfo(Buffer.from(sealed)));
  }

  /** Releases the native context. The instance is unusable afterwards. */
  close(): void {
    this.native.close();
  }
}

/** Generates a new master key (base64). Store it with restrictive permissions. */
export function keygen(): string {
  return wrap(() => native.keygen());
}

export const nativeVersion: string = native.version();

/** Test builds only (`npm run build:native:test`): inject randomness and the clock. */
export const testing: { enabled: boolean; setHooks?: (hooks: Record<string, unknown> | null) => void } = {
  enabled: !!native.testing,
  setHooks: native.setTestHooks,
};
