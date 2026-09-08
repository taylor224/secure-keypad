/**
 * secure-keypad server SDK running as WebAssembly — the same libskp code as the native bindings.
 *
 * Meant for (1) the zero-backend playground, where the "server" lives inside the page (which is a demo:
 * a keypad whose server runs in the same browser has no secrecy against that browser), and (2) Node
 * platforms without a prebuilt native addon. Loads `skp.js`/`skp.wasm` produced by build.sh.
 *
 * Usage (browser, classic script or module):
 *   const server = await SkpWasmServer.create({ masterKey, moduleUrl: "dist/skp.js" });
 *   server.createSession(requestJson, { ctx, layout }) → response object (sealed state kept in memory)
 *   server.relayout(requestJson) → response object
 *   server.decrypt(payloadJson, { ctx, keep }) → Uint8Array (UTF-8), single use
 *   server.handleFetch(input, init) → Response | null   (routes /keypad/* and /login like the example server)
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.SkpWasmServer = factory();
})(typeof self !== "undefined" ? self : this, function () {
  const ERROR_NAMES = {
    [-1]: "NOMEM", [-2]: "INVALID_ARG", [-3]: "BAD_KEY", [-4]: "BAD_REQUEST", [-5]: "CRYPTO", [-6]: "EXPIRED",
    [-7]: "BAD_MAC", [-8]: "TAMPERED", [-9]: "CTX_MISMATCH", [-10]: "SID_MISMATCH", [-11]: "RENDER", [-12]: "IO",
    [-13]: "UNSUPPORTED", [-100]: "SESSION_NOT_FOUND",
  };

  class SkpError extends Error {
    constructor(code, message) {
      super(message);
      this.name = "SkpError";
      this.code = code;
      this.kind = ERROR_NAMES[code] || "CRYPTO";
    }
  }

  async function loadModule(moduleUrl) {
    if (typeof createSkpModule === "function") return createSkpModule({ locateFile: (f) => new URL(f, moduleUrl || location.href).toString() });
    if (typeof window !== "undefined") {
      await new Promise((resolve, reject) => {
        const s = document.createElement("script");
        s.src = moduleUrl;
        s.onload = resolve;
        s.onerror = () => reject(new Error("cannot load " + moduleUrl));
        document.head.appendChild(s);
      });
      return createSkpModule({ locateFile: (f) => new URL(f, moduleUrl).toString() });
    }
    // node
    const factory = require(moduleUrl);
    return factory();
  }

  class SkpWasmServer {
    static async create(opts = {}) {
      const M = await loadModule(opts.moduleUrl || "skp.js");
      return new SkpWasmServer(M, opts);
    }

    constructor(M, opts) {
      this.M = M;
      this.store = new Map();
      this.defaultTtl = opts.defaultTtl || 0;
      this.c = {
        init: M.cwrap("skp_init", "number", ["number", "number"]),
        free: M.cwrap("skp_free", null, ["number"]),
        strerror: M.cwrap("skp_strerror", "string", ["number"]),
        publicKey: M.cwrap("skp_public_key", "number", ["number", "number", "number"]),
        keyId: M.cwrap("skp_key_id", "number", ["number", "number", "number"]),
        keygenB64: M.cwrap("skp_keygen_b64", "number", ["number", "number"]),
        create: M.cwrap("skp_session_create", "number", ["number", "number", "number", "number", "number", "number"]),
        relayout: M.cwrap("skp_session_relayout", "number", ["number", "number", "number", "number", "number", "number", "number"]),
        decrypt: M.cwrap("skp_session_decrypt", "number", ["number", "number", "number", "number", "number", "number", "number"]),
        info: M.cwrap("skp_session_info", "number", ["number", "number", "number", "number", "number", "number"]),
        secretLen: M.cwrap("skp_secret_len", "number", ["number"]),
        secretBytes: M.cwrap("skp_secret_bytes", "number", ["number"]),
        secretFree: M.cwrap("skp_secret_free", null, ["number"]),
        bufFree: M.cwrap("skp_buf_free", null, ["number"]),
        version: M.cwrap("skp_version", "string", []),
      };
      const masterKey = opts.masterKey || SkpWasmServer.keygen(M);
      // skp_config: { const char *path; const char *key; size_t key_len; const char *font_ios; const char *font_material; u32 ttl; u32 cap; }
      const cfg = M._malloc(32);
      M.HEAPU8.fill(0, cfg, cfg + 32);
      const keyPtr = this.str(masterKey);
      M.setValue(cfg + 4, keyPtr, "i32");
      M.setValue(cfg + 20, opts.defaultTtl || 0, "i32");
      M.setValue(cfg + 24, opts.maxLenCap || 0, "i32");
      const out = M._malloc(4);
      const rc = this.c.init(out, cfg);
      this.M.HEAPU8.fill(0, keyPtr, keyPtr + masterKey.length);
      M._free(keyPtr);
      M._free(cfg);
      this.ctx = M.getValue(out, "i32");
      M._free(out);
      if (rc !== 0) throw new SkpError(rc, "init: " + this.c.strerror(rc));
      const buf = M._malloc(64);
      this.c.publicKey(this.ctx, buf, 64);
      this.publicKey = M.UTF8ToString(buf);
      this.c.keyId(this.ctx, buf, 64);
      this.keyId = M.UTF8ToString(buf);
      M._free(buf);
      this.version = this.c.version();
    }

    static keygen(M) {
      const buf = M._malloc(64);
      const keygen = M.cwrap("skp_keygen_b64", "number", ["number", "number"]);
      keygen(buf, 64);
      const s = M.UTF8ToString(buf);
      M.HEAPU8.fill(0, buf, buf + 64);
      M._free(buf);
      return s;
    }

    str(s) {
      const n = this.M.lengthBytesUTF8(s) + 1;
      const p = this.M._malloc(n);
      this.M.stringToUTF8(s, p, n);
      return p;
    }

    /** Reads and frees an skp_buf {data, len} at ptr. */
    takeBuf(ptr, asString) {
      const data = this.M.getValue(ptr, "i32");
      const len = this.M.getValue(ptr + 4, "i32");
      const bytes = this.M.HEAPU8.slice(data, data + len);
      this.c.bufFree(ptr);
      return asString ? new TextDecoder().decode(bytes) : bytes;
    }

    fail(rc, what) {
      throw new SkpError(rc, what + ": " + this.c.strerror(rc));
    }

    sessionInfo(sealed) {
      const M = this.M;
      const p = M._malloc(sealed.length);
      M.HEAPU8.set(sealed, p);
      const exp = M._malloc(8);
      const sid = M._malloc(64);
      const rc = this.c.info(this.ctx, p, sealed.length, exp, sid, 64);
      const lo = M.getValue(exp, "i32") >>> 0;
      const hi = M.getValue(exp + 4, "i32");
      const info = { expires: hi * 4294967296 + lo, sid: M.UTF8ToString(sid) };
      M._free(p);
      M._free(exp);
      M._free(sid);
      if (rc !== 0) this.fail(rc, "sessionInfo");
      return info;
    }

    createSession(request, opts = {}) {
      const M = this.M;
      const req = typeof request === "string" ? request : JSON.stringify(request);
      const reqPtr = this.str(req);
      // skp_session_opts: { const char *ctx; const char *layout; const char *blank; u32 ttl; u32 max_len; }
      const o = M._malloc(20);
      M.HEAPU8.fill(0, o, o + 20);
      const strs = [];
      const set = (off, v) => {
        if (!v) return;
        const p = this.str(v);
        strs.push(p);
        M.setValue(o + off, p, "i32");
      };
      set(0, opts.ctx);
      set(4, opts.layout);
      set(8, opts.blank);
      M.setValue(o + 12, opts.ttl || 0, "i32");
      M.setValue(o + 16, opts.maxLen || 0, "i32");
      const resp = M._malloc(8), sealed = M._malloc(8);
      const rc = this.c.create(this.ctx, reqPtr, 0, o, resp, sealed);
      M._free(reqPtr);
      strs.forEach((p) => M._free(p));
      M._free(o);
      if (rc !== 0) {
        M._free(resp);
        M._free(sealed);
        this.fail(rc, "createSession");
      }
      const response = JSON.parse(this.takeBuf(resp, true));
      const blob = this.takeBuf(sealed, false);
      M._free(resp);
      M._free(sealed);
      const info = this.sessionInfo(blob);
      this.store.set(info.sid, { sealed: blob, expires: info.expires * 1000 });
      return response;
    }

    relayout(request) {
      const M = this.M;
      const req = typeof request === "string" ? JSON.parse(request) : request;
      const entry = this.store.get(req && req.sid);
      if (!entry) throw new SkpError(-100, "relayout: session not found");
      const reqPtr = this.str(JSON.stringify(req));
      const sp = M._malloc(entry.sealed.length);
      M.HEAPU8.set(entry.sealed, sp);
      const resp = M._malloc(8), sealed = M._malloc(8);
      const rc = this.c.relayout(this.ctx, sp, entry.sealed.length, reqPtr, 0, resp, sealed);
      M._free(reqPtr);
      M._free(sp);
      if (rc !== 0) {
        M._free(resp);
        M._free(sealed);
        this.fail(rc, "relayout");
      }
      const response = JSON.parse(this.takeBuf(resp, true));
      entry.sealed = this.takeBuf(sealed, false);
      M._free(resp);
      M._free(sealed);
      return response;
    }

    /** Returns the decrypted UTF-8 bytes. Zero them when done. */
    decrypt(payload, opts = {}) {
      const M = this.M;
      const p = typeof payload === "string" ? JSON.parse(payload) : payload;
      const sid = p && p.sid;
      const entry = this.store.get(sid);
      if (!entry || entry.expires < Date.now()) {
        this.store.delete(sid);
        throw new SkpError(-100, "decrypt: session not found (expired, already used, or unknown)");
      }
      if (!opts.keep) this.store.delete(sid);
      const sp = M._malloc(entry.sealed.length);
      M.HEAPU8.set(entry.sealed, sp);
      const payloadPtr = this.str(JSON.stringify(p));
      const ctxPtr = opts.ctx ? this.str(opts.ctx) : 0;
      const out = M._malloc(4);
      const rc = this.c.decrypt(this.ctx, sp, entry.sealed.length, payloadPtr, 0, ctxPtr, out);
      M._free(sp);
      M._free(payloadPtr);
      if (ctxPtr) M._free(ctxPtr);
      if (!opts.keep) entry.sealed.fill(0);
      if (rc !== 0) {
        M._free(out);
        this.fail(rc, "decrypt");
      }
      const secret = M.getValue(out, "i32");
      M._free(out);
      const len = this.c.secretLen(secret);
      const ptr = this.c.secretBytes(secret);
      const bytes = M.HEAPU8.slice(ptr, ptr + len);
      this.c.secretFree(secret);
      return bytes;
    }

    close() {
      if (this.ctx) this.c.free(this.ctx);
      this.ctx = 0;
      this.store.clear();
    }

    /**
     * Drop-in for `fetch`: serves the example server's routes in-page. Returns null for other URLs.
     * options: { ctxHeader: "x-login-ctx", echo: boolean, allowClientLayout: boolean, layout: "shuffle" }
     */
    makeFetch(options = {}) {
      const self = this;
      const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
      return async function skpFetch(input, init = {}) {
        const url = new URL(typeof input === "string" ? input : input.url, typeof location !== "undefined" ? location.href : "http://localhost/");
        const path = url.pathname.replace(/^.*?(\/keypad\/|\/login$)/, "$1");
        const headers = new Headers(init.headers || (typeof input !== "string" ? input.headers : undefined));
        const ctx = headers.get(options.ctxHeader || "x-login-ctx") || "demo";
        const body = init.body ? JSON.parse(init.body) : {};
        try {
          if (path === "/keypad/public-key") return json(200, { publicKey: self.publicKey, kid: self.keyId, wasm: true });
          if (path === "/keypad/session") {
            const layout = options.allowClientLayout !== false ? headers.get("x-keypad-layout") || options.layout : options.layout;
            return json(200, self.createSession(body, { ctx, layout }));
          }
          if (path === "/keypad/relayout") return json(200, self.relayout(body));
          if (path === "/login") {
            const out = { ok: false, demoEcho: !!options.echo, wasm: true };
            let count = 0;
            for (const field of ["pin", "password"]) {
              const payload = body[field + "_enc"];
              if (!payload) continue;
              const bytes = self.decrypt(payload, { ctx });
              count++;
              out[field + "Length"] = bytes.length;
              if (options.echo) out[field] = new TextDecoder().decode(bytes);
              bytes.fill(0);
            }
            out.ok = count > 0;
            return json(200, out);
          }
        } catch (e) {
          if (e instanceof SkpError) {
            const status = e.kind === "SESSION_NOT_FOUND" ? 410 : e.kind === "BAD_REQUEST" || e.kind === "UNSUPPORTED" ? 400 : 403;
            return json(status, { error: e.kind });
          }
          return json(500, { error: "internal", message: String(e && e.message) });
        }
        return null;
      };
    }
  }

  SkpWasmServer.SkpError = SkpError;
  return SkpWasmServer;
});
