import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  b64encode,
  buildInputPayload,
  buildRelayoutRequest,
  buildSessionRequest,
  generateClientKeys,
  hexToBytes,
  openRelayout,
  openSession,
  type LayoutSet,
  type OpenSession,
  type Tap,
} from "../../../clients/web/src/protocol";
import { keygen, MemoryStore, SecureKeypadServer, SkpError, Secret } from "../src/index";

const MASTER = "0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a5968778695a4b3c2d1e0f";
const vector = JSON.parse(readFileSync(join(__dirname, "..", "..", "..", "spec", "vectors", "qwerty-ios-390x3-shuffle.json"), "utf8"));

/** Characters of the fixed (unshuffled) layout in listing order, per mode. */
const FIXED: Record<string, string> = {
  lower: "qwertyuiopasdfghjklzxcvbnm",
  upper: "QWERTYUIOPASDFGHJKLZXCVBNM",
  sym1: "1234567890-/:;()$&@\".,?!'",
  sym2: "[]{}#%^*+=_\\|~<>€£¥•.,?!'",
};

function tapsForFixed(layout: LayoutSet, text: string): Tap[] {
  return Array.from(text).map((ch) => {
    for (const layer of layout.layouts) {
      if (ch === " ") {
        const k = layer.keys.find((k) => k.role === "space");
        if (k) return { layoutId: layer.id, x: k.r[0] + (k.r[2] >> 1), y: k.r[1] + (k.r[3] >> 1) };
      }
      const chars = FIXED[layer.mode];
      if (!chars) continue;
      const idx = Array.from(chars).indexOf(ch);
      if (idx < 0) continue;
      const key = layer.keys.filter((k) => k.role === "char")[idx];
      return { layoutId: layer.id, x: key.r[0] + (key.r[2] >> 1), y: key.r[1] + (key.r[3] >> 1) };
    }
    throw new Error(`no key for ${ch}`);
  });
}

async function open(server: SecureKeypadServer, type: "qwerty" | "number", opts: any = {}, viewport = { w: 390, dpr: 3, platform: "ios" as const }) {
  const keys = generateClientKeys();
  const request = buildSessionRequest(keys, type, viewport, opts.maxLen);
  const response = await server.createSession(request, opts);
  const session = openSession(response as any, keys, server.publicKey);
  return { session, sid: session.sidB64 };
}

describe("SecureKeypadServer", () => {
  let server: SecureKeypadServer;
  beforeAll(() => {
    server = new SecureKeypadServer({ masterKey: MASTER });
  });
  afterAll(() => server.close());

  it("derives the documented public key and key id", () => {
    expect(server.publicKey).toBe(b64encode(hexToBytes(vector.expect_master.pk_sign)));
    expect(server.keyId).toBe(vector.expect_master.kid);
    expect(keygen()).toHaveLength(44);
  });

  it("loads the key from a Buffer, hex, base64, and the environment", () => {
    const raw = hexToBytes(MASTER);
    for (const key of [Buffer.from(raw), MASTER, b64encode(raw)]) {
      const s = new SecureKeypadServer({ masterKey: key });
      expect(s.publicKey).toBe(server.publicKey);
      s.close();
    }
    process.env.SKP_MASTER_KEY = MASTER;
    const s = new SecureKeypadServer({});
    expect(s.publicKey).toBe(server.publicKey);
    s.close();
    delete process.env.SKP_MASTER_KEY;
    expect(() => new SecureKeypadServer({})).toThrow(SkpError);
    expect(() => new SecureKeypadServer({ masterKey: "nope" })).toThrow(/BAD_KEY|unreadable/);
  });

  it("round trips a fixed-layout qwerty session end to end", async () => {
    const { session } = await open(server, "qwerty", { layout: "fixed", ctx: "user-1", maxLen: 24 });
    expect(session.layout.maxLen).toBe(24);
    expect(session.tiles.length).toBeGreaterThan(100);
    const text = "Hello, w0rld! [€]";
    const payload = buildInputPayload(session, tapsForFixed(session.layout, text));
    const secret = await server.decrypt(payload, { ctx: "user-1" });
    expect(secret).toBeInstanceOf(Secret);
    expect(secret.toString()).toBe(text);
    expect(secret.length).toBe(Buffer.byteLength(text));
    secret.wipe();
    expect(secret.wiped).toBe(true);
    expect(() => secret.bytes).toThrow();
    // single use
    await expect(server.decrypt(payload, { ctx: "user-1" })).rejects.toMatchObject({ kind: "SESSION_NOT_FOUND" });
  });

  it("keeps the session when asked", async () => {
    const { session, sid } = await open(server, "number", { ctx: "k" });
    const first = session.layout.layouts[0].keys.filter((k) => k.role === "char")[0];
    const payload = buildInputPayload(session, [{ layoutId: session.layout.layouts[0].id, x: first.r[0] + 1, y: first.r[1] + 1 }]);
    const a = await server.decrypt(payload, { ctx: "k", keep: true });
    const b = await server.decrypt(payload, { ctx: "k" });
    expect(a.toString()).toBe(b.toString());
    expect(a.toString()).toMatch(/^[0-9]$/);
    expect(await server.store.get(sid)).toBeNull();
  });

  it("shuffles the number pad: tapping every slot yields a permutation of the digits", async () => {
    const { session } = await open(server, "number", { blank: "random" }, { w: 412, dpr: 2.625, platform: "android" });
    const layer = session.layout.layouts[0];
    const chars = layer.keys.filter((k) => k.role === "char");
    expect(chars).toHaveLength(10);
    expect(layer.keys.filter((k) => k.role === "blank")).toHaveLength(1);
    const taps = chars.map((k) => ({ layoutId: layer.id, x: k.r[0] + (k.r[2] >> 1), y: k.r[1] + (k.r[3] >> 1) }));
    const secret = await server.decrypt(buildInputPayload(session, taps));
    expect(Array.from(secret.toString()).sort().join("")).toBe("0123456789");
  });

  it("relayouts to a new viewport and decrypts taps from both generations", async () => {
    const { session, sid } = await open(server, "qwerty", { layout: "fixed", ctx: "rot" });
    const taps = tapsForFixed(session.layout, "ab");
    const response = await server.relayout(buildRelayoutRequest(session, { w: 844, dpr: 3, platform: "ios" }));
    const layout = openRelayout(session, response as any);
    expect(layout.gen).toBe(1);
    expect(layout.w).toBe(2532);
    taps.push(...tapsForFixed(layout, "CD 9"));
    const secret = await server.decrypt(buildInputPayload(session, taps), { ctx: "rot" });
    expect(secret.toString()).toBe("abCD 9");
    await expect(server.relayout({ v: 1, sid, viewport: { w: 1, dpr: 1, platform: "ios" } })).rejects.toMatchObject({ kind: "SESSION_NOT_FOUND" });
  });

  it("maps errors", async () => {
    const { session } = await open(server, "qwerty", { layout: "fixed", ctx: "owner" });
    const payload = buildInputPayload(session, tapsForFixed(session.layout, "x"));
    await expect(server.decrypt(payload, { ctx: "thief", keep: true })).rejects.toMatchObject({ kind: "CTX_MISMATCH" });
    await expect(server.decrypt({ ...payload, ct: "AAAA" + payload.ct.slice(4) }, { ctx: "owner", keep: true })).rejects.toMatchObject({ kind: "BAD_MAC" });
    await expect(server.decrypt({ v: 1, sid: "AAAAAAAAAAAAAAAAAAAAAA", ct: payload.ct })).rejects.toMatchObject({ kind: "SESSION_NOT_FOUND" });
    await expect(server.decrypt({ v: 1 } as any)).rejects.toMatchObject({ kind: "BAD_REQUEST" });
    await expect(server.createSession({ v: 2 })).rejects.toMatchObject({ kind: "BAD_REQUEST" });
    await expect(server.createSession(buildSessionRequest(generateClientKeys(), "qwerty", { w: 390, dpr: 3, platform: "ios" }), { layout: "diagonal" as any })).rejects.toMatchObject({ kind: "UNSUPPORTED" });
    const ok = await server.decrypt(payload, { ctx: "owner" });
    expect(ok.toString()).toBe("x");
  });

  it("honours a custom store and the session TTL", async () => {
    const store = new MemoryStore();
    const s = new SecureKeypadServer({ masterKey: MASTER, store, defaultTtl: 7 });
    const { sid } = await open(s, "number", {});
    expect(store.size).toBe(1);
    const info = s.sessionInfo((await store.get(sid))!);
    expect(info.sid).toBe(sid);
    expect(info.expires - Math.floor(Date.now() / 1000)).toBeGreaterThanOrEqual(6);
    s.close();
  });

  it("serves concurrent sessions", async () => {
    const results = await Promise.all(
      Array.from({ length: 16 }, async (_, i) => {
        const { session } = await open(server, "qwerty", { layout: "fixed", ctx: `c${i}` });
        const text = `user${i}`;
        const secret = await server.decrypt(buildInputPayload(session, tapsForFixed(session.layout, text)), { ctx: `c${i}` });
        return secret.toString() === text;
      }),
    );
    expect(results.every(Boolean)).toBe(true);
  });
});

describe("MemoryStore", () => {
  it("expires entries and zeroes on delete", () => {
    const store = new MemoryStore();
    const blob = new Uint8Array([1, 2, 3]);
    store.put("a", blob, 60);
    expect(store.get("a")).toEqual(blob);
    store.put("b", blob, -1);
    expect(store.get("b")).toBeNull();
    expect(store.take("a")).toEqual(blob);
    expect(store.get("a")).toBeNull();
  });
});

describe("OpenSession", () => {
  it("is consumed after building a payload", async () => {
    const server = new SecureKeypadServer({ masterKey: MASTER });
    const { session } = await open(server, "number", {});
    buildInputPayload(session, []);
    expect((session as OpenSession).consumed).toBe(true);
    server.close();
  });
});
