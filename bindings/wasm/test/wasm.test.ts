import { describe, expect, it, beforeAll } from "vitest";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { createRequire } from "node:module";
import { buildInputPayload, buildSessionRequest, generateClientKeys, openRelayout, openSession, buildRelayoutRequest, type LayoutSet, type Tap } from "../../../clients/web/src/protocol";

const require = createRequire(import.meta.url);
const dist = join(__dirname, "..", "dist", "skp.js");
const SkpWasmServer = require("../src/skp-wasm-server.js");

const FIXED: Record<string, string> = {
  lower: "qwertyuiopasdfghjklzxcvbnm",
  upper: "QWERTYUIOPASDFGHJKLZXCVBNM",
  sym1: "1234567890-/:;()$&@\".,?!'",
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

describe.skipIf(!existsSync(dist))("wasm server", () => {
  let server: any;
  beforeAll(async () => {
    server = await SkpWasmServer.create({ moduleUrl: dist, masterKey: "0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a5968778695a4b3c2d1e0f" });
  });

  it("derives the documented key id", () => {
    expect(server.keyId).toBe("d7458099");
    expect(server.publicKey).toHaveLength(44);
    expect(server.version).toBe("0.1.0");
  });

  it("round trips a fixed-layout qwerty session with rendering", () => {
    const keys = generateClientKeys();
    const response = server.createSession(buildSessionRequest(keys, "qwerty", { w: 390, dpr: 3, platform: "ios" }, 24), { ctx: "u1", layout: "fixed" });
    const session = openSession(response, keys, server.publicKey);
    expect(session.tiles.length).toBeGreaterThan(100);
    expect(session.layout.maxLen).toBe(24);
    const text = "Hello, w0rld!";
    const bytes = server.decrypt(buildInputPayload(session, tapsForFixed(session.layout, text)), { ctx: "u1" });
    expect(new TextDecoder().decode(bytes)).toBe(text);
    expect(() => server.decrypt({ v: 1, sid: response.sid, ct: "AA==" }, { ctx: "u1" })).toThrow(/not found/);
  });

  it("shuffles the number pad and relayouts", () => {
    const keys = generateClientKeys();
    const response = server.createSession(buildSessionRequest(keys, "number", { w: 412, dpr: 2.625, platform: "android" }), { ctx: "n" });
    const session = openSession(response, keys, server.publicKey);
    const layer = session.layout.layouts[0];
    const rr = server.relayout(buildRelayoutRequest(session, { w: 800, dpr: 2, platform: "android" }));
    const layout = openRelayout(session, rr);
    expect(layout.gen).toBe(1);
    const chars = layout.layouts[0].keys.filter((k) => k.role === "char");
    const taps = chars.map((k) => ({ layoutId: layout.layouts[0].id, x: k.r[0] + (k.r[2] >> 1), y: k.r[1] + (k.r[3] >> 1) }));
    const bytes = server.decrypt(buildInputPayload(session, taps), { ctx: "n" });
    expect(Array.from(new TextDecoder().decode(bytes)).sort().join("")).toBe("0123456789");
    void layer;
  });

  it("serves the example routes through makeFetch", async () => {
    const f = server.makeFetch({ echo: true });
    const pk = await (await f("http://x/keypad/public-key")).json();
    expect(pk.kid).toBe("d7458099");
    const keys = generateClientKeys();
    const res = await f("http://x/keypad/session", { method: "POST", headers: { "x-login-ctx": "c", "x-keypad-layout": "fixed" }, body: JSON.stringify(buildSessionRequest(keys, "qwerty", { w: 390, dpr: 3, platform: "web" })) });
    const session = openSession(await res.json(), keys, server.publicKey);
    const payload = buildInputPayload(session, tapsForFixed(session.layout, "abc"));
    const login = await (await f("http://x/login", { method: "POST", headers: { "x-login-ctx": "c" }, body: JSON.stringify({ password_enc: payload }) })).json();
    expect(login).toMatchObject({ ok: true, passwordLength: 3, password: "abc", wasm: true });
    const replay = await f("http://x/login", { method: "POST", headers: { "x-login-ctx": "c" }, body: JSON.stringify({ password_enc: payload }) });
    expect(replay.status).toBe(410);
    expect(await f("http://x/other")).toBeNull();
  });
});
