import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import {
  b64decode,
  b64encode,
  buildInputPayload,
  buildSessionRequest,
  bytesToHex,
  generateClientKeys,
  hexToBytes,
  hitTest,
  openRelayout,
  openSession,
  ProtocolError,
  type Layer,
} from "../src/protocol";

const dir = join(__dirname, "..", "..", "..", "spec", "vectors");
const vectors = readdirSync(dir)
  .filter((f) => f.endsWith(".json"))
  .map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")));

function pkB64(v: any): string {
  return b64encode(hexToBytes(v.expect_master.pk_sign));
}

describe("base64", () => {
  it("round trips standard and url variants", () => {
    for (const len of [0, 1, 2, 3, 16, 31, 32, 64]) {
      const b = new Uint8Array(len).map((_, i) => (i * 37 + 11) & 255);
      expect(b64decode(b64encode(b))).toEqual(b);
      expect(b64decode(b64encode(b, true), true)).toEqual(b);
    }
    expect(b64encode(new Uint8Array([0xfb, 0xff]))).toBe("+/8=");
    expect(b64encode(new Uint8Array([0xfb, 0xff]), true)).toBe("-_8");
  });
});

describe("protocol vectors", () => {
  for (const v of vectors) {
    it(v.name, () => {
      const keys = generateClientKeys(hexToBytes(v.client_sk));
      const req = buildSessionRequest(keys, v.request.type, v.request.viewport, v.request.opts?.maxLen);
      expect(req.kp).toBe(v.request.kp);
      const session = openSession(v.expect_session.response, keys, pkB64(v));
      expect(bytesToHex(session.kS2c)).toBe(v.expect_session.k_s2c);
      expect(bytesToHex(session.kC2s)).toBe(v.expect_session.k_c2s);
      expect(session.layout).toEqual(JSON.parse(v.expect_session.inner_json));
      expect(session.tiles.length).toBe(0); // vectors are generated without rendering
      // no character identifiers reach the client
      for (const layer of session.layout.layouts)
        for (const k of layer.keys) {
          expect(Object.keys(k).sort()).toEqual(k.role === "char" ? ["r", "role", "t"] : ["r", "role"]);
        }
      if (v.relayout) {
        const layout = openRelayout(session, v.relayout.expect.response);
        expect(layout).toEqual(JSON.parse(v.relayout.expect.inner_json));
        expect(session.s2cCtr).toBe(2);
      }
      const maxLen = JSON.parse(v.expect_session.inner_json).maxLen;
      const taps = v.input.taps.map(([layoutId, x, y]: number[]) => ({ layoutId, x, y }));
      const payload = buildInputPayload(session, taps, maxLen);
      expect(payload).toEqual(v.input.payload);
      expect(session.consumed).toBe(true);
      expect(() => buildInputPayload(session, taps, maxLen)).toThrow(ProtocolError);
    });
  }

  it("rejects a forged signature and a wrong public key", () => {
    const v = vectors[0];
    const keys = generateClientKeys(hexToBytes(v.client_sk));
    const forged = { ...v.expect_session.response, sig: b64encode(new Uint8Array(64)) };
    expect(() => openSession(forged, keys, pkB64(v))).toThrow(/signature/);
    const wrongKey = b64encode(new Uint8Array(32).fill(7));
    expect(() => openSession(v.expect_session.response, generateClientKeys(hexToBytes(v.client_sk)), wrongKey)).toThrow(/signature/);
    // without a configured key the response opens (TLS-only trust)
    expect(() => openSession(v.expect_session.response, generateClientKeys(hexToBytes(v.client_sk)), null)).not.toThrow();
  });

  it("rejects a tampered ciphertext", () => {
    const v = vectors[0];
    const ct = b64decode(v.expect_session.response.ct);
    ct[5] ^= 1;
    const bad = { ...v.expect_session.response, ct: b64encode(ct) };
    expect(() => openSession(bad, generateClientKeys(hexToBytes(v.client_sk)), null)).toThrow(/ciphertext/);
  });

  it("rejects too many taps", () => {
    const v = vectors.find((x) => x.name.startsWith("number-ios"));
    const session = openSession(v.expect_session.response, generateClientKeys(hexToBytes(v.client_sk)), null);
    const taps = new Array(session.layout.maxLen + 1).fill({ layoutId: 4, x: 1, y: 1 });
    expect(() => buildInputPayload(session, taps)).toThrow(/too many/);
  });
});

describe("hit test", () => {
  const layer: Layer = {
    id: 0,
    mode: "number",
    keys: [
      { r: [0, 0, 10, 10], role: "char", t: 0 },
      { r: [21, 0, 10, 10], role: "char", t: 1 },
      { r: [0, 21, 10, 10], role: "blank" },
    ],
  };
  it("prefers containing rects, then nearest, ties to first", () => {
    expect(hitTest(layer, 5, 5)).toBe(0);
    expect(hitTest(layer, 25, 5)).toBe(1);
    expect(hitTest(layer, 14, 5)).toBe(0); // 5px from key 0 (right edge 9), 7px from key 1 (left edge 21)
    expect(hitTest(layer, 15, 5)).toBe(0); // tie (6 / 6) → first listed
    expect(hitTest(layer, 16, 5)).toBe(1);
    expect(hitTest(layer, 5, 15)).toBe(0); // tie between key 0 (above) and the blank (below) → first
    expect(hitTest(layer, 5, 16)).toBe(2);
  });
});
