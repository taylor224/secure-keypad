"""Generate spec/vectors/*.json from the reference implementation.

Every vector fixes all randomness (client key, server ephemeral key, sid, seed, sealing nonce, clock)
so that other implementations can reproduce each byte.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import skp_ref as R  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "..", "spec", "vectors")
MASTER = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a5968778695a4b3c2d1e0f")
NOW = 1_757_000_000


def hx(b: bytes) -> str:
    return b.hex()


def make(name, request, opts, text, hooks, c_sk, relayout_vp=None, text2="", gap_offset=(0, 0), errors=None):
    mk = R.derive_master(MASTER)
    request = dict(request, kp=R.b64(R.x25519_public(c_sk)))
    resp, sealed, dbg = R.create_session(mk, request, opts, hooks)
    opened = R.client_open(resp, c_sk, mk.pk_sign)
    inner = opened["inner"]
    taps = R.taps_for_text(dbg["layout"], 0, text, gap_offset)
    vec = {
        "name": name,
        "master_key": hx(MASTER),
        "expect_master": {"kid": mk.kid, "pk_sign": hx(mk.pk_sign), "k_state": hx(mk.k_state)},
        "client_sk": hx(c_sk),
        "request": request,
        "server_opts": opts,
        "hooks": {"s_sk": hx(hooks.s_sk), "sid": hx(hooks.sid), "seed": hx(hooks.seed), "nonce24": hx(hooks.nonce24), "now": hooks.now},
        "expect_session": {
            "response": resp,
            "k_s2c": hx(dbg["k_s2c"]),
            "k_c2s": hx(dbg["k_c2s"]),
            "inner_json": R.canonical_json(inner).decode(),
            "sealed": hx(sealed),
            "mapping": {f"{slot}:" + (R.LANG_CODES[l.lang] + "/" if l.lang else "") + R.MODE_NAMES[l.mode]:
                        "".join(k.ch if k.ch else ("\\b" if k.role == "backspace" else "_") for k in l.keys)
                        for slot, l in enumerate(dbg["layout"].layers)},
        },
        "input": {"text": text, "taps": [list(t) for t in taps]},
    }
    final_sealed = sealed
    if relayout_vp:
        h2 = R.Hooks(nonce24=bytes([0xA5]) * 24, now=NOW + 30)
        rr, sealed2, dbg2 = R.relayout(mk, sealed, {"v": 1, "sid": resp["sid"], "viewport": relayout_vp}, h2)
        inner2 = R.client_open_relayout(opened["k_s2c"], 1, opened["sid"], rr)["inner"]
        taps2 = R.taps_for_text(dbg2["layout"], 1, text2)
        taps = taps + taps2
        vec["relayout"] = {
            "request": {"v": 1, "sid": resp["sid"], "viewport": relayout_vp},
            "hooks": {"nonce24": hx(h2.nonce24), "now": h2.now},
            "expect": {"response": rr, "inner_json": R.canonical_json(inner2).decode(), "sealed": hx(sealed2)},
            "text": text2, "taps": [list(t) for t in taps2],
        }
        vec["input"]["taps"] = [list(t) for t in taps]
        vec["input"]["text"] = text + text2
        final_sealed = sealed2
    payload = R.client_build_input(opened["k_c2s"], opened["sid"], inner["maxLen"], taps)
    plain = R.decrypt(mk, final_sealed, payload, ctx=opts.get("ctx"), now=NOW + 60)
    assert plain == vec["input"]["text"], (plain, vec["input"]["text"])
    vec["input"]["payload"] = payload
    vec["input"]["decrypt_now"] = NOW + 60
    vec["input"]["expect_plain"] = plain
    if errors:
        vec["errors"] = errors(mk, final_sealed, opened, dbg, payload)
    return vec


def number_errors(mk, sealed, opened, dbg, payload):
    bs = R.find_key(dbg["layout"], R.MODE_NUMBER, "backspace")
    lid = R.layout_id(0, 0)  # the number layer is slot 0
    ml = opened["inner"]["maxLen"]
    k = opened["k_c2s"]
    sid = opened["sid"]
    cases = [
        {"name": "wrong_ctx", "payload": payload, "ctx": "someone-else", "now": NOW + 60, "expect": "CTX_MISMATCH"},
        {"name": "missing_ctx", "payload": payload, "ctx": None, "now": NOW + 60, "expect": "CTX_MISMATCH"},
        {"name": "expired", "payload": payload, "ctx": "user-42", "now": NOW + 181, "expect": "EXPIRED"},
        {"name": "tap_on_backspace", "payload": R.client_build_input(k, sid, ml, [(lid, bs.r[0] + 1, bs.r[1] + 1)]), "ctx": "user-42", "now": NOW + 60, "expect": "TAMPERED"},
        {"name": "out_of_bounds", "payload": R.client_build_input(k, sid, ml, [(lid, 60000, 1)]), "ctx": "user-42", "now": NOW + 60, "expect": "TAMPERED"},
        {"name": "unknown_slot", "payload": R.client_build_input(k, sid, ml, [(R.layout_id(0, 1), 5, 5)]), "ctx": "user-42", "now": NOW + 60, "expect": "TAMPERED"},
        {"name": "unknown_gen", "payload": R.client_build_input(k, sid, ml, [(R.layout_id(3, 0), 5, 5)]), "ctx": "user-42", "now": NOW + 60, "expect": "TAMPERED"},
        {"name": "sid_mismatch", "payload": dict(payload, sid=R.b64url(bytes(16))), "ctx": "user-42", "now": NOW + 60, "expect": "SID_MISMATCH"},
    ]
    ct = bytearray(R.unb64(payload["ct"]))
    ct[7] ^= 0x80
    cases.append({"name": "bad_mac", "payload": dict(payload, ct=R.b64(bytes(ct))), "ctx": "user-42", "now": NOW + 60, "expect": "BAD_MAC"})
    for c in cases:
        try:
            R.decrypt(mk, sealed, c["payload"], ctx=c["ctx"], now=c["now"])
            raise AssertionError("expected failure " + c["name"])
        except R.SkpError as e:
            assert e.name == c["expect"], (c["name"], e.name)
    return cases


def main():
    os.makedirs(OUT, exist_ok=True)
    base_hooks = lambda tag: R.Hooks(  # noqa: E731
        s_sk=bytes([tag]) * 32, sid=bytes([tag, 0x5d]) * 8, seed=bytes([0x77, tag]) * 16, nonce24=bytes([tag ^ 0xff]) * 24, now=NOW)
    vectors = [
        # English-only sessions (server option "languages": ["en"]): no lang key, four layers
        make("qwerty-ios-390x3-shuffle", {"v": 1, "type": "qwerty", "viewport": {"w": 390, "dpr": 3, "platform": "ios"}, "opts": {"maxLen": 24}},
             {"ctx": "user-42", "layout": "shuffle", "blank": "fixed", "ttl": 180, "languages": ["en"]}, "Hello, w0rld!", base_hooks(0x01), bytes([0x21]) * 32),
        make("qwerty-material-360x2.625-full", {"v": 1, "type": "qwerty", "viewport": {"w": 360, "dpr": 2.625, "platform": "android"}},
             {"ctx": "login-7", "layout": "full", "ttl": 300, "languages": ["en"]}, "pa55w0rd#[€", base_hooks(0x02), bytes([0x22]) * 32),
        make("qwerty-web-1024x1-fixed", {"v": 1, "type": "qwerty", "viewport": {"w": 1024, "dpr": 1, "platform": "web"}},
             {"layout": "fixed", "maxLen": 12, "languages": ["en"]}, "fixed Layout", base_hooks(0x03), bytes([0x23]) * 32),
        make("qwerty-web-ios-style-375x2-gaps", {"v": 1, "type": "qwerty", "viewport": {"w": 375, "dpr": 2, "platform": "web", "style": "ios"}},
             {"ctx": "gap", "layout": "shuffle", "languages": ["en"]}, "zq", base_hooks(0x04), bytes([0x24]) * 32, gap_offset=(0, -25)),
        # Korean + English: the client asks for ["ko", "en"] (Korean first), six layers with a lang key
        make("qwerty-ios-390x3-ko-en-shuffle", {"v": 1, "type": "qwerty", "viewport": {"w": 390, "dpr": 3, "platform": "ios"}, "opts": {"maxLen": 24, "langs": ["ko", "en"]}},
             {"ctx": "user-ko", "layout": "shuffle"}, "한글 Pw1!", base_hooks(0x08), bytes([0x28]) * 32),
        # Korean only, full shuffle: compound finals, dokkaebi-bul carry, a standalone compound consonant
        make("qwerty-material-360x2.625-ko-full", {"v": 1, "type": "qwerty", "viewport": {"w": 360, "dpr": 2.625, "platform": "android"}, "opts": {"langs": ["ko"]}},
             {"ctx": "ko-only", "layout": "full"}, "닭갈비 뷁있ㄳ", base_hooks(0x09), bytes([0x29]) * 32),
        # neither side names languages: the default is en + ko; fixed layout on a wide web surface
        make("qwerty-web-1024x1-ko-en-fixed", {"v": 1, "type": "qwerty", "viewport": {"w": 1024, "dpr": 1, "platform": "web"}},
             {"layout": "fixed", "maxLen": 24}, "Mixed 혼합 텍스트!", base_hooks(0x0A), bytes([0x2A]) * 32),
        make("number-ios-390x3-blank-fixed", {"v": 1, "type": "number", "viewport": {"w": 390, "dpr": 3, "platform": "ios"}},
             {"ctx": "user-42", "layout": "shuffle", "blank": "fixed"}, "092817", base_hooks(0x05), bytes([0x25]) * 32, errors=number_errors),
        make("number-material-412x2.625-blank-random", {"v": 1, "type": "number", "viewport": {"w": 412, "dpr": 2.625, "platform": "web"}, "opts": {"maxLen": 6}},
             {"layout": "shuffle", "blank": "random"}, "000123", base_hooks(0x06), bytes([0x26]) * 32),
        make("qwerty-ios-relayout-portrait-to-landscape", {"v": 1, "type": "qwerty", "viewport": {"w": 390, "dpr": 3, "platform": "ios"}},
             {"ctx": "rot", "layout": "shuffle", "languages": ["en"]}, "ab", base_hooks(0x07), bytes([0x27]) * 32,
             relayout_vp={"w": 844, "dpr": 3, "platform": "ios"}, text2="CD 9"),
        # relayout with two languages: taps on the Korean layer of generation 0 and the English layer of 1
        make("qwerty-android-relayout-ko-en", {"v": 1, "type": "qwerty", "viewport": {"w": 412, "dpr": 2.625, "platform": "android"}},
             {"ctx": "rot-ko", "layout": "shuffle"}, "회전", base_hooks(0x0B), bytes([0x2B]) * 32,
             relayout_vp={"w": 915, "dpr": 2.625, "platform": "android"}, text2=" ok"),
    ]
    for v in vectors:
        path = os.path.join(OUT, v["name"] + ".json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(v, f, indent=1, ensure_ascii=False)
            f.write("\n")
        print("wrote", os.path.relpath(path), "taps", len(v["input"]["taps"]))


if __name__ == "__main__":
    main()
