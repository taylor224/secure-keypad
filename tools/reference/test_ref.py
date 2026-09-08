"""Round-trip and negative tests for the reference implementation."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import skp_ref as R  # noqa: E402

MASTER = bytes(range(32))


def mk():
    return R.derive_master(MASTER)


def c_keys(seed=b"\x11" * 32):
    return seed, R.x25519_public(seed)


def req(type_="qwerty", w=390, dpr=3, platform="ios", style=None, max_len=None, c_pk=None):
    vp = {"w": w, "dpr": dpr, "platform": platform}
    if style:
        vp["style"] = style
    r = {"v": 1, "kp": R.b64(c_pk), "type": type_, "viewport": vp}
    if max_len:
        r["opts"] = {"maxLen": max_len}
    return r


def test_master_parsing_formats():
    m = mk()
    assert R.parse_master(MASTER.hex()) == MASTER
    assert R.parse_master(MASTER.hex().upper() + "\n") == MASTER
    assert R.parse_master(R.b64(MASTER)) == MASTER
    assert R.parse_master(MASTER) == MASTER
    assert len(m.kid) == 8 and m.kid == R.sha256(m.pk_sign)[:4].hex()
    with pytest.raises(R.SkpError):
        R.parse_master("nope")


@pytest.mark.parametrize("type_,text,policy,platform,w,dpr", [
    ("qwerty", "Hello, w0rld!", "shuffle", "ios", 390, 3),
    ("qwerty", "pa55w0rd", "full", "android", 360, 2.625),
    ("qwerty", "fixed", "fixed", "web", 1024, 1),
    ("qwerty", "한글 비밀번호1 Mixed", "shuffle", "ios", 390, 3),
    ("qwerty", "닭갈비 뷁있ㄳ", "full", "android", 412, 2.625),
    ("number", "092817", "shuffle", "ios", 390, 3),
    ("number", "0000", "shuffle", "web", 412, 2.625),
])
def test_roundtrip(type_, text, policy, platform, w, dpr):
    m = mk()
    c_sk, c_pk = c_keys()
    resp, sealed, dbg = R.create_session(m, req(type_, w, dpr, platform, c_pk=c_pk), {"ctx": "user-1", "layout": policy, "blank": "random"})
    opened = R.client_open(resp, c_sk, m.pk_sign)
    assert opened["k_s2c"] == dbg["k_s2c"] and opened["k_c2s"] == dbg["k_c2s"]
    inner = opened["inner"]
    assert inner == dbg["inner"]
    assert inner["w"] == dbg["layout"].W and inner["h"] == dbg["layout"].H
    # no character identifiers leak: keys carry only r/role/t
    for layer in inner["layouts"]:
        assert set(layer.keys()) <= {"id", "mode", "lang", "keys"}
        for k in layer["keys"]:
            assert set(k.keys()) <= {"r", "role", "t"}
            assert ("t" in k) == (k["role"] == "char")
    if type_ == "qwerty":
        assert inner["langs"] == ["en", "ko"] and len(inner["layouts"]) == 6
    else:
        assert inner["langs"] == [] and len(inner["layouts"]) == 1
    taps = R.taps_for_text(dbg["layout"], 0, text)
    payload = R.client_build_input(opened["k_c2s"], opened["sid"], inner["maxLen"], taps)
    assert R.decrypt(m, sealed, payload, ctx="user-1") == text


def test_fixed_layout_is_identity():
    m = mk()
    c_sk, c_pk = c_keys()
    _, _, dbg = R.create_session(m, req(c_pk=c_pk), {"layout": "fixed"})
    lower = [k.ch for k in dbg["layout"].layers[0].keys if k.role == "char"]
    assert "".join(lower) == "qwertyuiopasdfghjklzxcvbnm"
    # the fixed number pad is the native phone pad whatever "blank" says; shuffled pads still move the blank
    for blank in ("fixed", "random"):
        _, _, dbg = R.create_session(m, req("number", c_pk=c_pk), {"layout": "fixed", "blank": blank})
        cells = [k.ch if k.role == "char" else k.role for k in dbg["layout"].layers[0].keys]
        assert cells == list("123456789") + ["blank", "0", "backspace"]
    _, _, dbg = R.create_session(m, req("number", c_pk=c_pk), {"layout": "shuffle"}, R.Hooks(seed=b"\x05" * 32))
    assert [k.ch for k in dbg["layout"].layers[0].keys if k.role == "char"] != list("1234567890")


def test_shuffle_is_seeded_and_upper_mirrors_lower():
    m = mk()
    c_sk, c_pk = c_keys()
    h = R.Hooks(seed=b"\x42" * 32)
    _, _, d1 = R.create_session(m, req(c_pk=c_pk), {}, h)
    _, _, d2 = R.create_session(m, req(c_pk=c_pk), {}, h)
    l1 = [k.ch for k in d1["layout"].layers[0].keys]
    assert l1 == [k.ch for k in d2["layout"].layers[0].keys]
    up = [k.ch for k in d1["layout"].layers[1].keys]
    assert up == [c.upper() if c else c for c in l1]
    assert sorted(c for c in l1 if c and c != " ") == sorted("qwertyuiopasdfghjklzxcvbnm")


def test_gap_taps_hit_nearest_key():
    m = mk()
    c_sk, c_pk = c_keys()
    resp, sealed, dbg = R.create_session(m, req("number", c_pk=c_pk), {})
    opened = R.client_open(resp, c_sk, m.pk_sign)
    layer = dbg["layout"].layers[0]
    first = layer.keys[0]
    # one pixel above the first key (in the top inset) and one pixel left of it
    taps = [(R.layout_id(0, 0), first.r[0] + 3, first.r[1] - 1), (R.layout_id(0, 0), first.r[0] - 1, first.r[1] + 3)]
    payload = R.client_build_input(opened["k_c2s"], opened["sid"], opened["inner"]["maxLen"], taps)
    assert R.decrypt(m, sealed, payload) == first.ch * 2


def test_relayout_keeps_mapping_and_old_taps():
    m = mk()
    c_sk, c_pk = c_keys()
    resp, sealed, dbg = R.create_session(m, req(c_pk=c_pk), {"ctx": "u"})
    opened = R.client_open(resp, c_sk, m.pk_sign)
    taps = R.taps_for_text(dbg["layout"], 0, "ab")
    rr, sealed2, dbg2 = R.relayout(m, sealed, {"v": 1, "sid": resp["sid"], "viewport": {"w": 844, "dpr": 3, "platform": "ios"}})
    assert rr["gen"] == 1
    inner2 = R.client_open_relayout(opened["k_s2c"], 1, opened["sid"], rr)["inner"]
    assert inner2["gen"] == 1 and inner2["layouts"][0]["id"] == 8
    lower1 = [k.ch for k in dbg["layout"].layers[0].keys]
    lower2 = [k.ch for k in dbg2["layout"].layers[0].keys]
    assert lower1 == lower2  # same mapping, new geometry
    assert dbg2["layout"].W == 2532
    taps += R.taps_for_text(dbg2["layout"], 1, "CD")
    payload = R.client_build_input(opened["k_c2s"], opened["sid"], opened["inner"]["maxLen"], taps)
    assert R.decrypt(m, sealed2, payload, ctx="u") == "abCD"
    # old sealed blob does not know generation 1
    with pytest.raises(R.SkpError) as e:
        R.decrypt(m, sealed, payload, ctx="u")
    assert e.value.name == "TAMPERED"


def test_negative_cases():
    m = mk()
    c_sk, c_pk = c_keys()
    h = R.Hooks(now=1_700_000_000)
    resp, sealed, dbg = R.create_session(m, req("number", c_pk=c_pk), {"ctx": "user-9", "ttl": 60}, h)
    opened = R.client_open(resp, c_sk, m.pk_sign)
    good = R.taps_for_text(dbg["layout"], 0, "12")
    payload = R.client_build_input(opened["k_c2s"], opened["sid"], opened["inner"]["maxLen"], good)

    def expect(name, **kw):
        with pytest.raises(R.SkpError) as e:
            R.decrypt(m, sealed, kw.pop("payload", payload), **kw)
        assert e.value.name == name

    expect("CTX_MISMATCH", ctx="someone-else", now=1_700_000_000)
    expect("CTX_MISMATCH", ctx=None, now=1_700_000_000)
    expect("EXPIRED", ctx="user-9", now=1_700_000_061)
    # tap on backspace key → tampered
    bs = R.find_key(dbg["layout"], R.MODE_NUMBER, "backspace")
    bad = R.client_build_input(opened["k_c2s"], opened["sid"], opened["inner"]["maxLen"],
                               [(R.layout_id(0, 0), bs.r[0] + 1, bs.r[1] + 1)])
    expect("TAMPERED", payload=bad, ctx="user-9", now=1_700_000_000)
    # coordinates outside the surface
    bad = R.client_build_input(opened["k_c2s"], opened["sid"], opened["inner"]["maxLen"], [(R.layout_id(0, 0), 5000, 5)])
    expect("TAMPERED", payload=bad, ctx="user-9", now=1_700_000_000)
    # a slot the number pad does not have
    bad = R.client_build_input(opened["k_c2s"], opened["sid"], opened["inner"]["maxLen"], [(R.layout_id(0, 1), 5, 5)])
    expect("TAMPERED", payload=bad, ctx="user-9", now=1_700_000_000)
    # sid mismatch
    other = dict(payload, sid=R.b64url(b"\x00" * 16))
    expect("SID_MISMATCH", payload=other, ctx="user-9", now=1_700_000_000)
    # flipped ciphertext bit
    ct = bytearray(R.unb64(payload["ct"]))
    ct[10] ^= 1
    expect("BAD_MAC", payload=dict(payload, ct=R.b64(bytes(ct))), ctx="user-9", now=1_700_000_000)
    # forged signature rejected by client
    forged = dict(resp, sig=R.b64(bytes(64)))
    with pytest.raises(R.SkpError):
        R.client_open(forged, c_sk, m.pk_sign)
    # decrypt with a different master key fails to unseal
    with pytest.raises(R.SkpError) as e:
        R.decrypt(R.derive_master(bytes(32)), sealed, payload, ctx="user-9", now=1_700_000_000)
    assert e.value.name == "BAD_MAC"


def test_low_order_point_rejected():
    m = mk()
    with pytest.raises(R.SkpError) as e:
        R.create_session(m, req(c_pk=bytes(32)), {})
    assert e.value.name == "CRYPTO"


def test_geometry_basics():
    lay = R.build_layout(R.TYPE_QWERTY, 0, 0, R.STYLES["ios"], [R.LANG_EN], 1170, 3000, b"\x01" * 32)
    assert lay.H == 648 and lay.tile_h == 126
    row0 = [k for k in lay.layers[0].keys][:10]
    assert row0[0].r[0] == 9 and row0[-1].r[0] + row0[-1].r[2] == 1170 - 9
    assert all(k.r[2] in (99, 100) for k in row0)
    assert len(lay.layers) == 4 and not any(k.role == "lang" for l in lay.layers for k in l.keys)
    lay_n = R.build_layout(R.TYPE_NUMBER, 0, 0, R.STYLES["material"], [], 1080, 2625, b"\x01" * 32)
    assert len(lay_n.layers[0].keys) == 12 and lay_n.layers[0].keys[11].role == "backspace"
    assert lay_n.tile_count == 10


def test_languages_layers_and_lang_key():
    lay = R.build_layout(R.TYPE_QWERTY, 2, 0, R.STYLES["ios"], [R.LANG_EN, R.LANG_KO], 1170, 3000, b"\x02" * 32)
    assert lay.langs == [R.LANG_EN, R.LANG_KO]
    assert [(l.mode, l.lang) for l in lay.layers] == [(0, 1), (1, 1), (0, 2), (1, 2), (2, 0), (3, 0)]
    assert lay.tile_count == 26 * 4 + 50
    ko_lower, ko_upper = lay.layers[2], lay.layers[3]
    assert "".join(k.ch for k in ko_lower.keys if k.role == "char") == "ㅂㅈㄷㄱㅅㅛㅕㅑㅐㅔㅁㄴㅇㄹㅎㅗㅓㅏㅣㅋㅌㅊㅍㅠㅜㅡ"
    assert "".join(k.ch for k in ko_upper.keys if k.role == "char") == "ㅃㅉㄸㄲㅆㅛㅕㅑㅒㅖㅁㄴㅇㄹㅎㅗㅓㅏㅣㅋㅌㅊㅍㅠㅜㅡ"
    # bottom row: mode | lang | space | done, gaps of px(gap) between them, done keeps the mode-key width
    for layer in lay.layers:
        roles = [k.role for k in layer.keys]
        assert roles[-4:] == [r for r in ("mode_sym1" if layer.lang else "mode_abc", "lang", "space", "done")]
        mode, lang, space, done = layer.keys[-4:]
        assert mode.r[2] == lang.r[2] == 126 and done.r[2] == 261  # side_key = 42pt, mode_key = 87pt at 3x
        assert lang.r[0] == mode.r[0] + mode.r[2] + 18 and space.r[0] == lang.r[0] + lang.r[2] + 18
        assert space.r[0] + space.r[2] + 18 == done.r[0] and done.r[0] + done.r[2] == 1170 - 9
    # a single language has no lang key and the wide mode key
    solo = R.build_layout(R.TYPE_QWERTY, 2, 0, R.STYLES["ios"], [R.LANG_KO], 1170, 3000, b"\x02" * 32)
    assert [k.role for k in solo.layers[0].keys][-3:] == ["mode_sym1", "space", "done"]
    assert solo.layers[0].keys[-3].r[2] == 261
    # shuffling is independent per language and per row
    sh = R.build_layout(R.TYPE_QWERTY, 0, 0, R.STYLES["ios"], [R.LANG_EN, R.LANG_KO], 1170, 3000, b"\x03" * 32)
    en_row0 = [k.ch for k in sh.layers[0].keys[:10]]
    ko_row0 = [k.ch for k in sh.layers[2].keys[:10]]
    assert sorted(en_row0) == sorted("qwertyuiop") and sorted(ko_row0) == sorted("ㅂㅈㄷㄱㅅㅛㅕㅑㅐㅔ")
    assert [k.ch for k in sh.layers[3].keys[:10]] == [R.shifted(R.LANG_KO, c) for c in ko_row0]
    with pytest.raises(R.SkpError):
        R.build_layout(R.TYPE_QWERTY, 0, 0, R.STYLES["ios"], [], 1170, 3000, b"\x03" * 32)
    with pytest.raises(R.SkpError):
        R.build_layout(R.TYPE_QWERTY, 0, 0, R.STYLES["ios"], [R.LANG_KO, R.LANG_KO], 1170, 3000, b"\x03" * 32)


def test_language_options_and_requests():
    m = mk()
    c_sk, c_pk = c_keys()
    # client request honoured when the server sets nothing
    r = req(c_pk=c_pk)
    r["opts"] = {"langs": ["ko"]}
    _, _, dbg = R.create_session(m, r, {})
    assert dbg["inner"]["langs"] == ["ko"] and len(dbg["inner"]["layouts"]) == 4
    # the server option overrides the client, as a list or a comma-separated string
    _, _, dbg = R.create_session(m, r, {"languages": ["en"]})
    assert dbg["inner"]["langs"] == ["en"]
    _, _, dbg = R.create_session(m, r, {"languages": "ko, en"})
    assert dbg["inner"]["langs"] == ["ko", "en"]
    # number pads ignore languages
    _, _, dbg = R.create_session(m, req("number", c_pk=c_pk), {"languages": ["ko"]})
    assert dbg["inner"]["langs"] == []
    for bad in (["xx"], [], ["en", "en"], "en", ["en", "ko", "en", "ko"]):
        r["opts"] = {"langs": bad}
        with pytest.raises(R.SkpError) as e:
            R.create_session(m, r, {})
        assert e.value.name == "BAD_REQUEST"
    for bad in (["xx"], ["ko", "ko"], "en,ko,en,ko", "en,,ko"):
        with pytest.raises(R.SkpError) as e:
            R.create_session(m, req(c_pk=c_pk), {"languages": bad})
        assert e.value.name == "UNSUPPORTED"
    # an empty option means "not set": the default applies
    _, _, dbg = R.create_session(m, req(c_pk=c_pk), {"languages": []})
    assert dbg["inner"]["langs"] == ["en", "ko"]
    # a tap on the lang key is rejected like any control key
    resp, sealed, dbg = R.create_session(m, req(c_pk=c_pk), {"ctx": "l"})
    opened = R.client_open(resp, c_sk, m.pk_sign)
    lang_key = R.find_key(dbg["layout"], R.MODE_LOWER, "lang", R.LANG_KO)
    slot, _ = R.find_layer(dbg["layout"], R.MODE_LOWER, R.LANG_KO)
    payload = R.client_build_input(opened["k_c2s"], opened["sid"], opened["inner"]["maxLen"],
                                   [(R.layout_id(0, slot), lang_key.r[0] + 2, lang_key.r[1] + 2)])
    with pytest.raises(R.SkpError) as e:
        R.decrypt(m, sealed, payload, ctx="l")
    assert e.value.name == "TAMPERED"


def test_hangul_vectors_and_decompose():
    import hangul
    import json
    path = os.path.join(os.path.dirname(__file__), "..", "..", "spec", "vectors", "hangul", "compose.json")
    with open(path, encoding="utf-8") as f:
        cases = json.load(f)["cases"]
    assert len(cases) >= 20
    for c in cases:
        assert hangul.compose(c["jamo"]) == c["expect"], c
    # every syllable decomposes into key presses that compose back to itself
    for cp in range(0xAC00, 0xD7A4):
        ch = chr(cp)
        assert hangul.compose(hangul.decompose(ch)) == ch
    assert hangul.decompose("뷁") == "ㅂㅜㅔㄹㄱ" and hangul.decompose("ㄳ") == "ㄱㅅ" and hangul.decompose("ㅘa") == "ㅗㅏa"
