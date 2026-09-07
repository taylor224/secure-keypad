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
        for k in layer["keys"]:
            assert set(k.keys()) <= {"r", "role", "t"}
            assert ("t" in k) == (k["role"] == "char")
    taps = R.taps_for_text(dbg["layout"], 0, text)
    payload = R.client_build_input(opened["k_c2s"], opened["sid"], inner["maxLen"], taps)
    assert R.decrypt(m, sealed, payload, ctx="user-1") == text


def test_fixed_layout_is_identity():
    m = mk()
    c_sk, c_pk = c_keys()
    _, _, dbg = R.create_session(m, req(c_pk=c_pk), {"layout": "fixed"})
    lower = [k.ch for k in dbg["layout"].layers[0].keys if k.role == "char"]
    assert "".join(lower) == "qwertyuiopasdfghjklzxcvbnm"


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
    taps = [(R.layout_id(0, 4), first.r[0] + 3, first.r[1] - 1), (R.layout_id(0, 4), first.r[0] - 1, first.r[1] + 3)]
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
    bs = R.find_key(dbg["layout"], 4, "backspace")
    bad = R.client_build_input(opened["k_c2s"], opened["sid"], opened["inner"]["maxLen"],
                               [(R.layout_id(0, 4), bs.r[0] + 1, bs.r[1] + 1)])
    expect("TAMPERED", payload=bad, ctx="user-9", now=1_700_000_000)
    # coordinates outside the surface
    bad = R.client_build_input(opened["k_c2s"], opened["sid"], opened["inner"]["maxLen"], [(R.layout_id(0, 4), 5000, 5)])
    expect("TAMPERED", payload=bad, ctx="user-9", now=1_700_000_000)
    # wrong mode for number pad
    bad = R.client_build_input(opened["k_c2s"], opened["sid"], opened["inner"]["maxLen"], [(R.layout_id(0, 0), 5, 5)])
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
    lay = R.build_layout(R.TYPE_QWERTY, 0, 0, R.STYLES["ios"], 1170, 3000, b"\x01" * 32)
    assert lay.H == 648 and lay.tile_h == 126
    row0 = [k for k in lay.layers[0].keys][:10]
    assert row0[0].r[0] == 9 and row0[-1].r[0] + row0[-1].r[2] == 1170 - 9
    assert all(k.r[2] in (99, 100) for k in row0)
    lay_n = R.build_layout(R.TYPE_NUMBER, 0, 0, R.STYLES["material"], 1080, 2625, b"\x01" * 32)
    assert len(lay_n.layers[0].keys) == 12 and lay_n.layers[0].keys[11].role == "backspace"
    assert lay_n.tile_count == 10
