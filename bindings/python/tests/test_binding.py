"""Tests for the Python server binding. The client side is played by the reference implementation
(tools/reference/skp_ref.py); no test hooks are used, so every session uses real randomness."""
import base64
import concurrent.futures
import json
import os
import subprocess

import pytest

import hangul
import skp_ref as R
from secure_keypad_server import (
    MemoryStore,
    Secret,
    SecureKeypadServer,
    SessionNotFound,
    SkpError,
    keygen,
)

MASTER_HEX = "0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a5968778695a4b3c2d1e0f"
MASTER = bytes.fromhex(MASTER_HEX)
KEYGEN = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "core", "build", "skp-keygen"))

ROWS = {
    "en/lower": ["qwertyuiop", "asdfghjkl", "zxcvbnm"],
    "en/upper": ["QWERTYUIOP", "ASDFGHJKL", "ZXCVBNM"],
    "ko/lower": ["ㅂㅈㄷㄱㅅㅛㅕㅑㅐㅔ", "ㅁㄴㅇㄹㅎㅗㅓㅏㅣ", "ㅋㅌㅊㅍㅠㅜㅡ"],
    "ko/upper": ["ㅃㅉㄸㄲㅆㅛㅕㅑㅒㅖ", "ㅁㄴㅇㄹㅎㅗㅓㅏㅣ", "ㅋㅌㅊㅍㅠㅜㅡ"],
    "sym1": ["1234567890", "-/:;()$&@\"", ".,?!'"],
    "sym2": ["[]{}#%^*+=", "_\\|~<>€£¥•", ".,?!'"],
}


def client_keys(seed=b"\x21" * 32):
    return seed, R.x25519_public(seed)


def request(c_pk, type_="qwerty", w=390, dpr=3, platform="ios", max_len=None):
    r = {"v": 1, "kp": R.b64(c_pk), "type": type_, "viewport": {"w": w, "dpr": dpr, "platform": platform}}
    if max_len:
        r["opts"] = {"maxLen": max_len}
    return r


def fixed_mapping(inner):
    """For layout='fixed': maps (layout_id, char) -> key rect from the decrypted inner JSON."""
    out = {}
    for layer in inner["layouts"]:
        chars = "".join(ROWS[(layer["lang"] + "/" + layer["mode"]) if "lang" in layer else layer["mode"]])
        keys = [k for k in layer["keys"] if k["role"] == "char"]
        assert len(keys) == len(chars)
        for k, ch in zip(keys, chars):
            out.setdefault(ch, (layer["id"], k["r"]))
        space = next(k for k in layer["keys"] if k["role"] == "space")
        out.setdefault(" ", (layer["id"], space["r"]))
    return out


def taps_for(mapping, text):
    taps = []
    for ch in hangul.decompose(text):
        lid, (x, y, w, h) = mapping[ch]
        taps.append((lid, x + w // 2, y + h // 2))
    return taps


@pytest.fixture
def server():
    with SecureKeypadServer(master_key=MASTER_HEX) as s:
        yield s


# ------------------------------------------------------------------------------- key loading


def test_key_sources_agree(tmp_path, monkeypatch):
    expected = R.derive_master(MASTER)
    pk_b64 = R.b64(expected.pk_sign)
    path = tmp_path / "master.key"
    path.write_text("  " + R.b64(MASTER) + "\n")
    with SecureKeypadServer(master_key_path=str(path)) as s:
        assert s.public_key == pk_b64 and s.key_id == expected.kid
    with SecureKeypadServer(master_key=MASTER_HEX) as s:
        assert s.public_key == pk_b64
    with SecureKeypadServer(master_key=R.b64(MASTER)) as s:
        assert s.public_key == pk_b64
    with SecureKeypadServer(master_key=MASTER) as s:  # raw 32 bytes
        assert s.public_key == pk_b64
    monkeypatch.setenv("SKP_MASTER_KEY", MASTER_HEX)
    with SecureKeypadServer() as s:
        assert s.public_key == pk_b64 and s.version()
    if os.path.exists(KEYGEN):
        out = subprocess.run([KEYGEN, "--pubkey", str(path)], capture_output=True, text=True, check=True).stdout
        assert f"public_key={pk_b64}" in out and f"kid={expected.kid}" in out


def test_key_errors(tmp_path, monkeypatch):
    monkeypatch.delenv("SKP_MASTER_KEY", raising=False)
    with pytest.raises(ValueError):
        SecureKeypadServer()
    with pytest.raises(ValueError):
        SecureKeypadServer(master_key_path="x", master_key="y")
    with pytest.raises(SkpError) as e:
        SecureKeypadServer(master_key="not-a-key")
    assert e.value.name == "BAD_KEY" and e.value.code == -3
    with pytest.raises(SkpError) as e:
        SecureKeypadServer(master_key_path=str(tmp_path / "missing.key"))
    assert e.value.name == "IO"


def test_keygen_roundtrip():
    k = keygen()
    assert len(base64.b64decode(k)) == 32
    with SecureKeypadServer(master_key=k) as s:
        assert len(s.key_id) == 8


# ------------------------------------------------------------------------------- round trips


@pytest.mark.parametrize("text,platform,w,dpr", [
    ("Hello, w0rld!", "ios", 390, 3),
    ("pa55w0rd#[€", "android", 360, 2.625),
    ("fixed Layout", "web", 1024, 1),
])
def test_qwerty_roundtrip_fixed_layout(server, text, platform, w, dpr):
    c_sk, c_pk = client_keys()
    pk = base64.b64decode(server.public_key)
    resp = server.create_session(request(c_pk, "qwerty", w, dpr, platform, max_len=24), ctx="user-1", layout="fixed")
    assert resp["kid"] == server.key_id and set(resp) == {"v", "sid", "kid", "sp", "sig", "ct"}
    opened = R.client_open(resp, c_sk, pk)
    inner = opened["inner"]
    assert inner["maxLen"] == 24 and len(inner["layouts"]) == 6 and inner["langs"] == ["en", "ko"]
    assert opened["tiles"][:4] == b"\x89PNG" and opened["popups"][:4] == b"\x89PNG"
    for layer in inner["layouts"]:
        for k in layer["keys"]:
            assert set(k) <= {"r", "role", "t"}
    taps = taps_for(fixed_mapping(inner), text)
    payload = R.client_build_input(opened["k_c2s"], opened["sid"], inner["maxLen"], taps)
    with server.decrypt(payload, ctx="user-1") as secret:
        assert secret.bytes == text.encode("utf-8")
        assert secret.text == text and len(secret) == len(text.encode("utf-8"))
    assert secret.wiped and len(secret) == 0
    with pytest.raises(ValueError):
        secret.bytes


def test_languages(server):
    c_sk, c_pk = client_keys()
    pk = base64.b64decode(server.public_key)
    resp = server.create_session(request(c_pk, "qwerty"), ctx="ko", layout="fixed", languages=["ko", "en"])
    opened = R.client_open(resp, c_sk, pk)
    inner = opened["inner"]
    assert inner["langs"] == ["ko", "en"] and [l.get("lang") for l in inner["layouts"]] == ["ko", "ko", "en", "en", None, None]
    assert all(sum(k["role"] == "lang" for k in l["keys"]) == 1 for l in inner["layouts"])
    taps = taps_for(fixed_mapping(inner), "한글 비밀번호 Pw1!")
    payload = R.client_build_input(opened["k_c2s"], opened["sid"], inner["maxLen"], taps)
    with server.decrypt(payload, ctx="ko") as secret:
        assert secret.text == "한글 비밀번호 Pw1!"
    # string form, single language: no lang key
    resp = server.create_session(request(c_pk, "qwerty"), layout="fixed", languages="ko")
    inner = R.client_open(resp, c_sk, pk)["inner"]
    assert inner["langs"] == ["ko"] and len(inner["layouts"]) == 4
    assert not any(k["role"] == "lang" for l in inner["layouts"] for k in l["keys"])
    # the client's request is honoured when the server passes nothing
    r = request(c_pk, "qwerty")
    r["opts"] = {"langs": ["ko"]}
    inner = R.client_open(server.create_session(r), c_sk, pk)["inner"]
    assert inner["langs"] == ["ko"]
    with pytest.raises(SkpError) as e:
        server.create_session(request(c_pk, "qwerty"), languages=["xx"])
    assert e.value.name == "UNSUPPORTED"
    r["opts"] = {"langs": ["en", "en"]}
    with pytest.raises(SkpError) as e:
        server.create_session(r)
    assert e.value.name == "BAD_REQUEST"
    inner = R.client_open(server.create_session(request(c_pk, "number"), languages=["ko"]), c_sk, pk)["inner"]
    assert inner["langs"] == []


def test_json_string_inputs(server):
    c_sk, c_pk = client_keys()
    resp = server.create_session(json.dumps(request(c_pk, "number")))
    opened = R.client_open(resp, c_sk, base64.b64decode(server.public_key))
    keys = [k for k in opened["inner"]["layouts"][0]["keys"] if k["role"] == "char"]
    taps = [(opened["inner"]["layouts"][0]["id"], k["r"][0] + 1, k["r"][1] + 1) for k in keys]
    payload = json.dumps(R.client_build_input(opened["k_c2s"], opened["sid"], opened["inner"]["maxLen"], taps))
    with server.decrypt(payload) as secret:
        assert sorted(secret.text) == list("0123456789")


def test_number_pad_is_a_permutation(server):
    c_sk, c_pk = client_keys()
    resp = server.create_session(request(c_pk, "number", 412, 2.625, "android"), blank="random", max_len=10)
    opened = R.client_open(resp, c_sk, base64.b64decode(server.public_key))
    layer = opened["inner"]["layouts"][0]
    roles = [k["role"] for k in layer["keys"]]
    assert roles.count("char") == 10 and roles.count("blank") == 1 and roles[-1] == "backspace"
    taps = [(layer["id"], k["r"][0] + k["r"][2] // 2, k["r"][1] + k["r"][3] // 2) for k in layer["keys"] if k["role"] == "char"]
    payload = R.client_build_input(opened["k_c2s"], opened["sid"], 10, taps)
    with server.decrypt(payload) as secret:
        assert sorted(secret.text) == list("0123456789")


def test_relayout_keeps_mapping(server):
    c_sk, c_pk = client_keys()
    pk = base64.b64decode(server.public_key)
    resp = server.create_session(request(c_pk), ctx="rot", layout="fixed")
    opened = R.client_open(resp, c_sk, pk)
    taps = taps_for(fixed_mapping(opened["inner"]), "ab")
    rr = server.relayout({"v": 1, "sid": resp["sid"], "viewport": {"w": 844, "dpr": 3, "platform": "ios"}})
    assert rr["gen"] == 1 and rr["sid"] == resp["sid"]
    inner2 = R.client_open_relayout(opened["k_s2c"], 1, opened["sid"], rr)["inner"]
    assert inner2["gen"] == 1 and inner2["w"] == 2532
    taps += taps_for(fixed_mapping(inner2), "CD 9")
    payload = R.client_build_input(opened["k_c2s"], opened["sid"], opened["inner"]["maxLen"], taps)
    with server.decrypt(payload, ctx="rot") as secret:
        assert secret.text == "abCD 9"
    with pytest.raises(SessionNotFound):
        server.relayout({"v": 1, "sid": resp["sid"], "viewport": {"w": 844, "dpr": 3, "platform": "ios"}})


def test_take_and_keep_semantics(server):
    c_sk, c_pk = client_keys()
    resp = server.create_session(request(c_pk, "number"), ctx="once")
    opened = R.client_open(resp, c_sk, None)
    payload = R.client_build_input(opened["k_c2s"], opened["sid"], opened["inner"]["maxLen"], [])
    assert len(server.store) == 1
    with server.decrypt(payload, ctx="once", keep=True) as s:
        assert len(s) == 0
    with server.decrypt(payload, ctx="once") as s:  # consumes
        assert len(s) == 0
    assert len(server.store) == 0
    with pytest.raises(SessionNotFound) as e:
        server.decrypt(payload, ctx="once")
    assert e.value.name == "SESSION_NOT_FOUND" and e.value.sid == resp["sid"]


def test_error_mapping(server):
    c_sk, c_pk = client_keys()
    resp = server.create_session(request(c_pk, "number"), ctx="user-9")
    opened = R.client_open(resp, c_sk, None)
    layer = opened["inner"]["layouts"][0]
    key = next(k for k in layer["keys"] if k["role"] == "char")
    payload = R.client_build_input(opened["k_c2s"], opened["sid"], opened["inner"]["maxLen"], [(layer["id"], key["r"][0] + 2, key["r"][1] + 2)])
    with pytest.raises(SkpError) as e:
        server.decrypt(payload, ctx="someone-else", keep=True)
    assert e.value.name == "CTX_MISMATCH" and e.value.code == -9
    ct = bytearray(base64.b64decode(payload["ct"]))
    ct[5] ^= 0x01
    with pytest.raises(SkpError) as e:
        server.decrypt(dict(payload, ct=base64.b64encode(bytes(ct)).decode()), ctx="user-9", keep=True)
    assert e.value.name == "BAD_MAC"
    bs = next(k for k in layer["keys"] if k["role"] == "backspace")
    bad = R.client_build_input(opened["k_c2s"], opened["sid"], opened["inner"]["maxLen"], [(layer["id"], bs["r"][0] + 1, bs["r"][1] + 1)])
    with pytest.raises(SkpError) as e:
        server.decrypt(bad, ctx="user-9", keep=True)
    assert e.value.name == "TAMPERED"
    with pytest.raises(SkpError) as e:
        server.create_session({"v": 2})
    assert e.value.name == "BAD_REQUEST"
    with pytest.raises(SkpError) as e:
        server.create_session(request(c_pk), layout="diagonal")
    assert e.value.name == "UNSUPPORTED"
    with pytest.raises(SkpError) as e:
        server.decrypt({"v": 1, "ct": "x"})
    assert e.value.name == "BAD_REQUEST"
    # the failed attempts used keep=True, so the session is still there and still works
    with server.decrypt(payload, ctx="user-9") as s:
        assert len(s) == 1


def test_ttl_is_reflected_in_store(server):
    c_sk, c_pk = client_keys()
    resp = server.create_session(request(c_pk, "number"), ttl=5)
    assert 3 < server.store.ttl(resp["sid"]) <= 5
    resp2 = server.create_session(request(c_pk, "number"))
    assert 170 < server.store.ttl(resp2["sid"]) <= 180
    store = MemoryStore()
    store.put("x", b"blob", 0)
    assert store.get("x") is None and store.take("x") is None


def test_secret_wipe_zeroes_buffer():
    data = bytearray(b"hunter2")
    s = Secret(data)
    assert s.bytes is data
    s.wipe()
    assert data == bytearray(7) and s.wiped
    s.wipe()  # idempotent
    with pytest.raises(ValueError):
        s.text


def test_concurrent_sessions(server):
    def one(i):
        c_sk = bytes([i + 1]) * 32
        c_pk = R.x25519_public(c_sk)
        text = f"user{i:02d}"
        resp = server.create_session(request(c_pk, "qwerty"), ctx=f"c{i}", layout="fixed")
        opened = R.client_open(resp, c_sk, base64.b64decode(server.public_key))
        taps = taps_for(fixed_mapping(opened["inner"]), text)
        payload = R.client_build_input(opened["k_c2s"], opened["sid"], opened["inner"]["maxLen"], taps)
        with server.decrypt(payload, ctx=f"c{i}") as secret:
            return secret.text == text

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        assert all(pool.map(one, range(20)))
    assert len(server.store) == 0
