package dev.securekeypad;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SecureKeypadServerTest {
    static final String MASTER_HEX = "0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a5968778695a4b3c2d1e0f";
    static final SessionOptions FIXED = SessionOptions.builder().ctx("attempt-1").layout("fixed").build();

    static SecureKeypadServer newServer() {
        return SecureKeypadServer.builder().masterKey(MASTER_HEX).build();
    }

    static byte[] serverSigningKey(SecureKeypadServer s) {
        return Base64.getDecoder().decode(s.publicKey());
    }

    static byte[] hex(String h) {
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    static String secretText(Secret s) {
        // tests may materialise the value; production code must not
        return new String(s.bytes(), StandardCharsets.UTF_8);
    }

    @Test
    void keyLoadingFormatsAgree(@TempDir Path dir) throws Exception {
        String b64 = Base64.getEncoder().encodeToString(hex(MASTER_HEX));
        Path file = dir.resolve("master.key");
        Files.write(file, ("  " + b64 + "\n").getBytes(StandardCharsets.US_ASCII));
        try (SecureKeypadServer fromPath = SecureKeypadServer.builder().masterKeyPath(file).build();
             SecureKeypadServer fromHex = newServer();
             SecureKeypadServer fromB64 = SecureKeypadServer.builder().masterKey(b64).build();
             SecureKeypadServer fromRaw = SecureKeypadServer.builder().masterKey(hex(MASTER_HEX)).build()) {
            assertEquals(fromHex.publicKey(), fromPath.publicKey());
            assertEquals(fromHex.publicKey(), fromB64.publicKey());
            assertEquals(fromHex.publicKey(), fromRaw.publicKey());
            assertEquals(8, fromHex.keyId().length());
            assertEquals(44, fromHex.publicKey().length());
        }
        SkpException bad = assertThrows(SkpException.class, () -> SecureKeypadServer.builder().masterKey("nope").build());
        assertEquals(SkpException.Code.BAD_KEY, bad.kind());
        SkpException missing = assertThrows(SkpException.class,
                () -> SecureKeypadServer.builder().masterKeyPath(dir.resolve("absent.key")).build());
        assertEquals(SkpException.Code.IO, missing.kind());
        assertThrows(IllegalArgumentException.class, () -> SecureKeypadServer.builder().build());
        // two different sources (text and raw bytes) are rejected; setting the same kind twice is fine
        assertThrows(IllegalArgumentException.class,
                () -> SecureKeypadServer.builder().masterKey(MASTER_HEX).masterKey(hex(MASTER_HEX)).build());
        assertThrows(IllegalArgumentException.class,
                () -> SecureKeypadServer.builder().masterKeyPath(file).masterKey(b64).build());
        String generated = SecureKeypadServer.keygen();
        assertEquals(32, Base64.getDecoder().decode(generated).length);
        assertNotEquals(generated, SecureKeypadServer.keygen());
        assertNotNull(SecureKeypadServer.coreVersion());
    }

    @Test
    @SuppressWarnings("unchecked")
    void publicKeyMatchesReferenceVector() throws Exception {
        String json = new String(Files.readAllBytes(Paths.get("../../spec/vectors/qwerty-ios-390x3-shuffle.json")), StandardCharsets.UTF_8);
        Map<String, Object> v = (Map<String, Object>) MiniJson.parse(json);
        Map<String, Object> em = (Map<String, Object>) v.get("expect_master");
        try (SecureKeypadServer s = SecureKeypadServer.builder().masterKey((String) v.get("master_key")).build()) {
            assertEquals(Base64.getEncoder().encodeToString(hex((String) em.get("pk_sign"))), s.publicKey());
            assertEquals(em.get("kid"), s.keyId());
        }
    }

    @Test
    void qwertyRoundTripOnFixedLayout() throws Exception {
        try (SecureKeypadServer s = newServer()) {
            TestClient c = new TestClient();
            String resp = s.createSession(c.request("qwerty", 390, 3, "ios", 24), FIXED);
            c.open(resp, serverSigningKey(s));
            assertEquals(24, c.maxLen());
            assertEquals(1170L, c.inner.get("w"));
            assertEquals(648L, c.inner.get("h"));
            assertTrue(c.tiles.length > 1000 && c.popups.length > 1000, "sprites present");
            assertEquals((byte) 0x89, c.tiles[0]);
            // no character identifiers in the key objects
            for (Object lo : (List<?>) c.inner.get("layouts")) {
                for (Object ko : (List<?>) ((Map<?, ?>) lo).get("keys")) {
                    Map<?, ?> k = (Map<?, ?>) ko;
                    assertTrue(k.keySet().stream().allMatch(key -> key.equals("r") || key.equals("role") || key.equals("t")));
                    assertEquals("char".equals(k.get("role")), k.containsKey("t"));
                }
            }
            String text = "Hello, w0rld!";
            String payload = c.payload(c.maxLen(), TestClient.tapsForFixed(c.inner, 0, text));
            try (Secret secret = s.decrypt(payload, "attempt-1")) {
                assertEquals(text, secretText(secret));
                char[] chars = secret.chars();
                assertArrayEquals(text.toCharArray(), chars);
                Arrays.fill(chars, '\0');
                assertEquals(text.length(), secret.length());
            }
            // consumed
            SkpException gone = assertThrows(SkpException.class, () -> s.decrypt(payload, "attempt-1"));
            assertEquals(SkpException.Code.SESSION_NOT_FOUND, gone.kind());
        }
    }

    @Test
    void numberPadRoundTripIsAPermutationOfDigits() throws Exception {
        try (SecureKeypadServer s = newServer()) {
            TestClient c = new TestClient();
            String resp = s.createSession(c.request("number", 412, 2.625, "android", null),
                    SessionOptions.builder().blank("random").build());
            c.open(resp, serverSigningKey(s));
            assertEquals(16, c.maxLen());
            List<int[]> taps = TestClient.allCharTaps(c.inner, 4);
            assertEquals(10, taps.size());
            try (Secret secret = s.decrypt(c.payload(c.maxLen(), taps), null)) {
                char[] digits = secretText(secret).toCharArray();
                Arrays.sort(digits);
                assertEquals("0123456789", new String(digits));
            }
        }
    }

    @Test
    void relayoutKeepsMappingAndOldTaps() throws Exception {
        try (SecureKeypadServer s = newServer()) {
            TestClient c = new TestClient();
            c.open(s.createSession(c.request("qwerty", 390, 3, "ios", null), FIXED), serverSigningKey(s));
            List<int[]> taps = new ArrayList<>(TestClient.tapsForFixed(c.inner, 0, "ab"));
            String sid = Base64.getUrlEncoder().withoutPadding().encodeToString(c.sid);
            String rr = s.relayout("{\"v\":1,\"sid\":\"" + sid + "\",\"viewport\":{\"w\":844,\"dpr\":3,\"platform\":\"ios\"}}");
            Map<String, Object> inner2 = c.openRelayout(rr, 1);
            assertEquals(1L, inner2.get("gen"));
            assertEquals(2532L, inner2.get("w"));
            taps.addAll(TestClient.tapsForFixed(inner2, 1, "CD 9"));
            try (Secret secret = s.decrypt(c.payload(c.maxLen(), taps), "attempt-1")) {
                assertEquals("abCD 9", secretText(secret));
            }
            SkpException unknown = assertThrows(SkpException.class, () -> s.relayout("{\"v\":1,\"sid\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"viewport\":{\"w\":844,\"dpr\":3,\"platform\":\"ios\"}}"));
            assertEquals(SkpException.Code.SESSION_NOT_FOUND, unknown.kind());
            SkpException noSid = assertThrows(SkpException.class, () -> s.relayout("{\"v\":1}"));
            assertEquals(SkpException.Code.BAD_REQUEST, noSid.kind());
        }
    }

    @Test
    void keepVersusTake() throws Exception {
        InMemorySessionStore store = new InMemorySessionStore();
        try (SecureKeypadServer s = SecureKeypadServer.builder().masterKey(MASTER_HEX).store(store).build()) {
            TestClient c = new TestClient();
            c.open(s.createSession(c.request("qwerty", 390, 3, "ios", null), FIXED), serverSigningKey(s));
            assertEquals(1, store.size());
            String payload = c.payload(c.maxLen(), TestClient.tapsForFixed(c.inner, 0, "keep"));
            try (Secret a = s.decrypt(payload, "attempt-1", true)) {
                assertEquals("keep", secretText(a));
            }
            assertEquals(1, store.size());
            try (Secret b = s.decrypt(payload, "attempt-1", true)) {
                assertEquals("keep", secretText(b));
            }
            try (Secret d = s.decrypt(payload, "attempt-1", false)) {
                assertEquals("keep", secretText(d));
            }
            assertEquals(0, store.size());
            assertEquals(SkpException.Code.SESSION_NOT_FOUND,
                    assertThrows(SkpException.class, () -> s.decrypt(payload, "attempt-1")).kind());
        }
    }

    @Test
    void errorMapping() throws Exception {
        try (SecureKeypadServer s = newServer()) {
            TestClient c = new TestClient();
            c.open(s.createSession(c.request("qwerty", 390, 3, "ios", null), FIXED), serverSigningKey(s));
            String payload = c.payload(c.maxLen(), TestClient.tapsForFixed(c.inner, 0, "x"));
            assertEquals(SkpException.Code.CTX_MISMATCH,
                    assertThrows(SkpException.class, () -> s.decrypt(payload, "someone-else", true)).kind());
            assertEquals(SkpException.Code.CTX_MISMATCH,
                    assertThrows(SkpException.class, () -> s.decrypt(payload, null, true)).kind());
            // flip one ciphertext byte
            Map<?, ?> p = (Map<?, ?>) MiniJson.parse(payload);
            byte[] ct = Base64.getDecoder().decode((String) p.get("ct"));
            ct[5] ^= 0x01;
            String tampered = c.payloadJson(Base64.getEncoder().encodeToString(ct));
            assertEquals(SkpException.Code.BAD_MAC,
                    assertThrows(SkpException.class, () -> s.decrypt(tampered, "attempt-1", true)).kind());
            // a tap on the shift key (first key of row 2 in the lower layer) is rejected as tampering
            List<int[]> shift = shiftTap(c.inner);
            String onShift = c.payload(c.maxLen(), shift);
            assertEquals(SkpException.Code.TAMPERED,
                    assertThrows(SkpException.class, () -> s.decrypt(onShift, "attempt-1", true)).kind());
            String unknownSid = "{\"v\":1,\"sid\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"ct\":\"AAAA\"}";
            assertEquals(SkpException.Code.SESSION_NOT_FOUND,
                    assertThrows(SkpException.class, () -> s.decrypt(unknownSid, "attempt-1")).kind());
            assertEquals(SkpException.Code.BAD_REQUEST,
                    assertThrows(SkpException.class, () -> s.decrypt("{}", "attempt-1")).kind());
            assertEquals(SkpException.Code.BAD_REQUEST,
                    assertThrows(SkpException.class, () -> s.createSession("{\"v\":2}", FIXED)).kind());
            assertEquals(SkpException.Code.UNSUPPORTED, assertThrows(SkpException.class,
                    () -> s.createSession(c.request("qwerty", 390, 3, "ios", null), SessionOptions.builder().layout("diagonal").build())).kind());
            // the good payload still works, and consumes the session
            try (Secret ok = s.decrypt(payload, "attempt-1")) {
                assertEquals("x", secretText(ok));
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static List<int[]> shiftTap(Map<String, Object> inner) {
        for (Object lo : (List<Object>) inner.get("layouts")) {
            Map<String, Object> l = (Map<String, Object>) lo;
            if (((Long) l.get("id")) != 0L) {
                continue;
            }
            for (Object ko : (List<Object>) l.get("keys")) {
                Map<String, Object> k = (Map<String, Object>) ko;
                if ("shift".equals(k.get("role"))) {
                    List<Object> r = (List<Object>) k.get("r");
                    return List.of(new int[] {0, ((Long) r.get(0)).intValue() + 2, ((Long) r.get(1)).intValue() + 2});
                }
            }
        }
        throw new IllegalStateException("no shift key");
    }

    @Test
    void secretCloseZeroes() throws Exception {
        try (SecureKeypadServer s = newServer()) {
            TestClient c = new TestClient();
            c.open(s.createSession(c.request("qwerty", 390, 3, "ios", null), FIXED), serverSigningKey(s));
            Secret secret = s.decrypt(c.payload(c.maxLen(), TestClient.tapsForFixed(c.inner, 0, "wipe me")), "attempt-1");
            byte[] ref = secret.bytes();
            assertEquals("wipe me", new String(ref, StandardCharsets.UTF_8));
            secret.close();
            assertTrue(secret.isClosed());
            for (byte b : ref) {
                assertEquals(0, b);
            }
            assertThrows(IllegalStateException.class, secret::bytes);
            assertThrows(IllegalStateException.class, secret::chars);
            secret.close(); // idempotent
        }
    }

    @Test
    void closedServerRejectsCalls() throws Exception {
        SecureKeypadServer s = newServer();
        TestClient c = new TestClient();
        String req = c.request("number", 390, 3, "ios", null);
        s.close();
        s.close();
        assertThrows(IllegalStateException.class, () -> s.createSession(req, null));
        assertThrows(IllegalStateException.class, s::publicKey);
    }

    @Test
    void inMemoryStoreExpiresEntries() throws Exception {
        InMemorySessionStore store = new InMemorySessionStore();
        store.put("a", new byte[] {1, 2, 3}, 60);
        store.put("b", new byte[] {4}, 0);
        Thread.sleep(15);
        assertArrayEquals(new byte[] {1, 2, 3}, store.get("a"));
        assertNull(store.get("b"));
        assertArrayEquals(new byte[] {1, 2, 3}, store.take("a"));
        assertNull(store.take("a"));
        store.put("c", new byte[] {9}, 60);
        store.delete("c");
        assertNull(store.get("c"));
        assertEquals(0, store.size());
    }

    @Test
    void concurrentSessions() throws Exception {
        try (SecureKeypadServer s = newServer()) {
            byte[] pk = serverSigningKey(s);
            ExecutorService pool = Executors.newFixedThreadPool(8);
            List<Future<Boolean>> results = new ArrayList<>();
            for (int t = 0; t < 8; t++) {
                final int id = t;
                results.add(pool.submit(() -> {
                    for (int i = 0; i < 12; i++) {
                        TestClient c = new TestClient();
                        String ctx = "thread-" + id + "-" + i;
                        c.open(s.createSession(c.request(i % 2 == 0 ? "qwerty" : "number", 390 + id, 3, "ios", null),
                                SessionOptions.builder().ctx(ctx).layout("fixed").build()), pk);
                        String text = i % 2 == 0 ? "t" + id + " q" : null;
                        List<int[]> taps = text != null ? TestClient.tapsForFixed(c.inner, 0, text) : TestClient.allCharTaps(c.inner, 4);
                        try (Secret secret = s.decrypt(c.payload(c.maxLen(), taps), ctx)) {
                            String got = secretText(secret);
                            if (text != null) {
                                if (!text.equals(got)) {
                                    return false;
                                }
                            } else {
                                char[] d = got.toCharArray();
                                Arrays.sort(d);
                                if (!"0123456789".equals(new String(d))) {
                                    return false;
                                }
                            }
                        }
                    }
                    return true;
                }));
            }
            pool.shutdown();
            assertTrue(pool.awaitTermination(120, TimeUnit.SECONDS));
            for (Future<Boolean> f : results) {
                assertTrue(f.get());
            }
            assertFalse(results.isEmpty());
        }
    }
}
