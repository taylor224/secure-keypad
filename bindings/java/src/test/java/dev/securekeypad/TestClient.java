package dev.securekeypad;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.XECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A test-only client built from JDK primitives (X25519, Ed25519, HKDF-SHA256 via HMAC, ChaCha20-Poly1305)
 * following spec/PROTOCOL.md §4.4 and §7. It knows nothing the real client would not know, except that the
 * tests run sessions with {@code layout = "fixed"} so the expected character positions are known.
 */
final class TestClient {
    static final String LOWER = "qwertyuiopasdfghjklzxcvbnm";
    static final String SYM1 = "1234567890-/:;()$&@\".,?!'";

    final KeyPair keyPair;
    final byte[] publicKeyRaw;
    byte[] sid;
    byte[] kS2c;
    byte[] kC2s;
    Map<String, Object> inner;
    byte[] tiles;
    byte[] popups;

    TestClient() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("XDH");
        g.initialize(NamedParameterSpec.X25519);
        keyPair = g.generateKeyPair();
        publicKeyRaw = toLittleEndian(((XECPublicKey) keyPair.getPublic()).getU(), 32);
    }

    String request(String type, double w, double dpr, String platform, Integer maxLen) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"v\":1,\"kp\":\"").append(Base64.getEncoder().encodeToString(publicKeyRaw))
          .append("\",\"type\":\"").append(type).append("\",\"viewport\":{\"w\":").append(w)
          .append(",\"dpr\":").append(dpr).append(",\"platform\":\"").append(platform).append("\"}");
        if (maxLen != null) {
            sb.append(",\"opts\":{\"maxLen\":").append(maxLen).append('}');
        }
        return sb.append('}').toString();
    }

    /** Verifies the signature (when serverPkSign != null), derives the keys, decrypts the inner frame. */
    @SuppressWarnings("unchecked")
    void open(String responseJson, byte[] serverPkSign) throws Exception {
        Map<String, Object> r = (Map<String, Object>) MiniJson.parse(responseJson);
        if (!Long.valueOf(1).equals(r.get("v"))) {
            throw new IllegalStateException("bad version");
        }
        sid = Base64.getUrlDecoder().decode((String) r.get("sid"));
        byte[] sp = Base64.getDecoder().decode((String) r.get("sp"));
        byte[] sig = Base64.getDecoder().decode((String) r.get("sig"));
        byte[] ct = Base64.getDecoder().decode((String) r.get("ct"));
        String kid = (String) r.get("kid");
        if (serverPkSign != null) {
            byte[] msg = concat("skp/v1/session".getBytes(StandardCharsets.US_ASCII), kid.getBytes(StandardCharsets.US_ASCII),
                    sid, publicKeyRaw, sp, sha256(ct));
            if (!ed25519Verify(serverPkSign, msg, sig)) {
                throw new SecurityException("bad server signature");
            }
        }
        byte[] ss = x25519(sp);
        byte[] prk = hmac(concat("skp/v1".getBytes(StandardCharsets.US_ASCII), sid), ss);
        kS2c = hmac(prk, concat("s2c".getBytes(StandardCharsets.US_ASCII), publicKeyRaw, sp, new byte[] {1}));
        kC2s = hmac(prk, concat("c2s".getBytes(StandardCharsets.US_ASCII), publicKeyRaw, sp, new byte[] {1}));
        Arrays.fill(ss, (byte) 0);
        Arrays.fill(prk, (byte) 0);
        byte[] pt = aead(Cipher.DECRYPT_MODE, kS2c, nonce(0), concat("skp/v1/session".getBytes(StandardCharsets.US_ASCII), sid), ct);
        unframe(pt);
    }

    /** Decrypts a relayout response with the server→client counter {@code ctr}. */
    @SuppressWarnings("unchecked")
    Map<String, Object> openRelayout(String responseJson, long ctr) throws Exception {
        Map<String, Object> r = (Map<String, Object>) MiniJson.parse(responseJson);
        byte[] ct = Base64.getDecoder().decode((String) r.get("ct"));
        byte[] pt = aead(Cipher.DECRYPT_MODE, kS2c, nonce(ctr), concat("skp/v1/relayout".getBytes(StandardCharsets.US_ASCII), sid), ct);
        unframe(pt);
        return inner;
    }

    /** Builds the padded, encrypted input payload (spec §7). taps: {layoutId, x, y}. */
    String payload(int maxLen, List<int[]> taps) throws Exception {
        byte[] batch = new byte[4 + 8 * maxLen];
        batch[0] = 1;
        batch[2] = (byte) (taps.size() >> 8);
        batch[3] = (byte) taps.size();
        for (int i = 0; i < taps.size(); i++) {
            int o = 4 + 8 * i;
            batch[o] = (byte) (i >> 8);
            batch[o + 1] = (byte) i;
            batch[o + 2] = (byte) taps.get(i)[0];
            batch[o + 3] = 0;
            batch[o + 4] = (byte) (taps.get(i)[1] >> 8);
            batch[o + 5] = (byte) taps.get(i)[1];
            batch[o + 6] = (byte) (taps.get(i)[2] >> 8);
            batch[o + 7] = (byte) taps.get(i)[2];
        }
        byte[] ct = aead(Cipher.ENCRYPT_MODE, kC2s, nonce(0), concat("skp/v1/input".getBytes(StandardCharsets.US_ASCII), sid), batch);
        Arrays.fill(batch, (byte) 0);
        return payloadJson(Base64.getEncoder().encodeToString(ct));
    }

    String payloadJson(String ctBase64) {
        return "{\"v\":1,\"sid\":\"" + Base64.getUrlEncoder().withoutPadding().encodeToString(sid) + "\",\"ct\":\"" + ctBase64 + "\"}";
    }

    int maxLen() {
        return ((Long) inner.get("maxLen")).intValue();
    }

    /** Key-centre taps for {@code text} on a {@code layout = "fixed"} QWERTY session. */
    @SuppressWarnings("unchecked")
    static List<int[]> tapsForFixed(Map<String, Object> inner, int gen, String text) {
        List<int[]> taps = new ArrayList<>();
        for (char c : text.toCharArray()) {
            int mode;
            int index;
            String role = "char";
            if (c == ' ') {
                mode = 0;
                index = 0;
                role = "space";
            } else if (LOWER.indexOf(c) >= 0) {
                mode = 0;
                index = LOWER.indexOf(c);
            } else if (LOWER.toUpperCase().indexOf(c) >= 0) {
                mode = 1;
                index = LOWER.toUpperCase().indexOf(c);
            } else if (SYM1.indexOf(c) >= 0) {
                mode = 2;
                index = SYM1.indexOf(c);
            } else {
                throw new IllegalArgumentException("character not on the fixed keypad: " + c);
            }
            int id = (gen << 3) | mode;
            Map<String, Object> layer = null;
            for (Object o : (List<Object>) inner.get("layouts")) {
                Map<String, Object> l = (Map<String, Object>) o;
                if (((Long) l.get("id")).intValue() == id) {
                    layer = l;
                }
            }
            if (layer == null) {
                throw new IllegalStateException("no layer with id " + id);
            }
            int seen = 0;
            int[] tap = null;
            for (Object o : (List<Object>) layer.get("keys")) {
                Map<String, Object> k = (Map<String, Object>) o;
                if (!role.equals(k.get("role"))) {
                    continue;
                }
                if (seen++ == index) {
                    List<Object> r = (List<Object>) k.get("r");
                    int x = ((Long) r.get(0)).intValue() + ((Long) r.get(2)).intValue() / 2;
                    int y = ((Long) r.get(1)).intValue() + ((Long) r.get(3)).intValue() / 2;
                    tap = new int[] {id, x, y};
                    break;
                }
            }
            if (tap == null) {
                throw new IllegalStateException("key not found for " + c);
            }
            taps.add(tap);
        }
        return taps;
    }

    /** Centres of every {@code char} key of the given layer id, in listing order. */
    @SuppressWarnings("unchecked")
    static List<int[]> allCharTaps(Map<String, Object> inner, int id) {
        List<int[]> taps = new ArrayList<>();
        for (Object o : (List<Object>) inner.get("layouts")) {
            Map<String, Object> l = (Map<String, Object>) o;
            if (((Long) l.get("id")).intValue() != id) {
                continue;
            }
            for (Object ko : (List<Object>) l.get("keys")) {
                Map<String, Object> k = (Map<String, Object>) ko;
                if ("char".equals(k.get("role"))) {
                    List<Object> r = (List<Object>) k.get("r");
                    taps.add(new int[] {id, ((Long) r.get(0)).intValue() + ((Long) r.get(2)).intValue() / 2,
                            ((Long) r.get(1)).intValue() + ((Long) r.get(3)).intValue() / 2});
                }
            }
        }
        return taps;
    }

    // ---- primitives -------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private void unframe(byte[] pt) {
        int pos = 0;
        int jl = readU32(pt, pos);
        pos += 4;
        String json = new String(pt, pos, jl, StandardCharsets.UTF_8);
        pos += jl;
        int tl = readU32(pt, pos);
        pos += 4;
        tiles = Arrays.copyOfRange(pt, pos, pos + tl);
        pos += tl;
        int pl = readU32(pt, pos);
        pos += 4;
        popups = Arrays.copyOfRange(pt, pos, pos + pl);
        pos += pl;
        if (pos != pt.length) {
            throw new IllegalStateException("trailing bytes in frame");
        }
        inner = (Map<String, Object>) MiniJson.parse(json);
    }

    private static int readU32(byte[] b, int o) {
        return ((b[o] & 0xFF) << 24) | ((b[o + 1] & 0xFF) << 16) | ((b[o + 2] & 0xFF) << 8) | (b[o + 3] & 0xFF);
    }

    static byte[] nonce(long ctr) {
        byte[] n = new byte[12];
        for (int i = 0; i < 8; i++) {
            n[4 + i] = (byte) (ctr >>> (56 - 8 * i));
        }
        return n;
    }

    static byte[] aead(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
        c.init(mode, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
        c.updateAAD(aad);
        return c.doFinal(data);
    }

    static byte[] hmac(byte[] key, byte[]... parts) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(key, "HmacSHA256"));
        for (byte[] p : parts) {
            m.update(p);
        }
        return m.doFinal();
    }

    static byte[] sha256(byte[] b) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(b);
    }

    private byte[] x25519(byte[] serverPublicRaw) throws Exception {
        byte[] u = serverPublicRaw.clone();
        u[31] &= 0x7F;
        PublicKey pub = KeyFactory.getInstance("XDH").generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, fromLittleEndian(u)));
        KeyAgreement ka = KeyAgreement.getInstance("XDH");
        ka.init(keyPair.getPrivate());
        ka.doPhase(pub, true);
        return ka.generateSecret();
    }

    static boolean ed25519Verify(byte[] pkRaw, byte[] msg, byte[] sig) throws Exception {
        byte[] y = pkRaw.clone();
        boolean xOdd = (y[31] & 0x80) != 0;
        y[31] &= 0x7F;
        PublicKey pub = KeyFactory.getInstance("Ed25519")
                .generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(xOdd, fromLittleEndian(y))));
        Signature s = Signature.getInstance("Ed25519");
        s.initVerify(pub);
        s.update(msg);
        return s.verify(sig);
    }

    static byte[] toLittleEndian(BigInteger v, int len) {
        byte[] be = v.toByteArray();
        byte[] le = new byte[len];
        for (int i = 0; i < len && i < be.length; i++) {
            le[i] = be[be.length - 1 - i];
        }
        return le;
    }

    static BigInteger fromLittleEndian(byte[] le) {
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) {
            be[i] = le[le.length - 1 - i];
        }
        return new BigInteger(1, be);
    }

    static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }
}
