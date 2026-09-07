package dev.securekeypad;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Server SDK entry point: turns client requests into keypad sessions and encrypted input payloads back
 * into the typed value. Thread safe; one instance per master key is enough for a whole process.
 *
 * <pre>{@code
 * SecureKeypadServer skp = SecureKeypadServer.builder().masterKeyPath(Paths.get("/etc/skp/master.key")).build();
 * String response = skp.createSession(requestJson, SessionOptions.withCtx(loginAttemptId));
 * ...
 * try (Secret s = skp.decrypt(payloadJson, loginAttemptId)) { verify(s.chars()); }
 * }</pre>
 *
 * <p>Sealed session blobs are kept in the configured {@link SessionStore} (in-memory by default).
 * {@link #decrypt(String, String)} takes the blob out of the store before opening it, so a session is
 * consumed by its first decrypt attempt whether it succeeds or not.
 */
public final class SecureKeypadServer implements AutoCloseable {
    private final long handle;
    private final SessionStore store;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private boolean closed;

    private SecureKeypadServer(long handle, SessionStore store) {
        this.handle = handle;
        this.store = store;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Generates a new random master key, base64 encoded. Store it with mode 0600. */
    public static String keygen() {
        return Native.keygen();
    }

    /** Core library version string. */
    public static String coreVersion() {
        return Native.version();
    }

    /** Ed25519 verification key (base64) to configure in clients. */
    public String publicKey() {
        return withHandle(() -> Native.publicKey(handle));
    }

    /** Eight-character key id carried in every session response. */
    public String keyId() {
        return withHandle(() -> Native.keyId(handle));
    }

    public SessionStore store() {
        return store;
    }

    /**
     * Creates a session from the client's request JSON and returns the JSON to send back. The sealed
     * blob is stored under the response's {@code sid} until the session expires.
     */
    public String createSession(String requestJson, SessionOptions opts) {
        SessionOptions o = opts == null ? SessionOptions.DEFAULT : opts;
        return withHandle(() -> {
            Object[] r = Native.createSession(handle, utf8(requestJson), utf8(o.ctx()), utf8(o.layout()),
                    utf8(o.blank()), o.ttlSec(), o.maxLen());
            byte[] resp = (byte[]) r[0];
            byte[] sealed = (byte[]) r[1];
            storeSealed(sealed);
            return new String(resp, StandardCharsets.UTF_8);
        });
    }

    public String createSession(String requestJson) {
        return createSession(requestJson, SessionOptions.DEFAULT);
    }

    /** Re-renders the session for a new viewport. The stored blob is replaced. */
    public String relayout(String requestJson) {
        return withHandle(() -> {
            String sid = MiniJson.topLevelString(requestJson, "sid");
            if (sid == null) {
                throw new SkpException(SkpException.Code.BAD_REQUEST, "request has no sid");
            }
            byte[] sealed = store.get(sid);
            if (sealed == null) {
                throw new SkpException(SkpException.Code.SESSION_NOT_FOUND, "unknown or expired session");
            }
            try {
                Object[] r = Native.relayout(handle, sealed, utf8(requestJson));
                storeSealed((byte[]) r[1]);
                return new String((byte[]) r[0], StandardCharsets.UTF_8);
            } finally {
                Arrays.fill(sealed, (byte) 0);
            }
        });
    }

    /** Decrypts and consumes the session ({@code keep = false}). */
    public Secret decrypt(String payloadJson, String ctx) {
        return decrypt(payloadJson, ctx, false);
    }

    /**
     * Decrypts the client's input payload.
     *
     * @param payloadJson the {@code {v, sid, ct}} object produced by the client SDK
     * @param ctx         the binding context given at session creation ({@code null} if none)
     * @param keep        when {@code false} (recommended) the blob is removed from the store first, so the
     *                    session is single use; when {@code true} the blob stays until it expires
     */
    public Secret decrypt(String payloadJson, String ctx, boolean keep) {
        return withHandle(() -> {
            String sid = MiniJson.topLevelString(payloadJson, "sid");
            if (sid == null) {
                throw new SkpException(SkpException.Code.BAD_REQUEST, "payload has no sid");
            }
            byte[] sealed = keep ? store.get(sid) : store.take(sid);
            if (sealed == null) {
                throw new SkpException(SkpException.Code.SESSION_NOT_FOUND, "unknown, expired, or already used session");
            }
            try {
                return new Secret(Native.decrypt(handle, sealed, utf8(payloadJson), utf8(ctx)));
            } finally {
                Arrays.fill(sealed, (byte) 0);
            }
        });
    }

    /** Frees the native context. Sessions still in the store cannot be decrypted afterwards. */
    @Override
    public void close() {
        lock.writeLock().lock();
        try {
            if (!closed) {
                closed = true;
                Native.free(handle);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    private void storeSealed(byte[] sealed) {
        Object[] info = Native.sessionInfo(handle, sealed);
        long expires = (Long) info[0];
        String sid = (String) info[1];
        long ttl = Math.max(1L, expires - System.currentTimeMillis() / 1000L);
        store.put(sid, sealed, ttl);
        Arrays.fill(sealed, (byte) 0);
    }

    private interface Op<T> {
        T run();
    }

    private <T> T withHandle(Op<T> op) {
        lock.readLock().lock();
        try {
            if (closed) {
                throw new IllegalStateException("SecureKeypadServer is closed");
            }
            return op.run();
        } finally {
            lock.readLock().unlock();
        }
    }

    private static byte[] utf8(String s) {
        return s == null ? null : s.getBytes(StandardCharsets.UTF_8);
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }

    public static final class Builder {
        private Path masterKeyPath;
        private String masterKeyText;
        private byte[] masterKeyRaw;
        private int defaultTtl;
        private int maxLenCap;
        private SessionStore store;

        private Builder() {
        }

        /** File holding the master key as 64 hex characters or base64 (whitespace ignored). */
        public Builder masterKeyPath(Path path) {
            this.masterKeyPath = path;
            return this;
        }

        /** Master key as 64 hex characters or standard base64. */
        public Builder masterKey(String hexOrBase64) {
            this.masterKeyText = hexOrBase64;
            return this;
        }

        /** Master key as 32 raw bytes. The array is copied; wipe the caller's copy afterwards. */
        public Builder masterKey(byte[] raw) {
            if (raw == null || raw.length != 32) {
                throw new IllegalArgumentException("master key must be 32 bytes");
            }
            this.masterKeyRaw = raw.clone();
            return this;
        }

        /** Default session lifetime in seconds (0 keeps the core default of 180). */
        public Builder defaultTtl(int seconds) {
            this.defaultTtl = seconds;
            return this;
        }

        /** Upper bound for the input length regardless of what clients request (0 keeps 256). */
        public Builder maxLenCap(int cap) {
            this.maxLenCap = cap;
            return this;
        }

        public Builder store(SessionStore store) {
            this.store = store;
            return this;
        }

        public SecureKeypadServer build() {
            int sources = (masterKeyPath != null ? 1 : 0) + (masterKeyText != null ? 1 : 0) + (masterKeyRaw != null ? 1 : 0);
            if (sources != 1) {
                throw new IllegalArgumentException("exactly one master key source must be configured");
            }
            byte[] path = null;
            byte[] text = null;
            if (masterKeyPath != null) {
                path = masterKeyPath.toAbsolutePath().toString().getBytes(StandardCharsets.UTF_8);
            } else if (masterKeyText != null) {
                text = masterKeyText.getBytes(StandardCharsets.UTF_8);
            } else {
                text = hex(masterKeyRaw).getBytes(StandardCharsets.US_ASCII);
            }
            long handle;
            try {
                handle = Native.init(path, text, defaultTtl, maxLenCap);
            } finally {
                if (text != null) {
                    Arrays.fill(text, (byte) 0);
                }
                if (masterKeyRaw != null) {
                    Arrays.fill(masterKeyRaw, (byte) 0);
                }
            }
            return new SecureKeypadServer(handle, store != null ? store : new InMemorySessionStore());
        }
    }
}
