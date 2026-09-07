package dev.securekeypad;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The decrypted keypad input. The bytes live in a plain Java array (the JVM offers no locked memory);
 * {@link #close()} zeroes it. Never turn the value into a {@link String}: strings are immutable, may be
 * interned, and cannot be wiped.
 *
 * <pre>{@code
 * try (Secret s = server.decrypt(payload, ctx)) {
 *     char[] pw = s.chars();
 *     try { verify(pw); } finally { Arrays.fill(pw, '\0'); }
 * }
 * }</pre>
 */
public final class Secret implements AutoCloseable {
    private final byte[] bytes;
    private boolean closed;

    Secret(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * The UTF-8 bytes of the input. The array is owned by this Secret and is zeroed by {@link #close()};
     * do not keep references to it beyond the Secret's lifetime.
     */
    public byte[] bytes() {
        checkOpen();
        return bytes;
    }

    /** Number of UTF-8 bytes. */
    public int length() {
        checkOpen();
        return bytes.length;
    }

    /**
     * Decodes the value into a fresh {@code char[]}. The caller owns the array and must wipe it with
     * {@code Arrays.fill(chars, '\0')} after use.
     */
    public char[] chars() {
        checkOpen();
        CharBuffer cb = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(bytes));
        char[] out = new char[cb.remaining()];
        cb.get(out);
        if (cb.hasArray()) {
            Arrays.fill(cb.array(), '\0');
        }
        return out;
    }

    public boolean isClosed() {
        return closed;
    }

    /** Zeroes the bytes. Idempotent. */
    @Override
    public void close() {
        if (!closed) {
            Arrays.fill(bytes, (byte) 0);
            closed = true;
        }
    }

    private void checkOpen() {
        if (closed) {
            throw new IllegalStateException("secret already wiped");
        }
    }

    @Override
    public String toString() {
        return "Secret[" + (closed ? "wiped" : bytes.length + " bytes") + "]";
    }
}
