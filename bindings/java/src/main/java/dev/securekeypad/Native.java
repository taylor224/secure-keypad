package dev.securekeypad;

/**
 * JNI surface over libskp. All text crosses the boundary as UTF-8 byte arrays so that Java's
 * modified UTF-8 never touches protocol data. Every native method throws {@link SkpException}
 * on a non-zero core status.
 */
final class Native {
    static {
        NativeLoader.load();
    }

    private Native() {
    }

    /** Exactly one of {@code path} / {@code keyText} is non-null. keyText is hex or base64. */
    static native long init(byte[] path, byte[] keyText, int defaultTtl, int maxLenCap);

    static native void free(long handle);

    static native String version();

    static native String publicKey(long handle);

    static native String keyId(long handle);

    static native String keygen();

    /** Returns {byte[] responseJson, byte[] sealed}. */
    static native Object[] createSession(long handle, byte[] requestJson, byte[] ctx, byte[] layout, byte[] blank,
                                         int ttlSec, int maxLen);

    /** Returns {byte[] responseJson, byte[] newSealed}. */
    static native Object[] relayout(long handle, byte[] sealed, byte[] requestJson);

    /** Returns the decrypted UTF-8 bytes; the native secret is freed before returning. */
    static native byte[] decrypt(long handle, byte[] sealed, byte[] payloadJson, byte[] ctx);

    /** Returns {Long expiresUnixSeconds, String sidBase64Url}. */
    static native Object[] sessionInfo(long handle, byte[] sealed);
}
