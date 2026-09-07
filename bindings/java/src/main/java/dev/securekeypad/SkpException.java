package dev.securekeypad;

/**
 * Raised for every failure reported by the core library or the session store. The message never
 * contains values, coordinates, or layouts: only the enumerated reason.
 */
public final class SkpException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /** Error reasons; the numeric codes match {@code spec/PROTOCOL.md} §11. */
    public enum Code {
        NOMEM(-1),
        INVALID_ARG(-2),
        BAD_KEY(-3),
        BAD_REQUEST(-4),
        CRYPTO(-5),
        EXPIRED(-6),
        BAD_MAC(-7),
        TAMPERED(-8),
        CTX_MISMATCH(-9),
        SID_MISMATCH(-10),
        RENDER(-11),
        IO(-12),
        UNSUPPORTED(-13),
        /** The session id is not (or no longer) in the session store. Java-side code. */
        SESSION_NOT_FOUND(-100),
        UNKNOWN(-999);

        private final int code;

        Code(int code) {
            this.code = code;
        }

        public int code() {
            return code;
        }

        public static Code of(int code) {
            for (Code c : values()) {
                if (c.code == code) {
                    return c;
                }
            }
            return UNKNOWN;
        }
    }

    private final int code;

    /** Used by the JNI layer. */
    public SkpException(int code, String message) {
        super(Code.of(code).name() + ": " + message);
        this.code = code;
    }

    public SkpException(Code code, String message) {
        this(code.code(), message);
    }

    /** Numeric code (negative). */
    public int code() {
        return code;
    }

    /** Enumerated reason. */
    public Code kind() {
        return Code.of(code);
    }
}
