package dev.securekeypad;

/**
 * Server-side options for a session. These never come from the client.
 *
 * <ul>
 *   <li>{@code ctx}: binding context (user id, login attempt id). The same value must be passed to
 *       {@link SecureKeypadServer#decrypt}; a mismatch fails with {@code CTX_MISMATCH}.</li>
 *   <li>{@code layout}: {@code "shuffle"} (default), {@code "full"}, or {@code "fixed"}. {@code fixed}
 *       keeps the native QWERTY order and therefore lets coordinates reveal characters; the core logs
 *       a warning.</li>
 *   <li>{@code blank}: {@code "fixed"} (default) or {@code "random"}; number pad only.</li>
 *   <li>{@code ttlSec}: session lifetime, 0 for the server default.</li>
 *   <li>{@code maxLen}: overrides the client's requested maximum length when {@code > 0}.</li>
 * </ul>
 */
public final class SessionOptions {
    public static final SessionOptions DEFAULT = builder().build();

    private final String ctx;
    private final String layout;
    private final String blank;
    private final int ttlSec;
    private final int maxLen;

    private SessionOptions(Builder b) {
        this.ctx = b.ctx;
        this.layout = b.layout;
        this.blank = b.blank;
        this.ttlSec = b.ttlSec;
        this.maxLen = b.maxLen;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Shorthand for {@code builder().ctx(ctx).build()}. */
    public static SessionOptions withCtx(String ctx) {
        return builder().ctx(ctx).build();
    }

    public String ctx() {
        return ctx;
    }

    public String layout() {
        return layout;
    }

    public String blank() {
        return blank;
    }

    public int ttlSec() {
        return ttlSec;
    }

    public int maxLen() {
        return maxLen;
    }

    public static final class Builder {
        private String ctx;
        private String layout;
        private String blank;
        private int ttlSec;
        private int maxLen;

        private Builder() {
        }

        public Builder ctx(String ctx) {
            this.ctx = ctx;
            return this;
        }

        public Builder layout(String layout) {
            this.layout = layout;
            return this;
        }

        public Builder blank(String blank) {
            this.blank = blank;
            return this;
        }

        public Builder ttlSec(int ttlSec) {
            if (ttlSec < 0) {
                throw new IllegalArgumentException("ttlSec");
            }
            this.ttlSec = ttlSec;
            return this;
        }

        public Builder maxLen(int maxLen) {
            if (maxLen < 0) {
                throw new IllegalArgumentException("maxLen");
            }
            this.maxLen = maxLen;
            return this;
        }

        public SessionOptions build() {
            return new SessionOptions(this);
        }
    }
}
