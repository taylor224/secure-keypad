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
 *   <li>{@code languages}: languages of the QWERTY keypad in switch order ({@code "en"} Latin,
 *       {@code "ko"} Korean 2-set, composed server-side), e.g. {@code ["en", "ko"]} or {@code ["ko"]}.
 *       Unset: the client's request ({@code opts.langs}) is honoured, else English + Korean. Ignored for
 *       number pads.</li>
 * </ul>
 */
public final class SessionOptions {
    public static final SessionOptions DEFAULT = builder().build();

    private final String ctx;
    private final String layout;
    private final String blank;
    private final int ttlSec;
    private final int maxLen;
    private final String languages;

    private SessionOptions(Builder b) {
        this.ctx = b.ctx;
        this.layout = b.layout;
        this.blank = b.blank;
        this.ttlSec = b.ttlSec;
        this.maxLen = b.maxLen;
        this.languages = b.languages;
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

    /** Comma-separated language codes, or {@code null} when unset. */
    public String languages() {
        return languages;
    }

    public static final class Builder {
        private String ctx;
        private String layout;
        private String blank;
        private int ttlSec;
        private int maxLen;
        private String languages;

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

        /** Languages in switch order, e.g. {@code languages("en", "ko")} or {@code languages("ko")}. */
        public Builder languages(String... codes) {
            this.languages = codes == null || codes.length == 0 ? null : String.join(",", codes);
            return this;
        }

        public Builder languages(java.util.List<String> codes) {
            this.languages = codes == null || codes.isEmpty() ? null : String.join(",", codes);
            return this;
        }

        public SessionOptions build() {
            return new SessionOptions(this);
        }
    }
}
