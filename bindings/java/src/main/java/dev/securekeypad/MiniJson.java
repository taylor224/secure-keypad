package dev.securekeypad;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON reader (RFC 8259) used to pick the session id out of client messages without pulling in a
 * dependency. Objects become {@link LinkedHashMap}, arrays {@link ArrayList}, numbers {@link Long} when
 * integral else {@link Double}, plus {@link String}, {@link Boolean}, and {@code null}.
 */
final class MiniJson {
    private final String s;
    private int i;

    private MiniJson(String s) {
        this.s = s;
    }

    static Object parse(String text) {
        MiniJson p = new MiniJson(text);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != p.s.length()) {
            throw p.err("trailing characters");
        }
        return v;
    }

    /** Returns the top-level string field {@code key}, or {@code null} when absent or not a string. */
    static String topLevelString(String json, String key) {
        Object o;
        try {
            o = parse(json);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (!(o instanceof Map)) {
            return null;
        }
        Object v = ((Map<?, ?>) o).get(key);
        return v instanceof String ? (String) v : null;
    }

    private IllegalArgumentException err(String what) {
        return new IllegalArgumentException("invalid JSON (" + what + ") at " + i);
    }

    private void ws() {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                i++;
            } else {
                break;
            }
        }
    }

    private Object value() {
        if (i >= s.length()) {
            throw err("unexpected end");
        }
        char c = s.charAt(i);
        switch (c) {
            case '{':
                return object();
            case '[':
                return array();
            case '"':
                return string();
            case 't':
                expect("true");
                return Boolean.TRUE;
            case 'f':
                expect("false");
                return Boolean.FALSE;
            case 'n':
                expect("null");
                return null;
            default:
                if (c == '-' || (c >= '0' && c <= '9')) {
                    return number();
                }
                throw err("unexpected character");
        }
    }

    private void expect(String lit) {
        if (!s.startsWith(lit, i)) {
            throw err("expected " + lit);
        }
        i += lit.length();
    }

    private Map<String, Object> object() {
        Map<String, Object> m = new LinkedHashMap<>();
        i++;
        ws();
        if (i < s.length() && s.charAt(i) == '}') {
            i++;
            return m;
        }
        for (;;) {
            ws();
            if (i >= s.length() || s.charAt(i) != '"') {
                throw err("expected key");
            }
            String k = string();
            ws();
            if (i >= s.length() || s.charAt(i) != ':') {
                throw err("expected ':'");
            }
            i++;
            ws();
            m.put(k, value());
            ws();
            if (i >= s.length()) {
                throw err("unterminated object");
            }
            char c = s.charAt(i++);
            if (c == '}') {
                return m;
            }
            if (c != ',') {
                throw err("expected ',' or '}'");
            }
        }
    }

    private List<Object> array() {
        List<Object> l = new ArrayList<>();
        i++;
        ws();
        if (i < s.length() && s.charAt(i) == ']') {
            i++;
            return l;
        }
        for (;;) {
            ws();
            l.add(value());
            ws();
            if (i >= s.length()) {
                throw err("unterminated array");
            }
            char c = s.charAt(i++);
            if (c == ']') {
                return l;
            }
            if (c != ',') {
                throw err("expected ',' or ']'");
            }
        }
    }

    private String string() {
        i++;
        StringBuilder sb = new StringBuilder();
        for (;;) {
            if (i >= s.length()) {
                throw err("unterminated string");
            }
            char c = s.charAt(i++);
            if (c == '"') {
                return sb.toString();
            }
            if (c == '\\') {
                if (i >= s.length()) {
                    throw err("bad escape");
                }
                char e = s.charAt(i++);
                switch (e) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u':
                        if (i + 4 > s.length()) {
                            throw err("bad unicode escape");
                        }
                        sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                        break;
                    default:
                        throw err("bad escape");
                }
            } else if (c < 0x20) {
                throw err("control character in string");
            } else {
                sb.append(c);
            }
        }
    }

    private Object number() {
        int start = i;
        if (s.charAt(i) == '-') {
            i++;
        }
        boolean integral = true;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c >= '0' && c <= '9') {
                i++;
            } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                integral = false;
                i++;
            } else {
                break;
            }
        }
        String t = s.substring(start, i);
        try {
            if (integral) {
                return Long.parseLong(t);
            }
            return Double.parseDouble(t);
        } catch (NumberFormatException e) {
            throw err("bad number");
        }
    }
}
