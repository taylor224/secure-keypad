package dev.securekeypad.example;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import dev.securekeypad.Secret;
import dev.securekeypad.SecureKeypadServer;
import dev.securekeypad.SessionOptions;
import dev.securekeypad.SkpException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.concurrent.Executors;

/**
 * Dependency-free example integration.
 *
 * <pre>
 * POST /keypad/session   body: client request JSON        → session response JSON
 * POST /keypad/relayout  body: client relayout JSON       → relayout response JSON
 * POST /login            body: client payload {v,sid,ct}  → {"ok":true,"length":N}
 * </pre>
 *
 * The binding context is taken from the {@code X-Login-Ctx} header (a real application binds the keypad
 * session to its own login attempt or user session). The value itself is never echoed or logged.
 */
public final class ExampleServer {
    private static final int MAX_BODY = 1 << 20;

    interface Handler {
        String handle(HttpExchange ex, String body);
    }

    public static void main(String[] args) throws Exception {
        SecureKeypadServer skp = buildServer();
        int port = Integer.parseInt(env("PORT", "8080"));
        String layout = env("SKP_LAYOUT", "shuffle");
        HttpServer http = HttpServer.create(new InetSocketAddress(port), 0);
        http.createContext("/keypad/session", ex -> serve(ex, (e, body) ->
                skp.createSession(body, SessionOptions.builder().ctx(ctxOf(e)).layout(layout).build())));
        http.createContext("/keypad/relayout", ex -> serve(ex, (e, body) -> skp.relayout(body)));
        http.createContext("/login", ex -> serve(ex, (e, body) -> {
            try (Secret secret = skp.decrypt(body, ctxOf(e))) {
                char[] value = secret.chars();
                try {
                    // a real application verifies the password here and never keeps it
                    return "{\"ok\":true,\"length\":" + value.length + "}";
                } finally {
                    Arrays.fill(value, '\0');
                }
            }
        }));
        http.setExecutor(Executors.newFixedThreadPool(4));
        http.start();
        System.out.println("secure-keypad example server on http://localhost:" + port);
        System.out.println("public_key=" + skp.publicKey());
        System.out.println("kid=" + skp.keyId());
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            http.stop(0);
            skp.close();
        }));
    }

    private static SecureKeypadServer buildServer() {
        SecureKeypadServer.Builder b = SecureKeypadServer.builder();
        String path = System.getenv("SKP_MASTER_KEY_PATH");
        String key = System.getenv("SKP_MASTER_KEY");
        if (path != null && !path.isEmpty()) {
            b.masterKeyPath(Paths.get(path));
        } else if (key != null && !key.isEmpty()) {
            b.masterKey(key);
        } else {
            System.err.println("warning: no SKP_MASTER_KEY_PATH / SKP_MASTER_KEY set; using a throw-away key (development only)");
            b.masterKey(SecureKeypadServer.keygen());
        }
        return b.build();
    }

    private static String ctxOf(HttpExchange ex) {
        String c = ex.getRequestHeaders().getFirst("X-Login-Ctx");
        return c == null || c.isEmpty() ? "demo" : c;
    }

    private static void serve(HttpExchange ex, Handler h) throws IOException {
        try {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                reply(ex, 405, "{\"error\":\"METHOD_NOT_ALLOWED\"}");
                return;
            }
            String body = readBody(ex.getRequestBody());
            String out;
            try {
                out = h.handle(ex, body);
            } catch (SkpException e) {
                int status;
                switch (e.kind()) {
                    case BAD_REQUEST:
                    case UNSUPPORTED:
                        status = 400;
                        break;
                    case EXPIRED:
                    case SESSION_NOT_FOUND:
                        status = 410;
                        break;
                    case BAD_MAC:
                    case TAMPERED:
                    case CTX_MISMATCH:
                    case SID_MISMATCH:
                        status = 403;
                        break;
                    default:
                        status = 500;
                }
                reply(ex, status, "{\"error\":\"" + e.kind().name() + "\"}");
                return;
            }
            reply(ex, 200, out);
        } catch (RuntimeException e) {
            reply(ex, 500, "{\"error\":\"INTERNAL\"}");
        } finally {
            ex.close();
        }
    }

    private static String readBody(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int n;
        while ((n = in.read(chunk)) > 0) {
            if (buf.size() + n > MAX_BODY) {
                throw new IOException("body too large");
            }
            buf.write(chunk, 0, n);
        }
        return new String(buf.toByteArray(), StandardCharsets.UTF_8);
    }

    private static void reply(HttpExchange ex, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String env(String name, String def) {
        String v = System.getenv(name);
        return v == null || v.isEmpty() ? def : v;
    }
}
