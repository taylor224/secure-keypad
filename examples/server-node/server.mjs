// Express example: keypad routes + a login route + the static web demo.
//
//   SKP_MASTER_KEY_PATH=/etc/skp/master.key node server.mjs      (or SKP_MASTER_KEY=<base64|hex>)
//   without either, a throw-away key is generated for development.
//
// Dev/test switches (never enable in production):
//   SKP_CORS_ORIGIN=https://x   allow a statically hosted playground (GitHub Pages) to call this server
//   SKP_ALLOW_CLIENT_LAYOUT=1   honour the X-Keypad-Layout header (demo picker)
//   SKP_DEMO_ECHO=1             /login echoes the decrypted value (playground result panel, E2E asserts)
import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SecureKeypadServer, SkpError, keygen } from "@secure-keypad/server";

const here = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.PORT || 3789);
const masterKeyPath = process.env.SKP_MASTER_KEY_PATH;
const masterKey = masterKeyPath ? undefined : process.env.SKP_MASTER_KEY || keygen();
if (!masterKeyPath && !process.env.SKP_MASTER_KEY) console.warn("[example] no master key configured: using a throw-away key for this process");

const skp = new SecureKeypadServer({ masterKeyPath, masterKey });
const allowClientLayout = process.env.SKP_ALLOW_CLIENT_LAYOUT === "1";
const echo = process.env.SKP_DEMO_ECHO === "1";
const app = express();
app.use(express.json({ limit: "64kb" }));

// CORS for a statically hosted playground (GitHub Pages). SKP_CORS_ORIGIN: comma-separated origins or "*".
const corsOrigins = (process.env.SKP_CORS_ORIGIN || "").split(",").map((s) => s.trim()).filter(Boolean);
if (corsOrigins.length) {
  app.use((req, res, next) => {
    const origin = req.get("origin");
    if (origin && (corsOrigins.includes("*") || corsOrigins.includes(origin))) {
      res.set("access-control-allow-origin", origin);
      res.set("vary", "origin");
      res.set("access-control-allow-headers", "content-type, x-login-ctx, x-keypad-layout");
      res.set("access-control-allow-methods", "GET, POST, OPTIONS");
      res.set("access-control-max-age", "600");
      // Chrome's private-network-access preflight when a public site calls a local backend
      if (req.get("access-control-request-private-network") === "true") res.set("access-control-allow-private-network", "true");
    }
    if (req.method === "OPTIONS") return res.sendStatus(204);
    next();
  });
}

// The binding context ties a session to this login attempt: the same value must be presented at decrypt.
const ctxOf = (req) => String(req.get("x-login-ctx") || "demo");

function fail(res, e) {
  if (e instanceof SkpError) {
    const status = e.kind === "SESSION_NOT_FOUND" ? 410 : e.kind === "BAD_REQUEST" || e.kind === "UNSUPPORTED" ? 400 : 403;
    return res.status(status).json({ error: e.kind });
  }
  console.error(e);
  return res.status(500).json({ error: "internal" });
}

app.get("/keypad/public-key", (_req, res) => res.json({ publicKey: skp.publicKey, kid: skp.keyId }));

app.post("/keypad/session", async (req, res) => {
  try {
    const layout = allowClientLayout ? req.get("x-keypad-layout") || undefined : undefined;
    res.json(await skp.createSession(req.body, { ctx: ctxOf(req), layout }));
  } catch (e) {
    fail(res, e);
  }
});

app.post("/keypad/relayout", async (req, res) => {
  try {
    res.json(await skp.relayout(req.body));
  } catch (e) {
    fail(res, e);
  }
});

// A login: decrypt the keypad payloads, use the values, wipe them. Values are never logged or returned.
app.post("/login", async (req, res) => {
  const out = { ok: false };
  const secrets = [];
  try {
    for (const field of ["pin", "password"]) {
      const payload = req.body?.[`${field}_enc`];
      if (!payload) continue;
      const secret = await skp.decrypt(payload, { ctx: ctxOf(req) });
      secrets.push(secret);
      out[`${field}Length`] = secret.length;
      if (echo) out[field] = secret.toString(); // demo/test only: a real service never returns the value
    }
    // A real app would verify the credential here (constant-time compare / password hash).
    out.ok = secrets.length > 0 && secrets.every((s) => s.length > 0);
    if (echo) out.demoEcho = true;
    res.json(out);
  } catch (e) {
    fail(res, e);
  } finally {
    secrets.forEach((s) => s.wipe());
  }
});

app.use("/dist", express.static(path.join(here, "..", "..", "clients", "web", "dist")));
app.use(express.static(path.join(here, "..", "web-vanilla")));

app.listen(port, () => console.log(`secure-keypad example on http://localhost:${port}  (kid ${skp.keyId})`));
