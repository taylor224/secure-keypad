// Shared wiring for the playground pages: creates the two keypads, submits to /login, reports results.
// Everything here is demo plumbing; the only SDK calls are createSecureKeypad / attach / submit / reset.
(function () {
  const qs = new URLSearchParams(location.search);
  const base = window.SKP_API_BASE || "";
  const api = (path) => base + path;

  function showBanner(message) {
    // inside a device frame the host page shows the notice next to the phone instead of over the screen
    if (qs.get("embedded") === "1" && window.parent !== window) {
      window.parent.postMessage({ type: "skp-banner", message }, "*");
      return;
    }
    let el = document.getElementById("backend-banner");
    if (!el) {
      el = document.createElement("div");
      el.id = "backend-banner";
      el.setAttribute("role", "alert");
      el.style.cssText = "position:fixed;left:0;right:0;top:0;z-index:2147483001;background:#fff3d1;color:#5a3d00;padding:12px 16px;font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;border-bottom:1px solid #e6c860;white-space:pre-wrap";
      document.body.prepend(el);
    }
    el.textContent = message;
  }

  let fetchImpl = (...a) => fetch(...a);
  let wasmServer = null;

  /** Loads the WebAssembly build of the server SDK and serves the routes inside this page. */
  async function startWasmServer() {
    const load = (src) =>
      new Promise((resolve, reject) => {
        const s = document.createElement("script");
        s.src = src;
        s.onload = resolve;
        s.onerror = () => reject(new Error("cannot load " + src));
        document.head.appendChild(s);
      });
    if (typeof SkpWasmServer === "undefined") await load("dist/skp-wasm-server.js");
    const moduleUrl = new URL("dist/skp.js", location.href).toString();
    wasmServer = await SkpWasmServer.create({ moduleUrl });
    fetchImpl = wasmServer.makeFetch({ echo: true, allowClientLayout: true });
    window.__skpWasm = wasmServer;
    showBanner(
      "브라우저 내장 서버(WebAssembly)로 동작 중 — 같은 C 코어가 이 페이지 안에서 세션을 만들고 복호화합니다. " +
        "UI와 프로토콜 데모용입니다. 실제 서비스에서는 서버 SDK가 서버에서 실행되어야 브라우저가 입력값을 알 수 없습니다.",
    );
  }

  async function setup(o) {
    let publicKey, kid;
    const wantWasm = qs.get("mode") === "wasm";
    try {
      if (wantWasm) throw new Error("wasm mode requested");
      const res = await fetch(api("/keypad/public-key"));
      if (!res.ok) throw new Error("HTTP " + res.status);
      ({ publicKey, kid } = await res.json());
    } catch (e) {
      try {
        await startWasmServer();
        ({ publicKey, kid } = await (await fetchImpl("/keypad/public-key")).json());
      } catch (e2) {
        showBanner(
          "백엔드에 연결할 수 없고 내장 WebAssembly 서버도 불러오지 못했습니다 (" + (base || location.origin) + ").\n" +
            "로컬에서 `cd examples/server-node && npm run demo` 를 실행한 뒤 이 주소 뒤에 ?api=http://localhost:3789 를 붙여 여세요. " +
            "호스팅한 백엔드가 있으면 그 주소를 ?api= 로 지정하면 기억됩니다. (" + e2.message + ")",
        );
        throw e2;
      }
    }
    const ctx = "demo-" + Math.random().toString(36).slice(2, 10);
    const getLayout = () => (typeof o.layout === "function" ? o.layout() : o.layout || qs.get("layout") || "shuffle");
    const common = {
      sessionUrl: api("/keypad/session"),
      relayoutUrl: api("/keypad/relayout"),
      serverPublicKey: publicKey,
      headers: () => ({ "x-login-ctx": ctx, "x-keypad-layout": getLayout() }),
      credentials: "omit",
      fetch: (...a) => fetchImpl(...a),
      style: o.style || qs.get("style") || "auto",
      theme: o.theme || qs.get("theme") || "auto",
      popups: o.popups ?? "auto",
      safeAreaBottom: o.safeAreaBottom || 0,
      doneLabel: o.doneLabel || "Done",
      mount: o.mount,
    };
    const pin = SecureKeypad.createSecureKeypad({ ...common, type: "number", maxLen: 6 });
    const password = SecureKeypad.createSecureKeypad({ ...common, type: "qwerty", maxLen: 32 });
    pin.attach(o.pinEl);
    password.attach(o.passwordEl);
    const layouts = {};
    pin.on("ready", ({ layout }) => (layouts.pin = layout));
    password.on("ready", ({ layout }) => (layouts.password = layout));
    for (const [name, kp] of [["pin", pin], ["password", password]]) {
      kp.on("error", ({ error }) => o.onStatus?.(name + ": " + error.message));
      kp.on("expire", () => o.onStatus?.(name + ": 세션 만료 — 다시 입력하세요"));
    }

    async function login() {
      const body = {};
      if (pin.length) body.pin_enc = JSON.parse(pin.submit());
      if (password.length) body.password_enc = JSON.parse(password.submit());
      const res = await fetchImpl(api("/login"), {
        method: "POST",
        headers: { "content-type": "application/json", "x-login-ctx": ctx },
        body: JSON.stringify(body),
      });
      const json = await res.json();
      pin.reset();
      password.reset();
      return json;
    }

    return { pin, password, login, ctx, kid, layouts, wasm: !!wasmServer, reset: () => (pin.reset(), password.reset()) };
  }

  /** Renders the /login result into a container: lengths always, values only when the server is in demo-echo mode. */
  function renderResult(el, json) {
    if (!json) {
      el.innerHTML = "";
      return;
    }
    if (json.error) {
      el.innerHTML = `<div class="res err">서버 거부: <code>${escapeHtml(json.error)}</code></div>`;
      return;
    }
    const rows = [];
    if (json.pinLength !== undefined) rows.push(["PIN", json.pinLength, json.pin]);
    if (json.passwordLength !== undefined) rows.push(["비밀번호", json.passwordLength, json.password]);
    if (!rows.length) {
      el.innerHTML = `<div class="res err">입력된 값이 없습니다</div>`;
      return;
    }
    el.innerHTML =
      `<div class="res ${json.ok ? "ok" : "err"}">` +
      `<div class="res-title">서버 복호화 결과 ${json.ok ? "✓" : "✗"}</div>` +
      rows
        .map(
          ([label, len, value]) =>
            `<div class="res-row"><span>${label}</span><span>${len}자</span>` +
            (value !== undefined ? `<code class="res-value">${escapeHtml(value)}</code>` : `<span class="res-hidden">값은 서버만 압니다</span>`) +
            `</div>`,
        )
        .join("") +
      (json.demoEcho ? `<div class="res-note">데모 모드: 서버가 복호화한 값을 표시합니다. 실제 서비스는 값을 절대 돌려주지 않습니다.</div>` : "") +
      `</div>`;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  }

  window.SkpDemo = { setup, renderResult, qs, api };
})();
