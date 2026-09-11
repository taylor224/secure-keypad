// Shared wiring for the playground pages: creates the two keypads, submits to /login, reports results.
// Everything here is demo plumbing; the only SDK calls are createSecureKeypad / attach / submit / reset / destroy.
(function () {
  const qs = new URLSearchParams(location.search);
  const base = window.SKP_API_BASE || "";
  const api = (path) => base + path;
  const LANGUAGE_NAMES = { en: "English", ko: "한국어" };

  function showBanner(message) {
    // inside a device frame the host page shows the notice next to the phone instead of over the screen
    if (qs.get("embedded") === "1" && window.parent !== window) {
      window.parent.postMessage({ type: "skp-banner", message }, "*");
      return;
    }
    // in normal flow at the very top: a fixed overlay used to cover the sticky navigation underneath it
    let el = document.getElementById("backend-banner");
    if (!el) {
      el = document.createElement("div");
      el.id = "backend-banner";
      el.setAttribute("role", "alert");
      el.style.cssText =
        "position:relative;z-index:2147483001;background:#fff3d1;color:#5a3d00;padding:12px 44px 12px 16px;" +
        "font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;border-bottom:1px solid #e6c860;white-space:pre-wrap";
      const text = document.createElement("span");
      text.id = "backend-banner-text";
      const close = document.createElement("button");
      close.type = "button";
      close.textContent = "×";
      close.setAttribute("aria-label", "안내 닫기");
      close.style.cssText =
        "position:absolute;top:6px;right:8px;width:28px;height:28px;border:0;border-radius:6px;background:transparent;" +
        "color:inherit;font:20px/1 system-ui,sans-serif;cursor:pointer";
      close.addEventListener("click", () => el.remove());
      el.append(text, close);
      document.body.prepend(el);
    }
    el.querySelector("#backend-banner-text").textContent = message;
  }

  let fetchImpl = (...a) => fetch(...a);
  let wasmServer = null;
  let backend = null; // { publicKey, kid } once resolved

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

  /** Finds a backend once: the configured/same-origin server, else the in-page WebAssembly server. */
  async function resolveBackend() {
    if (backend) return backend;
    const wantWasm = qs.get("mode") === "wasm";
    try {
      if (wantWasm) throw new Error("wasm mode requested");
      const res = await fetch(api("/keypad/public-key"));
      if (!res.ok) throw new Error("HTTP " + res.status);
      backend = await res.json();
    } catch (e) {
      try {
        await startWasmServer();
        backend = await (await fetchImpl("/keypad/public-key")).json();
      } catch (e2) {
        showBanner(
          "백엔드에 연결할 수 없고 내장 WebAssembly 서버도 불러오지 못했습니다 (" + (base || location.origin) + ").\n" +
            "로컬에서 `cd examples/server-node && npm run demo` 를 실행한 뒤 이 주소 뒤에 ?api=http://localhost:3789 를 붙여 여세요. " +
            "호스팅한 백엔드가 있으면 그 주소를 ?api= 로 지정하면 기억됩니다. (" + e2.message + ")",
        );
        throw e2;
      }
    }
    return backend;
  }

  /** "en,ko" | ["en","ko"] → ["en","ko"]; empty → undefined (the server decides: en + ko). */
  function parseLangs(value) {
    if (Array.isArray(value)) return value.length ? value : undefined;
    if (typeof value !== "string" || !value.trim()) return undefined;
    return value.split(",").map((s) => s.trim()).filter(Boolean);
  }

  function languageLabel(codes) {
    return (codes || ["en", "ko"]).map((c) => LANGUAGE_NAMES[c] || c).join(" · ");
  }

  /**
   * Creates the PIN and password keypads. Options: pinEl, passwordEl, layout (value or function), style, theme,
   * languages ("ko,en" or array), popups, safeAreaBottom, doneLabel, mount, onStatus, onLang(code).
   * The returned object can `apply({ layout, style, languages })` to rebuild the keypads without reloading.
   */
  /** Height of the open keypad sheet, read from the client's open shadow root (0 when none is open). */
  function openSheetHeight() {
    for (const host of document.querySelectorAll(".skp-host")) {
      const sheet = host.shadowRoot && host.shadowRoot.querySelector(".sheet.open");
      if (sheet) return Math.round(sheet.getBoundingClientRect().height);
    }
    return 0;
  }

  /**
   * Keeps the page usable while a keypad covers the bottom of the screen: reserve the sheet's height at the
   * end of the document (like a native keyboard does) and scroll the field being typed into view.
   */
  function reserveSpaceFor(input) {
    const scroller = document.querySelector(".scroll") || document.body;
    const reserve = () => {
      const h = openSheetHeight();
      scroller.style.paddingBottom = h ? h + 24 + "px" : "";
      return h;
    };
    // Scroll once, when the keypad opens, and only if the sheet actually covers the field. Instantly and
    // never again while it is open: any later movement would shift the keys under the finger.
    const h = reserve();
    if (h && input) {
      const rect = input.getBoundingClientRect();
      const limit = window.innerHeight - h - 12;
      if (rect.bottom > limit) window.scrollBy({ top: Math.ceil(rect.bottom - limit + 16), behavior: "auto" });
    }
    setTimeout(reserve, 280); // the sheet slides in over 240ms; only the reserved height is refreshed
  }

  function releaseSpace() {
    const scroller = document.querySelector(".scroll") || document.body;
    if (!openSheetHeight()) scroller.style.paddingBottom = "";
  }

  async function setup(o) {
    const { publicKey, kid } = await resolveBackend();
    const ctx = "demo-" + Math.random().toString(36).slice(2, 10);
    const settings = {
      layout: typeof o.layout === "function" ? o.layout() : o.layout || qs.get("layout") || "shuffle",
      style: o.style || qs.get("style") || "auto",
      languages: parseLangs(o.languages !== undefined ? o.languages : qs.get("langs")),
    };
    const layouts = {};
    const demo = { pin: null, password: null, ctx, kid, layouts, wasm: !!wasmServer, settings };

    function build() {
      const common = {
        sessionUrl: api("/keypad/session"),
        relayoutUrl: api("/keypad/relayout"),
        serverPublicKey: publicKey,
        headers: () => ({ "x-login-ctx": ctx, "x-keypad-layout": settings.layout }),
        credentials: "omit",
        fetch: (...a) => fetchImpl(...a),
        style: settings.style,
        theme: o.theme || qs.get("theme") || "auto",
        popups: o.popups ?? "auto",
        safeAreaBottom: o.safeAreaBottom || 0,
        doneLabel: o.doneLabel || "Done",
        desktopWidth: o.desktopWidth ?? 480, // the app column is 480px wide (bank.css --max-w)
        mount: o.mount,
      };
      const pin = SecureKeypad.createSecureKeypad({ ...common, type: "number", maxLen: o.pinMaxLen ?? 6 });
      const password = SecureKeypad.createSecureKeypad({ ...common, type: "qwerty", maxLen: o.passwordMaxLen ?? 32, languages: settings.languages });
      demo.pin = pin;
      demo.password = password;
      delete layouts.pin;
      delete layouts.password;
      pin.on("ready", ({ layout }) => (layouts.pin = layout));
      password.on("ready", ({ layout }) => (layouts.password = layout));
      password.on("lang", ({ lang }) => o.onLang?.(lang));
      for (const [name, kp] of [["pin", pin], ["password", password]]) {
        kp.on("error", ({ error }) => o.onStatus?.(name + ": " + error.message));
        kp.on("expire", () => o.onStatus?.(name + ": 세션 만료 — 다시 입력하세요"));
        kp.on("open", () => reserveSpaceFor(name === "pin" ? o.pinEl : o.passwordEl));
        kp.on("close", () => setTimeout(releaseSpace, 300));
        kp.on("submit", () => setTimeout(releaseSpace, 300));
        kp.on("change", ({ length }) => o.onChange?.(name, length));
        kp.on("done", () => o.onDone?.(name, kp.length));
        kp.on("ready", () => o.onReady?.(name, kp));
      }
      pin.attach(o.pinEl);
      password.attach(o.passwordEl);
    }
    build();

    async function login() {
      const body = {};
      if (demo.pin.length) body.pin_enc = JSON.parse(demo.pin.submit());
      if (demo.password.length) body.password_enc = JSON.parse(demo.password.submit());
      const res = await fetchImpl(api("/login"), {
        method: "POST",
        headers: { "content-type": "application/json", "x-login-ctx": ctx },
        body: JSON.stringify(body),
      });
      const json = await res.json();
      demo.pin.reset();
      demo.password.reset();
      return json;
    }

    /** Rebuilds both keypads with new settings (style, languages need new instances; layout needs new sessions). */
    async function apply(next) {
      const wasOpen = demo.password.isOpen ? "password" : demo.pin.isOpen ? "pin" : null;
      if (next.layout) settings.layout = next.layout;
      if (next.style) settings.style = next.style;
      if (next.languages !== undefined) settings.languages = parseLangs(next.languages);
      demo.pin.destroy();
      demo.password.destroy();
      build();
      window.__skp = Object.assign(window.__skp || {}, { pin: demo.pin, password: demo.password, layouts, ctx });
      // show the result right away: reopen the keypad that was open (or the password keypad on desktop)
      const target = wasOpen || (matchMedia("(pointer: fine)").matches ? "password" : null);
      if (target) await demo[target].open();
      return settings;
    }

    Object.assign(demo, {
      login,
      apply,
      reset: () => (demo.pin.reset(), demo.password.reset()),
      describe: () => {
        const auto = /iPhone|iPad|iPod|Macintosh/.test(navigator.userAgent) ? "iOS" : "Material";
        const style = settings.style === "auto" ? `auto → ${auto}` : settings.style === "ios" ? "iOS" : "Material";
        return `배열 ${settings.layout} · 스타일 ${style} · 언어 ${languageLabel(settings.languages)}`;
      },
    });
    return demo;
  }

  /**
   * Renders the /login result as a transfer receipt: what the server decrypted from the tap coordinates.
   * Values appear only when the example server runs in demo-echo mode; a real bank never returns them.
   */
  function renderResult(el, json, extra) {
    if (!json) {
      el.innerHTML = "";
      return;
    }
    if (json.error) {
      const reason = json.error === "SESSION_NOT_FOUND" ? "세션이 이미 사용되었거나 만료되었습니다" : "서버가 요청을 거부했습니다";
      el.innerHTML = `<div class="receipt err"><div class="rt">이체 실패</div><div class="row"><span>사유</span><span>${reason} <code>${escapeHtml(json.error)}</code></span></div></div>`;
      return;
    }
    const rows = [];
    if (extra && extra.payee) rows.push(["받는 분", escapeHtml(extra.payee)]);
    if (extra && extra.amount) rows.push(["보낸 금액", escapeHtml(extra.amount) + "원"]);
    const secret = (label, len, value) =>
      rows.push([label, len === undefined ? "입력 없음" : `${len}자 · ` + (value !== undefined ? `<code>${escapeHtml(value)}</code>` : "값은 서버만 압니다")]);
    secret("출금 비밀번호", json.pinLength, json.pin);
    secret("인증서 비밀번호", json.passwordLength, json.password);
    if (json.pinLength === undefined && json.passwordLength === undefined) {
      el.innerHTML = `<div class="receipt err"><div class="rt">이체 실패</div><div class="row"><span>사유</span><span>입력된 비밀번호가 없습니다</span></div></div>`;
      return;
    }
    rows.push(["거래번호", "CDL" + Date.now().toString().slice(-9)]);
    el.innerHTML =
      `<div class="receipt${json.ok ? "" : " err"}">` +
      `<div class="rt">${json.ok ? "이체 완료 ✓" : "이체 실패"}</div>` +
      rows.map(([k, v]) => `<div class="row"><span>${k}</span><span>${v}</span></div>`).join("") +
      (json.demoEcho
        ? `<div class="note">데모 모드라서 서버가 복원한 값을 그대로 보여줍니다. 실제 서비스는 값을 화면으로 돌려주지 않습니다. 한글은 서버가 자모를 음절로 조합한 결과입니다.</div>`
        : "") +
      `</div>`;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  }

  window.SkpDemo = { setup, renderResult, qs, api, parseLangs, languageLabel, LANGUAGE_NAMES };
})();
