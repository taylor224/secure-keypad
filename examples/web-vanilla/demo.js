// Shared wiring for the playground pages: creates the two keypads, submits to /login, reports results.
// Everything here is demo plumbing; the only SDK calls are createSecureKeypad / attach / submit / reset.
(function () {
  const qs = new URLSearchParams(location.search);

  async function setup(o) {
    const { publicKey, kid } = await (await fetch("/keypad/public-key")).json();
    const ctx = "demo-" + Math.random().toString(36).slice(2, 10);
    const getLayout = () => (typeof o.layout === "function" ? o.layout() : o.layout || qs.get("layout") || "shuffle");
    const common = {
      sessionUrl: "/keypad/session",
      relayoutUrl: "/keypad/relayout",
      serverPublicKey: publicKey,
      headers: () => ({ "x-login-ctx": ctx, "x-keypad-layout": getLayout() }),
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
      const res = await fetch("/login", {
        method: "POST",
        headers: { "content-type": "application/json", "x-login-ctx": ctx },
        body: JSON.stringify(body),
      });
      const json = await res.json();
      pin.reset();
      password.reset();
      return json;
    }

    return { pin, password, login, ctx, kid, layouts, reset: () => (pin.reset(), password.reset()) };
  }

  /** Renders the /login result into a container: lengths always, values only when the server is in demo-echo mode. */
  function renderResult(el, json) {
    if (!json) {
      el.innerHTML = "";
      return;
    }
    if (json.error) {
      el.innerHTML = `<div class="res err">서버 거부: <code>${json.error}</code></div>`;
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

  window.SkpDemo = { setup, renderResult, qs };
})();
