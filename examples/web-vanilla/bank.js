// Page logic shared by the web banking page and the app screen: the transfer form, the two secure inputs
// (withdrawal password on the number pad, certificate password on the full keyboard) and the demo settings
// panel. Only the SkpDemo calls touch the keypad SDK.
(function () {
  const PIN_LEN = 4;

  async function start(opts = {}) {
    const qs = SkpDemo.qs;
    const $ = (id) => document.getElementById(id);
    const status = $("status");
    const result = $("result");
    const hint = $("hint");
    const amount = $("amount");
    const layoutSel = $("layout");
    const styleSel = $("style");
    const langsSel = $("langs");
    let settings = null;

    const won = (n) => n.toLocaleString("ko-KR");
    const parseWon = (v) => Number(String(v).replace(/[^0-9]/g, "")) || 0;
    amount.addEventListener("input", () => {
      const n = parseWon(amount.value);
      amount.value = n ? won(n) : "";
    });

    const demo = await SkpDemo.setup({
      pinEl: $("pin"),
      passwordEl: $("password"),
      pinMaxLen: PIN_LEN,
      passwordMaxLen: 32,
      layout: () => layoutSel.value,
      style: opts.style || (styleSel ? styleSel.value : "auto"),
      theme: opts.theme,
      languages: langsSel.value,
      popups: opts.popups,
      safeAreaBottom: opts.safeAreaBottom || 0,
      doneLabel: "확인",
      onStatus: (m) => (status.textContent = m),
      onChange: (name, length) => {
        // the withdrawal password is exactly four digits: move on to the certificate password by itself
        if (name === "pin" && length >= PIN_LEN) {
          hint.textContent = "인증서 비밀번호를 입력하세요.";
          setTimeout(() => $("password").focus(), 120);
        }
      },
      onLang: (code) => settings && settings.setLanguage(code),
    });

    settings = SkpSettings.wire({
      demo,
      layout: layoutSel,
      style: styleSel,
      langs: langsSel,
      status: "settings-status",
      onApply: () => SkpDemo.renderResult(result, null),
    });
    settings.describe();

    // E2E hooks: rects and roles only, never characters
    window.__skp = { pin: demo.pin, password: demo.password, layouts: demo.layouts, ctx: demo.ctx, demo };

    $("login").addEventListener("submit", async (e) => {
      e.preventDefault();
      status.textContent = "";
      try {
        const json = await demo.login();
        window.__skp.lastLogin = json;
        SkpDemo.renderResult(result, json, { amount: amount.value, payee: "츄르마켓 3333-01-1234567" });
        if (opts.postToParent) parent.postMessage({ type: "skp-login", json }, "*");
        hint.textContent = "새 세션이 준비됐습니다. 다시 입력해 보세요.";
      } catch (err) {
        status.textContent = err.message;
      }
    });

    void qs;
    return demo;
  }

  window.SkpBank = { start, PIN_LEN };
})();
