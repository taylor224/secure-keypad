// Device-frame playground: builds the iframe URL from the controls and relays login results.
(function () {
  const device = document.documentElement.dataset.device; // "ios" | "android"
  const frame = document.getElementById("screen");
  const layout = document.getElementById("layout");
  const theme = document.getElementById("theme");
  const langs = document.getElementById("langs");
  const result = document.getElementById("result");
  const clock = document.querySelectorAll(".clock");
  const qs = new URLSearchParams(location.search);
  if (qs.get("layout")) layout.value = qs.get("layout");
  if (qs.get("theme")) theme.value = qs.get("theme");
  if (langs && qs.get("langs") && [...langs.options].some((o) => o.value === qs.get("langs"))) langs.value = qs.get("langs");

  function load() {
    const u = new URL("app.html", location.href);
    if (window.SKP_API_BASE) u.searchParams.set("api", window.SKP_API_BASE);
    if (qs.get("mode")) u.searchParams.set("mode", qs.get("mode"));
    u.searchParams.set("embedded", "1");
    u.searchParams.set("device", device);
    u.searchParams.set("theme", theme.value);
    u.searchParams.set("layout", layout.value);
    if (langs) u.searchParams.set("langs", langs.value);
    u.searchParams.set("statusH", device === "ios" ? "54" : "32");
    u.searchParams.set("safeBottom", device === "ios" ? "34" : "24");
    frame.src = u.toString();
    document.body.dataset.theme = theme.value;
    result.innerHTML = "";
    if (note) note.textContent = "";
    const url = new URL(location.href);
    url.searchParams.set("layout", layout.value);
    url.searchParams.set("theme", theme.value);
    if (langs) url.searchParams.set("langs", langs.value);
    history.replaceState(null, "", url);
  }
  layout.addEventListener("change", load);
  theme.addEventListener("change", load);
  langs?.addEventListener("change", load);
  document.getElementById("reload").addEventListener("click", load);
  const note = document.getElementById("banner-note");
  window.addEventListener("message", (e) => {
    if (!e.data) return;
    if (e.data.type === "skp-login") SkpDemo.renderResult(result, e.data.json);
    if (e.data.type === "skp-banner" && note) note.textContent = e.data.message;
  });
  // the frames are fixed-size desktop previews (414 / 432 px): scale them down rather than overflow a phone
  const deviceEl = document.querySelector(".device");
  function fitDevice() {
    deviceEl.style.transform = "";
    deviceEl.style.margin = "";
    const avail = (deviceEl.parentElement.clientWidth || window.innerWidth) - 8;
    const w = deviceEl.offsetWidth;
    const h = deviceEl.offsetHeight;
    if (!w || avail >= w) return;
    const s = Math.max(0.4, avail / w);
    deviceEl.style.transformOrigin = "top left";
    deviceEl.style.transform = `scale(${s})`;
    deviceEl.style.marginRight = `${-Math.round(w * (1 - s))}px`;
    deviceEl.style.marginBottom = `${-Math.round(h * (1 - s))}px`;
  }
  fitDevice();
  window.addEventListener("resize", fitDevice);
  frame.addEventListener("load", fitDevice);

  function tick() {
    const d = new Date();
    const t = `${d.getHours() % 12 || 12}:${String(d.getMinutes()).padStart(2, "0")}`;
    clock.forEach((c) => (c.textContent = t));
  }
  tick();
  setInterval(tick, 15000);
  load();
})();
