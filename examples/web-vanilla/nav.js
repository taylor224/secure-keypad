// Shared navigation for the demo pages. Each page has <nav class="topnav" data-page="…"></nav>.
// The per-device "실기기 화면" / "SDK 예제" links live in the copy of the simulation pages themselves.
(function () {
  const nav = document.querySelector("nav.topnav");
  if (!nav) return;
  const page = nav.dataset.page || "";
  const link = (href, label, key) => `<a href="${href}"${key === page ? ' class="active"' : ""}>${label}</a>`;
  nav.innerHTML =
    `<a class="brand" href="./">secure-keypad 데모</a>` +
    link("./", "웹뱅킹", "web") +
    link("ios.html", "iPhone 시뮬레이션", "ios") +
    link("android.html", "Pixel 시뮬레이션", "android") +
    link("native.html", "SDK 예제", "native") +
    `<a class="gh" href="https://github.com/taylor224/secure-keypad" target="_blank" rel="noopener">GitHub ↗</a>`;
})();
