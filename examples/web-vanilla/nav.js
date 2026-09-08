// Shared top navigation for the playground pages. Each page has <nav class="topnav" data-page="…"></nav>.
(function () {
  const nav = document.querySelector("nav.topnav");
  if (!nav) return;
  const page = nav.dataset.page || "";
  const link = (href, label, key) => `<a href="${href}"${key === page ? ' class="active"' : ""}>${label}</a>`;
  nav.innerHTML =
    `<a class="brand" href="./">secure-keypad</a>` +
    link("./", "일반 웹", "web") +
    `<span class="group"><span class="glabel">iOS</span>` +
    link("ios.html", "iPhone 시뮬레이션", "ios") +
    link("app.html?device=ios", "실기기 화면", "app-ios") +
    link("native.html#ios", "SDK 예제", "native-ios") +
    `</span>` +
    `<span class="group"><span class="glabel">Android</span>` +
    link("android.html", "Pixel 시뮬레이션", "android") +
    link("app.html?device=android", "실기기 화면", "app-android") +
    link("native.html#android", "SDK 예제", "native-android") +
    `</span>` +
    `<a class="gh" href="https://github.com/taylor224/secure-keypad" target="_blank" rel="noopener">GitHub ↗</a>`;
})();
