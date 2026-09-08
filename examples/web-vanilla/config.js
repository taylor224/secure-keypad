// Backend location for the playground pages.
//
// The example Express server serves these pages itself, so the default is "same origin". When the pages
// are hosted statically (GitHub Pages) they need a backend running the server SDK somewhere else:
//   - open any page with ?api=https://your-backend.example.com  (remembered in localStorage), or
//   - set SKP_DEFAULT_API below (the Pages workflow fills it from the SKP_API_BASE repository variable).
window.SKP_DEFAULT_API = window.SKP_DEFAULT_API || "";
window.SKP_API_BASE = (function () {
  var q = new URLSearchParams(location.search).get("api");
  try {
    if (q !== null) {
      if (q === "") localStorage.removeItem("skp-api");
      else localStorage.setItem("skp-api", q);
    }
    var saved = q || localStorage.getItem("skp-api") || window.SKP_DEFAULT_API || "";
    return saved.replace(/\/+$/, "");
  } catch (e) {
    return (q || window.SKP_DEFAULT_API || "").replace(/\/+$/, "");
  }
})();
