// Demo settings shared by the bank pages: layout / style / languages selects wired to SkpDemo.apply().
// The keypads are rebuilt in place and reopened, so a change is visible without reloading the page.
(function () {
  const LAYOUT_TEXT = { shuffle: "shuffle (줄 안에서 섞기)", full: "full (전체 섞기)", fixed: "fixed (표준 배열)" };

  const el = (v) => (typeof v === "string" ? document.getElementById(v) : v);
  const pick = (sel, value) => {
    if (sel && value && [...sel.options].some((o) => o.value === value)) sel.value = value;
  };

  /** Copies ?layout / ?style / ?langs into the selects. Call before creating the keypads, which read them. */
  function preselect(sel) {
    const qs = new URLSearchParams(location.search);
    pick(el(sel.layout), qs.get("layout"));
    pick(el(sel.style), qs.get("style"));
    pick(el(sel.langs), qs.get("langs"));
  }

  /**
   * opts: { demo, layout, style, langs, status, onApply }  — elements or ids.
   * Returns { describe(), setLanguage(code), values(), layoutText() }.
   */
  function wire(opts) {
    const demo = opts.demo;
    const layout = el(opts.layout);
    const style = el(opts.style);
    const langs = el(opts.langs);
    const status = el(opts.status);
    let current = null; // language the user switched to with the globe key
    preselect({ layout, style, langs });

    const describe = () => {
      if (!status) return;
      const now = current ? ` · 지금 ${SkpDemo.LANGUAGE_NAMES[current] || current}` : "";
      status.textContent = (demo ? demo.describe() : "") + now;
    };

    const syncUrl = () => {
      const u = new URL(location.href);
      if (layout) u.searchParams.set("layout", layout.value);
      if (style) u.searchParams.set("style", style.value);
      if (langs) u.searchParams.set("langs", langs.value);
      history.replaceState(null, "", u);
    };

    const apply = async () => {
      syncUrl();
      if (!demo) return;
      current = null;
      try {
        await demo.apply({
          layout: layout && layout.value,
          style: style && style.value,
          languages: langs ? langs.value : undefined,
        });
        opts.onApply?.();
      } catch (e) {
        console.error(e);
      }
      describe();
    };

    for (const sel of [layout, style, langs]) sel?.addEventListener("change", apply);
    return {
      describe,
      values: () => ({ layout: layout?.value, style: style?.value, langs: langs?.value }),
      setLanguage(code) {
        current = code;
        describe();
      },
      layoutText: () => LAYOUT_TEXT[layout?.value] || layout?.value,
    };
  }

  window.SkpSettings = { wire, preselect };
})();
