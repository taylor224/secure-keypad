/**
 * @secure-keypad/web — public API.
 *
 *   const kp = createSecureKeypad({ sessionUrl: "/keypad/session", serverPublicKey, type: "number", maxLen: 6 });
 *   kp.attach(document.querySelector("#pin"));
 *   const payload = kp.submit(); // opaque JSON for your server's decrypt()
 */
import {
  buildInputPayload,
  buildRelayoutRequest,
  buildSessionRequest,
  consumeSession,
  generateClientKeys,
  openRelayout,
  openSession,
  ProtocolError,
  type KeypadLanguage,
  type KeypadType,
  type LayoutSet,
  type OpenSession,
  type RelayoutResponse,
  type SessionResponse,
  type Style,
  type Tap,
  type Viewport,
} from "./protocol";
import { KeypadUI } from "./keypad";
import { resolveTheme, type ThemeName, type ThemeTokens } from "./theme";

export * from "./protocol";
export { THEMES, resolveTheme, type ThemeName, type ThemeTokens } from "./theme";

export interface SecureKeypadConfig {
  /** Endpoint that forwards the request to the server SDK's createSession. */
  sessionUrl: string;
  /** Endpoint for relayout on rotation/resize. Optional: without it the session is recreated. */
  relayoutUrl?: string;
  /** The server's Ed25519 public key (base64) from `skp-keygen --pubkey`. Strongly recommended. */
  serverPublicKey?: string | null;
  /** Refuse to run without `serverPublicKey`. */
  strict?: boolean;
  type: KeypadType;
  maxLen?: number;
  /**
   * Keyboard languages requested for QWERTY keypads, in switch order (the first is shown initially),
   * e.g. ["en", "ko"] or ["ko"]. The server may override it; when neither side says anything the server
   * installs ["en", "ko"]. With two or more languages the keypad shows a globe key that cycles them.
   */
  languages?: (KeypadLanguage | string)[];
  /** Space-bar labels per language code when several are installed (default: English / 한국어). */
  languageNames?: Record<string, string>;
  /** "auto" picks iOS style on Apple devices and Material elsewhere. */
  style?: "auto" | Style;
  theme?: "auto" | ThemeName;
  themeOverrides?: Partial<ThemeTokens>;
  haptics?: boolean;
  /** Key popups: "auto" (touch pointers only), true (always, e.g. device simulations), false (default). The pressed key always changes colour. */
  popups?: boolean | "auto";
  /** Extra bottom padding in CSS px under the keys (home indicator / gesture bar), added to the safe-area inset. */
  safeAreaBottom?: number;
  /** Accessory bar with a Done button: "auto" shows it for number pads only. */
  accessory?: "auto" | "always" | "never";
  doneLabel?: string;
  /** Create the session as soon as the input is attached (default true). */
  prefetch?: boolean;
  /** Close the sheet when Done is pressed (default true). */
  closeOnDone?: boolean;
  /** When set, a hidden input with this name is kept filled with the payload on form submit. */
  hiddenInputName?: string;
  fetch?: typeof fetch;
  credentials?: RequestCredentials;
  headers?: Record<string, string> | (() => Record<string, string> | Promise<Record<string, string>>);
  /** Element that hosts the sheet (default document.body). */
  mount?: HTMLElement;
}

export type SecureKeypadEvent = "open" | "close" | "ready" | "change" | "done" | "submit" | "error" | "expire" | "lang";

export interface SecureKeypadEvents {
  open: void;
  close: void;
  /** A layout is installed. `layout` holds rects and roles only; it never identifies characters. */
  ready: { gen: number; layout: LayoutSet };
  change: { length: number };
  done: { length: number };
  submit: { payload: string; length: number };
  error: { error: Error };
  expire: void;
  /** The user switched keyboard language. */
  lang: { lang: string };
}

export interface SecureKeypad {
  attach(input: HTMLInputElement): void;
  detach(): void;
  open(): Promise<void>;
  close(): void;
  readonly isOpen: boolean;
  readonly ready: boolean;
  readonly length: number;
  /** Current keyboard language code ("en", "ko", …), or null for number pads / before the first layout. */
  readonly language: string | null;
  /** Switches to one of the installed languages; returns false if the current layout does not offer it. */
  setLanguage(code: string): boolean;
  /** Encrypts the taps and consumes the session. Synchronous. Throws if no session is ready. */
  submit(): string;
  /** Drops the current session and typed input; a new session is created lazily (or now if prefetch is on). */
  reset(): Promise<void>;
  clear(): void;
  on<E extends SecureKeypadEvent>(event: E, handler: (detail: SecureKeypadEvents[E]) => void): () => void;
  destroy(): void;
}

type Handler = (detail: any) => void;

function detectStyle(): Style {
  if (typeof navigator === "undefined") return "material";
  return /iPhone|iPad|iPod|Macintosh/.test(navigator.userAgent) ? "ios" : "material";
}

function detectDesktop(): boolean {
  if (typeof window === "undefined") return false;
  const coarse = window.matchMedia?.("(pointer: coarse)").matches;
  return !coarse && window.innerWidth >= 768;
}

export function createSecureKeypad(config: SecureKeypadConfig): SecureKeypad {
  if (typeof document === "undefined") throw new Error("createSecureKeypad needs a DOM");
  if (!config.sessionUrl || !config.type) throw new Error("sessionUrl and type are required");
  if (config.strict && !config.serverPublicKey) throw new Error("serverPublicKey is required in strict mode");
  if (!config.serverPublicKey && typeof console !== "undefined")
    console.warn("[secure-keypad] no serverPublicKey configured: the keypad cannot detect a substituted server");

  const style: Style = !config.style || config.style === "auto" ? detectStyle() : config.style;
  const desktop = detectDesktop();
  const fetcher = config.fetch ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  const listeners = new Map<string, Set<Handler>>();
  const emit = <E extends SecureKeypadEvent>(event: E, detail?: SecureKeypadEvents[E]) => {
    listeners.get(event)?.forEach((h) => {
      try {
        h(detail);
      } catch (e) {
        console.error(e);
      }
    });
  };

  const darkQuery = window.matchMedia?.("(prefers-color-scheme: dark)");
  const themeName = (): ThemeName => (config.theme && config.theme !== "auto" ? config.theme : darkQuery?.matches ? "dark" : "light");
  const theme = () => resolveTheme(style, themeName(), config.themeOverrides);

  let session: OpenSession | null = null;
  let taps: Tap[] = [];
  let input: HTMLInputElement | null = null;
  let hidden: HTMLInputElement | null = null;
  let form: HTMLFormElement | null = null;
  let creating: Promise<void> | null = null;
  let expiryTimer: ReturnType<typeof setTimeout> | null = null;
  let relayoutTimer: ReturnType<typeof setTimeout> | null = null;
  let lastViewport: Viewport | null = null;
  let destroyed = false;

  const ui = new KeypadUI(config.mount ?? document.body, {
    style,
    theme: theme(),
    haptics: config.haptics ?? true,
    popups: config.popups ?? false,
    safeAreaBottom: config.safeAreaBottom ?? 0,
    accessory: config.accessory === "always" || (config.accessory !== "never" && config.type === "number"),
    doneLabel: config.doneLabel ?? "Done",
    languageNames: config.languageNames ?? {},
    desktop,
    onTap: (tap) => {
      if (!session || session.consumed) return;
      if (taps.length >= session.layout.maxLen) return;
      taps.push(tap);
      syncInput();
      emit("change", { length: taps.length });
    },
    onBackspace: () => {
      if (!taps.length) return;
      taps.pop();
      syncInput();
      emit("change", { length: taps.length });
    },
    onDone: () => {
      emit("done", { length: taps.length });
      if (config.closeOnDone !== false) api.close();
    },
    onLang: (lang) => emit("lang", { lang }),
    onOutsidePress: () => api.close(),
  });

  const syncInput = () => {
    if (input) input.value = "•".repeat(taps.length);
  };

  const viewport = (): Viewport => {
    const dpr = window.devicePixelRatio || 1;
    const { cssWidth } = ui.measure(dpr);
    return { w: Math.max(200, cssWidth), dpr, platform: "web", style };
  };

  const headers = async (): Promise<Record<string, string>> => {
    const h = typeof config.headers === "function" ? await config.headers() : config.headers;
    return { "content-type": "application/json", ...(h ?? {}) };
  };

  const post = async <T>(url: string, body: unknown): Promise<T> => {
    const res = await fetcher(url, {
      method: "POST",
      headers: await headers(),
      credentials: config.credentials ?? "same-origin",
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`secure-keypad: ${url} responded ${res.status}`);
    return (await res.json()) as T;
  };

  const clearExpiry = () => {
    if (expiryTimer) clearTimeout(expiryTimer);
    expiryTimer = null;
  };

  const armExpiry = (seconds: number) => {
    clearExpiry();
    const ms = Math.max(1000, (seconds - 5) * 1000);
    expiryTimer = setTimeout(async () => {
      if (!session || session.consumed) return;
      if (taps.length === 0) {
        await createSession().catch(() => undefined);
      } else {
        dropSession();
        emit("expire");
      }
    }, ms);
  };

  const dropSession = () => {
    clearExpiry();
    if (session) consumeSession(session);
    session = null;
    taps = [];
    ui.clear();
    syncInput();
  };

  const createSession = async (): Promise<void> => {
    if (creating) return creating;
    creating = (async () => {
      dropSession();
      const keys = generateClientKeys();
      const vp = viewport();
      lastViewport = vp;
      const request = buildSessionRequest(keys, config.type, vp, config.maxLen, config.type === "qwerty" ? config.languages : undefined);
      const response = await post<SessionResponse>(config.sessionUrl, request);
      if (destroyed) return;
      const s = openSession(response, keys, config.serverPublicKey ?? null);
      session = s;
      armExpiry(s.layout.exp);
      await ui.setLayout(s.layout, s.tiles, s.popups);
      emit("ready", { gen: s.layout.gen, layout: s.layout });
    })().finally(() => {
      creating = null;
    });
    return creating;
  };

  const relayout = async (): Promise<void> => {
    if (!session || session.consumed || creating) return;
    const vp = viewport();
    if (lastViewport && Math.abs(vp.w - lastViewport.w) < 0.5 && vp.dpr === lastViewport.dpr) return;
    if (!config.relayoutUrl) {
      if (taps.length === 0) await createSession();
      return;
    }
    const s = session;
    const response = await post<RelayoutResponse>(config.relayoutUrl, buildRelayoutRequest(s, vp));
    if (session !== s || s.consumed) return;
    const layout = openRelayout(s, response);
    lastViewport = vp;
    await ui.setLayout(layout, s.tiles, s.popups);
    emit("ready", { gen: layout.gen, layout });
  };

  const scheduleRelayout = () => {
    if (relayoutTimer) clearTimeout(relayoutTimer);
    relayoutTimer = setTimeout(() => {
      relayoutTimer = null;
      relayout().catch((error) => emit("error", { error }));
    }, 150);
  };

  const resizeObserver = typeof ResizeObserver !== "undefined" ? new ResizeObserver(() => ui.isOpen && scheduleRelayout()) : null;
  resizeObserver?.observe(document.documentElement);
  window.visualViewport?.addEventListener("resize", () => ui.isOpen && scheduleRelayout());
  const themeListener = () => ui.applyTheme(theme());
  darkQuery?.addEventListener?.("change", themeListener);
  const visibilityListener = () => {
    if (document.visibilityState === "hidden") ui.close();
  };
  document.addEventListener("visibilitychange", visibilityListener);
  const pageHideListener = () => dropSession();
  window.addEventListener("pagehide", pageHideListener);
  const keyListener = (e: KeyboardEvent) => {
    if (e.key === "Escape" && ui.isOpen) api.close();
  };
  document.addEventListener("keydown", keyListener);

  const onInputFocus = () => void api.open();
  const onInputKeydown = (e: KeyboardEvent) => {
    if (e.key.length === 1 || e.key === "Backspace") e.preventDefault();
  };
  const onFormSubmit = () => {
    if (!hidden) return;
    try {
      hidden.value = session && !session.consumed ? api.submit() : "";
    } catch (error) {
      emit("error", { error: error as Error });
    }
  };

  const api: SecureKeypad = {
    attach(el) {
      api.detach();
      input = el;
      el.readOnly = true;
      el.inputMode = "none";
      el.autocomplete = "off";
      el.setAttribute("autocorrect", "off");
      el.setAttribute("autocapitalize", "off");
      el.spellcheck = false;
      el.setAttribute("data-secure-keypad", "");
      el.addEventListener("focus", onInputFocus);
      el.addEventListener("click", onInputFocus);
      el.addEventListener("keydown", onInputKeydown);
      if (config.hiddenInputName) {
        form = el.form;
        hidden = document.createElement("input");
        hidden.type = "hidden";
        hidden.name = config.hiddenInputName;
        el.insertAdjacentElement("afterend", hidden);
        form?.addEventListener("submit", onFormSubmit);
      }
      syncInput();
      if (config.prefetch !== false) createSession().catch((error) => emit("error", { error }));
      // the field may already have focus (attached late, or restored focus): open right away
      if (document.activeElement === el) void api.open();
    },
    detach() {
      if (!input) return;
      input.removeEventListener("focus", onInputFocus);
      input.removeEventListener("click", onInputFocus);
      input.removeEventListener("keydown", onInputKeydown);
      input.removeAttribute("data-secure-keypad");
      form?.removeEventListener("submit", onFormSubmit);
      hidden?.remove();
      input = null;
      hidden = null;
      form = null;
    },
    async open() {
      if (destroyed) return;
      ui.open();
      emit("open");
      if (!session || session.consumed) {
        try {
          await createSession();
        } catch (error) {
          emit("error", { error: error as Error });
        }
      } else {
        scheduleRelayout();
      }
    },
    close() {
      if (!ui.isOpen) return;
      ui.close();
      input?.blur();
      emit("close");
    },
    get isOpen() {
      return ui.isOpen;
    },
    get ready() {
      return !!session && !session.consumed;
    },
    get length() {
      return taps.length;
    },
    get language() {
      return ui.language;
    },
    setLanguage(code) {
      const ok = ui.setLanguage(code);
      if (ok) emit("lang", { lang: code });
      return ok;
    },
    submit() {
      if (!session || session.consumed) throw new ProtocolError("no session: call open() or reset() first", "CONSUMED");
      const payload = JSON.stringify(buildInputPayload(session, taps));
      const length = taps.length;
      clearExpiry();
      taps = [];
      ui.clear();
      session = null;
      emit("submit", { payload, length });
      return payload;
    },
    async reset() {
      dropSession();
      if (config.prefetch !== false || ui.isOpen) await createSession();
    },
    clear() {
      taps = [];
      syncInput();
      emit("change", { length: 0 });
    },
    on(event, handler) {
      if (!listeners.has(event)) listeners.set(event, new Set());
      listeners.get(event)!.add(handler as Handler);
      return () => listeners.get(event)?.delete(handler as Handler);
    },
    destroy() {
      destroyed = true;
      api.detach();
      dropSession();
      if (relayoutTimer) clearTimeout(relayoutTimer);
      resizeObserver?.disconnect();
      darkQuery?.removeEventListener?.("change", themeListener);
      document.removeEventListener("visibilitychange", visibilityListener);
      window.removeEventListener("pagehide", pageHideListener);
      document.removeEventListener("keydown", keyListener);
      ui.destroy();
      listeners.clear();
    },
  };
  return api;
}
