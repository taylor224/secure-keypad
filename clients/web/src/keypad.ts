/**
 * Keypad UI: shadow-DOM bottom sheet with a canvas surface, pointer handling, the shift/mode state
 * machine and press feedback. It knows rects and roles, never characters.
 */
import { hitTest, type KeyRect, type Layer, type LayoutSet, type Mode, type Style, type Tap } from "./protocol";
import { drawKeypad, drawPopup, popupGeometry, tintSprite, type DrawState, type Sprites } from "./render";
import type { ThemeTokens } from "./theme";

export interface KeypadUIOptions {
  style: Style;
  theme: ThemeTokens;
  haptics: boolean;
  popups: boolean;
  accessory: boolean;
  doneLabel: string;
  desktop: boolean;
  onTap: (tap: Tap) => void;
  onBackspace: () => void;
  onDone: () => void;
  onOutsidePress?: () => void;
}

type Base = "letters" | "sym1" | "sym2" | "number";

const CSS = `
:host { all: initial; }
* { box-sizing: border-box; }
.sheet {
  position: fixed; left: 0; right: 0; bottom: 0; z-index: 2147483000;
  background: var(--tray); padding-bottom: env(safe-area-inset-bottom, 0px);
  transform: translateY(105%); transition: transform 240ms cubic-bezier(.2,.8,.2,1);
  touch-action: none; user-select: none; -webkit-user-select: none; -webkit-touch-callout: none;
  -webkit-tap-highlight-color: transparent; font-family: var(--font);
}
.sheet.open { transform: translateY(0); }
.sheet.desktop {
  left: 50%; right: auto; width: min(520px, 100vw); transform: translate(-50%, 105%);
  border-radius: 12px 12px 0 0; box-shadow: 0 -4px 28px rgba(0,0,0,.25); overflow: hidden;
}
.sheet.desktop.open { transform: translate(-50%, 0); }
.accessory {
  display: none; align-items: center; justify-content: flex-end; height: 44px;
  background: var(--accessory); border-bottom: 1px solid rgba(0,0,0,.08);
}
.accessory.show { display: flex; }
.accessory button {
  height: 100%; padding: 0 18px; border: 0; background: none; color: var(--accent);
  font: 600 17px var(--font); cursor: pointer;
}
.accessory button:focus-visible { outline: 2px solid var(--accent); outline-offset: -4px; border-radius: 6px; }
.surface { position: relative; margin: 0 auto; }
canvas.keys { display: block; }
canvas.popup { position: absolute; pointer-events: none; display: none; }
@media (prefers-reduced-motion: reduce) { .sheet { transition: none; } }
`;

export class KeypadUI {
  readonly host: HTMLDivElement;
  private readonly sheet: HTMLDivElement;
  private readonly accessoryBar: HTMLDivElement;
  private readonly surface: HTMLDivElement;
  private readonly canvas: HTMLCanvasElement;
  private readonly popup: HTMLCanvasElement;
  private readonly ctx: CanvasRenderingContext2D;
  private readonly popupCtx: CanvasRenderingContext2D;
  private opts: KeypadUIOptions;
  private layout: LayoutSet | null = null;
  private sprites: Sprites | null = null;
  private spriteGen = 0;
  private base: Base = "letters";
  private shift: "off" | "once" | "caps" = "off";
  private pressed = -1;
  private pointerId: number | null = null;
  private lastShiftTap = 0;
  private repeatTimer: ReturnType<typeof setTimeout> | null = null;
  private repeatInterval: ReturnType<typeof setInterval> | null = null;
  private _open = false;
  private dpr = 1;
  private rawTiles: Uint8Array | null = null;
  private rawPopups: Uint8Array | null = null;
  private outsideHandler = (e: PointerEvent) => {
    if (!this._open) return;
    const path = e.composedPath();
    if (path.includes(this.sheet)) return;
    this.opts.onOutsidePress?.();
  };

  constructor(mount: HTMLElement, opts: KeypadUIOptions) {
    this.opts = opts;
    this.host = document.createElement("div");
    this.host.className = "skp-host";
    // open: a closed root is not a security boundary, and open roots keep the sheet testable
    const shadow = this.host.attachShadow({ mode: "open" });
    const style = document.createElement("style");
    style.textContent = CSS;
    shadow.appendChild(style);
    this.sheet = document.createElement("div");
    this.sheet.className = "sheet" + (opts.desktop ? " desktop" : "");
    this.sheet.setAttribute("role", "application");
    this.sheet.setAttribute("aria-label", "Secure keypad");
    this.accessoryBar = document.createElement("div");
    this.accessoryBar.className = "accessory" + (opts.accessory ? " show" : "");
    const done = document.createElement("button");
    done.type = "button";
    done.textContent = opts.doneLabel;
    done.addEventListener("click", () => this.opts.onDone());
    this.accessoryBar.appendChild(done);
    this.surface = document.createElement("div");
    this.surface.className = "surface";
    this.canvas = document.createElement("canvas");
    this.canvas.className = "keys";
    this.canvas.setAttribute("aria-hidden", "true");
    this.popup = document.createElement("canvas");
    this.popup.className = "popup";
    this.popup.setAttribute("aria-hidden", "true");
    this.surface.append(this.canvas, this.popup);
    this.sheet.append(this.accessoryBar, this.surface);
    shadow.appendChild(this.sheet);
    this.ctx = this.canvas.getContext("2d")!;
    this.popupCtx = this.popup.getContext("2d")!;
    this.applyTheme(opts.theme);
    mount.appendChild(this.host);
    this.canvas.addEventListener("pointerdown", this.onDown);
    this.canvas.addEventListener("pointermove", this.onMove);
    this.canvas.addEventListener("pointerup", this.onUp);
    this.canvas.addEventListener("pointercancel", this.onCancel);
    this.canvas.addEventListener("contextmenu", (e) => e.preventDefault());
    document.addEventListener("pointerdown", this.outsideHandler, true);
  }

  /** Width available for the keypad surface, in CSS px, snapped so that width × dpr is an integer. */
  measure(dpr: number): { cssWidth: number; dpr: number } {
    this.dpr = dpr;
    const raw = this.sheet.getBoundingClientRect().width || window.innerWidth;
    const cssWidth = Math.floor(raw * dpr) / dpr;
    return { cssWidth, dpr };
  }

  get isOpen(): boolean {
    return this._open;
  }

  open(): void {
    this._open = true;
    // force a layout so the transition runs
    void this.sheet.offsetHeight;
    this.sheet.classList.add("open");
  }

  close(): void {
    this._open = false;
    this.sheet.classList.remove("open");
    this.release();
  }

  applyTheme(theme: ThemeTokens): void {
    this.opts.theme = theme;
    const s = this.sheet.style;
    s.setProperty("--tray", theme.tray);
    s.setProperty("--accessory", theme.accessory);
    s.setProperty("--accent", theme.accent);
    s.setProperty("--font", theme.font);
    if (this.rawTiles && this.rawPopups) void this.decodeSprites(this.rawTiles, this.rawPopups);
    this.draw();
  }

  setAccessory(show: boolean): void {
    this.accessoryBar.classList.toggle("show", show);
  }

  /** Installs a layout set (new session or relayout). Sprites decode asynchronously; chrome draws at once. */
  async setLayout(layout: LayoutSet, tiles: Uint8Array, popups: Uint8Array): Promise<void> {
    this.layout = layout;
    this.base = layout.type === "number" ? "number" : this.base === "number" ? "letters" : this.base;
    this.canvas.width = layout.w;
    this.canvas.height = layout.h;
    this.canvas.style.width = `${layout.w / this.dpr}px`;
    this.canvas.style.height = `${layout.h / this.dpr}px`;
    this.surface.style.width = `${layout.w / this.dpr}px`;
    this.rawTiles = tiles;
    this.rawPopups = popups;
    this.draw();
    await this.decodeSprites(tiles, popups);
  }

  private async decodeSprites(tiles: Uint8Array, popups: Uint8Array): Promise<void> {
    if (!tiles.length || typeof createImageBitmap === "undefined") return;
    const gen = ++this.spriteGen;
    const [t, p] = await Promise.all([tintSprite(tiles, this.opts.theme.keyText), tintSprite(popups, this.opts.theme.popupText)]);
    if (gen !== this.spriteGen) return;
    this.sprites = { tiles: t, popups: p };
    this.draw();
  }

  /** Drops layout, sprites and press state (session consumed or destroyed). */
  clear(): void {
    this.release();
    this.layout = null;
    this.sprites = null;
    this.rawTiles = null;
    this.rawPopups = null;
    this.shift = "off";
    this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
  }

  destroy(): void {
    this.clear();
    document.removeEventListener("pointerdown", this.outsideHandler, true);
    this.host.remove();
  }

  currentLayer(): Layer | null {
    if (!this.layout) return null;
    const mode: Mode = this.base === "number" ? "number" : this.base === "letters" ? (this.shift === "off" ? "lower" : "upper") : this.base;
    return this.layout.layouts.find((l) => l.mode === mode) ?? this.layout.layouts[0] ?? null;
  }

  private draw(): void {
    const layer = this.currentLayer();
    if (!this.layout || !layer) return;
    const state: DrawState = { pressed: this.pressed, shift: this.shift, popupCovers: this.popup.style.display === "block" };
    drawKeypad({ ctx: this.ctx, layout: this.layout, layer, sprites: this.sprites, theme: this.opts.theme, dpr: this.dpr, state });
  }

  private devicePoint(e: PointerEvent): { x: number; y: number } {
    const rect = this.canvas.getBoundingClientRect();
    const w = this.layout?.w ?? 1;
    const h = this.layout?.h ?? 1;
    const x = Math.round(((e.clientX - rect.left) / rect.width) * w);
    const y = Math.round(((e.clientY - rect.top) / rect.height) * h);
    return { x: Math.max(0, Math.min(w - 1, x)), y: Math.max(0, Math.min(h - 1, y)) };
  }

  private showPopup(layer: Layer, index: number): void {
    const key = layer.keys[index];
    if (!this.layout || !this.opts.popups || key.role !== "char") {
      this.hidePopup();
      return;
    }
    const geom = popupGeometry(this.layout, key, this.dpr);
    this.popup.width = geom.w;
    this.popup.height = geom.h;
    this.popup.style.width = `${geom.w / this.dpr}px`;
    this.popup.style.height = `${geom.h / this.dpr}px`;
    this.popup.style.left = `${geom.x / this.dpr}px`;
    this.popup.style.top = `${geom.y / this.dpr}px`;
    this.popup.style.display = "block";
    drawPopup(this.popupCtx, this.layout, key, geom, this.sprites, this.opts.theme, this.dpr);
  }

  private hidePopup(): void {
    this.popup.style.display = "none";
  }

  private haptic(e: PointerEvent): void {
    if (this.opts.haptics && e.pointerType === "touch" && typeof navigator !== "undefined" && "vibrate" in navigator) {
      try {
        navigator.vibrate(8);
      } catch {
        /* ignore */
      }
    }
  }

  private onDown = (e: PointerEvent): void => {
    if (this.pointerId !== null) return; // single touch
    const layer = this.currentLayer();
    if (!layer) return;
    e.preventDefault();
    this.pointerId = e.pointerId;
    this.canvas.setPointerCapture(e.pointerId);
    const { x, y } = this.devicePoint(e);
    const i = hitTest(layer, x, y);
    const key = layer.keys[i];
    if (!key || key.role === "blank") {
      this.pointerId = null;
      return;
    }
    this.pressed = i;
    this.haptic(e);
    if (e.pointerType !== "mouse") this.showPopup(layer, i);
    if (key.role === "backspace") {
      this.opts.onBackspace();
      this.repeatTimer = setTimeout(() => {
        this.repeatInterval = setInterval(() => this.opts.onBackspace(), 100);
      }, 500);
    }
    this.draw();
  };

  private onMove = (e: PointerEvent): void => {
    if (e.pointerId !== this.pointerId) return;
    const layer = this.currentLayer();
    if (!layer) return;
    const { x, y } = this.devicePoint(e);
    const i = hitTest(layer, x, y);
    if (i !== this.pressed) {
      const from = layer.keys[this.pressed];
      // sliding off a backspace key stops the auto repeat; sliding between character keys moves the popup
      if (from?.role === "backspace") this.stopRepeat();
      this.pressed = layer.keys[i]?.role === "blank" ? -1 : i;
      if (e.pointerType !== "mouse" && this.pressed >= 0) this.showPopup(layer, this.pressed);
      else this.hidePopup();
      this.draw();
    }
  };

  private onUp = (e: PointerEvent): void => {
    if (e.pointerId !== this.pointerId) return;
    const layer = this.currentLayer();
    const index = this.pressed;
    const { x, y } = this.devicePoint(e);
    this.release();
    if (!layer || index < 0) return;
    const key: KeyRect = layer.keys[index];
    if (hitTest(layer, x, y) !== index) return; // released elsewhere: cancel
    this.commit(layer, key);
  };

  private onCancel = (e: PointerEvent): void => {
    if (e.pointerId !== this.pointerId) return;
    this.release();
  };

  private stopRepeat(): void {
    if (this.repeatTimer) clearTimeout(this.repeatTimer);
    if (this.repeatInterval) clearInterval(this.repeatInterval);
    this.repeatTimer = null;
    this.repeatInterval = null;
  }

  private release(): void {
    this.stopRepeat();
    if (this.pointerId !== null) {
      try {
        this.canvas.releasePointerCapture(this.pointerId);
      } catch {
        /* already released */
      }
    }
    this.pointerId = null;
    this.pressed = -1;
    this.hidePopup();
    this.draw();
  }

  private commit(layer: Layer, key: KeyRect): void {
    switch (key.role) {
      case "char":
      case "space": {
        const [rx, ry, rw, rh] = key.r;
        // record the tap at the key centre: the server hit-tests the same rects, and the exact finger
        // position inside the key carries no information worth transmitting
        this.opts.onTap({ layoutId: layer.id, x: rx + Math.floor(rw / 2), y: ry + Math.floor(rh / 2) });
        if (this.shift === "once") this.shift = "off";
        break;
      }
      case "shift": {
        const now = Date.now();
        if (this.shift === "off") this.shift = now - this.lastShiftTap < 320 ? "caps" : "once";
        else if (this.shift === "once") this.shift = now - this.lastShiftTap < 320 ? "caps" : "off";
        else this.shift = "off";
        this.lastShiftTap = now;
        break;
      }
      case "mode_abc":
        this.base = "letters";
        this.shift = "off";
        break;
      case "mode_sym1":
        this.base = "sym1";
        break;
      case "mode_sym2":
        this.base = "sym2";
        break;
      case "done":
        this.opts.onDone();
        break;
      default:
        break;
    }
    this.draw();
  }
}
