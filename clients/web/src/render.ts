/**
 * Canvas rendering of the keypad chrome + sprite tiles. Everything is drawn in device pixels on a
 * canvas whose backing store is exactly the server's surface (W × H), so tiles are blitted 1:1.
 */
import type { Layer, LayoutSet, KeyRect, Role } from "./protocol";
import type { ThemeTokens } from "./theme";

export interface Sprites {
  tiles: HTMLCanvasElement | OffscreenCanvas;
  popups: HTMLCanvasElement | OffscreenCanvas;
}

type Canvas2D = CanvasRenderingContext2D | OffscreenCanvasRenderingContext2D;

function makeCanvas(w: number, h: number): HTMLCanvasElement | OffscreenCanvas {
  if (typeof OffscreenCanvas !== "undefined") return new OffscreenCanvas(w, h);
  const c = document.createElement("canvas");
  c.width = w;
  c.height = h;
  return c;
}

/** Turns an 8-bit coverage sprite into a tinted RGBA canvas (coverage → alpha, colour → tint). */
export async function tintSprite(png: Uint8Array, color: string): Promise<HTMLCanvasElement | OffscreenCanvas> {
  const bitmap = await createImageBitmap(new Blob([png as BlobPart], { type: "image/png" }));
  const c = makeCanvas(bitmap.width, bitmap.height);
  const ctx = c.getContext("2d") as Canvas2D;
  ctx.drawImage(bitmap, 0, 0);
  bitmap.close();
  const img = ctx.getImageData(0, 0, c.width, c.height);
  const rgb = parseColor(color);
  const d = img.data;
  for (let i = 0; i < d.length; i += 4) {
    const coverage = d[i]; // grayscale: R = G = B = coverage
    d[i] = rgb[0];
    d[i + 1] = rgb[1];
    d[i + 2] = rgb[2];
    d[i + 3] = coverage;
  }
  ctx.putImageData(img, 0, 0);
  return c;
}

function parseColor(color: string): [number, number, number] {
  const m = color.trim().match(/^#([0-9a-f]{3,8})$/i);
  if (m) {
    let h = m[1];
    if (h.length === 3 || h.length === 4) h = h.split("").map((c) => c + c).join("");
    return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
  }
  const rgb = color.match(/rgba?\(\s*(\d+)[,\s]+(\d+)[,\s]+(\d+)/i);
  if (rgb) return [+rgb[1], +rgb[2], +rgb[3]];
  return [0, 0, 0];
}

function roundRect(ctx: Canvas2D, x: number, y: number, w: number, h: number, r: number): void {
  const rr = Math.min(r, w / 2, h / 2);
  ctx.beginPath();
  ctx.moveTo(x + rr, y);
  ctx.lineTo(x + w - rr, y);
  ctx.arcTo(x + w, y, x + w, y + rr, rr);
  ctx.lineTo(x + w, y + h - rr);
  ctx.arcTo(x + w, y + h, x + w - rr, y + h, rr);
  ctx.lineTo(x + rr, y + h);
  ctx.arcTo(x, y + h, x, y + h - rr, rr);
  ctx.lineTo(x, y + rr);
  ctx.arcTo(x, y, x + rr, y, rr);
  ctx.closePath();
}

export interface DrawState {
  pressed: number; // key index or -1
  shift: "off" | "once" | "caps";
  /** hide the pressed char key body while a popup covers it (iOS) */
  popupCovers: boolean;
}

function isSpecial(role: Role): boolean {
  return role !== "char" && role !== "space" && role !== "blank";
}

const LABELS: Partial<Record<Role, string>> = {
  space: "space",
  done: "Done",
  mode_abc: "ABC",
  mode_sym1: "123",
  mode_sym2: "#+=",
};

function labelFor(role: Role, style: "ios" | "material"): string {
  if (style === "material") {
    if (role === "mode_sym1") return "?123";
    if (role === "mode_sym2") return "=\\<";
  }
  return LABELS[role] ?? "";
}

function drawShift(ctx: Canvas2D, cx: number, cy: number, s: number, color: string, fill: boolean): void {
  ctx.beginPath();
  ctx.moveTo(cx, cy - s * 0.55);
  ctx.lineTo(cx + s * 0.55, cy);
  ctx.lineTo(cx + s * 0.25, cy);
  ctx.lineTo(cx + s * 0.25, cy + s * 0.45);
  ctx.lineTo(cx - s * 0.25, cy + s * 0.45);
  ctx.lineTo(cx - s * 0.25, cy);
  ctx.lineTo(cx - s * 0.55, cy);
  ctx.closePath();
  ctx.lineWidth = Math.max(1, s * 0.09);
  ctx.lineJoin = "round";
  ctx.strokeStyle = color;
  if (fill) {
    ctx.fillStyle = color;
    ctx.fill();
  }
  ctx.stroke();
}

function drawBackspace(ctx: Canvas2D, cx: number, cy: number, s: number, color: string): void {
  const w = s * 1.2;
  const h = s * 0.8;
  ctx.beginPath();
  ctx.moveTo(cx - w / 2, cy);
  ctx.lineTo(cx - w / 2 + h * 0.5, cy - h / 2);
  ctx.lineTo(cx + w / 2, cy - h / 2);
  ctx.lineTo(cx + w / 2, cy + h / 2);
  ctx.lineTo(cx - w / 2 + h * 0.5, cy + h / 2);
  ctx.closePath();
  ctx.lineWidth = Math.max(1, s * 0.09);
  ctx.lineJoin = "round";
  ctx.strokeStyle = color;
  ctx.stroke();
  const x0 = cx + w * 0.12;
  const k = h * 0.22;
  ctx.beginPath();
  ctx.moveTo(x0 - k, cy - k);
  ctx.lineTo(x0 + k, cy + k);
  ctx.moveTo(x0 + k, cy - k);
  ctx.lineTo(x0 - k, cy + k);
  ctx.stroke();
}

export interface DrawParams {
  ctx: Canvas2D;
  layout: LayoutSet;
  layer: Layer;
  sprites: Sprites | null;
  theme: ThemeTokens;
  dpr: number;
  state: DrawState;
}

/** Draws the whole keypad surface. */
export function drawKeypad(p: DrawParams): void {
  const { ctx, layout, layer, sprites, theme, dpr, state } = p;
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.clearRect(0, 0, layout.w, layout.h);
  ctx.fillStyle = theme.tray;
  ctx.fillRect(0, 0, layout.w, layout.h);
  const radius = theme.radius * dpr;
  const shadow = Math.round(theme.shadow * dpr);
  const labelPx = Math.round(16 * dpr);
  const iconPx = Math.round(18 * dpr);
  layer.keys.forEach((key: KeyRect, i: number) => {
    const [x, y, w, h] = key.r;
    if (key.role === "blank") return;
    const pressed = i === state.pressed;
    if (key.role === "char" && pressed && state.popupCovers) return; // hidden behind the popup bubble
    const special = isSpecial(key.role);
    let fill: string;
    if (special) fill = pressed ? theme.keySpecialPressed : theme.keySpecial;
    else fill = pressed ? theme.keyPressed : theme.key;
    if (key.role === "shift" && state.shift === "caps") fill = theme.keySpecialPressed;
    if (shadow > 0) {
      ctx.fillStyle = theme.keyShadow;
      roundRect(ctx, x, y + shadow, w, h, radius);
      ctx.fill();
    }
    ctx.fillStyle = fill;
    roundRect(ctx, x, y, w, h, radius);
    ctx.fill();
    const textColor = special ? theme.keySpecialText : theme.keyText;
    const cx = x + w / 2;
    const cy = y + h / 2;
    switch (key.role) {
      case "char": {
        if (sprites && key.t !== undefined) {
          const { w: tw, h: th, cols } = layout.tile;
          const sx = (key.t % cols) * tw;
          const sy = Math.floor(key.t / cols) * th;
          ctx.drawImage(sprites.tiles as CanvasImageSource, sx, sy, tw, th, x + Math.floor((w - tw) / 2), y + Math.floor((h - th) / 2), tw, th);
        }
        break;
      }
      case "shift":
        drawShift(ctx, cx, cy, iconPx, textColor, state.shift !== "off");
        break;
      case "backspace":
        drawBackspace(ctx, cx, cy, iconPx, textColor);
        break;
      default: {
        const label = labelFor(key.role, layout.style);
        if (label) {
          ctx.fillStyle = key.role === "done" && layout.style === "material" ? theme.keySpecialText : textColor;
          ctx.font = `${key.role === "space" ? 400 : 500} ${labelPx}px ${theme.font}`;
          ctx.textAlign = "center";
          ctx.textBaseline = "middle";
          ctx.fillText(label, cx, cy + Math.round(0.5 * dpr));
        }
      }
    }
  });
}

/** Geometry of the iOS-style popup bubble for a key, in device pixels relative to the surface. */
export interface PopupGeometry {
  x: number;
  y: number;
  w: number;
  h: number;
}

export function popupGeometry(layout: LayoutSet, key: KeyRect, dpr: number): PopupGeometry {
  const [kx, ky, kw, kh] = key.r;
  const pw = Math.max(layout.popup.w, kw + Math.round(16 * dpr));
  const ph = layout.popup.h + kh + Math.round(6 * dpr);
  let x = Math.round(kx + kw / 2 - pw / 2);
  x = Math.max(Math.round(2 * dpr), Math.min(x, layout.w - pw - Math.round(2 * dpr)));
  const y = ky + kh - ph;
  return { x, y, w: pw, h: ph };
}

/** Draws the popup bubble (its own canvas: `geom.w × geom.h`). */
export function drawPopup(ctx: Canvas2D, layout: LayoutSet, key: KeyRect, geom: PopupGeometry, sprites: Sprites | null, theme: ThemeTokens, dpr: number): void {
  const [kx, ky, kw, kh] = key.r;
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.clearRect(0, 0, geom.w, geom.h);
  const r = theme.radius * 1.6 * dpr;
  const topH = layout.popup.h;
  const stemLeft = kx - geom.x;
  const stemRight = stemLeft + kw;
  const flare = Math.round(6 * dpr);
  ctx.beginPath();
  ctx.moveTo(r, 0);
  ctx.lineTo(geom.w - r, 0);
  ctx.arcTo(geom.w, 0, geom.w, r, r);
  ctx.lineTo(geom.w, topH - flare);
  ctx.quadraticCurveTo(geom.w, topH, stemRight, topH + flare);
  ctx.lineTo(stemRight, geom.h - r);
  ctx.arcTo(stemRight, geom.h, stemRight - r, geom.h, r);
  ctx.lineTo(stemLeft + r, geom.h);
  ctx.arcTo(stemLeft, geom.h, stemLeft, geom.h - r, r);
  ctx.lineTo(stemLeft, topH + flare);
  ctx.quadraticCurveTo(0, topH, 0, topH - flare);
  ctx.lineTo(0, r);
  ctx.arcTo(0, 0, r, 0, r);
  ctx.closePath();
  ctx.shadowColor = theme.popupShadow;
  ctx.shadowBlur = 6 * dpr;
  ctx.shadowOffsetY = 1 * dpr;
  ctx.fillStyle = theme.popup;
  ctx.fill();
  ctx.shadowColor = "transparent";
  if (sprites && key.t !== undefined) {
    const { w: pw, h: ph, cols } = layout.popup;
    const sx = (key.t % cols) * pw;
    const sy = Math.floor(key.t / cols) * ph;
    ctx.drawImage(sprites.popups as CanvasImageSource, sx, sy, pw, ph, Math.floor((geom.w - pw) / 2), 0, pw, ph);
  }
  void ky;
  void kh;
}
