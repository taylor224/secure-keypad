import { expect, test, type Page } from "@playwright/test";

type Key = { r: [number, number, number, number]; role: string; t?: number };
type Layer = { id: number; mode: string; keys: Key[] };
type Layout = { w: number; h: number; layouts: Layer[]; maxLen: number };

const FIXED: Record<string, string> = {
  lower: "qwertyuiopasdfghjklzxcvbnm",
  upper: "QWERTYUIOPASDFGHJKLZXCVBNM",
  sym1: "1234567890-/:;()$&@\".,?!'",
};

/** Loads the demo and waits until both keypads are attached (the page fetches the public key first). */
async function load(page: Page, url: string) {
  await page.goto(url);
  await page.waitForFunction(() => !!(window as any).__skp, null, { timeout: 20_000 });
}

/** Waits until the demo page has attached both keypads and the given one has a layout. */
async function ready(page: Page, name: "pin" | "password"): Promise<Layout> {
  // `ready` flips to false when a session is consumed and back to true once the next one is installed
  await page.waitForFunction((n) => (window as any).__skp?.layouts?.[n] && (window as any).__skp[n].ready === true, name, { timeout: 20_000 });
  return page.evaluate((n) => (window as any).__skp.layouts[n], name);
}

/** Bounding box of the visible keypad canvas (inside the open shadow root). */
async function surface(page: Page) {
  // two keypads live on the page (PIN and password); only the open sheet's canvas is the target
  const canvas = page.locator(".skp-host .sheet.open canvas.keys");
  await expect(canvas).toBeVisible();
  // the sheet slides in with a CSS transition: wait until its position stops changing
  let box = (await canvas.boundingBox())!;
  for (let i = 0; i < 40; i++) {
    await page.waitForTimeout(50);
    const next = (await canvas.boundingBox())!;
    if (next.x === box.x && next.y === box.y && next.width === box.width && next.height === box.height && next.width > 0) {
      box = next;
      break;
    }
    box = next;
  }
  return { canvas, box };
}

async function tapDevicePoint(page: Page, box: { x: number; y: number; width: number; height: number }, layout: Layout, x: number, y: number) {
  const cx = box.x + (x / layout.w) * box.width;
  const cy = box.y + (y / layout.h) * box.height;
  const touch = await page.evaluate(() => matchMedia("(pointer: coarse)").matches && "ontouchstart" in window);
  if (touch) await page.touchscreen.tap(cx, cy);
  else await page.mouse.click(cx, cy);
}

function centre(k: Key): [number, number] {
  return [k.r[0] + Math.floor(k.r[2] / 2), k.r[1] + Math.floor(k.r[3] / 2)];
}

test.describe("secure-keypad web demo", () => {
  test("PIN pad: four taps on distinct keys decrypt to four distinct digits", async ({ page }) => {
    await load(page, "/?layout=fixed");
    const pin = page.locator("#pin");
    await pin.click();
    const layout = await ready(page, "pin");
    const { box } = await surface(page);
    const layer = layout.layouts[0];
    const chars = layer.keys.filter((k) => k.role === "char");
    expect(chars).toHaveLength(10);
    for (const k of chars.slice(0, 4)) {
      const [x, y] = centre(k);
      await tapDevicePoint(page, box, layout, x, y);
    }
    await expect(pin).toHaveValue("••••");
    // backspace removes the last digit, then type one more
    const bs = layer.keys.find((k) => k.role === "backspace")!;
    await tapDevicePoint(page, box, layout, ...centre(bs));
    await expect(pin).toHaveValue("•••");
    await tapDevicePoint(page, box, layout, ...centre(chars[5]));
    await expect(pin).toHaveValue("••••");
    await page.getByRole("button", { name: "Done" }).click();
    await page.getByRole("button", { name: "로그인" }).click();
    await page.waitForFunction(() => (window as any).__skp?.lastLogin);
    const result = await page.evaluate(() => (window as any).__skp.lastLogin);
    expect(result.ok).toBe(true);
    expect(result.pinLength).toBe(4);
    expect(result.pin).toMatch(/^[0-9]{4}$/);
    expect(new Set(result.pin.split("")).size).toBe(4);
    // the DOM never held the value
    await expect(pin).toHaveValue("");
  });

  test("QWERTY (fixed layout): shift, symbols and space type the expected text", async ({ page }) => {
    await load(page, "/?layout=fixed");
    const pw = page.locator("#password");
    await pw.click();
    const layout = await ready(page, "password");
    const { box } = await surface(page);
    const byMode = Object.fromEntries(layout.layouts.map((l) => [l.mode, l])) as Record<string, Layer>;
    const charKey = (mode: string, ch: string): Key => {
      const idx = Array.from(FIXED[mode]).indexOf(ch);
      return byMode[mode].keys.filter((k) => k.role === "char")[idx];
    };
    const roleKey = (mode: string, role: string): Key => byMode[mode].keys.find((k) => k.role === role)!;
    const tap = (k: Key) => tapDevicePoint(page, box, layout, ...centre(k));

    // "Hi 42"
    await tap(roleKey("lower", "shift"));
    await tap(charKey("upper", "H"));
    await tap(charKey("lower", "i"));
    await tap(roleKey("lower", "space"));
    await tap(roleKey("lower", "mode_sym1"));
    await tap(charKey("sym1", "4"));
    await tap(charKey("sym1", "2"));
    await expect(pw).toHaveValue("•••••");
    await tap(roleKey("sym1", "done"));
    await page.getByRole("button", { name: "로그인" }).click();
    await page.waitForFunction(() => (window as any).__skp?.lastLogin);
    const result = await page.evaluate(() => (window as any).__skp.lastLogin);
    expect(result.ok).toBe(true);
    expect(result.password).toBe("Hi 42");
  });

  test("shuffled layout: the same slot order decrypts to a permutation, never the fixed string", async ({ page }) => {
    await load(page, "/?layout=shuffle");
    const pw = page.locator("#password");
    await pw.click();
    const layout = await ready(page, "password");
    const { box } = await surface(page);
    const lower = layout.layouts.find((l) => l.mode === "lower")!;
    const chars = lower.keys.filter((k) => k.role === "char");
    for (const k of chars.slice(0, 10)) await tapDevicePoint(page, box, layout, ...centre(k));
    await page.getByRole("button", { name: "로그인" }).click();
    await page.waitForFunction(() => (window as any).__skp?.lastLogin);
    const result = await page.evaluate(() => (window as any).__skp.lastLogin);
    expect(result.password).toHaveLength(10);
    expect(result.password.split("").sort().join("")).toBe("eiopqrtuwy");
  });

  test("a used session cannot be replayed", async ({ page, request }) => {
    await load(page, "/?layout=fixed");
    await page.locator("#pin").click();
    const layout = await ready(page, "pin");
    const { box } = await surface(page);
    const chars = layout.layouts[0].keys.filter((k) => k.role === "char");
    await tapDevicePoint(page, box, layout, ...centre(chars[0]));
    const payload = await page.evaluate(() => JSON.parse((window as any).__skp.pin.submit()));
    const ctx = await page.evaluate(() => (window as any).__skp.ctx);
    const first = await request.post("/login", { data: { pin_enc: payload }, headers: { "x-login-ctx": ctx } });
    expect(first.ok()).toBe(true);
    const second = await request.post("/login", { data: { pin_enc: payload }, headers: { "x-login-ctx": ctx } });
    expect(second.status()).toBe(410);
    // and a different binding context is refused even for a fresh session
    await page.locator("#pin").click();
    await ready(page, "pin");
    await tapDevicePoint(page, box, layout, ...centre(chars[1]));
    const payload2 = await page.evaluate(() => JSON.parse((window as any).__skp.pin.submit()));
    const stolen = await request.post("/login", { data: { pin_enc: payload2 }, headers: { "x-login-ctx": "someone-else" } });
    expect(stolen.status()).toBe(403);
  });
});
