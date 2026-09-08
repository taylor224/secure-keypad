import type { Style } from "./protocol";

/** Colour tokens for the client-drawn chrome. Only colours are configurable; geometry comes from the server. */
export interface ThemeTokens {
  tray: string;
  key: string;
  keyPressed: string;
  keySpecial: string;
  keySpecialPressed: string;
  keyText: string;
  keySpecialText: string;
  keyShadow: string;
  popup: string;
  popupText: string;
  popupShadow: string;
  accessory: string;
  accessoryText: string;
  accent: string;
  /** corner radius in logical px */
  radius: number;
  /** key shadow height in logical px (0 for none) */
  shadow: number;
  font: string;
}

export type ThemeName = "light" | "dark";

const SYSTEM_FONT = '-apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';
const ROBOTO_FONT = 'Roboto, "Segoe UI", -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif';

export const THEMES: Record<Style, Record<ThemeName, ThemeTokens>> = {
  ios: {
    light: {
      tray: "#d1d3d9",
      key: "#ffffff",
      keyPressed: "#c9ccd3",
      keySpecial: "#adb3bc",
      keySpecialPressed: "#ffffff",
      keyText: "#000000",
      keySpecialText: "#000000",
      keyShadow: "#898a8d",
      popup: "#ffffff",
      popupText: "#000000",
      popupShadow: "rgba(0,0,0,0.28)",
      accessory: "#f1f1f3",
      accessoryText: "#1c1c1e",
      accent: "#0a7aff",
      radius: 5,
      shadow: 1,
      font: SYSTEM_FONT,
    },
    dark: {
      tray: "#2b2b2d",
      key: "#6b6b6e",
      keyPressed: "#9a9a9e",
      keySpecial: "#464648",
      keySpecialPressed: "#6b6b6e",
      keyText: "#ffffff",
      keySpecialText: "#ffffff",
      keyShadow: "#0d0d0e",
      popup: "#6b6b6e",
      popupText: "#ffffff",
      popupShadow: "rgba(0,0,0,0.6)",
      accessory: "#1c1c1e",
      accessoryText: "#f2f2f7",
      accent: "#0a84ff",
      radius: 5,
      shadow: 1,
      font: SYSTEM_FONT,
    },
  },
  material: {
    light: {
      tray: "#eceff3",
      key: "#ffffff",
      keyPressed: "#d5d9df",
      keySpecial: "#d9dde3",
      keySpecialPressed: "#c3c8cf",
      keyText: "#1f1f1f",
      keySpecialText: "#1f1f1f",
      keyShadow: "rgba(0,0,0,0)",
      popup: "#ffffff",
      popupText: "#1f1f1f",
      popupShadow: "rgba(0,0,0,0.25)",
      accessory: "#eceff3",
      accessoryText: "#1f1f1f",
      accent: "#1a73e8",
      radius: 8,
      shadow: 0,
      font: ROBOTO_FONT,
    },
    dark: {
      tray: "#2a2b2e",
      key: "#4b4d52",
      keyPressed: "#6a6d73",
      keySpecial: "#37393d",
      keySpecialPressed: "#55585e",
      keyText: "#f1f1f1",
      keySpecialText: "#f1f1f1",
      keyShadow: "rgba(0,0,0,0)",
      popup: "#4b4d52",
      popupText: "#f1f1f1",
      popupShadow: "rgba(0,0,0,0.6)",
      accessory: "#2a2b2e",
      accessoryText: "#f1f1f1",
      accent: "#8ab4f8",
      radius: 8,
      shadow: 0,
      font: ROBOTO_FONT,
    },
  },
};

export function resolveTheme(style: Style, name: ThemeName, overrides?: Partial<ThemeTokens>): ThemeTokens {
  return { ...THEMES[style][name], ...(overrides ?? {}) };
}
