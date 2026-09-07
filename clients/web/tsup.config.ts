import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: { index: "src/index.ts", protocol: "src/protocol.ts" },
    format: ["esm", "cjs"],
    dts: true,
    sourcemap: true,
    clean: true,
    target: "es2020",
    treeshake: true,
  },
  {
    entry: { "secure-keypad": "src/index.ts" },
    format: ["iife"],
    globalName: "SecureKeypad",
    minify: true,
    sourcemap: true,
    target: "es2020",
    outExtension: () => ({ js: ".iife.js" }),
  },
]);
