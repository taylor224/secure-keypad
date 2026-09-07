#!/usr/bin/env node
// Build-time helper: turns a binary file into a C array (same output as core/tools/embed.c).
const fs = require("fs");
const path = require("path");
const [input, output, symbol] = process.argv.slice(2);
if (!input || !output || !symbol) {
  console.error("usage: embed.js <input> <output.c> <symbol>");
  process.exit(2);
}
const data = fs.readFileSync(input);
const parts = [`#include <stddef.h>\nconst unsigned char ${symbol}[] = {\n`];
for (let i = 0; i < data.length; i += 32) {
  parts.push(Array.from(data.subarray(i, i + 32)).join(",") + ",\n");
}
parts.push(`};\nconst size_t ${symbol}_len = ${data.length};\n`);
fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, parts.join(""));
