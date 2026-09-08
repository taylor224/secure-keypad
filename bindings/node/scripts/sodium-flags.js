#!/usr/bin/env node
// Prints linker flags for libsodium: the static archive when pkg-config can locate it, else -lsodium.
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const mode = process.argv[2] || "libs";
function pkg(args) {
  try {
    return execSync(`pkg-config ${args} libsodium`, { stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
  } catch {
    return "";
  }
}
if (mode === "include") {
  const flags = pkg("--cflags-only-I");
  process.stdout.write(flags.split(/\s+/).filter(Boolean).map((f) => f.replace(/^-I/, "")).join(" "));
} else {
  // Static archive: explicit SKP_SODIUM_STATIC_LIB, or auto-detected on macOS only (Homebrew builds PIC
  // archives; Linux distro archives are non-PIC and cannot be linked into the addon). Else shared.
  const explicit = process.env.SKP_SODIUM_STATIC_LIB;
  const libdir = pkg("--variable=libdir");
  const archive = explicit || (process.platform === "darwin" && libdir ? path.join(libdir, "libsodium.a") : "");
  if (archive && fs.existsSync(archive)) process.stdout.write(archive);
  else process.stdout.write((pkg("--libs") || "-lsodium").trim());
}
