// Prebuild step: copy the buf-generated OpenAPI spec into the site's public/
// directory and stamp info.title / info.version so the served spec never
// drifts from the proto or the displayed docs version.
//
// The remote buf plugin can't read a local base file, so it emits `info: {}`.
// We fill it here from the repo VERSION file (the single source of truth that
// also feeds the VersionPill via src/version.ts). YAML's `info: {}` is rewritten
// to a populated block with a simple, dependency-free line replacement so we
// don't pull a YAML parser into the docs toolchain.

import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const DOCS_ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const REPO_ROOT = path.resolve(DOCS_ROOT, "..");

const SRC_SPEC = path.join(REPO_ROOT, "gen", "openapi", "identity.openapi.yaml");
const OUT_DIR = path.join(DOCS_ROOT, "public", "openapi");
const OUT_SPEC = path.join(OUT_DIR, "identity.openapi.yaml");

// Scalar's standalone browser bundle isn't exposed via the package `exports`
// map, so we copy it from the installed (version-pinned) package into public/
// rather than deep-importing it. This keeps the rendered reference fully
// offline/self-hosted — no runtime CDN dependency.
const SCALAR_STANDALONE_SRC = path.join(
  DOCS_ROOT,
  "node_modules",
  "@scalar",
  "api-reference",
  "dist",
  "browser",
  "standalone.js",
);
const SCALAR_OUT = path.join(DOCS_ROOT, "public", "scalar", "standalone.js");

const API_TITLE = "Identity API";

function readVersion() {
  const raw = readFileSync(path.join(REPO_ROOT, "VERSION"), "utf8").trim();
  if (!raw) throw new Error("VERSION file is empty");
  return raw;
}

function stampInfo(spec, version) {
  // buf emits an empty `info: {}` at column 0. Replace it with a populated
  // block. Fail loudly if the expected anchor is missing so a plugin change
  // can't silently ship an untitled/unversioned spec.
  const anchor = /^info:\s*\{\}\s*$/m;
  if (!anchor.test(spec)) {
    throw new Error(
      "expected `info: {}` in generated spec — buf plugin output changed; update prepare-openapi.mjs",
    );
  }
  const block = `info:\n  title: ${API_TITLE}\n  version: ${version}`;
  return spec.replace(anchor, block);
}

const version = readVersion();
const spec = readFileSync(SRC_SPEC, "utf8");
const stamped = stampInfo(spec, version);

mkdirSync(OUT_DIR, { recursive: true });
writeFileSync(OUT_SPEC, stamped);

mkdirSync(path.dirname(SCALAR_OUT), { recursive: true });
copyFileSync(SCALAR_STANDALONE_SRC, SCALAR_OUT);

console.log(`prepared OpenAPI spec → ${path.relative(REPO_ROOT, OUT_SPEC)} (v${version})`);
console.log(`copied Scalar bundle → ${path.relative(REPO_ROOT, SCALAR_OUT)}`);
