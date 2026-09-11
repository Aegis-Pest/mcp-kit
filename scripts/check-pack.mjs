#!/usr/bin/env node
/**
 * Prove the published tarball contains only what the README promises: the
 * compiled output under dist/ plus package.json, README.md, LICENSE, NOTICE
 * (Apache-2.0 §4(d) requires it to travel with the code) and CHANGELOG.md.
 * Anything else (tests, sources, configs, coverage, env files) fails the
 * check. Run after `npm run build`; CI runs it on every push.
 */
import { execFileSync } from "node:child_process";

const ALLOWED_TOP_LEVEL = new Set([
  "package.json",
  "README.md",
  "LICENSE",
  "NOTICE",
  "CHANGELOG.md",
]);

const raw = execFileSync("npm", ["pack", "--dry-run", "--json"], {
  encoding: "utf8",
  shell: process.platform === "win32",
});
const [pack] = JSON.parse(raw);
const files = pack.files.map((f) => f.path).sort();

const offenders = files.filter(
  (p) => !(p.startsWith("dist/") || ALLOWED_TOP_LEVEL.has(p)),
);
const missing = [...ALLOWED_TOP_LEVEL, "dist/index.js", "dist/index.d.ts"].filter(
  (p) => !files.includes(p),
);
const leakedTests = files.filter((p) => /__tests__|\.test\./.test(p));

for (const f of files) console.log(f);
console.log(`\n${files.length} files, ${pack.unpackedSize} bytes unpacked`);

let failed = false;
if (offenders.length) {
  console.error(`\nUnexpected files in tarball:\n  ${offenders.join("\n  ")}`);
  failed = true;
}
if (missing.length) {
  console.error(`\nExpected files missing from tarball:\n  ${missing.join("\n  ")}`);
  failed = true;
}
if (leakedTests.length) {
  console.error(`\nTest files leaked into tarball:\n  ${leakedTests.join("\n  ")}`);
  failed = true;
}
process.exit(failed ? 1 : 0);
