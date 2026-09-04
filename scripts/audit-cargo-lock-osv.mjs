#!/usr/bin/env node
import { createHash } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";

const COMMIT = "a57975d499a660fd11da05a9010e93fe245525ba";
const LOCK_BLOB = "ef047c8faab35b8fed2203aaed73e71482f96b7b";
const LOCK_SHA256 = "603ffab1532a5bc934214693623e1fdb27ae5b40e016f88a3b4ce384b571694e";
const REGISTRY = "registry+https://github.com/rust-lang/crates.io-index";
const WORKSPACE = [
  "guide-helper", "mdbook", "mdbook-compare", "mdbook-core", "mdbook-driver",
  "mdbook-html", "mdbook-markdown", "mdbook-preprocessor",
  "mdbook-remove-emphasis", "mdbook-renderer", "mdbook-summary", "xtask",
].sort();
const CONTROLS = [
  { name: "crossbeam-epoch", version: "0.9.18", id: "RUSTSEC-2026-0204" },
  { name: "h2", version: "0.4.15", id: "RUSTSEC-2026-0258" },
];
const lockPath = process.argv[2];
if (!lockPath || process.argv.length !== 3) {
  console.error("usage: node scripts/audit-cargo-lock-osv.mjs <Cargo.lock>");
  process.exit(2);
}

const hash = (algorithm, value) =>
  createHash(algorithm).update(value).digest("hex");
const field = (block, name) =>
  block.match(new RegExp("^" + name + ' = "([^"]+)"$', "mu"))?.[1];

async function query(body) {
  let reason;
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    try {
      const response = await fetch("https://api.osv.dev/v1/querybatch", {
        method: "POST",
        redirect: "error",
        signal: AbortSignal.timeout(20_000),
        headers: { "content-type": "application/json" },
        body,
      });
      if (response.status !== 200)
        throw new Error("OSV returned HTTP " + response.status);
      const text = await response.text();
      if (text.length > 5_000_000) throw new Error("OSV response is too large");
      return JSON.parse(text);
    } catch (error) {
      reason = error;
      if (attempt === 2) break;
    }
  }
  throw reason;
}

async function main() {
  const stat = await lstat(lockPath);
  if (!stat.isFile() || stat.isSymbolicLink())
    throw new Error("Cargo.lock must be a regular non-symlink file");
  await realpath(lockPath);
  const bytes = await readFile(lockPath);
  if (hash("sha256", bytes) !== LOCK_SHA256)
    throw new Error("Cargo.lock SHA-256 does not match the pinned mdBook source");
  const header = Buffer.from("blob " + bytes.length + "\0");
  if (hash("sha1", Buffer.concat([header, bytes])) !== LOCK_BLOB)
    throw new Error("Cargo.lock Git blob does not match the pinned mdBook source");

  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const packages = text.split("[[package]]").slice(1).map((block, index) => {
    const name = field(block, "name");
    const version = field(block, "version");
    const source = field(block, "source");
    const checksum = field(block, "checksum");
    if (!name || !version)
      throw new Error("Incomplete package record " + (index + 1));
    if (source && source !== REGISTRY)
      throw new Error("Unexpected package source for " + name + ": " + source);
    if (source && !/^[0-9a-f]{64}$/u.test(checksum ?? ""))
      throw new Error("Missing or invalid checksum for " + name);
    if (!source && checksum)
      throw new Error("Workspace package unexpectedly has a checksum: " + name);
    return { name, version, source };
  });

  const registry = packages.filter((item) => item.source === REGISTRY);
  const workspace = packages.filter((item) => !item.source)
    .map((item) => item.name).sort();
  if (packages.length !== 261 || registry.length !== 249)
    throw new Error("Pinned lockfile package counts changed");
  if (workspace.join("\n") !== WORKSPACE.join("\n"))
    throw new Error("Pinned workspace package set changed");

  const queries = [
    ...CONTROLS.map(({ name, version }) => ({
      package: { ecosystem: "crates.io", name }, version,
    })),
    ...packages.map(({ name, version }) => ({
      package: { ecosystem: "crates.io", name }, version,
    })),
  ];
  const body = JSON.stringify({ queries });
  const result = await query(body);
  if (!result || !Array.isArray(result.results) ||
      result.results.length !== queries.length)
    throw new Error("OSV response shape or result count is invalid");

  for (const [index, item] of result.results.entries()) {
    if (!item || typeof item !== "object" || Array.isArray(item))
      throw new Error("Invalid OSV result at index " + index);
    if ("next_page_token" in item)
      throw new Error("OSV pagination is unsupported and cannot be ignored");
    if (item.vulns !== undefined && !Array.isArray(item.vulns))
      throw new Error("Invalid OSV vulnerability list at index " + index);
  }

  for (const [index, control] of CONTROLS.entries()) {
    const ids = new Set((result.results[index].vulns ?? []).map((item) => item.id));
    if (!ids.has(control.id))
      throw new Error("OSV positive control failed: " + control.id);
  }

  const findings = [];
  for (let index = CONTROLS.length; index < result.results.length; index += 1) {
    for (const vulnerability of result.results[index].vulns ?? []) {
      if (!vulnerability || typeof vulnerability.id !== "string")
        throw new Error("OSV returned an invalid vulnerability record");
      const packageItem = packages[index - CONTROLS.length];
      findings.push(packageItem.name + "@" + packageItem.version + ": " +
        vulnerability.id);
    }
  }

  console.log("OSV audit UTC: " + new Date().toISOString());
  console.log("mdBook source commit: " + COMMIT);
  console.log("Cargo.lock SHA-256: " + LOCK_SHA256);
  console.log("Cargo.lock packages queried: " + packages.length +
    " (249 registry, 12 pinned workspace)");
  console.log("OSV request SHA-256: " + hash("sha256", body));
  console.log("OSV positive controls: passed");
  console.log("OSV findings returned: " + findings.length);
  if (findings.length)
    throw new Error(findings.slice(0, 50).join("\n"));
}

main().catch((error) => {
  console.error("OSV audit failed: " + error.message);
  process.exitCode = 1;
});
