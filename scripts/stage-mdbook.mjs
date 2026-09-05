#!/usr/bin/env node
import {
  lstat, mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile,
} from "node:fs/promises";
import { dirname, join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ASSETS, PAGES, stagedPage } from "./site-manifest.mjs";

const ROOT = await realpath(resolve(dirname(fileURLToPath(import.meta.url)), ".."));
const STAGE = join(ROOT, "_mdbook-src");
const decoder = new TextDecoder("utf-8", { fatal: true });
const fail = (message) => { throw new Error(message); };
const safe = (value) => Boolean(value) && !posix.isAbsolute(value) &&
  !value.includes("\\") && !/[\0-\x1f\x7f]/u.test(value) &&
  posix.normalize(value) === value &&
  value.split("/").every((part) => part && part !== "." && part !== "..");

async function source(relative, asText = false) {
  if (!safe(relative)) fail("Unsafe source path: " + relative);
  const absolute = join(ROOT, ...relative.split("/"));
  const stat = await lstat(absolute);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size === 0)
    fail("Source is not a nonempty regular file: " + relative);
  if (await realpath(absolute) !== absolute)
    fail("Source resolves through a symlink: " + relative);
  const content = await readFile(absolute);
  if (!asText) return content;
  try { return decoder.decode(content); }
  catch { fail("Source is not valid UTF-8: " + relative); }
}

async function put(root, relative, content) {
  const destination = join(root, ...relative.split("/"));
  await mkdir(dirname(destination), { recursive: true });
  await writeFile(destination, content, { flag: "wx", mode: 0o644 });
}

function imageTarget(raw, page) {
  if (/^(?:\/|\/\/)|\\|[?#]/u.test(raw) || /^[a-z][a-z0-9+.-]*:/iu.test(raw))
    fail("Unsafe image target in " + page + ": " + raw);
  let decoded;
  try { decoded = decodeURIComponent(raw); }
  catch { fail("Malformed image target in " + page + ": " + raw); }
  const target = posix.normalize(posix.join(posix.dirname(page), decoded));
  if (!safe(target)) fail("Image escapes the repository in " + page);
  return target;
}

function checkImage(relative, content) {
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (relative.endsWith(".png") && !content.subarray(0, 8).equals(png))
    fail("Invalid PNG signature: " + relative);
  if (relative.endsWith(".webp") &&
      (content.subarray(0, 4).toString("ascii") !== "RIFF" ||
       content.subarray(8, 12).toString("ascii") !== "WEBP"))
    fail("Invalid WebP signature: " + relative);
}

async function main() {
  if (PAGES.length !== 52 || new Set(PAGES).size !== 52)
    fail("Page manifest must contain 52 unique paths");
  if (ASSETS.length !== 9 || new Set(ASSETS).size !== 9)
    fail("Asset manifest must contain 9 unique paths");
  if (![...PAGES, ...ASSETS].every(safe))
    fail("Site manifest contains an unsafe path");

  const summary = await source("SUMMARY.md", true);
  const targets = [...summary.matchAll(
    /^\s*[*+-]\s+\[[^\]]+\]\(([^)]+)\)\s*$/gmu,
  )].map((match) => match[1]);
  if (targets.join("\n") !== PAGES.join("\n"))
    fail("SUMMARY.md does not exactly match the 52-page manifest");
  if (/%[0-9a-f]{2}/iu.test(targets.join("\n")))
    fail("SUMMARY.md contains a URL-encoded Markdown path");
  for (const part of ["Core Modules", "Practical Labs", "Resources & References"]) {
    if (!summary.includes("\n# " + part + "\n") ||
        summary.includes("\n## " + part + "\n"))
      fail("SUMMARY.md part must be H1: " + part);
  }

  const pages = new Map();
  const referenced = new Set();
  for (const page of PAGES) {
    const markdown = await source(page, true);
    if (/\{\{\s*#/u.test(markdown))
      fail("mdBook directive is forbidden: " + page);
    for (const match of markdown.matchAll(/!\[[^\]]*\]\(\s*<?([^)\s>]+)>?/gu))
      referenced.add(imageTarget(match[1], page));
    pages.set(page, Buffer.from(markdown, "utf8"));
  }
  if ([...referenced].sort().join("\n") !== [...ASSETS].sort().join("\n"))
    fail("Referenced images do not exactly match the 9-asset manifest");

  const assets = new Map();
  for (const asset of ASSETS) {
    const content = await source(asset);
    checkImage(asset, content);
    assets.set(asset, content);
  }

  const stagedSummary = summary.replace("(README.md)", "(index.md)");
  if (stagedSummary === summary ||
      stagedSummary.replace("(index.md)", "(README.md)") !== summary)
    fail("SUMMARY.md must contain exactly one README.md landing page");

  const temp = await mkdtemp(join(ROOT, "._mdbook-src-"));
  try {
    await put(temp, "SUMMARY.md", Buffer.from(stagedSummary, "utf8"));
    for (const page of PAGES) await put(temp, stagedPage(page), pages.get(page));
    for (const asset of ASSETS) await put(temp, asset, assets.get(asset));

    try {
      const old = await lstat(STAGE);
      if (!old.isDirectory() || old.isSymbolicLink() ||
          await realpath(STAGE) !== STAGE)
        fail("_mdbook-src is not a real repository directory");
      await rm(STAGE, { recursive: true });
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    await rename(temp, STAGE);
  } catch (error) {
    await rm(temp, { recursive: true, force: true });
    throw error;
  }

  console.log("Staged 52 pages and 9 assets in _mdbook-src.");
}

main().catch((error) => {
  console.error("Staging failed: " + error.message);
  process.exitCode = 1;
});
