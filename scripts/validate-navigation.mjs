#!/usr/bin/env node
import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { dirname, join, posix, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { ASSETS, PAGES, outputPage } from "./site-manifest.mjs";

const ROOT = await realpath(resolve(dirname(fileURLToPath(import.meta.url)), ".."));
const MODE = process.argv[2];
const decoder = new TextDecoder("utf-8", { fatal: true });
const ENFORCED_FRAGMENTS = new Set([
  "03-Scanning_Networks.md",
  "14-Hacking_Web_Applications.md",
  "17-Hacking_Mobile_Platforms.md",
  "20-Cryptography.md",
]);
const CSP = "default-src 'none'; base-uri 'none'; connect-src 'none'; " +
  "font-src 'self'; form-action 'none'; frame-src 'none'; img-src 'self'; " +
  "object-src 'none'; script-src 'none'; style-src 'self'";
const TOKENS = [
  "--ink:#f3f6ef", "--muted:#929b8d", "--muted-2:#7f887b",
  "--void:#070a07", "--panel:#0d110d", "--panel-2:#111611",
  "--line:#252c24", "--line-soft:#171d17", "--acid:#adff23",
  "--brand-light:#c7c8ca", "--signal-cyan:#39e6c5",
  "--signal-violet:#7466ff",
];
const fail = (message) => { throw new Error(message); };
const safe = (value) => Boolean(value) && value === value.normalize("NFC") &&
  !posix.isAbsolute(value) && !value.includes("\\") &&
  !/[\0-\x1f\x7f]/u.test(value) && posix.normalize(value) === value &&
  value.split("/").every((part) => part && part !== "." && part !== "..");

function entities(value) {
  return value.replace(
    /&(?:#([0-9]+)|#x([0-9a-f]+)|amp|apos|colon|gt|lt|newline|quot|tab);/giu,
    (whole, decimal, hex) => {
      if (decimal || hex) {
        const point = Number.parseInt(decimal ?? hex, decimal ? 10 : 16);
        return Number.isSafeInteger(point) && point <= 0x10ffff
          ? String.fromCodePoint(point) : whole;
      }
      return new Map([
        ["&amp;", "&"], ["&apos;", "'"], ["&colon;", ":"], ["&gt;", ">"],
        ["&lt;", "<"], ["&newline;", "\n"], ["&quot;", '"'], ["&tab;", "\t"],
      ]).get(whole.toLowerCase()) ?? whole;
    },
  );
}

async function file(relative, text = false, root = ROOT) {
  if (!safe(relative)) fail("Unsafe path: " + relative);
  const absolute = join(root, ...relative.split("/"));
  const stat = await lstat(absolute);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size === 0)
    fail("Not a nonempty regular file: " + relative);
  if (await realpath(absolute) !== absolute)
    fail("Path resolves through a symlink: " + relative);
  const bytes = await readFile(absolute);
  if (!text) return bytes;
  try { return decoder.decode(bytes); }
  catch { fail("Not valid UTF-8: " + relative); }
}

async function absent(relative) {
  try { await lstat(join(ROOT, relative)); }
  catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  fail("Removed dependency/configuration file is still present: " + relative);
}

function prose(markdown, page) {
  const kept = [];
  let fence = null;
  for (const line of markdown.split("\n")) {
    if (!fence) {
      const open = line.match(/^\s*(\x60{3,}|~{3,})/u);
      if (open) {
        fence = { character: open[1][0], length: open[1].length };
        kept.push("");
        continue;
      }
    } else {
      const close = line.match(/^\s*(\x60{3,}|~{3,})\s*$/u);
      if (close && close[1][0] === fence.character &&
          close[1].length >= fence.length) {
        fence = null;
        kept.push("");
        continue;
      }
    }
    kept.push(fence ? "" : line);
  }
  if (fence) fail("Unclosed Markdown code fence in " + page);
  return kept.join("\n")
    .replace(/<!--[\s\S]*?-->/gu, "")
    .replace(/(\x60+)[^\n]*?\1/gu, "");
}

function attributes(tag) {
  const result = new Map();
  const pattern = /\s([a-z_:][a-z0-9_.:-]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>]+)))?/giu;
  for (const match of tag.matchAll(pattern))
    result.set(match[1].toLowerCase(), entities(match[2] ?? match[3] ?? match[4] ?? ""));
  return result;
}

function textContent(value) {
  return entities(value.replace(/<[^>]*>/gu, " ").replace(/\s+/gu, " ").trim());
}

function splitUrl(raw, origin) {
  const decodedEntities = entities(raw.trim());
  if (!decodedEntities || /[\0-\x1f\x7f\\]/u.test(decodedEntities))
    fail("Unsafe URL in " + origin + ": " + raw);
  if (/^(?:\/|\/\/)/u.test(decodedEntities) ||
      /%(?:00|0a|0d|2f|5c)/iu.test(decodedEntities))
    fail("Absolute or encoded-separator URL in " + origin + ": " + raw);
  const scheme = decodedEntities.match(/^([a-z][a-z0-9+.-]*):/iu)?.[1]?.toLowerCase();
  if (scheme) return { external: scheme, raw: decodedEntities };
  const hashAt = decodedEntities.indexOf("#");
  const beforeHash = hashAt < 0 ? decodedEntities : decodedEntities.slice(0, hashAt);
  const fragmentRaw = hashAt < 0 ? "" : decodedEntities.slice(hashAt + 1);
  const queryAt = beforeHash.indexOf("?");
  const pathRaw = queryAt < 0 ? beforeHash : beforeHash.slice(0, queryAt);
  let path;
  let fragment;
  try {
    path = decodeURIComponent(pathRaw);
    fragment = decodeURIComponent(fragmentRaw);
  } catch {
    fail("Malformed percent-encoding in " + origin + ": " + raw);
  }
  if (path.includes("%") || fragment.includes("%") || fragment.includes("#") ||
      /[\0-\x1f\x7f\\]/u.test(path + fragment))
    fail("Ambiguous encoded URL in " + origin + ": " + raw);
  return { external: "", path, fragment, raw: decodedEntities };
}

function summaryEntries(summary) {
  const matches = [...summary.matchAll(
    /^\s*[*+-]\s+\[([^\]]+)\]\(([^)]+)\)\s*$/gmu,
  )].map((match) => ({ title: match[1], path: match[2] }));
  if (matches.length !== 52)
    fail("SUMMARY.md must contain exactly 52 page entries");
  if (matches.map((item) => item.path).join("\n") !== PAGES.join("\n"))
    fail("SUMMARY.md does not exactly match the page manifest");
  if (matches.some((item) => /%[0-9a-f]{2}/iu.test(item.path)))
    fail("SUMMARY.md contains a URL-encoded page path");
  if (matches.some((item) => item.path.includes(" ")))
    fail("SUMMARY.md contains a page filename with spaces");
  return matches;
}

function checkCollisions(paths, label) {
  const normalized = new Set();
  const folded = new Set();
  for (const path of paths) {
    if (!safe(path)) fail(label + " contains an unsafe path: " + path);
    const nfc = path.normalize("NFC");
    const lower = nfc.toLocaleLowerCase("en-US");
    if (normalized.has(nfc) || folded.has(lower))
      fail(label + " contains a duplicate or case-fold collision: " + path);
    normalized.add(nfc);
    folded.add(lower);
  }
}

function checkCss(css, label) {
  const compact = css.replace(/\s+/gu, "").toLowerCase();
  for (const token of TOKENS)
    if (!compact.includes(token)) fail(label + " is missing token " + token);
  if (!compact.includes("color-scheme:dark"))
    fail(label + " does not default to dark color controls");
  if (/@import|url\s*\(|expression\s*\(|javascript\s*:|data\s*:/iu.test(css))
    fail(label + " contains a forbidden external or executable CSS construct");
}

function markdownTargets(markdown, page) {
  const clean = prose(markdown, page);
  if (/\{\{\s*#/u.test(clean))
    fail("mdBook directive is forbidden in " + page);
  if (/!\[\[[^\]]+\]\]/u.test(clean))
    fail("Obsidian image syntax is forbidden in " + page);
  if (/\[[^\]]+\]:\s*\S+/u.test(clean))
    fail("Reference-style Markdown links are unsupported in " + page);
  if (/\[[^\]]*\]\(\s*<[^>]+>\s*(?:["'][^"']*["'])?\s*\)/u.test(clean))
    fail("Angle-bracket Markdown destinations are unsupported in " + page);
  if (/\[[^\]]*\]\(\s*[^)\n]*\s+["'][^"']*["']\s*\)/u.test(clean))
    fail("Titled Markdown destinations are unsupported in " + page);
  if (/\[[^\]]*\]\([^\n)]*\([^\n)]*\)/u.test(clean))
    fail("Nested Markdown destinations are unsupported in " + page);
  if (/\[[^\]]*\]\(\s*[^)\n]*\s+[^)\n]*\)/u.test(clean))
    fail("Markdown destinations containing spaces are unsupported in " + page);
  if (/\]\(#\)/u.test(clean))
    fail("Placeholder fragment is forbidden in " + page);

  const active = /<(?:script|style|iframe|object|embed|form|meta|base|link|svg|use|video|audio|source|track|area|html|head|body|nav|main)\b/iu;
  if (active.test(clean)) fail("Active raw HTML is forbidden in " + page);
  if (/\s(?:on[a-z]+|style|srcdoc)\s*=/iu.test(clean))
    fail("Inline active HTML attribute is forbidden in " + page);

  const results = [];
  const pattern = /(!?)\[([^\]]*)\]\(\s*([^)]+?)\s*\)/gu;
  for (const match of clean.matchAll(pattern))
    results.push({ image: match[1] === "!", title: match[2], raw: match[3] });
  return results;
}

function sourceTarget(raw, page, image) {
  const url = splitUrl(raw, page);
  if (url.external) {
    if (image || !["http", "https", "mailto"].includes(url.external))
      fail("Forbidden URL scheme in " + page + ": " + raw);
    return null;
  }
  if (!url.path) return null;
  const target = posix.normalize(posix.join(posix.dirname(page), url.path));
  if (!safe(target)) fail("Local link escapes the repository in " + page);
  if (image) {
    if (!ASSETS.includes(target))
      fail("Image is not in the exact asset manifest: " + page + " -> " + target);
  } else if (/\.md$/iu.test(target) && !PAGES.includes(target)) {
    fail("Markdown target is not a published page: " + page + " -> " + target);
  }
  return target;
}

async function validateSource() {
  if (process.versions.node.split(".")[0] !== "24")
    fail("Validation requires Node.js 24");
  if (PAGES.length !== 52 || ASSETS.length !== 9)
    fail("Manifest counts changed");
  checkCollisions(PAGES, "Page manifest");
  checkCollisions(ASSETS, "Asset manifest");
  await Promise.all([
    absent("package.json"), absent("package-lock.json"), absent(".gitbook.yaml"),
    absent(".bookignore"), absent("GITBOOK_SETUP.md"),
  ]);

  const summary = await file("SUMMARY.md", true);
  const entries = summaryEntries(summary);
  for (const part of ["Core Modules", "Practical Labs", "Resources & References"]) {
    if (!summary.includes("\n# " + part + "\n") ||
        summary.includes("\n## " + part + "\n"))
      fail("SUMMARY.md part must be an H1: " + part);
  }

  await Promise.all([
    file("README.md"), file("SECURITY.md"), file("book.toml"),
    file("MDBOOK_SETUP.md"), file("theme/index.hbs"),
  ]);
  checkCss(await file("theme/css/general.css", true), "Theme CSS");

  const images = new Set();
  for (const page of PAGES) {
    const markdown = await file(page, true);
    for (const target of markdownTargets(markdown, page)) {
      const resolved = sourceTarget(target.raw, page, target.image);
      if (target.image && resolved) images.add(resolved);
    }
  }
  if ([...images].sort().join("\n") !== [...ASSETS].sort().join("\n"))
    fail("Markdown image references do not exactly match the asset manifest");
  for (const asset of ASSETS) {
    const bytes = await file(asset);
    const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    if (asset.endsWith(".png") && !bytes.subarray(0, 8).equals(png))
      fail("Invalid PNG signature: " + asset);
    if (asset.endsWith(".webp") &&
        (bytes.subarray(0, 4).toString("ascii") !== "RIFF" ||
         bytes.subarray(8, 12).toString("ascii") !== "WEBP"))
      fail("Invalid WebP signature: " + asset);
  }

  console.log("SUMMARY.md page entries: " + entries.length);
  console.log("Validated source pages: " + PAGES.length);
  console.log("Validated referenced images: " + images.size);
}

async function walk(root, relative = "") {
  const directory = relative ? join(root, ...relative.split("/")) : root;
  const stat = await lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() ||
      await realpath(directory) !== directory)
    fail("Output directory is unsafe: " + (relative || "_book"));
  const results = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const child = relative ? relative + "/" + entry.name : entry.name;
    if (!safe(child) || entry.isSymbolicLink())
      fail("Unsafe output entry: " + child);
    if (entry.isDirectory()) results.push(...await walk(root, child));
    else if (entry.isFile()) results.push(child);
    else fail("Unsupported output entry: " + child);
  }
  return results;
}

function htmlIds(html, page) {
  const ids = new Set();
  for (const match of html.matchAll(/\sid\s*=\s*(?:"([^"]+)"|'([^']+)')/giu)) {
    const id = entities(match[1] ?? match[2]);
    if (ids.has(id)) fail("Duplicate generated id in " + page + ": " + id);
    ids.add(id);
  }
  return ids;
}

function generatedTarget(raw, origin, kind) {
  const url = splitUrl(raw, origin);
  if (url.external) {
    if (kind !== "a" || !["http", "https", "mailto"].includes(url.external))
      fail("Forbidden generated URL scheme in " + origin + ": " + raw);
    return { external: true };
  }
  const base = posix.dirname(origin);
  let target = url.path ? posix.normalize(posix.join(base, url.path)) : origin;
  if (url.path.endsWith("/")) target = posix.join(target, "index.html");
  if (!safe(target)) fail("Generated link escapes the artifact in " + origin);
  return { external: false, target, fragment: url.fragment };
}

async function validateGenerated() {
  if (process.versions.node.split(".")[0] !== "24")
    fail("Validation requires Node.js 24");
  const book = join(ROOT, "_book");
  const entries = summaryEntries(await file("SUMMARY.md", true));
  const expected = [
    ...PAGES.map(outputPage), "css/general.css", ...ASSETS, ".nojekyll",
  ].sort();
  const actual = (await walk(book)).sort();
  checkCollisions(actual, "Generated artifact");
  if (actual.join("\n") !== expected.join("\n"))
    fail("Generated artifact does not match the exact 63-file allowlist");
  if (actual.some((path) => /\.(?:c?m?js|map|wasm|md|markdown)$/iu.test(path)))
    fail("Generated artifact contains forbidden code, map, or raw Markdown");

  const sourceCss = await file("theme/css/general.css");
  const outputCss = await file("css/general.css", false, book);
  if (!sourceCss.equals(outputCss))
    fail("Generated CSS differs from the reviewed theme CSS");
  checkCss(decoder.decode(outputCss), "Generated CSS");
  for (const asset of ASSETS) {
    const source = await file(asset);
    const output = await file(asset, false, book);
    if (!source.equals(output)) fail("Generated asset differs from source: " + asset);
  }

  const htmlByPage = new Map();
  const idsByPage = new Map();
  for (const page of PAGES) {
    const output = outputPage(page);
    const html = await file(output, true, book);
    htmlByPage.set(output, html);
    idsByPage.set(output, htmlIds(html, output));
  }

  let references = 0;
  let unresolvedLegacyFragments = 0;
  for (let index = 0; index < PAGES.length; index += 1) {
    const source = PAGES[index];
    const output = outputPage(source);
    const html = htmlByPage.get(output);
    if (!/<html\b[^>]*\bclass="cybrief-dark"/iu.test(html))
      fail("Generated page is not dark by default: " + output);
    if (!/<main\b[^>]*\bid="main-content"/iu.test(html) ||
        !/<a\b[^>]*\bclass="skip-link"[^>]*\bhref="#main-content"/iu.test(html) ||
        !/<nav\b[^>]*\bdata-docs-sidebar\b/iu.test(html))
      fail("Generated page is missing accessibility/navigation structure: " + output);
    if (/<(?:script|style|base|iframe|object|embed|form|svg|use|video|audio|source|track|area)\b/iu.test(html) ||
        /\s(?:on[a-z]+|style|srcdoc|srcset|poster)\s*=/iu.test(html))
      fail("Generated page contains active content: " + output);

    const cspTags = [...html.matchAll(/<meta\b[^>]*http-equiv="Content-Security-Policy"[^>]*>/giu)];
    if (cspTags.length !== 1 || attributes(cspTags[0][0]).get("content") !== CSP)
      fail("Generated page CSP is missing or changed: " + output);
    const cssTags = [...html.matchAll(/<link\b[^>]*rel="stylesheet"[^>]*>/giu)];
    if (cssTags.length !== 1 || html.indexOf(cspTags[0][0]) > html.indexOf(cssTags[0][0]))
      fail("CSP must precede the one generated stylesheet: " + output);
    const cssTarget = generatedTarget(attributes(cssTags[0][0]).get("href") ?? "", output, "link");
    if (cssTarget.external || cssTarget.target !== "css/general.css")
      fail("Generated stylesheet target changed: " + output);
    const schemes = [...html.matchAll(/<meta\b[^>]*name="color-scheme"[^>]*>/giu)];
    if (schemes.length !== 1 || attributes(schemes[0][0]).get("content") !== "dark")
      fail("Generated page color scheme is not dark: " + output);

    const sidebarMatch = html.match(/<nav\b[^>]*data-docs-sidebar[^>]*>([\s\S]*?)<\/nav>/iu);
    if (!sidebarMatch) fail("Generated sidebar is missing: " + output);
    const sidebarLinks = [...sidebarMatch[1].matchAll(/<a\b[^>]*>[\s\S]*?<\/a>/giu)];
    if (sidebarLinks.length !== 52)
      fail("Generated sidebar must contain exactly 52 page links: " + output);
    for (let item = 0; item < sidebarLinks.length; item += 1) {
      const tag = sidebarLinks[item][0];
      const href = attributes(tag.slice(0, tag.indexOf(">") + 1)).get("href") ?? "";
      const target = generatedTarget(href, output, "a");
      if (target.external || target.target !== outputPage(entries[item].path) ||
          target.fragment)
        fail("Generated sidebar order or target changed: " + output);
      const title = textContent(tag.replace(/^<a\b[^>]*>|<\/a>$/giu, ""));
      if (title !== entities(entries[item].title))
        fail("Generated sidebar title changed: " + output + " -> " + title);
    }

    for (const direction of ["previous", "next"]) {
      const expectedIndex = direction === "previous" ? index - 1 : index + 1;
      const match = html.match(new RegExp(
        '<a\\b[^>]*class="pager-link pager-' + direction + '"[^>]*>[\\s\\S]*?<\\/a>',
        "iu",
      ));
      if (expectedIndex < 0 || expectedIndex >= PAGES.length) {
        if (match) fail("Unexpected " + direction + " link: " + output);
      } else {
        if (!match) fail("Missing " + direction + " link: " + output);
        const open = match[0].slice(0, match[0].indexOf(">") + 1);
        const attrs = attributes(open);
        const target = generatedTarget(attrs.get("href") ?? "", output, "a");
        if (target.external || target.target !== outputPage(PAGES[expectedIndex]) ||
            attrs.get("rel") !== (direction === "previous" ? "prev" : "next") ||
            !(attrs.get("aria-label") ?? "").trim())
          fail("Incorrect or inaccessible " + direction + " link: " + output);
      }
    }

    for (const match of html.matchAll(/<(a|img|link)\b[^>]*>/giu)) {
      const kind = match[1].toLowerCase();
      const attrs = attributes(match[0]);
      const raw = attrs.get(kind === "img" ? "src" : "href");
      if (raw === undefined) fail("Generated " + kind + " lacks a URL: " + output);
      const target = generatedTarget(raw, output, kind);
      references += 1;
      if (target.external) continue;
      if (!actual.includes(target.target))
        fail("Generated link target is missing: " + output + " -> " + target.target);
      if (/\.md$/iu.test(target.target))
        fail("Generated artifact links to raw Markdown: " + output);
      if (target.fragment && /\.html$/iu.test(target.target) &&
          !idsByPage.get(target.target)?.has(target.fragment)) {
        if (ENFORCED_FRAGMENTS.has(source))
          fail("Malformed enforced fragment: " + source + " -> #" + target.fragment);
        unresolvedLegacyFragments += 1;
      }
    }
  }

  console.log("Generated HTML pages: " + PAGES.length);
  console.log("Generated artifact files: " + actual.length);
  console.log("Generated references checked: " + references);
  console.log("Raw Markdown files in artifact: 0");
  console.log("Unresolved legacy fragments (non-blocking): " +
    unresolvedLegacyFragments);
}

if (!["source", "generated"].includes(MODE) || process.argv.length !== 3) {
  console.error("usage: node scripts/validate-navigation.mjs <source|generated>");
  process.exit(2);
}
(MODE === "source" ? validateSource() : validateGenerated()).catch((error) => {
  console.error("Validation failed: " + error.message);
  process.exitCode = 1;
});
