import fs from "node:fs";
import path from "node:path";

const root = fs.realpathSync(".");
const summary = path.join(root, "SUMMARY.md");
const errors = [];
const external = /^[a-z][a-z\d+.-]*:/i;
const show = (file) =>
  JSON.stringify(path.relative(root, file).split(path.sep).join("/") || ".");
const issue = (context, message) => errors.push(`${context}: ${message}`);

function within(base, target) {
  const value = path.relative(base, target);
  return value === "" ||
    (value !== ".." && !value.startsWith(`..${path.sep}`) && !path.isAbsolute(value));
}

function regular(base, file, context) {
  let info;
  try { info = fs.lstatSync(file); }
  catch { issue(context, `missing file ${show(file)}`); return false; }
  if (info.isSymbolicLink() || !info.isFile()) {
    issue(context, `not a regular file: ${show(file)}`);
    return false;
  }
  let actual;
  try { actual = fs.realpathSync(file); }
  catch { issue(context, `cannot resolve ${show(file)}`); return false; }
  if (!within(base, actual)) {
    issue(context, `resolved path escapes ${show(base)}: ${show(file)}`);
    return false;
  }
  return true;
}

function summaryEntries() {
  if (!regular(root, summary, "SUMMARY.md")) return [];
  return fs.readFileSync(summary, "utf8").split(/\r?\n/)
    .map((line, index) => ({ line, number: index + 1 }))
    .filter(({ line }) => /^\s*[-+*]\s+/.test(line));
}

function prose(markdown) {
  let fence;
  return markdown.replace(/<!--[\s\S]*?-->/g, "").split(/\r?\n/).map((line) => {
    const match = line.match(/^\s{0,3}(`{3,}|~{3,})/);
    if (match) {
      const next = [match[1][0], match[1].length];
      if (!fence) fence = next;
      else if (fence[0] === next[0] && next[1] >= fence[1]) fence = undefined;
      return "";
    }
    return fence ? "" : line.replace(/`+[^`]*`+/g, "");
  });
}

function validateSource() {
  const entries = summaryEntries();
  const pages = new Set();
  for (const entry of entries) {
    const context = `SUMMARY.md:${entry.number}`;
    const match = entry.line.match(/^\s*[-+*]\s+\[[^\]\n]+\]\(([^)\s]+)\)\s*$/);
    if (!match) { issue(context, "malformed page entry"); continue; }
    const destination = match[1];
    if (destination.startsWith("//") || destination.startsWith("#") ||
        external.test(destination)) {
      issue(context, "entry is not a local page");
      continue;
    }

    const encoded = destination.split(/[?#]/, 1)[0];
    let decoded;
    try { decoded = decodeURIComponent(encoded); }
    catch {
      issue(context, `malformed URI encoding: ${JSON.stringify(destination)}`);
      continue;
    }
    if (/%[0-9a-f]{2}/i.test(encoded)) {
      issue(context, `URL-encoded Markdown path: ${JSON.stringify(destination)}`);
    }
    if (/[\u0000-\u001f\u007f]/.test(decoded) || decoded.includes("\\")) {
      issue(context, `unsafe path: ${JSON.stringify(destination)}`);
      continue;
    }
    if (!/\.md$/i.test(decoded)) {
      issue(context, `page target is not Markdown: ${JSON.stringify(destination)}`);
      continue;
    }

    const file = path.resolve(root, decoded);
    if (!within(root, file)) {
      issue(context, `path escapes repository: ${JSON.stringify(destination)}`);
      continue;
    }
    if (!regular(root, file, context)) continue;
    if (!fs.readFileSync(file, "utf8").trim()) {
      issue(context, `empty linked page ${show(file)}`);
      continue;
    }
    pages.add(file);
  }

  for (const file of [...pages].sort()) {
    const name = path.relative(root, file).split(path.sep).join("/");
    prose(fs.readFileSync(file, "utf8")).forEach((line, index) => {
      if (/\]\(#\s/.test(line)) issue(`${name}:${index + 1}`, "fragment begins with whitespace");
      if (/\[[^\]\n]*\(#[-\w]/.test(line)) {
        issue(`${name}:${index + 1}`, "probable missing ] before fragment");
      }
    });
  }
  console.log(`SUMMARY.md page entries: ${entries.length}`);
  console.log(`SUMMARY.md local pages checked: ${pages.size}`);
}

function walk(directory, files) {
  const entries = fs.readdirSync(directory, { withFileTypes: true })
    .sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    const file = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) issue(show(file), "generated output contains a symbolic link");
    else if (entry.isDirectory()) walk(file, files);
    else if (entry.isFile()) files.push(file);
    else issue(show(file), "generated output contains an unsupported file");
  }
}

function decodeHtml(value) {
  const named = { amp: "&", apos: "'", colon: ":", quot: '"', sol: "/" };
  return value.replace(/&(?:#(\d+)|#x([0-9a-f]+)|([a-z]+));/gi,
    (entity, decimal, hexadecimal, name) => {
      if (name) return named[name.toLowerCase()] ?? entity;
      const code = Number.parseInt(decimal ?? hexadecimal, hexadecimal ? 16 : 10);
      return code >= 0 && code <= 0x10ffff ? String.fromCodePoint(code) : "\ufffd";
    });
}

function inspect(html) {
  const clean = html.replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<(script|style)\b([^>]*)>[\s\S]*?<\/\1\s*>/gi, "<$1$2></$1>");
  const anchors = new Set();
  const references = [];
  if (/<base\b[^>]*\shref\s*=/i.test(clean)) {
    references.push({ attribute: "base", value: "" });
  }
  for (const match of clean.matchAll(/\s(?:id|name)\s*=\s*(["'])([^"']*)\1/gi)) {
    if (match[2]) anchors.add(decodeHtml(match[2]));
  }
  for (const match of clean.matchAll(/\s(href|src)\s*=\s*(["'])([^"']*)\2/gi)) {
    references.push({ attribute: match[1].toLowerCase(), value: decodeHtml(match[3]) });
  }
  return { anchors, references };
}

function validateBook(argument) {
  const requested = path.resolve(root, argument);
  if (!within(root, requested)) {
    issue("--book", `path escapes repository: ${JSON.stringify(argument)}`);
    return;
  }
  let info;
  try { info = fs.lstatSync(requested); }
  catch { issue("--book", `missing directory ${show(requested)}`); return; }
  if (info.isSymbolicLink() || !info.isDirectory()) {
    issue("--book", `${show(requested)} is not a regular directory`);
    return;
  }
  const book = fs.realpathSync(requested);
  if (!within(root, book)) {
    issue("--book", `resolved directory escapes repository: ${show(requested)}`);
    return;
  }

  const files = [];
  walk(book, files);
  const markdown = files.filter((file) => /\.md$/i.test(file));
  markdown.forEach((file) => issue(show(file), "raw Markdown in generated output"));
  const htmlFiles = files.filter((file) => /\.html?$/i.test(file)).sort();
  const documents = new Map(htmlFiles.map((file) =>
    [file, inspect(fs.readFileSync(file, "utf8"))]));
  const expected = summaryEntries().length;
  if (htmlFiles.length !== expected) {
    issue("--book", `expected ${expected} HTML pages, found ${htmlFiles.length}`);
  }

  let checked = 0;
  for (const [page, document] of documents) {
    const relative = path.relative(book, page).split(path.sep)
      .map(encodeURIComponent).join("/");
    const base = new URL(relative, "https://validator.invalid/");
    for (const reference of document.references) {
      checked += 1;
      const context = `${show(page)} ${reference.attribute}=${
        JSON.stringify(reference.value)}`;
      if (reference.attribute === "base") {
        issue(context, "<base href> is unsupported");
        continue;
      }
      const value = reference.value.trim();
      if (!value) {
        if (reference.attribute === "src") issue(context, "empty source URL");
        continue;
      }
      if (value.startsWith("//") || external.test(value)) continue;

      let url;
      try { url = new URL(value, base); }
      catch { issue(context, "malformed local URL"); continue; }
      if (url.origin !== base.origin) continue;
      if (/%(?:2f|5c)/i.test(url.pathname)) {
        issue(context, "encoded path separator");
        continue;
      }

      let pathname;
      let fragment;
      try {
        pathname = decodeURIComponent(url.pathname);
        fragment = decodeURIComponent(url.hash.slice(1));
      } catch { issue(context, "malformed percent encoding"); continue; }
      if (/[\u0000-\u001f\u007f]/.test(pathname) || pathname.includes("\\")) {
        issue(context, "unsafe decoded path");
        continue;
      }
      if (/\.md$/i.test(pathname)) issue(context, "generated link points to raw Markdown");

      let target = path.resolve(book, `.${pathname}`);
      if (!within(book, target)) {
        issue(context, "target escapes generated output");
        continue;
      }
      try {
        const targetInfo = fs.lstatSync(target);
        if (pathname.endsWith("/") && !targetInfo.isDirectory()) {
          issue(context, "trailing slash targets a non-directory");
          continue;
        }
        if (targetInfo.isDirectory()) target = path.join(target, "index.html");
      } catch { issue(context, `missing target ${show(target)}`); continue; }
      if (!regular(book, target, context)) continue;
      if (fragment && fragment.toLowerCase() !== "top" && /\.html?$/i.test(target) &&
          !documents.get(target)?.anchors.has(fragment)) {
        issue(context, `missing fragment ${JSON.stringify(fragment)} in ${show(target)}`);
      }
    }
  }
  console.log(`Generated HTML pages: ${htmlFiles.length}`);
  console.log(`Generated HTML references inspected: ${checked}`);
  console.log(`Raw Markdown files in generated output: ${markdown.length}`);
}

const [mode, argument] = process.argv.slice(2);
try {
  if (mode === "--source" && argument === undefined) validateSource();
  else if (mode === "--book") validateBook(argument ?? "_book");
  else {
    console.error("Usage: node scripts/validate-navigation.mjs --source | --book [directory]");
    process.exitCode = 2;
  }
} catch (error) {
  issue("validator", error instanceof Error ? error.message : String(error));
}

if (errors.length) {
  const unique = [...new Set(errors)].sort();
  console.error(`Navigation validation failed with ${unique.length} error(s):`);
  unique.forEach((error) => console.error(`- ${error}`));
  process.exitCode = 1;
} else if (process.exitCode === undefined) {
  console.log("Navigation validation passed.");
}
