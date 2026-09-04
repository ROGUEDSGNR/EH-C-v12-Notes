#!/usr/bin/env node
import { lstat, readFile, realpath } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, extname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const HOST = "127.0.0.1";
const PORT = 4000;
const ROOT = await realpath(resolve(dirname(fileURLToPath(import.meta.url)), ".."));
const BOOK = join(ROOT, "_book");
const CSP = "default-src 'none'; base-uri 'none'; connect-src 'none'; " +
  "font-src 'self'; form-action 'none'; frame-src 'none'; img-src 'self'; " +
  "object-src 'none'; script-src 'none'; style-src 'self'";
const HEADERS = {
  "Cache-Control": "no-store",
  "Content-Security-Policy": CSP + "; frame-ancestors 'none'",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};
const TYPES = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".png", "image/png"],
  [".webp", "image/webp"],
]);

function reply(response, status, body) {
  response.writeHead(status, {
    ...HEADERS,
    "Content-Type": "text/plain; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
  });
  response.end(body);
}

async function main() {
  const rootStat = await lstat(BOOK);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink() ||
      await realpath(BOOK) !== BOOK)
    throw new Error("_book is not a real repository directory");

  const server = createServer((request, response) => {
    void (async () => {
      if (request.method !== "GET" && request.method !== "HEAD") {
        reply(response, 405, "Method Not Allowed\n");
        return;
      }
      const raw = request.url ?? "";
      if (!raw.startsWith("/") || raw.startsWith("//") ||
          raw.includes("\\") || raw.length > 2048)
        throw new Error("bad path");
      const encoded = raw.split("?", 1)[0];
      if (/%(?:2f|5c)/iu.test(encoded)) throw new Error("bad path");
      const decoded = decodeURIComponent(encoded);
      if (decoded.includes("%") || /[\0-\x1f\x7f]/u.test(decoded) ||
          decoded.split("/").some((part) => part === "." || part === ".."))
        throw new Error("bad path");

      let file = resolve(BOOK, "." + decoded);
      if (file !== BOOK && !file.startsWith(BOOK + sep))
        throw new Error("bad path");
      let stat = await lstat(file);
      if (stat.isDirectory()) {
        file = join(file, "index.html");
        stat = await lstat(file);
      }
      if (!stat.isFile() || stat.isSymbolicLink() ||
          await realpath(file) !== file || stat.size > 32 * 1024 * 1024)
        throw new Error("unsafe file");

      const type = TYPES.get(extname(file).toLowerCase());
      if (!type) {
        reply(response, 415, "Unsupported Media Type\n");
        return;
      }
      const body = await readFile(file);
      response.writeHead(200, {
        ...HEADERS,
        "Content-Type": type,
        "Content-Length": body.length,
      });
      response.end(request.method === "HEAD" ? undefined : body);
    })().catch(() => reply(response, 404, "Not Found\n"));
  });

  server.once("error", (error) => {
    console.error("Preview failed: " + error.message);
    process.exitCode = 1;
  });
  for (const signal of ["SIGINT", "SIGTERM"])
    process.once(signal, () => server.close());

  server.listen(PORT, HOST, () => {
    console.log("Private preview: http://" + HOST + ":" + PORT + "/");
  });
}

main().catch((error) => {
  console.error("Preview failed: " + error.message);
  process.exitCode = 1;
});
