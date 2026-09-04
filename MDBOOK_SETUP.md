# Hardened mdBook maintenance

The supported development environment is GitHub Codespaces. The repository does not require an npm install: Node.js 24 runs dependency-free validation and preview scripts, while mdBook builds the static site.

## Rebuild the Codespace container

After a generator or container change, run **Dev Containers: Rebuild Container** from the Codespaces command palette. The checked-in container requires at least two CPUs, runs as the unprivileged `node` user, and forwards preview port 4000 as private.

Confirm the toolchain:

```sh
node --version
mdbook --version
```

Node must report major version 24.

## Validate and build

Run these commands from the repository root in Codespaces:

```sh
node scripts/validate-navigation.mjs source
node scripts/audit-cargo-lock-osv.mjs /usr/local/share/mdbook/Cargo.lock
node scripts/stage-mdbook.mjs
mdbook build
test -f _book/toc.html
test ! -L _book/toc.html
rm -- _book/toc.html
node scripts/validate-navigation.mjs generated
node scripts/preview.mjs
```

Open the forwarded port only after confirming its visibility remains **private**. The preview server binds to `127.0.0.1:4000`; stop it with `Ctrl+C`.

The final validation accepts exactly 52 HTML pages, `css/general.css`, nine referenced images, and `.nojekyll`. It rejects scripts, JavaScript files, raw Markdown, undeclared files, symlinks, unsafe URLs, missing navigation targets, and changes to the reviewed theme or assets.

## Generator trust boundary

The container builds mdBook from upstream commit `a57975d499a660fd11da05a9010e93fe245525ba` with Rust 1.88, `--locked`, and `--no-default-features`. It verifies:

- Cargo.lock SHA-256 `603ffab1532a5bc934214693623e1fdb27ae5b40e016f88a3b4ce384b571694e` and Git blob `ef047c8faab35b8fed2203aaed73e71482f96b7b`;
- the local JS-removal patch SHA-256 `a1693479d4bccf30a7e494923a17dd40a544a79846cc506a1622533c2060e947`;
- upstream and patched Rust source blob IDs;
- absence of all 11 upstream browser/template blobs from the compiled binary; and
- the generated artifact's no-script, no-JavaScript allowlist.

The patch is necessary because the stock generator embeds browser JavaScript that this site neither needs nor permits. The theme is dark by default, uses the CyBrief/0x5244 palette, and has no theme toggle, client-side search, or syntax-highlighting runtime. Use the browser's Find command for current-page search.

The OSV check sends all 261 exact Cargo.lock package name/version pairs to the live OSV `querybatch` API and requires two known-vulnerable positive controls to be returned. It fails closed on network, schema, count, pagination, or finding errors. A successful run means zero advisories known to OSV for this exact locked Rust graph at query time—not zero vulnerabilities. Database ingestion delay, newly disclosed issues, reachability, the compiler, runner, base image, and source-level defects remain separate risks.

`npm audit` is not applicable after this migration: there is no package manifest, npm lockfile, or installed npm dependency graph. Node 24 is used only for dependency-free repository scripts.

## Updating mdBook

Make generator updates in a pull request; never update `main` directly. Review the upstream diff, rebase the JS-removal patch, refresh every pinned commit/blob/digest/hash, rerun the targeted mdBook HTML tests, and rerun the full source, OSV, build, artifact, link, and preview checks. Docker and GitHub Actions pins receive weekly Dependabot proposals. The arbitrary mdBook Git commit and its Rust lockfile require manual review; the weekly Actions run checks the existing lock against newly published OSV advisories without deploying.
