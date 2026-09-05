FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS mdbook-builder

COPY mdbook-no-client-js.patch /tmp/mdbook-no-client-js.patch
COPY verify-binary.rs /tmp/verify-binary.rs

RUN set -eux; \
    test "$(sha256sum /tmp/mdbook-no-client-js.patch | cut -d' ' -f1)" = "69c8843879961d6e8d130714d0a5306ada41dff12b1aa2c84a2efb29a31223d6"; \
    git init /tmp/mdbook; \
    cd /tmp/mdbook; \
    git remote add origin https://github.com/rust-lang/mdBook.git; \
    git fetch --depth=1 origin "a57975d499a660fd11da05a9010e93fe245525ba"; \
    git checkout --detach FETCH_HEAD; \
    test "$(git rev-parse 'HEAD^{commit}')" = "a57975d499a660fd11da05a9010e93fe245525ba"; \
    test "$(git rev-parse HEAD:Cargo.lock)" = "ef047c8faab35b8fed2203aaed73e71482f96b7b"; \
    test "$(sha256sum Cargo.lock | cut -d' ' -f1)" = "603ffab1532a5bc934214693623e1fdb27ae5b40e016f88a3b4ce384b571694e"; \
    test "$(git rev-parse HEAD:crates/mdbook-html/src/theme/mod.rs)" = "c55a30eff360db1ee2e49cff647ecf2f2313a2ce"; \
    test "$(git rev-parse HEAD:crates/mdbook-html/src/theme/playground_editor.rs)" = "2fd385acf041032a0fcb541c75666719810289ed"; \
    test "$(git rev-parse HEAD:crates/mdbook-html/src/html_handlebars/static_files.rs)" = "e0415cb40bfa50306fca15480295cd3bce974784"; \
    git apply --check --index /tmp/mdbook-no-client-js.patch; \
    git apply --index /tmp/mdbook-no-client-js.patch; \
    git diff --check; \
    test "$(git hash-object crates/mdbook-html/src/theme/mod.rs)" = "8ffeecfcf5f0cc5f537c35e6eaf17adaf0fe99b8"; \
    test "$(git hash-object crates/mdbook-html/src/theme/playground_editor.rs)" = "f526db83b73e5501e4c07ccad0fc55078177b729"; \
    test "$(git hash-object crates/mdbook-html/src/html_handlebars/static_files.rs)" = "7523f134995555aebf46d4f23a102bcd55189c1a"; \
    cargo test --locked --no-default-features -p mdbook-html; \
    cargo build --release --locked --no-default-features --bin mdbook; \
    rustc --edition=2021 -O /tmp/verify-binary.rs -o /tmp/verify-binary; \
    /tmp/verify-binary target/release/mdbook \
      crates/mdbook-html/front-end/templates/index.hbs \
      crates/mdbook-html/front-end/templates/redirect.hbs \
      crates/mdbook-html/front-end/templates/toc.js.hbs \
      crates/mdbook-html/front-end/js/book.js \
      crates/mdbook-html/front-end/js/highlight.js \
      crates/mdbook-html/front-end/js/clipboard.min.js \
      crates/mdbook-html/front-end/playground_editor/editor.js \
      crates/mdbook-html/front-end/playground_editor/ace.js \
      crates/mdbook-html/front-end/playground_editor/mode-rust.js \
      crates/mdbook-html/front-end/playground_editor/theme-dawn.js \
      crates/mdbook-html/front-end/playground_editor/theme-tomorrow_night.js; \
    ! grep -aFq "Highlight.js 10.1.1" target/release/mdbook; \
    ! grep -aFq "clipboard.js v2.0.4" target/release/mdbook; \
    ! grep -aFq "window.location.replace(redirectUrl)" target/release/mdbook

FROM mcr.microsoft.com/devcontainers/javascript-node:5-24-bookworm@sha256:fe599ef9d866c4adb1fbb1f8a37af2892a090e5fd0d93feb8471e9de15a5f14d

COPY --from=mdbook-builder --chmod=0755 /tmp/mdbook/target/release/mdbook /usr/local/bin/mdbook
COPY --from=mdbook-builder --chmod=0644 /tmp/mdbook/Cargo.lock /usr/local/share/mdbook/Cargo.lock
COPY --from=mdbook-builder --chmod=0644 /tmp/mdbook/LICENSE /usr/local/share/licenses/mdbook/LICENSE

RUN node --version | grep -Eq '^v24[.]' && mdbook --version
USER node
