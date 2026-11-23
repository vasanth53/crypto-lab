# Task-first redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reorganise Crypto Lab around four plain-language tasks plus an Advanced tab, with tests that gate deploy.

**Architecture:** Crypto moves to `cryptolab.core` (no DOM); `cryptolab.app` is DOM wiring only. The self-test list lives in `core` and is run both by the in-page Self-test button and by a Node test build in CI.

**Tech Stack:** ClojureScript, shadow-cljs 2.28.20, Web Crypto, Google Closure hashes, GitHub Pages.

**Spec:** `docs/superpowers/specs/2026-11-23-task-first-redesign-design.md`

## Global Constraints

- No new dependencies, no server.
- Lock format v1: text `cl1.` + base64(`salt16 | iv12 | ciphertext`); file bytes `CL1` + `salt16 | iv12 | ciphertext`; PBKDF2-SHA256, 600,000 iterations.
- Text without the `cl1.` prefix unlocks with 210,000 iterations.
- Simple-tab signing is ECDSA P-256 / SHA-256, keys as PEM (SPKI, PKCS#8), signature base64.
- Error copy: "Wrong password, or the text was changed." / "That isn't a key this tool can read." / "That doesn't look like a checksum".
- No prefilled password.

## Review Focus

1. Pasted checksum in `sha256sum` form (`<hash>  file.iso`) or upper case: should still match. Test in Task 1.
2. Unlocking garbage or truncated text: plain error, no raw exception. Test in Task 1.
3. Unlocking a file that was never locked here: says so, distinct from wrong password. Test in Task 1.
4. Typing fast in a live field: an older, slower result must not overwrite a newer one. Guard in Task 2 (`show!`), checked by hand.
5. Hex or base64 that is not text in Convert: text field empties with a note, other fields still right. Test in Task 1.

---

### Task 1: `cryptolab.core` and Node tests

**Files:** Create `src/cryptolab/core.cljs`, `src/cryptolab/core_test.cljs`. Modify `shadow-cljs.edn` (add `:test` build, `:target :node-test`, `:output-to "out/test.js"`), `.gitignore` (`out/`).

**Produces:**
- `(digest alg data)` → Promise<hex>; `alg` one of MD5, SHA-1, SHA-256, SHA-384, SHA-512; `data` string, ArrayBuffer or Uint8Array
- `(browser-hash alg data hmac-key)`, `(reference-hash alg data)` as today
- `(clean-checksum s)` → string; `(checksum-alg s)` → alg name or nil
- `(encrypt pw text)` → Promise<"cl1.…">; `(decrypt pw text)` → Promise<string>
- `(lock-file pw buf)` → Promise<Uint8Array>; `(unlock-file pw buf)` → Promise<ArrayBuffer>
- `(gen-key kind)`, `(export-key k)` as today
- `(sign private-pem msg)` → Promise<base64>; `(verify public-pem msg sig-b64)` → Promise<bool>
- `(convert fmt s)` with `fmt` "text" | "hex" | "base64" → `{"text" string-or-nil "hex" … "base64" …}`, throws on invalid input
- `tests`, `(run-test [name f])` → Promise<{:note :ok}>; `:ok` absent means skipped

- [ ] Move existing crypto and the test list out of `app.cljs` into `core.cljs`.
- [ ] Add tests to `tests`: v1 round-trip and `cl1.` prefix; old-format unlock; garbage text rejected; file round-trip; non-locked file rejected; sign→verify through PEM and tamper fails; bad PEM rejected; checksum detection (upper case, `sha256sum` line, junk → nil); convert round-trips, invalid hex throws, non-text bytes give nil text; Ed25519 (skip when unsupported).
- [ ] `core_test.cljs`: one async `deftest` that runs `tests` and asserts none has `:ok false`.
- [ ] Implement until `clojure -M:cljs -m shadow.cljs.devtools.cli compile test && node out/test.js` passes.

### Task 2: page and wiring

**Files:** Modify `resources/public/index.html`, `src/cryptolab/app.cljs`.

- [ ] Tabs: Check a file, Lock a message, Sign & verify, Convert, Advanced (Hash, Keys, Self-test stacked, same ids as today).
- [ ] `show!` takes a function, ignores results that are no longer the latest for that output.
- [ ] Check: file drop zone or text, live SHA-256, expected-checksum match.
- [ ] Lock: text or file, Lock/Unlock, file results download as `<name>.locked` / name without `.locked`.
- [ ] Sign & verify: Make a key pair, Sign, Verify.
- [ ] Convert: three linked fields with `aria-invalid` on bad input.
- [ ] Inputs at 16px so phones don't zoom; check layout at 390px wide.
- [ ] Verify in a browser: each tab once, plus Self-test all green.

### Task 3: CI and README

**Files:** Modify `.github/workflows/pages.yml`, `README.md`.

- [ ] Before the release build: `clojure -M:cljs -m shadow.cljs.devtools.cli compile test` then `node out/test.js`.
- [ ] README describes the five tabs, the lock format and the test command.
