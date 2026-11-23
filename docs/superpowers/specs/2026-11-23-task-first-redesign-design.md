# Crypto Lab: task-first redesign

## Intent

Crypto Lab should be a tool anyone can use, and simple to use (the owner's words). Today it speaks to developers: the first screen asks for a choice between SHA-384 and MD5. The redesign organises the app around what people want to do and hides algorithm choices behind sensible defaults.

## Goals

- A non-technical person can check a download, lock a message or file with a password, and sign or verify a message without knowing any algorithm name.
- Everything still runs in the browser, as a static site on GitHub Pages.
- Existing developer features stay reachable under Advanced.

## Non-goals

JWT tools, ECDH key exchange demo, accounts, any server, share links, translations.

## Anti-goals

- A first screen that requires picking an algorithm.
- Locked data that a later version of the app cannot unlock.
- Prefilled passwords or anything that suggests the sample values are safe to use.

## Approaches

- **A. Keep the four tabs (Hash, Encrypt, Keys, Self-test) and add features.** Least work, still developer-facing.
- **B. Rebuild the tabs around tasks, same crypto engine.** Chosen: the owner asked which was better and the recommendation was B, because "anyone can use it" is a wording-and-defaults problem that more features don't fix.

## Design

Tabs, in order. The first is selected on load.

### 1. Check a file
- Drop a file or pick one (or switch to typing text). Its SHA-256 appears with no button press.
- Optional "Expected checksum" field. The pasted value's length picks the algorithm (32 hex = MD5, 40 = SHA-1, 64 = SHA-256, 96 = SHA-384, 128 = SHA-512); the file is hashed with that and the result is "✓ Match" or "✗ Different". Whitespace and letter case are ignored. Any other length: "That doesn't look like a checksum".
- The file is read fully into memory (Web Crypto cannot hash a stream). Files too large to read show a plain error.

### 2. Lock a message
- Text or a file, plus a password. Buttons: Lock, Unlock. No prefilled password.
- Text output: `cl1.` followed by base64 of `salt16 | iv12 | ciphertext`. File output: the bytes `CL1` followed by `salt16 | iv12 | ciphertext`, downloaded as `<name>.locked`; unlocking downloads it with `.locked` removed.
- Version 1 uses PBKDF2-SHA256 with 600,000 iterations (current OWASP figure; the present 210,000 is the SHA-512 figure).
- Text with no `cl1.` prefix is treated as the old format (210,000 iterations) so existing output still unlocks.
- Failure message: "Wrong password, or the text was changed."

### 3. Sign & verify
- "Make a key pair" creates ECDSA P-256 (supported by every current browser) and fills in both keys as PEM.
- Sign: private key + message gives a base64 signature.
- Verify: public key + message + signature gives "✓ Valid" or "✗ Not valid".
- Keys pasted in are parsed from PEM. A malformed key gives "That isn't a key this tool can read."

### 4. Convert
Three fields: text, hex, base64. Editing one updates the other two. Invalid hex or base64 marks that field and leaves the others unchanged.

### 5. Advanced
The current Hash panel (algorithm picker, HMAC key, compare implementations), the Keys panel (all six key types) and Self-test, unchanged in behaviour.

### Across all tabs
- Results update as the user types (debounced) or drops a file. Buttons remain only where an action has a cost or side effect (Lock, Unlock, Make a key pair, Sign, Verify, Run tests).
- Errors are plain sentences.
- Layout works at phone width.
- Existing accessibility (tab roles, `aria-live` outputs) is kept and extended to new panels.

### Code shape
- Move the crypto functions out of `cryptolab.app` into `cryptolab.core` (no DOM), leaving `app` as wiring. This is what lets the tests run outside a browser.
- The self-test list moves to `core` and gains: version 1 lock round-trip (text and bytes), old-format unlock, sign then verify through PEM export and import, checksum length detection, convert round-trips, Ed25519 (skipped with a note where unsupported).
- A `:node-test` shadow-cljs build runs the same list under Node (which has Web Crypto), and the Pages workflow runs it before the release build, so a failing test blocks deploy.

## Calls made by the designer, not the owner

ECDSA P-256 as the only signing type on the simple tab; 600,000 iterations; the `cl1.` / `CL1` format; keeping old-format unlock; length-based checksum detection; splitting `core` from `app`; tests in CI through Node.

## Left to the builder

Visual styling of the new panels within the existing look, debounce interval, exact wording beyond the messages quoted above.
