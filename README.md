# Crypto Lab

Check downloads, lock messages and sign things in the browser. A static web app written in ClojureScript on top of Web Crypto; nothing you type or drop is sent anywhere.

- **Check a file**: drop a file to get its SHA-256. Paste the checksum from the download page and it says whether they match. The checksum's length picks the algorithm (MD5, SHA-1, SHA-256, SHA-384, SHA-512).
- **Lock a message**: protect text or a file with a password, and unlock it again.
- **Sign & verify**: make a key pair, sign a message, check a signature.
- **Convert**: text, hex and base64, each updating the others.
- **Advanced**: pick the hash algorithm, HMAC, compare Web Crypto against Google Closure's independent implementation, generate AES, HMAC, RSA, ECDSA and Ed25519 keys, and run the self-test.

## Formats

- **Locked text** is `cl1.` followed by `base64(salt16 | iv12 | ciphertext)`. **Locked files** are the bytes `CL1` followed by `salt16 | iv12 | ciphertext`. Both use AES-256-GCM with a key from PBKDF2-SHA256 at 600,000 iterations.
- Text with no `cl1.` prefix is read as the first release's format (210,000 iterations), so it still unlocks.
- **Signatures** are ECDSA P-256 with SHA-256, base64 of the raw `r | s` form Web Crypto produces (OpenSSL expects DER, so convert before verifying there). Keys are PEM: SPKI public, PKCS#8 private.
- Files are read into memory, so very large ones (around a gigabyte and up) may fail.

## Develop

```sh
clojure -M:cljs -m shadow.cljs.devtools.cli watch app     # dev with live reload at http://localhost:8080
clojure -M:cljs -m shadow.cljs.devtools.cli release app   # production build into resources/public
clojure -M:cljs -m shadow.cljs.devtools.cli compile test && node out/test.js   # tests, under Node
```

The crypto is in `src/cryptolab/core.cljs` with no DOM code, so the same test list runs under Node and behind the page's Self-test button. Every push to `main` runs the tests, then builds and deploys to GitHub Pages through `.github/workflows/pages.yml`; a failing test stops the deploy.

This is a learning and testing tool. Generated private keys appear on screen, so don't use it for real secrets.
