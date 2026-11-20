# Crypto Lab

A static web app, written in ClojureScript, for hashing, encrypting and generating keys, with a built-in self-test. Everything runs in the browser, with no server.

- **Hash / HMAC**: SHA-1/256/384/512 via Web Crypto, and MD5 via Google Closure. "Compare implementations" checks Web Crypto against Closure's independent code.
- **Encrypt / Decrypt**: AES-256-GCM with a key derived from a password (PBKDF2-SHA256, 210k iterations). The output is `base64(salt16 | iv12 | ciphertext)`.
- **Keys**: AES-GCM-256 and HMAC (as hex/base64), RSA-OAEP, RSA-PSS, ECDSA P-256 and Ed25519 (as PEM SPKI/PKCS8)
- **Self-test**: published test vectors, round-trips, signature checks, and Web Crypto/Closure agreement

```sh
clojure -M:cljs -m shadow.cljs.devtools.cli watch app     # dev with live reload at http://localhost:8080
clojure -M:cljs -m shadow.cljs.devtools.cli release app   # production build into resources/public
```

Every push to `main` builds and deploys to GitHub Pages through `.github/workflows/pages.yml`.

This is a learning and testing tool. Generated private keys appear on screen, so don't use it for real secrets.
