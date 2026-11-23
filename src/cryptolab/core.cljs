(ns cryptolab.core
  "All the crypto, with no DOM, so the same code runs in the page and under Node for tests."
  (:require [clojure.string :as str])
  (:import [goog.crypt Md5 Sha1 Sha256 Sha384 Sha512]))

(def ^js subtle (.-subtle js/crypto))
(def ^js enc (js/TextEncoder.))
(def ^js decoder (js/TextDecoder.))
(def ^js strict-decoder (js/TextDecoder. "utf-8" #js {:fatal true}))

;; ---- byte helpers ----
(defn to-bytes
  "A Uint8Array from a string (as UTF-8), an ArrayBuffer or a Uint8Array, without copying binary input."
  [x]
  (cond (string? x) (.encode enc x)
        (instance? js/Uint8Array x) x
        :else (js/Uint8Array. x)))
(defn bytes-of [buf] (js/Array.from (to-bytes buf)))
(defn hex [buf] (apply str (map #(.padStart (.toString % 16) 2 "0") (bytes-of buf))))
(defn unhex [s]
  (let [c (str/replace s #"\s+" "")]
    (when-not (re-matches #"([0-9a-fA-F]{2})*" c) (throw (js/Error. "not hex")))
    (js/Uint8Array. (into-array (map #(js/parseInt (apply str %) 16) (partition 2 c))))))
(defn b64 [buf] (js/btoa (apply str (map char (bytes-of buf)))))
(defn unb64 [s] (js/Uint8Array.from (js/atob (str/trim s)) #(.charCodeAt % 0)))
(defn rand-bytes [n] (.getRandomValues js/crypto (js/Uint8Array. n)))
(defn concat-bytes [& arrs]
  (let [out (js/Uint8Array. (reduce + (map #(.-length %) arrs)))]
    (reduce (fn [off ^js a] (.set out a off) (+ off (.-length a))) 0 arrs)
    out))
(defn pem [label buf]
  (str "-----BEGIN " label "-----\n" (str/join "\n" (re-seq #".{1,64}" (b64 buf))) "\n-----END " label "-----"))
(defn unpem [s] (unb64 (str/replace s #"-----[^-]+-----|\s+" "")))

;; ---- hashing ----
(defn browser-hash [alg data hmac-key]
  (if (str/blank? hmac-key)
    (-> (.digest subtle alg (to-bytes data)) (.then hex))
    (-> (.importKey subtle "raw" (.encode enc hmac-key) #js {:name "HMAC" :hash alg} false #js ["sign"])
        (.then #(.sign subtle "HMAC" % (to-bytes data)))
        (.then hex))))

;; Google Closure's pure-JS hashes: MD5 (which Web Crypto lacks) and an independent implementation to compare against
(def closure-hashers {"MD5" #(Md5.) "SHA-1" #(Sha1.) "SHA-256" #(Sha256.) "SHA-384" #(Sha384.) "SHA-512" #(Sha512.)})
(defn closure-hash [alg data]
  (let [^js h ((closure-hashers alg))]
    (.update h (to-bytes data))
    (hex (.digest h))))

(defn reference-hash
  "Resolves to [hex source-name], computed by Closure rather than Web Crypto."
  [alg data]
  (js/Promise.resolve [(closure-hash alg data) "the Closure library"]))

(defn digest
  "Resolves to the hex digest of a string or of bytes."
  [alg data]
  (if (= alg "MD5") (js/Promise.resolve (closure-hash alg data)) (browser-hash alg data "")))

;; a pasted checksum names its own algorithm by its length
(def checksum-algs {32 "MD5" 40 "SHA-1" 64 "SHA-256" 96 "SHA-384" 128 "SHA-512"})
(defn clean-checksum
  "Lower-cased checksum from what someone pasted: spaced-out hex is joined, a `sha256sum` line loses its file name."
  [s]
  (let [l (str/lower-case (str/trim s)) joined (str/replace l #"\s+" "")]
    (if (checksum-algs (count joined)) joined (first (str/split l #"\s+")))))
(defn checksum-alg [s]
  (let [c (clean-checksum s)] (when (re-matches #"[0-9a-f]+" c) (checksum-algs (count c)))))

;; ---- password locking: AES-256-GCM, key from PBKDF2-SHA256 ----
;; v1 text = "cl1." + base64(salt16 | iv12 | ciphertext); v1 file = bytes "CL1" + salt16 | iv12 | ciphertext
(def iterations 600000)
(def legacy-iterations 210000) ; text from the first release, which had no "cl1." prefix
(def text-prefix "cl1.")
(def magic (.encode enc "CL1"))

(defn derive-key [pw salt iters]
  (-> (.importKey subtle "raw" (.encode enc pw) "PBKDF2" false #js ["deriveKey"])
      (.then #(.deriveKey subtle #js {:name "PBKDF2" :salt salt :iterations iters :hash "SHA-256"}
                          % #js {:name "AES-GCM" :length 256} false #js ["encrypt" "decrypt"]))))

(defn lock-bytes [pw data iters]
  (let [salt (rand-bytes 16) iv (rand-bytes 12)]
    (-> (derive-key pw salt iters)
        (.then #(.encrypt subtle #js {:name "AES-GCM" :iv iv} % (to-bytes data)))
        (.then #(concat-bytes salt iv (js/Uint8Array. %))))))

(defn unlock-bytes [pw ^js b iters]
  (-> (derive-key pw (.subarray b 0 16) iters)
      (.then #(.decrypt subtle #js {:name "AES-GCM" :iv (.subarray b 16 28)} % (.subarray b 28)))))

(defn- changed [what] #(throw (js/Error. (str "Wrong password, or the " what " was changed."))))

(defn encrypt [pw text]
  (.then (lock-bytes pw text iterations) #(str text-prefix (b64 %))))

(defn decrypt [pw data]
  (let [s (str/trim data) v1 (str/starts-with? s text-prefix)]
    (-> (js/Promise.resolve)
        (.then #(unlock-bytes pw (unb64 (if v1 (subs s (count text-prefix)) s)) (if v1 iterations legacy-iterations)))
        (.then #(.decode decoder %))
        (.catch (changed "text")))))

(defn lock-file [pw buf]
  (.then (lock-bytes pw buf iterations) #(concat-bytes magic %)))

(defn unlock-file [pw buf]
  (let [^js b (to-bytes buf)]
    (if (= (hex (.subarray b 0 3)) (hex magic))
      (.catch (unlock-bytes pw (.subarray b 3) iterations) (changed "file"))
      (js/Promise.reject (js/Error. "This file wasn't locked with Crypto Lab.")))))

;; ---- key generation ----
(def key-specs
  {"AES-GCM-256"   [#js {:name "AES-GCM" :length 256} #js ["encrypt" "decrypt"]]
   "HMAC-SHA-256"  [#js {:name "HMAC" :hash "SHA-256"} #js ["sign" "verify"]]
   "RSA-OAEP-2048" [#js {:name "RSA-OAEP" :modulusLength 2048 :publicExponent (js/Uint8Array. #js [1 0 1]) :hash "SHA-256"} #js ["encrypt" "decrypt"]]
   "RSA-PSS-2048"  [#js {:name "RSA-PSS" :modulusLength 2048 :publicExponent (js/Uint8Array. #js [1 0 1]) :hash "SHA-256"} #js ["sign" "verify"]]
   "ECDSA-P-256"   [#js {:name "ECDSA" :namedCurve "P-256"} #js ["sign" "verify"]]
   "Ed25519"       [#js {:name "Ed25519"} #js ["sign" "verify"]]})

(defn gen-key [kind]
  (let [[alg usages] (key-specs kind)] (.generateKey subtle alg true usages)))

(defn export-key [^js k]
  (if (.-privateKey k)
    (-> (js/Promise.all #js [(.exportKey subtle "spki" (.-publicKey k)) (.exportKey subtle "pkcs8" (.-privateKey k))])
        (.then (fn [[pub priv]] [["Public key (PEM)" (pem "PUBLIC KEY" pub)] ["Private key (PEM)" (pem "PRIVATE KEY" priv)]])))
    (-> (.exportKey subtle "raw" k)
        (.then #(vector ["Key (hex)" (hex %)] ["Key (base64)" (b64 %)])))))

;; ---- sign / verify: ECDSA P-256 with SHA-256, PEM keys, base64 signature (raw r|s, as Web Crypto emits it) ----
(def sign-alg #js {:name "ECDSA" :hash "SHA-256"})

(defn import-pem [s private?]
  (-> (js/Promise.resolve)
      (.then #(.importKey subtle (if private? "pkcs8" "spki") (unpem s)
                          #js {:name "ECDSA" :namedCurve "P-256"} false #js [(if private? "sign" "verify")]))
      (.catch #(throw (js/Error. "That isn't a key this tool can read.")))))

(defn sign [private-pem msg]
  (-> (import-pem private-pem true)
      (.then #(.sign subtle sign-alg % (to-bytes msg)))
      (.then b64)))

(defn verify
  "Resolves to true or false. A signature that isn't even base64 is simply not valid."
  [public-pem msg sig]
  (let [sig-bytes (try (unb64 sig) (catch :default _ (js/Uint8Array. 0)))]
    (.then (import-pem public-pem false) #(.verify subtle sign-alg % sig-bytes (to-bytes msg)))))

;; ---- convert between text, hex and base64 ----
(defn convert
  "All three forms of the bytes that `s` spells in `fmt`. Throws when `s` isn't valid `fmt`; \"text\" is nil when the bytes aren't UTF-8."
  [fmt s]
  (let [b (case fmt "text" (to-bytes s) "hex" (unhex s) "base64" (unb64 s))]
    {"text" (try (.decode strict-decoder b) (catch :default _ nil)) "hex" (hex b) "base64" (b64 b)}))

;; ---- self-tests: each is [name f], f returns (a promise of) true, false or :skip ----
(defn- fails [p] (.then p (constantly false) (constantly true)))
(defn- throws? [f] (try (f) false (catch :default _ true)))
(def ^:private abc-sha256 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

(def tests
  [["SHA-256 'abc' (FIPS 180 vector)"
    #(-> (digest "SHA-256" "abc") (.then (partial = abc-sha256)))]
   ["SHA-1 'abc' (FIPS 180 vector)"
    #(-> (digest "SHA-1" "abc") (.then (partial = "a9993e364706816aba3e25717850c26c9cd0d89d")))]
   ["HMAC-SHA-256 (RFC 4231 case 2)"
    #(-> (browser-hash "SHA-256" "what do ya want for nothing?" "Jefe")
         (.then (partial = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")))]
   ["MD5 'abc' (RFC 1321 vector), from text and from bytes"
    #(-> (js/Promise.all #js [(digest "MD5" "abc") (digest "MD5" (.-buffer (.encode enc "abc")))])
         (.then (fn [[a b]] (= a b "900150983cd24fb0d6963f7d28e17f72"))))]
   ["Web Crypto and the reference implementation agree on SHA-512 of unicode text"
    #(let [t (str "héllo 🔐 " (hex (rand-bytes 8)))]
       (-> (js/Promise.all #js [(digest "SHA-512" t) (reference-hash "SHA-512" t)])
           (.then (fn [[a [b]]] (= a b)))))]
   ["Checksum is recognised in upper case and in `sha256sum` form; junk is not"
    #(and (= "SHA-256" (checksum-alg (str/upper-case abc-sha256)))
          (= "SHA-256" (checksum-alg (str abc-sha256 "  ubuntu.iso\n")))
          (= abc-sha256 (clean-checksum (str " " (str/upper-case abc-sha256) "  ubuntu.iso")))
          (= "MD5" (checksum-alg "900150983cd24fb0d6963f7d28e17f72"))
          (nil? (checksum-alg "not a checksum"))
          (nil? (checksum-alg "abc123")))]
   ["Lock -> unlock round-trip, output carries the cl1. version prefix"
    #(-> (encrypt "pw" "secret ✓")
         (.then (fn [c] (.then (decrypt "pw" (str "  " c "\n"))
                               (fn [p] (and (str/starts-with? c "cl1.") (= p "secret ✓")))))))]
   ["Unlock rejects a wrong password"
    #(-> (encrypt "pw" "x") (.then (partial decrypt "nope")) fails)]
   ["Unlock rejects garbage and truncated text with a plain message"
    #(-> (js/Promise.all #js [(.catch (decrypt "pw" "cl1.!!not base64!!") (fn [e] (.-message e)))
                              (.catch (decrypt "pw" "cl1.AAAA") (fn [e] (.-message e)))
                              (.catch (decrypt "pw" "") (fn [e] (.-message e)))])
         (.then (fn [msgs] (every? (partial = "Wrong password, or the text was changed.") msgs))))]
   ["Text locked by the first release (no prefix, 210,000 rounds) still unlocks"
    #(-> (lock-bytes "pw" "old" legacy-iterations) (.then (fn [b] (decrypt "pw" (b64 b)))) (.then (partial = "old")))]
   ["File lock -> unlock round-trip returns the same bytes"
    #(let [data (rand-bytes 1000)]
       (-> (lock-file "pw" (.-buffer data))
           (.then (fn [locked] (unlock-file "pw" (.-buffer locked))))
           (.then (fn [out] (= (hex out) (hex data))))))]
   ["Unlocking a file that was never locked says so; a wrong password says that instead"
    #(-> (js/Promise.all #js [(.catch (unlock-file "pw" (rand-bytes 100)) (fn [e] (.-message e)))
                              (.catch (.then (lock-file "pw" "x") (partial unlock-file "nope")) (fn [e] (.-message e)))])
         (.then (fn [[a b]] (and (= a "This file wasn't locked with Crypto Lab.")
                                 (= b "Wrong password, or the file was changed.")))))]
   ["RSA-OAEP encrypt -> decrypt round-trip"
    (fn [] (-> (gen-key "RSA-OAEP-2048")
               (.then (fn [^js kp]
                        (-> (.encrypt subtle #js {:name "RSA-OAEP"} (.-publicKey kp) (.encode enc "hi"))
                            (.then #(.decrypt subtle #js {:name "RSA-OAEP"} (.-privateKey kp) %))
                            (.then #(= "hi" (.decode decoder %))))))))]
   ["Sign with a pasted private key, verify with the public key; a changed message or signature fails"
    #(-> (gen-key "ECDSA-P-256") (.then export-key)
         (.then (fn [[[_ pub] [_ priv]]]
                  (-> (sign priv "msg")
                      (.then (fn [sig] (js/Promise.all #js [(verify pub "msg" sig) (verify pub "msG" sig)
                                                            (verify pub "msg" "not a signature")])))
                      (.then (fn [[good tampered junk]] (and good (not tampered) (not junk))))))))]
   ["A pasted key that isn't a key is refused with a plain message"
    #(-> (sign "hello" "msg") (.catch (fn [e] (= "That isn't a key this tool can read." (.-message e)))))]
   ["Convert: text, hex and base64 agree; bad hex is refused; non-text bytes have no text form"
    #(and (= {"text" "hi ✓" "hex" "686920e29c93" "base64" "aGkg4pyT"} (convert "text" "hi ✓"))
          (= "hi ✓" ((convert "hex" "68 69 20 E2 9C 93") "text") ((convert "base64" "aGkg4pyT") "text"))
          (throws? (fn [] (convert "hex" "abc")))
          (throws? (fn [] (convert "base64" "***")))
          (= {"text" nil "hex" "ff" "base64" "/w=="} (convert "hex" "ff")))]
   ["Ed25519 signature verifies"
    #(-> (gen-key "Ed25519")
         (.then (fn [^js kp]
                  (-> (.sign subtle "Ed25519" (.-privateKey kp) (.encode enc "msg"))
                      (.then (fn [sig] (.verify subtle "Ed25519" (.-publicKey kp) sig (.encode enc "msg"))))))
                (constantly :skip)))]])

(defn run-test
  "Resolves to {:note name :ok bool}, or {:note ..} with no :ok when skipped. A thrown error counts as a failure."
  [[name t]]
  (-> (js/Promise.resolve) (.then t)
      (.then #(if (= :skip %)
                {:note (str name " (skipped: not supported here)")}
                {:note name :ok (true? %)})
             #(hash-map :note (str name ": " (or (.-message %) %)) :ok false))))
