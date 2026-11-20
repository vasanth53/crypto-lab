(ns cryptolab.app
  (:require [clojure.string :as str]
            [goog.crypt :as gcrypt])
  (:import [goog.crypt Md5 Sha1 Sha256 Sha384 Sha512]))

(def ^js subtle (.-subtle js/crypto))
(def ^js enc (js/TextEncoder.))
(def ^js decoder (js/TextDecoder.))

;; ---- byte helpers ----
(defn bytes-of [buf] (js/Array.from (js/Uint8Array. buf)))
(defn hex [buf] (apply str (map #(.padStart (.toString % 16) 2 "0") (bytes-of buf))))
(defn b64 [buf] (js/btoa (apply str (map char (bytes-of buf)))))
(defn unb64 [s] (js/Uint8Array.from (js/atob (str/trim s)) #(.charCodeAt % 0)))
(defn rand-bytes [n] (.getRandomValues js/crypto (js/Uint8Array. n)))
(defn concat-bytes [& arrs]
  (let [out (js/Uint8Array. (reduce + (map #(.-length %) arrs)))]
    (reduce (fn [off ^js a] (.set out a off) (+ off (.-length a))) 0 arrs)
    out))
(defn pem [label buf]
  (str "-----BEGIN " label "-----\n" (str/join "\n" (re-seq #".{1,64}" (b64 buf))) "\n-----END " label "-----"))

;; ---- hashing ----
(defn browser-hash [alg text hmac-key]
  (if (str/blank? hmac-key)
    (-> (.digest subtle alg (.encode enc text)) (.then hex))
    (-> (.importKey subtle "raw" (.encode enc hmac-key) #js {:name "HMAC" :hash alg} false #js ["sign"])
        (.then #(.sign subtle "HMAC" % (.encode enc text)))
        (.then hex))))

;; Google Closure's pure-JS hashes: MD5 (which Web Crypto lacks) and an independent implementation to compare against
(def closure-hashers {"MD5" #(Md5.) "SHA-1" #(Sha1.) "SHA-256" #(Sha256.) "SHA-384" #(Sha384.) "SHA-512" #(Sha512.)})
(defn closure-hash [alg text]
  (let [^js h ((closure-hashers alg))]
    (.update h (gcrypt/stringToUtf8ByteArray text))
    (gcrypt/byteArrayToHex (.digest h))))

(defn reference-hash
  "Resolves to [hex source-name], computed by Closure rather than Web Crypto."
  [alg text]
  (js/Promise.resolve [(closure-hash alg text) "the Closure library"]))

;; ---- password encryption: AES-256-GCM, key from PBKDF2-SHA256; output = base64(salt16 | iv12 | ciphertext) ----
(defn derive-key [pw salt]
  (-> (.importKey subtle "raw" (.encode enc pw) "PBKDF2" false #js ["deriveKey"])
      (.then #(.deriveKey subtle #js {:name "PBKDF2" :salt salt :iterations 210000 :hash "SHA-256"}
                          % #js {:name "AES-GCM" :length 256} false #js ["encrypt" "decrypt"]))))

(defn encrypt [pw text]
  (let [salt (rand-bytes 16) iv (rand-bytes 12)]
    (-> (derive-key pw salt)
        (.then #(.encrypt subtle #js {:name "AES-GCM" :iv iv} % (.encode enc text)))
        (.then #(b64 (concat-bytes salt iv (js/Uint8Array. %)))))))

(defn decrypt [pw data]
  (let [b (unb64 data)]
    (-> (derive-key pw (.slice b 0 16))
        (.then #(.decrypt subtle #js {:name "AES-GCM" :iv (.slice b 16 28)} % (.slice b 28)))
        (.then #(.decode decoder %))
        (.catch #(throw (js/Error. "decryption failed: wrong password or corrupted data"))))))

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

;; ---- self-tests ----
(def tests
  [["SHA-256 'abc' (FIPS 180 vector)"
    #(-> (browser-hash "SHA-256" "abc" "") (.then (partial = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")))]
   ["SHA-1 'abc' (FIPS 180 vector)"
    #(-> (browser-hash "SHA-1" "abc" "") (.then (partial = "a9993e364706816aba3e25717850c26c9cd0d89d")))]
   ["HMAC-SHA-256 (RFC 4231 case 2)"
    #(-> (browser-hash "SHA-256" "what do ya want for nothing?" "Jefe")
         (.then (partial = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")))]
   ["MD5 'abc' (RFC 1321 vector)"
    #(-> (reference-hash "MD5" "abc") (.then (fn [[h]] (= h "900150983cd24fb0d6963f7d28e17f72"))))]
   ["Web Crypto and the reference implementation agree on SHA-512 of unicode text"
    #(let [t (str "héllo 🔐 " (hex (rand-bytes 8)))]
       (-> (js/Promise.all #js [(browser-hash "SHA-512" t "") (reference-hash "SHA-512" t)])
           (.then (fn [[a [b]]] (= a b)))))]
   ["AES-GCM password encrypt -> decrypt round-trip"
    #(-> (encrypt "pw" "secret ✓") (.then (partial decrypt "pw")) (.then (partial = "secret ✓")))]
   ["AES-GCM rejects wrong password"
    #(-> (encrypt "pw" "x") (.then (partial decrypt "nope")) (.then (constantly false) (constantly true)))]
   ["RSA-OAEP encrypt -> decrypt round-trip"
    (fn [] (-> (gen-key "RSA-OAEP-2048")
               (.then (fn [^js kp]
                        (-> (.encrypt subtle #js {:name "RSA-OAEP"} (.-publicKey kp) (.encode enc "hi"))
                            (.then #(.decrypt subtle #js {:name "RSA-OAEP"} (.-privateKey kp) %))
                            (.then #(= "hi" (.decode decoder %))))))))]
   ["ECDSA signature verifies, tampered message does not"
    #(let [alg #js {:name "ECDSA" :hash "SHA-256"}]
       (-> (gen-key "ECDSA-P-256")
           (.then (fn [^js kp]
                    (-> (.sign subtle alg (.-privateKey kp) (.encode enc "msg"))
                        (.then (fn [sig]
                                 (js/Promise.all #js [(.verify subtle alg (.-publicKey kp) sig (.encode enc "msg"))
                                                      (.verify subtle alg (.-publicKey kp) sig (.encode enc "msG"))])))
                        (.then (fn [[good bad]] (and good (not bad)))))))))]])

;; returns {:note name :ok bool}; a thrown error counts as a failure
(defn run-test [[name t]]
  (-> (js/Promise.resolve) (.then t)
      (.then #(hash-map :note name :ok (true? %))
             #(hash-map :note (str name ": " (or (.-message %) %)) :ok false))))

;; ---- DOM wiring ----
(defn $ [id] (.getElementById js/document id))
(defn value [id] (.-value ($ id)))
(defn picked [group] (.-value (.querySelector js/document (str "input[name='" group "']:checked"))))

(defn el [tag cls text]
  (let [e (.createElement js/document tag)]
    (set! (.-className e) cls)
    (when text (set! (.-textContent e) text))
    e))

;; one coloured cell per byte, so two equal digests are recognisable at a glance
(defn fingerprint [hex-str]
  (let [strip (el "div" "fingerprint" nil)]
    (.setAttribute strip "aria-hidden" "true")
    (doseq [pair (partition 2 hex-str)]
      (let [c (el "span" "" nil)]
        (set! (.. c -style -background) (str "hsl(" (js/Math.round (* 360 (/ (js/parseInt (apply str pair) 16) 256))) " 62% 52%)"))
        (.append strip c)))
    strip))

(defn block [[label text]]
  (let [d (el "div" "result" nil)]
    (.append d (el "div" "result-label" label) (el "pre" "" text))
    (when (re-matches #"[0-9a-f]{16,}" text) (.append d (fingerprint text)))
    (.append d (el "button" "copy" "Copy"))
    d))

(defn note [{:keys [note ok busy]}]
  (el "p" (str "note" (cond busy " busy" (true? ok) " ok" (false? ok) " bad")) note))

;; items are [label text] result blocks or {:note .. :ok ..} status lines
(defn render! [^js e items]
  (set! (.-textContent e) "")
  (doseq [it items] (.append e (if (map? it) (note it) (block it)))))

(defn show! [id p]
  (render! ($ id) [{:note "Working…" :busy true}])
  (-> p (.then #(render! ($ id) %))
      (.catch #(render! ($ id) [{:note (str (or (.-message %) %)) :ok false}]))))
(defn on-click [id f] (.addEventListener ($ id) "click" f))

(defn flash! [^js btn msg]
  (set! (.-textContent btn) msg)
  (js/setTimeout #(set! (.-textContent btn) "Copy") 1500))

(defn copy! [^js btn]
  (-> (.writeText (.-clipboard js/navigator) (.-textContent (.querySelector (.closest btn ".result") "pre")))
      (.then #(flash! btn "Copied ✓") #(flash! btn "Copy failed"))))

(defn select-tab! [^js tab]
  (doseq [^js t (js/Array.from (.querySelectorAll js/document "[role=tab]"))]
    (let [on (= t tab)]
      (.setAttribute t "aria-selected" (str on))
      (set! (.-hidden ($ (.getAttribute t "aria-controls"))) (not on)))))

(defn hash-clicked []
  (let [alg (picked "hash-alg") text (value "hash-in") k (value "hmac-key")]
    (show! "hash-out"
           (cond (and (= alg "MD5") (str/blank? k)) (.then (reference-hash alg text) (fn [[h src]] [[(str "MD5, computed by " src) h]]))
                 (= alg "MD5") (js/Promise.reject (js/Error. "HMAC with MD5 isn't supported. Clear the HMAC key or pick a SHA algorithm."))
                 :else (.then (browser-hash alg text k) #(vector [(if (str/blank? k) alg (str "HMAC-" alg)) %]))))))

(defn compare-clicked []
  (let [alg (picked "hash-alg") text (value "hash-in")]
    (show! "hash-out"
           (if (= alg "MD5")
             (js/Promise.reject (js/Error. "Web Crypto has no MD5, so there's nothing to compare. Pick a SHA algorithm."))
             (-> (js/Promise.all #js [(browser-hash alg text "") (reference-hash alg text)])
                 (.then (fn [[a [b src]]] [{:note (if (= a b) "Both hashes match" "The hashes differ") :ok (= a b)}
                                           [(str alg " from Web Crypto") a]
                                           [(str alg " from " src) b]])))))))

(defn crypt-clicked [f label]
  (set! (.-hidden ($ "enc-use")) true)
  (show! "enc-out" (-> (f (value "enc-pw") (value "enc-in"))
                       (.then (fn [r] (set! (.-hidden ($ "enc-use")) false) [[label r]])))))

(defn init []
  (.addEventListener js/document "click"
                     (fn [^js e]
                       (when-let [b (.closest (.-target e) ".copy")] (copy! b))
                       (when-let [t (.closest (.-target e) "[role=tab]")] (select-tab! t))))
  (on-click "enc-use" #(set! (.-value ($ "enc-in")) (.-textContent (.querySelector ($ "enc-out") "pre"))))
  (on-click "hash-btn" hash-clicked)
  (on-click "cross-btn" compare-clicked)
  (on-click "enc-btn" #(crypt-clicked encrypt "Encrypted text (base64)"))
  (on-click "dec-btn" #(crypt-clicked decrypt "Decrypted text"))
  (on-click "key-btn" #(show! "key-out" (-> (gen-key (picked "key-alg")) (.then export-key))))
  (on-click "test-btn" #(show! "test-out"
                               (-> (js/Promise.all (into-array (map run-test tests)))
                                   (.then (fn [rs]
                                            (let [n (count (filter :ok rs))]
                                              (into [{:note (str n " of " (count rs) " tests passed") :ok (= n (count rs))}] rs))))))))
