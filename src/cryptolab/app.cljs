(ns cryptolab.app
  "DOM wiring only. The crypto lives in cryptolab.core."
  (:require [clojure.string :as str]
            [cryptolab.core :as c]))

(defn $ [id] (.getElementById js/document id))
(defn value [id] (.-value ($ id)))
(defn set-value! [id v] (set! (.-value ($ id)) v))
(defn picked [group] (.-value (.querySelector js/document (str "input[name='" group "']:checked"))))
(defn picked-file [id] (aget (.-files ($ id)) 0))
(defn on [id event f] (.addEventListener ($ id) event f))
(defn fail [msg] (throw (js/Error. msg)))

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

(defonce latest (atom {}))

(defn show!
  "Renders what `f` returns (items, or a promise of them) into the output `id`; an error becomes a red line.
  Live fields call this on every keystroke, so a result that is no longer the newest for `id` is dropped."
  [id f]
  (let [n (get (swap! latest update id (fnil inc 0)) id)
        put! #(when (= n (@latest id)) (render! ($ id) %))]
    (put! [{:note "Working…" :busy true}])
    (-> (js/Promise.resolve) (.then f) (.then put!)
        (.catch #(put! [{:note (str (or (.-message %) %)) :ok false}])))))

(defn debounced [f]
  (let [t (atom nil)] (fn [] (js/clearTimeout @t) (reset! t (js/setTimeout f 250)))))

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

;; ---- files ----
(defn size-label [n]
  (cond (< n 1024) (str n " bytes")
        (< n 1048576) (str (.toFixed (/ n 1024) 1) " KB")
        :else (str (.toFixed (/ n 1048576) 1) " MB")))

;; the drop zone's label names the chosen file, or goes back to its prompt (kept in data-prompt)
(defn label-file! [id ^js f]
  (let [^js e ($ id)]
    (set! (.-textContent e) (if f (str (.-name f) " (" (size-label (.-size f)) ")") (.getAttribute e "data-prompt")))))

(defn read-file [^js f]
  (.catch (.arrayBuffer f) #(fail "This file couldn't be read. It may be too large for the browser.")))

(defn download! [data fname]
  (let [url (js/URL.createObjectURL (js/Blob. #js [data])) ^js a (el "a" "" nil)]
    (set! (.-href a) url)
    (set! (.-download a) fname)
    (.click a)
    (js/setTimeout #(js/URL.revokeObjectURL url) 1000)))

;; ---- Check a file ----
(defonce check-src (atom nil)) ; a File or a string, whichever the person gave last

(defn check! []
  (let [src @check-src
        text? (string? src)
        expected (value "check-expected")
        alg (if (str/blank? expected) "SHA-256" (c/checksum-alg expected))]
    (show! "check-out"
           (fn []
             (cond
               (or (nil? src) (= "" src)) []
               (nil? alg) (fail "That doesn't look like a checksum. Paste the long string of letters and numbers from the download page.")
               :else
               (-> (js/Promise.resolve (if text? src (read-file src)))
                   (.then #(c/digest alg %))
                   (.then (fn [h]
                            (let [thing (if text? "text" "file")
                                  result [(str alg " checksum of " (if text? "your text" (.-name ^js src))) h]]
                              (cond
                                (str/blank? expected) [result]
                                (= h (c/clean-checksum expected)) [{:note (str "Match. This is exactly the " thing " the checksum describes.") :ok true} result]
                                :else [{:note (str "Different. This is not the " thing " the checksum describes, so don't trust it.") :ok false} result]))))))))))

;; ---- Lock a message ----
(defn unlocked-name [n]
  (if (str/ends-with? n ".locked") (subs n 0 (- (count n) (count ".locked"))) (str "unlocked-" n)))

(defn crypt-clicked [lock?]
  (set! (.-hidden ($ "enc-use")) true)
  (let [pw (value "enc-pw") text (value "enc-in") ^js f (picked-file "lock-file")]
    (show! "enc-out"
           (fn []
             (cond
               (= "" pw) (fail "Enter a password first.")
               f (-> (read-file f)
                     (.then #((if lock? c/lock-file c/unlock-file) pw %))
                     (.then (fn [out]
                              (let [fname (if lock? (str (.-name f) ".locked") (unlocked-name (.-name f)))]
                                (download! out fname)
                                [{:note (str "Done. Downloaded as " fname) :ok true}]))))
               (str/blank? text) (fail "Type a message or choose a file first.")
               :else (-> ((if lock? c/encrypt c/decrypt) pw text)
                         (.then (fn [r]
                                  (set! (.-hidden ($ "enc-use")) false)
                                  [[(if lock? "Locked text. Copy it and send it; share the password another way." "Unlocked message") r]]))))))))

(defn lock-file-changed []
  (let [f (picked-file "lock-file")]
    (label-file! "lock-name" f)
    (set! (.-hidden ($ "lock-clear")) (nil? f))))

;; ---- Sign & verify ----
(defn make-keys-clicked []
  (show! "sig-out"
         #(-> (c/gen-key "ECDSA-P-256") (.then c/export-key)
              (.then (fn [[[_ pub] [_ priv]]]
                       (set-value! "sig-pub" pub)
                       (set-value! "sig-priv" priv)
                       [{:note "New key pair made. Keep the private key secret; give the public key to anyone." :ok true}])))))

(defn sign-clicked []
  (show! "sig-out"
         #(-> (c/sign (value "sig-priv") (value "sig-msg"))
              (.then (fn [sig]
                       (set-value! "sig-sig" sig)
                       [{:note "Signed. Send the message, the signature and your public key." :ok true}])))))

(defn verify-clicked []
  (show! "sig-out"
         #(-> (c/verify (value "sig-pub") (value "sig-msg") (value "sig-sig"))
              (.then (fn [ok]
                       [{:note (if ok "Valid. The owner of this public key signed exactly this message."
                                   "Not valid. The message, the signature or the key doesn't match.")
                         :ok ok}])))))

;; ---- Convert ----
(def conv-ids {"text" "conv-text" "hex" "conv-hex" "base64" "conv-b64"})

(defn conv-changed [fmt]
  (let [r (try (c/convert fmt (value (conv-ids fmt))) (catch :default _ nil))]
    (doseq [[f id] conv-ids]
      (.setAttribute ($ id) "aria-invalid" (str (and (nil? r) (= f fmt))))
      (when (and r (not= f fmt)) (set-value! id (or (r f) ""))))
    (render! ($ "conv-out")
             (cond (nil? r) [{:note (str "That isn't valid " fmt ", so the other boxes were left as they were.") :ok false}]
                   (nil? (r "text")) [{:note "These bytes aren't readable text, so the text box is empty."}]
                   :else []))))

;; ---- Advanced ----
(defn hash-clicked []
  (let [alg (picked "hash-alg") text (value "hash-in") k (value "hmac-key")]
    (show! "hash-out"
           #(cond (str/blank? k) (.then (c/digest alg text) (fn [h] [[alg h]]))
                  (= alg "MD5") (fail "HMAC with MD5 isn't supported. Clear the HMAC key or pick a SHA algorithm.")
                  :else (.then (c/browser-hash alg text k) (fn [h] [[(str "HMAC-" alg) h]]))))))

(defn compare-clicked []
  (let [alg (picked "hash-alg") text (value "hash-in")]
    (show! "hash-out"
           #(if (= alg "MD5")
              (fail "Web Crypto has no MD5, so there's nothing to compare. Pick a SHA algorithm.")
              (-> (js/Promise.all #js [(c/browser-hash alg text "") (c/reference-hash alg text)])
                  (.then (fn [[a [b src]]] [{:note (if (= a b) "Both hashes match" "The hashes differ") :ok (= a b)}
                                            [(str alg " from Web Crypto") a]
                                            [(str alg " from " src) b]])))))))

(defn tests-clicked []
  (show! "test-out"
         #(-> (js/Promise.all (into-array (map c/run-test c/tests)))
              (.then (fn [rs]
                       (let [ran (remove (comp nil? :ok) rs) n (count (filter :ok ran))]
                         (into [{:note (str n " of " (count ran) " tests passed") :ok (= n (count ran))}] rs)))))))

(defn init []
  (.addEventListener js/document "click"
                     (fn [^js e]
                       (when-let [b (.closest (.-target e) ".copy")] (copy! b))
                       (when-let [t (.closest (.-target e) "[role=tab]")] (select-tab! t))))

  (on "check-file" "change" #(when-let [f (picked-file "check-file")]
                               (reset! check-src f)
                               (label-file! "check-name" f)
                               (check!)))
  (on "check-text" "input" (debounced #(do (reset! check-src (value "check-text"))
                                           (set-value! "check-file" "")
                                           (label-file! "check-name" nil)
                                           (check!))))
  (on "check-expected" "input" (debounced check!))

  (on "lock-file" "change" lock-file-changed)
  (on "lock-clear" "click" #(do (set-value! "lock-file" "") (lock-file-changed)))
  (on "enc-btn" "click" #(crypt-clicked true))
  (on "dec-btn" "click" #(crypt-clicked false))
  (on "enc-use" "click" #(set-value! "enc-in" (.-textContent (.querySelector ($ "enc-out") "pre"))))

  (on "sig-gen" "click" make-keys-clicked)
  (on "sig-sign" "click" sign-clicked)
  (on "sig-verify" "click" verify-clicked)

  (doseq [[fmt id] conv-ids] (on id "input" #(conv-changed fmt)))

  (on "hash-btn" "click" hash-clicked)
  (on "cross-btn" "click" compare-clicked)
  (on "key-btn" "click" #(show! "key-out" (fn [] (-> (c/gen-key (picked "key-alg")) (.then c/export-key)))))
  (on "test-btn" "click" tests-clicked))
