(ns cryptolab.core-test
  (:require [cljs.test :refer [deftest is async]]
            [cryptolab.core :as c]))

;; the same list the page's Self-test button runs
(deftest self-tests
  (async done
    (-> (js/Promise.all (into-array (map c/run-test c/tests)))
        (.then (fn [results]
                 (doseq [{:keys [note ok]} results] (is (not (false? ok)) note))
                 (done))))))
