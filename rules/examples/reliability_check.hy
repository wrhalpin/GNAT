;; Example: Reliability and credibility check
;;
;; Demonstrates the confidence helpers: has-confidence?,
;; reliability-at-least?, credibility-at-least?, stix-confidence.
;;
;; This rule blocks promotion (via no-op) when confidence is too low.

(require gnat.analysis.rules.macros *)
(import gnat.analysis.rules.helpers *)

(defrule reliability-check-example
  :description "Block promotion when reliability is below C"
  :phase "open"
  :priority 95
  :tags ["example" "confidence"]
  :when (fn [h ctx]
          (and (is-open? h)
               (has-confidence? h)
               (not (reliability-at-least? h "C"))))
  :then (fn [h ctx]
          (no-op :reason "Reliability below C threshold — blocking promotion")))
