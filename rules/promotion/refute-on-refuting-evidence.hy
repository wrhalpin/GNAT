;; Mark hypothesis REFUTED when refuting evidence is dominant and credible.
;;
;; Fires when:
;; - 2+ refuting evidence items
;; - Refuting count exceeds supporting count
;; - Reliability C or better (refutations from unreliable sources are ignored)
;;
;; Priority 90 — fires after strong-evidence promotion (100) but before
;; lower-priority rules.

(require gnat.analysis.rules.macros *)
(import gnat.analysis.rules.helpers *)

(defrule refute-on-refuting-evidence
  :description "Mark REFUTED when refuting > supporting and meets reliability threshold"
  :phase "open"
  :target-status "refuted"
  :priority 90
  :tags ["refutation" "evidence-based"]
  :when (fn [h ctx]
          (and (is-open? h)
               (>= (refuting-count h) 2)
               (> (refuting-count h) (supporting-count h))
               (has-confidence? h)
               (reliability-at-least? h "C")))
  :then (fn [h ctx]
          (set-status "refuted"
                      :reason "Refuting evidence exceeds supporting and meets reliability threshold")))
