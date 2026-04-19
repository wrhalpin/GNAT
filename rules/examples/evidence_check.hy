;; Example: Evidence count check
;;
;; Demonstrates the evidence helpers: supporting-count, refuting-count,
;; evidence-count, has-refutation?, and support-ratio.
;;
;; This rule annotates hypotheses that have fewer than 3 supporting
;; evidence items as "needs-more-evidence".

(require gnat.analysis.rules.macros *)
(import gnat.analysis.rules.helpers *)

(defrule evidence-check-example
  :description "Annotate hypotheses with insufficient evidence"
  :phase "open"
  :priority 10
  :tags ["example" "evidence"]
  :when (fn [h ctx]
          (and (is-open? h)
               (< (supporting-count h) 3)))
  :then (fn [h ctx]
          (annotate "needs-more-evidence" True
                    :reason (+ "Only " (str (supporting-count h)) " supporting items"))))
