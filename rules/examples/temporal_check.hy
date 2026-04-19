;; Example: Temporal staleness check
;;
;; Demonstrates the temporal helpers: stale?, fresh?, age-days,
;; days-since-update.
;;
;; This rule marks stale hypotheses as INCONCLUSIVE after 90 days
;; without updates.

(require gnat.analysis.rules.macros *)
(import gnat.analysis.rules.helpers *)

(defrule temporal-check-example
  :description "Mark INCONCLUSIVE when hypothesis is stale (90+ days)"
  :phase "open"
  :priority 20
  :tags ["example" "temporal"]
  :when (fn [h ctx]
          (and (is-open? h)
               (stale? h 90)))
  :then (fn [h ctx]
          (set-status "inconclusive"
                      :reason (+ "Stale: " (str (days-since-update h)) " days without update"))))
