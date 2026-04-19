;; Promote OPEN → SUPPORTED when evidence is strong and well-sourced.
;;
;; This rule fires when a hypothesis has:
;; - 3+ supporting evidence items
;; - No refuting evidence
;; - Reliability B or better, credibility 2 or better
;; - At least one trusted_internal evidence source
;; - Passes the AI confidence ceiling check
;;
;; Priority 100 — standard promotion. Analyst-override (priority 200)
;; can preempt this rule.

(require gnat.analysis.rules.macros *)
(import gnat.analysis.rules.helpers *)

(defrule support-on-strong-evidence
  :description "Mark hypothesis SUPPORTED when 3+ evidence, B2+ confidence, trusted source, no refutation"
  :phase "open"
  :target-status "supported"
  :priority 100
  :tags ["promotion" "evidence-based"]
  :when (fn [h ctx]
          (and (is-open? h)
               (>= (supporting-count h) 3)
               (not (has-refutation? h))
               (has-confidence? h)
               (reliability-at-least? h "B")
               (credibility-at-least? h 2)
               (has-trusted-evidence? h ctx)
               (within-ai-ceiling? h ctx)))
  :then (fn [h ctx]
          (set-status "supported"
                      :reason "3+ supporting, no refutation, B2+ confidence, trusted source present")))
