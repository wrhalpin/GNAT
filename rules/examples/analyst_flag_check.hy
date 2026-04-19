;; Example: AI-only source check
;;
;; Demonstrates the source helpers: ai-only?, has-trusted-evidence?,
;; evidence-sources, within-ai-ceiling?.
;;
;; This rule blocks promotion for hypotheses where ALL evidence
;; originates from AI connectors (ChatGPT, Copilot, etc.).

(require gnat.analysis.rules.macros *)
(import gnat.analysis.rules.helpers *)

(defrule ai-source-check-example
  :description "Block promotion when evidence is exclusively AI-sourced"
  :phase "open"
  :priority 110
  :tags ["example" "source" "ai-ceiling"]
  :when (fn [h ctx]
          (and (is-open? h)
               (> (evidence-count h) 0)
               (ai-only? h ctx)))
  :then (fn [h ctx]
          (no-op :reason "All evidence from AI connectors — requires human corroboration")))
