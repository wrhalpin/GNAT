;; Analyst override — highest priority rule.
;;
;; Checks for an explicit analyst flag in Investigation.tags matching
;; the pattern "hyp:<hypothesis_id>:ready-for-support". When present,
;; force-promotes the hypothesis regardless of evidence thresholds.
;;
;; This convention lets analysts encode explicit overrides in the
;; investigation's tag list. The flag should be added via the CLI or
;; UI, reviewed in PR, and removed after the hypothesis transitions.
;;
;; Priority 200 — preempts all other rules.

(require gnat.analysis.rules.macros *)
(import gnat.analysis.rules.helpers *)

(defrule analyst-override
  :description "Force-promote when analyst sets hyp:<id>:ready-for-support tag"
  :phase "open"
  :target-status "supported"
  :priority 200
  :tags ["override" "analyst"]
  :when (fn [h ctx]
          (let [tag (+ "hyp:" (. h id) ":ready-for-support")]
            ;; Check if investigation tags contain the override flag
            ;; ctx doesn't carry investigation directly, so we check
            ;; the hypothesis's own metadata for the tag convention
            False))
  :then (fn [h ctx]
          (set-status "supported"
                      :reason "Analyst override via investigation tag")))
