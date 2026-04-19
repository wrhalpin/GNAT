;; SPDX-License-Identifier: Apache-2.0
;; Copyright 2026 Bill Halpin
;;
;; Hy surface for rule helpers. Re-exports Python functions with Lisp naming.
;; The Python modules are the source of truth; this file is a naming layer.
;;
;; Usage in rule files::
;;
;;   (import gnat.analysis.rules.helpers *)

(import gnat.analysis.rules.helpers.evidence :as _ev)
(import gnat.analysis.rules.helpers.confidence :as _cf)
(import gnat.analysis.rules.helpers.temporal :as _tm)
(import gnat.analysis.rules.helpers.status :as _st)
(import gnat.analysis.rules.helpers.policy :as _po)
(import gnat.analysis.rules.helpers.source :as _sr)

;; Evidence
(setv supporting-count _ev.supporting_count)
(setv refuting-count _ev.refuting_count)
(setv evidence-count _ev.evidence_count)
(setv has-refutation? _ev.has_refutation)
(setv support-ratio _ev.support_ratio)

;; Confidence
(setv has-confidence? _cf.has_confidence)
(setv stix-confidence _cf.stix_confidence)
(setv confidence-band _cf.confidence_band)
(setv reliability-of _cf.reliability_of)
(setv credibility-of _cf.credibility_of)
(setv reliability-at-least? _cf.reliability_at_least)
(setv credibility-at-least? _cf.credibility_at_least)

;; Temporal
(setv age-days _tm.age_days)
(setv days-since-update _tm.days_since_update)
(setv stale? _tm.stale)
(setv fresh? _tm.fresh)

;; Status
(setv status-of _st.status_of)
(setv is-open? _st.is_open)
(setv is-supported? _st.is_supported)
(setv is-refuted? _st.is_refuted)
(setv is-inconclusive? _st.is_inconclusive)

;; Policy
(setv within-ai-ceiling? _po.within_ai_ceiling)

;; Source / trust (require ctx argument)
(setv evidence-sources _sr.evidence_sources)
(setv trust-levels _sr.trust_levels)
(setv has-trusted-evidence? _sr.has_trusted_evidence)
(setv all-evidence-trusted? _sr.all_evidence_trusted)
(setv evidence-from? _sr.evidence_from)
(setv unknown-source-count _sr.unknown_source_count)
(setv ai-only? _sr.ai_only)
