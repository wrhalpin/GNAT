;; SPDX-License-Identifier: Apache-2.0
;; Copyright 2026 Bill Halpin
;;
;; gnat.analysis.rules.macros
;; =============================
;;
;; Analyst-facing macros for authoring hypothesis evaluation rules.
;;
;; Usage in a .hy rule file::
;;
;;   (require gnat.analysis.rules.macros *)
;;
;;   (defrule my-rule
;;     :description "Promote when evidence is strong"
;;     :phase "open"
;;     :target-status "supported"
;;     :priority 100
;;     :tags ["promotion" "evidence-based"]
;;     :when (fn [h ctx] (>= (supporting-count h) 3))
;;     :then (fn [h ctx] (set-status "supported" :reason "Strong evidence")))

(import gnat.analysis.rules.registry [register-rule])
(import gnat.analysis.rules.decisions [set-status annotate no-op])

(defmacro defrule [rule-name #* body]
  "Define and register a hypothesis evaluation rule."
  (setv parsed {})
  (setv i 0)
  (while (< i (len body))
    (setv key (get body i))
    (setv val (get body (+ i 1)))
    (setv key-str (name key))
    (assoc parsed key-str val)
    (+= i 2))

  ;; Validate required keys
  (for [required ["phase" "when" "then"]]
    (when (not (in required parsed))
      (raise (ValueError f"defrule {rule-name}: missing required key :{required}"))))

  (setv rule-name-str (name rule-name))
  (setv phase-val (.get parsed "phase" None))
  (setv target-val (.get parsed "target-status" None))
  (setv desc-val (.get parsed "description" ""))
  (setv priority-val (.get parsed "priority" 50))
  (setv tags-val (.get parsed "tags" []))
  (setv when-val (get parsed "when"))
  (setv then-val (get parsed "then"))

  `(register-rule
     {"name" ~(str rule-name-str)
      "description" ~desc-val
      "phase" ~phase-val
      "target_status" ~target-val
      "priority" ~priority-val
      "tags" ~tags-val
      "when_fn" ~when-val
      "then_fn" ~then-val
      "source_file" __file__}))
