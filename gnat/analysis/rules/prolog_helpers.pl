%% gnat/analysis/rules/prolog_helpers.pl
%% Pre-loaded Prolog predicates mirroring the Python helper library.
%% These predicates operate on dynamically asserted hypothesis facts.

%% Evidence predicates
has_refutation :- refuting_count(N), N > 0.
evidence_count(N) :- supporting_count(S), refuting_count(R), N is S + R.
support_ratio(R) :- supporting_count(S), evidence_count(T), T1 is T + 1, R is S / T1.

%% Confidence predicates
has_confidence :- stix_confidence(C), C > 0.

%% Reliability ordering: A > B > C > D > E > F
rel_order('A', 6).
rel_order('B', 5).
rel_order('C', 4).
rel_order('D', 3).
rel_order('E', 2).
rel_order('F', 1).

reliability_at_least(Min) :-
    reliability(Actual),
    rel_order(Actual, AO),
    rel_order(Min, MO),
    AO >= MO.

%% Credibility: lower is better (1=confirmed ... 6=cannot be judged)
credibility_at_least(Max) :-
    credibility(Actual),
    Actual =< Max.

%% Temporal predicates (days_since_update asserted as fact)
stale(Days) :- days_since_update(D), D >= Days.
fresh(Days) :- days_since_update(D), D =< Days.

%% Status predicates
is_open :- hypothesis_status(open).
is_supported :- hypothesis_status(supported).
is_refuted :- hypothesis_status(refuted).
is_inconclusive :- hypothesis_status(inconclusive).

%% AI ceiling
within_ai_ceiling :- \+ ai_only.
within_ai_ceiling :- ai_only, stix_confidence(C), ai_confidence_ceiling(Max), C =< Max.

%% Trust predicates
has_trusted_evidence :- trusted_source_present.
