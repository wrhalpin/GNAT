%% Mark REFUTED when refuting evidence dominates
rule(refute_on_refuting_evidence, [
    phase(open),
    priority(90),
    description('Refute when refuting exceeds supporting')
]).

when(refute_on_refuting_evidence) :-
    refuting_count(R), R >= 2,
    supporting_count(S), R > S,
    has_confidence,
    reliability_at_least('C').

then(refute_on_refuting_evidence, set_status(refuted,
    'Refuting evidence exceeds supporting and meets reliability threshold')).
