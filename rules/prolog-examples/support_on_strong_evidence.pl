%% Promote OPEN -> SUPPORTED on strong evidence
rule(support_on_strong_evidence, [
    phase(open),
    priority(100),
    description('Promote when evidence is strong and well-sourced')
]).

when(support_on_strong_evidence) :-
    supporting_count(N), N >= 3,
    \+ has_refutation,
    has_confidence,
    reliability_at_least('B'),
    credibility_at_least(2),
    has_trusted_evidence,
    within_ai_ceiling.

then(support_on_strong_evidence, set_status(supported,
    '3+ supporting, no refutation, B2+ confidence, trusted source')).
