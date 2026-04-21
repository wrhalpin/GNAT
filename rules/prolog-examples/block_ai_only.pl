%% Block promotion when all evidence is AI-sourced
rule(block_ai_only, [
    phase(open),
    priority(110),
    description('Block promotion for AI-only evidence')
]).

when(block_ai_only) :-
    evidence_count(N), N > 0,
    ai_only.

then(block_ai_only, no_op('All evidence from AI connectors')).
