# Investigation Copilot & Assistant Examples

Code examples for using the Investigation Copilot and Live Analyst Assistant programmatically.

---

## Investigation Copilot

### Basic Usage: Start a Copilot Session

```python
from gnat.agents import (
    InvestigationCopilotSession,
    ConversationStore,
    AgentConfig,
)

# Initialize
config = AgentConfig.from_ini()
store = ConversationStore()

# Create session
session_ctx = store.create_session(
    analyst_id="alice@company.com",
    investigation_id="inv_phishing_20260426_001",
    agent_type="copilot",
)

# Initialize copilot
copilot = InvestigationCopilotSession(
    conversation_id=session_ctx.conversation_id,
    config=config,
    conversation_store=store,
)

print(f"Copilot session started: {session_ctx.conversation_id}")
print(f"Phase: {session_ctx.state}")
```

### Ask Clarifying Questions

```python
# Analyst provides initial context
question_1 = await copilot.ask_clarifying_question(
    "We found suspicious emails from external sender"
)
print(f"Copilot: {question_1}")
# Output: "How many unique recipients were targeted?"

# Answer the question
question_2 = await copilot.ask_clarifying_question("About 50 users in our finance department")
print(f"Copilot: {question_2}")
# Output: "Are there any common attributes? (same department, same role, etc)"

# Continue conversation
question_3 = await copilot.ask_clarifying_question("Yes, all finance team members")
print(f"Copilot: {question_3}")
# Output: "Any evidence of successful credential compromise, or just emails received?"
```

### Get Next Step Recommendation

```python
suggestion = await copilot.suggest_next_step()

print(f"Recommended action: {suggestion.text}")
print(f"Confidence: {suggestion.confidence:.0%}")
print(f"Estimated duration: {suggestion.metadata.get('estimated_duration_sec')}s")

# Output:
# Recommended action: Query Recorded Future for sender domain reputation
# Confidence: 0.92
# Estimated duration: 30s
```

### Refine Hypotheses Based on Feedback

```python
# Copilot proposes hypothesis
hypothesis_response = await copilot.refine_hypothesis(
    "I think this is a targeted phishing campaign against finance"
)

print(f"Updated hypothesis: {hypothesis_response}")
# Returns refined hypothesis with new confidence scores
```

### Access Audit Trail

```python
# Get all operations logged for this investigation
audit_entries = copilot.audit_log.get_audit_trail(
    investigation_id="inv_phishing_20260426_001"
)

for entry in audit_entries:
    print(f"{entry['timestamp']}: {entry['operation']} (confidence: {entry['confidence']:.0%})")

# Output:
# 2026-04-26T14:32:10.123456: ask_question (confidence: 0.0%)
# 2026-04-26T14:33:45.654321: ask_question (confidence: 0.0%)
# 2026-04-26T14:35:20.987654: suggest_step (confidence: 0.92%)
```

### Check Cost Usage

```python
stats = copilot.cost_tracker.get_stats()

print(f"Tokens used: {stats['total_tokens']}")
print(f"Estimated cost: ${stats['cost_estimate_usd']:.2f}")
print(f"Average latency: {stats['avg_latency_ms']:.0f}ms")

# Output:
# Tokens used: 2,450
# Estimated cost: $0.037
# Average latency: 892ms
```

---

## Live Analyst Assistant

### Basic Usage: Start Assistant Session

```python
from gnat.agents import LiveAnalystAssistantSession

config = AgentConfig.from_ini()
store = ConversationStore()

# Create session
session_ctx = store.create_session(
    analyst_id="alice@company.com",
    investigation_id="inv_phishing_20260426_001",
    agent_type="assistant",
)

# Initialize assistant
assistant = LiveAnalystAssistantSession(
    conversation_id=session_ctx.conversation_id,
    config=config,
    conversation_store=store,
)

print(f"Assistant ready: {session_ctx.conversation_id}")
```

### Get Enrichment Suggestions (Streaming)

```python
from gnat.orm import Indicator

# Create a STIX indicator for enrichment
indicator = Indicator(
    pattern="[domain-name:value = 'suspicious.example.com']",
    pattern_type="stix",
)

# Get streaming suggestions
print("Suggested enrichment sources:")
async for suggestion in assistant.suggest_enrichment(indicator):
    print(f"  • {suggestion.connector_name}")
    print(f"    {suggestion.reason}")
    print(f"    Est. {suggestion.estimated_duration_sec}s\n")

# Output:
# Suggested enrichment sources:
#   • Recorded Future
#     Specialized in domain reputation scoring. Highest coverage for phishing domains
#     Est. 5s
#   
#   • URLhaus
#     Public malware distribution tracking. Fast response for recently active domains
#     Est. 3s
#   
#   • VirusTotal
#     Community threat voting on domains. Good FP filtering
#     Est. 2s
```

### Draft Report Sections (Batched)

```python
# Get multiple options for a findings section
options = await assistant.draft_report_section(
    section_type="findings",
    investigation_context={
        "ioc_count": 47,
        "suspected_actor": "APT29",
        "confidence": 0.78,
        "affected_systems": 12,
    },
)

# Choose preferred tone
for i, option in enumerate(options, 1):
    print(f"\n--- Option {i} ({option.tone} tone) ---")
    print(option.text)
    print(f"Quality: {option.quality_score:.0%}")

# Output:
# --- Option 1 (formal tone) ---
# Our investigation identified 47 indicators of compromise associated with APT29 activity...
# Quality: 88%
#
# --- Option 2 (technical tone) ---
# Analysis reveals high-confidence IOC clustering consistent with APT29 TTPs...
# Quality: 91%
```

### Explain a Finding (Streaming)

```python
# Analyst asks: "What does this IP matter?"
finding = Indicator(pattern="[ipv4-addr:value = '192.168.1.100']")

print("Explanation:")
async for token in assistant.explain_finding(finding, context={}):
    print(token, end="", flush=True)
print()

# Output:
# This IP is associated with APT29's Cozy Bear infrastructure based on
# Recorded Future historical sightings. It was observed in the SolarWinds
# supply chain attack (Dec 2020) and linked to multiple intrusions in
# government and energy sectors. The C2 communication patterns match known
# Cozy Bear playbooks.
```

### Search Help (Routing)

```python
# Analyst natural language query
async for token in assistant.search_help("Find APT29 infrastructure in Russia"):
    print(token, end="", flush=True)
print()

# Output:
# Try these connectors:
#
# 1. ThreatQ (primary):
#    STIX pattern: [location-ref:country_code = 'RU'] AND [relationship-type = 'attributed-to'] AND [identity:name = 'APT29']
#
# 2. Recorded Future (supplement):
#    API query: apt29 infrastructure russia
#
# 3. Shodan (network validation):
#    Query: country:RU "Cozy Bear" OR "Sofacy"
```

---

## Guided Workflows

### Phishing Triage Workflow

```python
from gnat.agents.copilot_workflows import WorkflowFactory

# Create phishing triage workflow
workflow = WorkflowFactory.create(
    workflow_type="phishing_triage",
    copilot_session=copilot,
)

# Run workflow (copilot guides analyst through steps)
result = await workflow.run()

print(f"Workflow status: {result['status']}")
print(f"Steps executed: {len(result['steps_executed'])}")
print(f"Recommendation: {result['recommendation']}")

# Output:
# Workflow status: completed
# Steps executed: 5
# Recommendation: ESCALATE: Submit to incident response for containment
```

### Incident Response Workflow

```python
# Create incident response workflow
ir_workflow = WorkflowFactory.create(
    workflow_type="incident_response",
    copilot_session=copilot,
)

# Run (copilot orchestrates investigation)
result = await ir_workflow.run()

print(f"Incident summary:")
print(f"  Scope: {result['incident_summary'].get('scope')}")
print(f"  Impact: {result['incident_summary'].get('impact')}")
print(f"  Status: {result['status']}")
```

---

## Governance & Audit

### Check Action Permissions

```python
from gnat.agents import CopilotAction, ActionRisk

# Check if action is permitted
permitted = await copilot.governor.check_copilot_action(
    action=CopilotAction.REFINE_HYPOTHESIS,
    investigation_id="inv_phishing_20260426_001",
    analyst_id="alice@company.com",
    confidence=0.92,  # High confidence
    description="Hypothesis: This is a targeted phishing campaign",
)

if not permitted:
    print("Action requires analyst approval")
    # Submit to ReviewService for HITL gate
    review_id = await copilot.review_manager.submit_hypothesis_for_review(
        hypothesis_text="Targeted phishing campaign against finance",
        investigation_id="inv_phishing_20260426_001",
        analyst_id="alice@company.com",
        confidence=0.92,
    )
    print(f"Submitted for review: {review_id}")
    
    # Wait for decision
    decision = await copilot.review_manager.await_review_decision(review_id)
    print(f"Decision: {decision['status']}")
```

### Get Investigation Summary

```python
# Get stats for entire investigation
summary = copilot.audit_log.get_investigation_summary(
    investigation_id="inv_phishing_20260426_001"
)

print(f"Investigation: {summary['investigation_id']}")
print(f"  Operations: {summary['operation_count']}")
print(f"  Copilot questions: {summary['copilot_questions']}")
print(f"  Assistant queries: {summary['assistant_queries']}")
print(f"  Total tokens: {summary['total_tokens']}")
print(f"  Avg confidence: {summary['avg_confidence']:.0%}")
print(f"  Reviews required: {summary['reviews_required']}")
print(f"  Timespan: {summary['first_operation']} → {summary['last_operation']}")

# Output:
# Investigation: inv_phishing_20260426_001
#   Operations: 18
#   Copilot questions: 7
#   Assistant queries: 8
#   Total tokens: 5,892
#   Avg confidence: 0.81
#   Reviews required: 1
#   Timespan: 2026-04-26T14:30:00 → 2026-04-26T15:45:00
```

### Export Audit Log

```python
# Export for compliance review
json_log = copilot.audit_log.export_audit_log(
    investigation_id="inv_phishing_20260426_001",
    format="json"
)

# Save to file
with open("audit_log.json", "w") as f:
    f.write(json_log)

# Or CSV
csv_log = copilot.audit_log.export_audit_log(
    investigation_id="inv_phishing_20260426_001",
    format="csv"
)

with open("audit_log.csv", "w") as f:
    f.write(csv_log)
```

---

## Configuration

### Copilot Config (config.ini)

```ini
[claude]
api_key = sk-proj-...
model = claude-sonnet-4-6
ai_confidence_ceiling = 60

[copilot]
cost_alert_threshold = 10.0  # USD
review_required_threshold = 0.80  # Confidence
```

### Environment Variables

```bash
# Override config
export GNAT_CONFIG=/path/to/config.ini
export CLAUDE_API_KEY=sk-proj-...

# Run TUI with copilot ready
gnat tui --initial-tab investigations
```

---

## Best Practices

1. **Start with Copilot for structure.** Let it ask clarifying questions to narrow scope.
2. **Use Assistant for quick lookups.** Don't wait for full copilot workflow if you just need enrichment suggestions.
3. **Review high-confidence decisions.** Copilot gates >80% confidence hypotheses for analyst approval.
4. **Monitor cost.** Check cost_tracker stats periodically, especially on long-running investigations.
5. **Export audit logs.** Use export_audit_log() for compliance and incident post-mortems.

---

## Troubleshooting

**Copilot not responding?**
- Check CLAUDE_API_KEY is set
- Verify config.ini [claude] section
- Check cost hasn't exceeded alert threshold

**Assistant drafting slow?**
- Draft operations are batched for efficiency (5-10s typical)
- If consistently slow, check network latency

**High cost?**
- Check investigation token counts
- Consider using Assistant instead of Copilot for simple enrichment
- Limit conversation length (summarize periodically)
