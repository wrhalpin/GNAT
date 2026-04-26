# Investigation Copilot & Live Analyst Assistant

**GNAT v1.9.0** includes two AI-powered agents to accelerate threat intelligence investigations:

1. **Investigation Copilot (F10)** — Multi-turn conversational guide that asks clarifying questions and orchestrates investigation workflows
2. **Live Analyst Assistant (F11)** — On-demand helper for enrichment suggestions, report drafting, and finding explanations

---

## Investigation Copilot

The copilot is your investigation partner. It asks clarifying questions to narrow scope, proposes hypotheses, and suggests next steps.

### Quick Start (TUI)

1. Open an investigation in GNAT TUI (`gnat tui → F5 Investigations`)
2. Press **F10** to open Copilot
3. Answer initial questions (scope, timeline, impact)
4. Copilot will suggest next investigation steps
5. Type `/next` to get action recommendations, or type your own thoughts

### How It Works

**Phase Machine:**
- **GATHERING** → Collect initial details (IOCs, timeline, impact)
- **HYPOTHESIZING** → Build theories about who/what is behind the activity
- **TESTING** → Run enrichment and validation
- **CLOSING** → Draft report and escalation decision
- **COMPLETE** → Investigation finished

**Example Conversation:**

```
Copilot: Let's begin. What do you know about this activity?

You: We found some suspicious IP addresses in our firewall logs

Copilot: How many unique IPs are we talking about? (give a rough count)

You: About 15-20 different ones

Copilot: Are these IPs from a single geographic region, or scattered?

You: Mostly from Russia and Eastern Europe

Copilot: Based on that clustering, I recommend:
1. Query Recorded Future for reputation (low FP risk with geo-clustering)
2. Check for campaign overlap in ThreatQ
3. Correlate with known APT infrastructure

Run enrichment? (type /next or your thoughts)

You: /next

Copilot: Next step: Query ThreatQ for campaign overlap (est. 2 min)
```

### Slash Commands

| Command | Purpose |
|---------|---------|
| `/next` | Get copilot's recommended next investigation step |
| `/close` | Mark investigation as closing (move to final phase) |
| `/help` | Show available commands |

### Safety & Approvals

**High-confidence suggestions are gated:**
- Hypotheses with >80% confidence → Analyst approval required
- Escalations to Incident Response → Always require approval
- All operations logged to audit trail for compliance

**Cost tracking:**
- Each LLM call is tracked (tokens, latency, cost)
- Investigation-level cost summary available
- Alerts if investigation exceeds $10 USD threshold

---

## Live Analyst Assistant

The assistant provides on-demand help without interrupting your investigation flow. Use it for quick suggestions or deep dives.

### Quick Start (TUI)

1. Press **F11** while in an investigation to open Assistant
2. Use commands:
   - `/enrich` → Get 3-5 connector suggestions for current object
   - `/draft <section>` → Generate report section options (executive_summary, findings, recommendations)
   - `/explain <type>:<value>` → Explain a STIX object (e.g., `/explain ipv4-addr:1.2.3.4`)
   - Or just ask a question → Gets search routing help

### Examples

**Enrichment Suggestions:**
```
You: /enrich