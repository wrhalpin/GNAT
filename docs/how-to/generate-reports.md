# How-to: Generate Reports

Create PDF, HTML, Markdown, and DOCX threat intelligence reports — with or without AI assistance.

---

## Daily report — no AI

```python
from gnat.reports import ReportGenerator, ReportConfig, AIMode

config = ReportConfig(
    report_type = "daily",
    workspaces  = ["_ctmsak_library", "analyst-workspace"],
    sectors     = ["Healthcare", "Insurance", "Opportunistic"],
    ai_mode     = AIMode.NONE,
    formats     = ["pdf", "html", "markdown"],
    delivery    = ["email", "file"],
    email_to    = ["soc-team@example.com"],
    output_dir  = "/var/reports/daily",
    org_name    = "Acme Health",
)

result = ReportGenerator(manager, config).run()
print(result.files_written)
```

---

## Trends report — AI-assisted

```python
from gnat.agents import AgentConfig

config = ReportConfig(
    report_type = "trends",
    workspaces  = ["_ctmsak_library"],
    sectors     = ["Healthcare", "Opportunistic"],
    ai_mode     = AIMode.ASSISTED,
    formats     = ["pdf", "docx"],
    delivery    = ["sharepoint", "email"],
    sharepoint_url = "https://contoso.sharepoint.com/sites/Security/Reports",
    email_to    = ["soc-leads@example.com"],
    output_dir  = "/var/reports/trends",
    window_days = 30,
    org_name    = "Acme Health",
)

result = ReportGenerator(
    manager          = manager,
    config           = config,
    agent_config     = AgentConfig.from_ini(),
    research_library = ResearchLibrary.default(),
).run()
```

---

## Scheduled reports

Combine daily and yearly jobs in a single scheduler:

```python
from gnat.reports import ReportJob
from gnat.schedule import FeedScheduler

daily_job = ReportJob(
    manager      = manager,
    config       = ReportConfig(
        report_type = "daily",
        formats     = ["pdf", "html"],
        delivery    = ["email"],
        email_to    = ["soc@example.com"],
        schedule    = "0 6 * * *",     # 06:00 daily
        org_name    = "Acme Health",
    ),
    agent_config     = AgentConfig.from_ini(),
    research_library = ResearchLibrary.default(),
)

yearly_job = ReportJob(
    manager = manager,
    config  = ReportConfig(
        report_type = "yearly",
        ai_mode     = AIMode.FULL,
        formats     = ["pdf", "docx"],
        delivery    = ["sharepoint", "email"],
        schedule    = "0 6 1 1 *",    # January 1st
    ),
    agent_config = AgentConfig.from_ini(),
)

with FeedScheduler() as sched:
    sched.add(daily_job)
    sched.add(yearly_job)
```

---

## See Also

- [How-to: Use the Research Library](use-research-library.md)
- [How-to: Schedule Feeds](schedule-feeds.md)
