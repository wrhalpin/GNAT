# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.research
=================

Three-tier shared research knowledge base for threat intelligence teams.

Tiers
-----
1. **Personal workspaces** — analyst-owned, arbitrary names. Work happens here.
2. **Staging** (_ctmsak_staging) — anyone can promote to here, nothing reads automatically.
3. **Library** (_ctmsak_library) — curated, read-only to analysts, managed by CurationJob.

Typical analyst workflow::

    from gnat.research import ResearchLibrary
    from gnat.agents import ResearchAgent, ParsingAgent, AgentConfig

    lib    = ResearchLibrary.default()
    config = AgentConfig.from_ini()

    # 1. Check library before running research
    if lib.is_fresh("APT29"):
        entry = lib.get("APT29")
        print(f"Using cached research from {entry.researcher}: {entry.note}")
        lib.load_into_workspace("APT29", my_workspace)
    else:
        # 2. Run research agent
        from gnat.ingest import IngestPipeline
        pipeline = (
            IngestPipeline("apt29-research")
            .read_from(ResearchAgent(config, topics=["APT29"]))
            .map_with(ParsingAgent(config))
        )
        pipeline.run()

        # 3. Review results, then promote to staging with a note
        lib.promote(
            workspace  = my_workspace,
            topic      = "APT29",
            researcher = "analyst1",
            note       = "New C2 infra and 3 CVEs. Unit42 + Mandiant corroborated.",
        )

    # 4. List what others have shared
    for summary in lib.list_entries():
        print(summary["topic"], summary["age_hours"], "h",
              "✓" if summary["is_fresh"] else "STALE")

    # 5. Search across all library topics
    results = lib.search("phishing")

Scheduled curation (server-side)::

    from gnat.research import ResearchLibrary, CurationJob
    from gnat.schedule import FeedScheduler

    lib = ResearchLibrary.default()
    job = CurationJob(lib, interval_seconds=4 * 3600)  # every 4 hours

    with FeedScheduler() as scheduler:
        scheduler.add(job)
"""

from gnat.research.curation import CurationJob
from gnat.research.entry import (
    DEFAULT_TTLS,
    ResearchEntry,
    categorise_topic,
    topic_key,
)
from gnat.research.library import ResearchLibrary

__all__ = [
    "ResearchEntry",
    "DEFAULT_TTLS",
    "categorise_topic",
    "topic_key",
    "ResearchLibrary",
    "CurationJob",
]
