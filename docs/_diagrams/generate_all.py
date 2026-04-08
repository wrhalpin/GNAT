# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Generate all GNAT diagrams in one step.

Run from the repo root:
    python docs/_diagrams/generate_all.py

Generates:
  docs/explanation/architecture/img/system_overview.png
  docs/explanation/architecture/img/connector_architecture.png
  docs/explanation/architecture/img/ai_agent_layer.png
  docs/explanation/architecture/img/ingest_pipeline.png
"""

import importlib
import sys
from pathlib import Path

SCRIPTS = [
    "generate_system_overview",
    "generate_connector_arch",
    "generate_ai_agents",
    "generate_ingest_pipeline",
]

diagrams_dir = Path(__file__).parent
sys.path.insert(0, str(diagrams_dir))

for script in SCRIPTS:
    print(f"\n─── Running {script} ───")
    mod = importlib.import_module(script)

print("\n✓  All diagrams generated successfully.")
