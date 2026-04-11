"""Pre-built GNAT investigation workflows."""

from gnat.agents.workflows.incident_response import build_incident_response_workflow
from gnat.agents.workflows.phishing_triage import build_phishing_triage_workflow

__all__ = [
    "build_phishing_triage_workflow",
    "build_incident_response_workflow",
]
