"""
gnat.cli.main
=================

GNAT command-line interface.

Entry point: ``gnat`` (installed via ``pyproject.toml`` scripts).

Sub-commands
------------

.. code-block:: text

    gnat ping      --target threatq
    gnat query     --target threatq --type indicator --id indicator--abc
    gnat list      --target crowdstrike --type indicator --limit 20
    gnat ingest    --target threatq --source iocs.txt --format plaintext
    gnat ingest    --target threatq --source feed.json --format stix-bundle
    gnat ingest    --target threatq --source export.csv --format csv
    gnat ingest    --target threatq --source events.json --format misp
    gnat codegen   openapi --spec openapi.json --name myplatform --auth oauth2
    gnat codegen   xsoar   --connector threatq --output ./packs/
    gnat report    list
    gnat report    run --config daily_healthcare
    gnat report    run --config daily_healthcare --formats pdf,html --no-ai
    gnat config    --show
    gnat config    --validate
    gnat client    capabilities --platform threatq
    gnat client    call         --platform threatq --method list_objects --args type=indicator
    gnat nlq       "Get all IPs for APT28 from the last 30 days"
    gnat nlq       "Lazarus Group domains since January" --platform threatq --backend claude
    gnat serve     --api-key mysecret --port 8088
    gnat serve     --host 0.0.0.0 --port 8088 --reports-dir /var/gnat/reports
    gnat health    check
    gnat health    check --platform threatq --no-schema
    gnat health    baseline threatq
    gnat contribute --connector myplatform --message "Add MyPlatform connector"
    gnat contribute --connector myplatform --dry-run
    gnat contribute --connector myplatform --no-pr

Global flags
------------

.. code-block:: text

    --config PATH      Path to config.ini  (default: ~/.gnat/config.ini)
    --output FORMAT    Output format: json | table | stix  (default: table)
    --quiet            Suppress informational output
    --no-color         Disable ANSI color output
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("gnat.cli")


# ── ANSI color helpers ─────────────────────────────────────────────────────

_NO_COLOR = False


def _c(code: str, text: str) -> str:
    if _NO_COLOR or not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def _green(t: str)  -> str: return _c("32", t)
def _red(t: str)    -> str: return _c("31", t)
def _yellow(t: str) -> str: return _c("33", t)
def _bold(t: str)   -> str: return _c("1",  t)
def _dim(t: str)    -> str: return _c("2",  t)


# ── Output formatters ──────────────────────────────────────────────────────

def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, default=str))


def _print_table(rows: List[Dict[str, Any]], fields: Optional[List[str]] = None) -> None:
    """Print a list of dicts as a plain ASCII table."""
    if not rows:
        print(_dim("(no results)"))
        return
    cols = fields or list(rows[0].keys())
    widths = {c: max(len(str(c)), max(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    header = "  ".join(str(c).ljust(widths[c]) for c in cols)
    sep    = "  ".join("─" * widths[c] for c in cols)
    print(_bold(header))
    print(_dim(sep))
    for row in rows:
        print("  ".join(str(row.get(c, "")).ljust(widths[c]) for c in cols))


def _print_stix(obj: Any) -> None:
    d = obj.to_dict() if hasattr(obj, "to_dict") else obj
    _print_json(d)


# ── Build argument parser ──────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gnat",
        description=_bold("GNAT — Cybersecurity Threat Management Swiss Army Knife"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              gnat ping   --target threatq
              gnat query  --target crowdstrike --type indicator --id indicator--abc
              gnat list   --target xsoar --type indicator --limit 50
              gnat ingest --target threatq --source iocs.txt --format plaintext
              gnat ingest --target threatq --source bundle.json --format stix-bundle
              gnat codegen --spec openapi.json --name myplatform --auth oauth2
              gnat config --validate
        """),
    )

    # Global flags
    parser.add_argument("--config",   metavar="PATH",
                        help="Path to config.ini (default: ~/.gnat/config.ini)")
    parser.add_argument("--output",   choices=["json", "table", "stix"],
                        default="table", help="Output format (default: table)")
    parser.add_argument("--quiet",    action="store_true",
                        help="Suppress informational messages")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color output")
    parser.add_argument("--debug",    action="store_true",
                        help="Enable debug logging")

    subs = parser.add_subparsers(dest="command", title="commands", metavar="<command>")
    subs.required = True

    # ── ping ──────────────────────────────────────────────────────────────
    p_ping = subs.add_parser("ping", help="Check connectivity to a platform")
    p_ping.add_argument("--target", required=True, metavar="NAME",
                        help="Platform target (threatq, crowdstrike, …)")

    # ── query ─────────────────────────────────────────────────────────────
    p_query = subs.add_parser("query", help="Fetch a single object by id")
    p_query.add_argument("--target", required=True, metavar="NAME")
    p_query.add_argument("--type",   required=True, metavar="STIX_TYPE",
                         help="STIX type (indicator, malware, vulnerability, …)")
    p_query.add_argument("--id",     required=True, metavar="OBJECT_ID",
                         help="Object id (STIX or platform-native)")

    # ── list ──────────────────────────────────────────────────────────────
    p_list = subs.add_parser("list", help="List objects from a platform")
    p_list.add_argument("--target", required=True, metavar="NAME")
    p_list.add_argument("--type",   required=True, metavar="STIX_TYPE")
    p_list.add_argument("--limit",  type=int, default=20, metavar="N",
                        help="Max results (default: 20)")
    p_list.add_argument("--page",   type=int, default=1,  metavar="N")
    p_list.add_argument("--filter", dest="filters", nargs="*", metavar="KEY=VALUE",
                        help="Filter expressions, e.g. --filter status=Active type=IP")

    # ── ingest ────────────────────────────────────────────────────────────
    p_ingest = subs.add_parser("ingest", help="Ingest IOCs from a file into a platform")
    p_ingest.add_argument("--target",     required=True, metavar="NAME")
    p_ingest.add_argument("--source",     required=True, metavar="PATH",
                          help="Source file path")
    p_ingest.add_argument("--format",     required=True, metavar="FORMAT",
                          choices=["plaintext", "csv", "json", "jsonl",
                                   "stix-bundle", "misp", "cef", "openioc", "nvd"],
                          help="Source file format")
    p_ingest.add_argument("--tlp",        default="white",
                          choices=["white", "green", "amber", "red"],
                          help="TLP marking for ingested objects (default: white)")
    p_ingest.add_argument("--confidence", type=int, default=50, metavar="0-100",
                          help="Confidence score (default: 50)")
    p_ingest.add_argument("--dry-run",    action="store_true",
                          help="Map and print objects but do not write to platform")
    p_ingest.add_argument("--deduplicate", action="store_true", default=True,
                          help="Deduplicate by name (default: on)")
    p_ingest.add_argument("--value-col",  default="value", metavar="COL",
                          help="CSV column containing IOC value (default: value)")
    p_ingest.add_argument("--type-col",   default=None,    metavar="COL",
                          help="CSV column containing IOC type")
    p_ingest.add_argument("--records-key", default=None,   metavar="KEY",
                          help="JSON key containing the array of records")

    # ── codegen ───────────────────────────────────────────────────────────
    p_cg = subs.add_parser("codegen", help="Code generation utilities")
    cg_subs = p_cg.add_subparsers(dest="codegen_command", title="codegen commands",
                                   metavar="<codegen_command>")
    cg_subs.required = True

    p_cg_oa = cg_subs.add_parser("openapi",
                                  help="Generate a connector from an OpenAPI spec")
    p_cg_oa.add_argument("--spec",     required=True, metavar="PATH",
                         help="OpenAPI spec file (JSON or YAML)")
    p_cg_oa.add_argument("--name",     required=True, metavar="NAME",
                         help="Connector name (snake_case)")
    p_cg_oa.add_argument("--auth",     default="oauth2",
                         choices=["oauth2", "api_key", "basic"])
    p_cg_oa.add_argument("--out-dir",  default="./gnat/connectors", metavar="DIR")
    p_cg_oa.add_argument("--test-dir", default="./tests/unit/connectors", metavar="DIR")
    p_cg_oa.add_argument("--overwrite", action="store_true")

    p_cg_xs = cg_subs.add_parser("xsoar",
                                  help="Generate an XSOAR content pack from a GNAT connector")
    p_cg_xs.add_argument("--connector", required=True, metavar="NAME",
                         help="GNAT connector key (e.g. threatq, crowdstrike)")
    p_cg_xs.add_argument("--output",    default="./packs", metavar="DIR",
                         help="Output directory for the generated .zip (default: ./packs)")
    p_cg_xs.add_argument("--version",   default="1.0.0", metavar="X.Y.Z",
                         help="Pack semantic version (default: 1.0.0)")
    p_cg_xs.add_argument("--auth",      default=None,
                         choices=["oauth2", "api_key", "basic"],
                         help="Override auth type (auto-detected when omitted)")
    p_cg_xs.add_argument("--overwrite", action="store_true",
                         help="Overwrite existing zip file")

    # ── viz ───────────────────────────────────────────────────────────────
    p_viz = subs.add_parser("viz", help="Workspace visualization")
    viz_subs = p_viz.add_subparsers(dest="viz_command", title="viz commands",
                                    metavar="<viz_command>")
    viz_subs.required = True

    p_vt = viz_subs.add_parser("table", help="Render workspace as table")
    p_vt.add_argument("--workspace", required=True, metavar="NAME")
    p_vt.add_argument("--type",      default=None,  metavar="STIX_TYPE")
    p_vt.add_argument("--sort",      default="confidence")
    p_vt.add_argument("--top",       type=int, default=100)
    p_vt.add_argument("--file",      default=None, metavar="PATH",
                      help="Save output to file (format inferred from extension)")

    p_vg = viz_subs.add_parser("graph", help="Open 3D STIX relationship graph")
    p_vg.add_argument("--workspace", required=True, metavar="NAME")
    p_vg.add_argument("--types",     nargs="*",  metavar="STIX_TYPE")
    p_vg.add_argument("--file",      default=None, metavar="PATH")

    p_vs = viz_subs.add_parser("serve", help="Start Grafana datasource server")
    p_vs.add_argument("--port",  type=int, default=3001)
    p_vs.add_argument("--host",  default="0.0.0.0")  # nosec B104 — user-facing CLI arg
    p_vs.add_argument("--with-solr", action="store_true",
                      help="Mount /solr/ endpoints from the configured search index")

    p_vd = viz_subs.add_parser("dashboard", help="Export Grafana dashboard JSON")
    p_vd.add_argument("--workspace", required=True, metavar="NAME")
    p_vd.add_argument("--file",      default="dashboard.json")
    p_vd.add_argument("--datasource", default="GNAT")

    p_vsd = viz_subs.add_parser("solr-dashboard",
                                 help="Export Grafana dashboard JSON for Solr search sidecar")
    p_vsd.add_argument("--file",       default="solr_dashboard.json")
    p_vsd.add_argument("--datasource", default="GNAT-Solr",
                       help="Grafana datasource name for /solr/ endpoints (default: GNAT-Solr)")
    p_vsd.add_argument("--title",      default="GNAT Search Index")

    p_vpb = viz_subs.add_parser("powerbi", help="Export workspace to Power BI Excel")
    p_vpb.add_argument("--workspace", required=True, metavar="NAME")
    p_vpb.add_argument("--file",      default="workspace.xlsx")

    # ── report ────────────────────────────────────────────────────────────
    p_rp = subs.add_parser("report", help="Generate or list configured reports")
    rp_subs = p_rp.add_subparsers(dest="report_command", title="report commands",
                                   metavar="<report_command>")
    rp_subs.required = True

    p_rp_run = rp_subs.add_parser("run", help="Generate a report immediately")
    p_rp_run.add_argument("--config", dest="report_config", required=True,
                          metavar="NAME",
                          help="Report config name from ini, e.g. daily_healthcare")
    p_rp_run.add_argument("--output-dir", default=None, metavar="DIR",
                          help="Override output directory from config")
    p_rp_run.add_argument("--formats", default=None, metavar="FORMATS",
                          help="Comma-separated formats to render, "
                               "e.g. pdf,html,markdown (overrides config)")
    p_rp_run.add_argument("--no-ai", action="store_true",
                          help="Disable AI narrative generation for this run")

    rp_subs.add_parser("list", help="List configured report profiles from ini")

    # ── schedule ──────────────────────────────────────────────────────────
    p_sc = subs.add_parser("schedule", help="Manage scheduled feed jobs")
    sc_subs = p_sc.add_subparsers(dest="schedule_command", title="schedule commands",
                                   metavar="<schedule_command>")
    sc_subs.required = True

    p_sc_list = sc_subs.add_parser("list",   help="List registered jobs and status")
    p_sc_run  = sc_subs.add_parser("run",    help="Run one or all jobs immediately")
    p_sc_run.add_argument("--job", default=None, metavar="JOB_ID",
                          help="Run a specific job (omit to run all)")
    p_sc_run.add_argument("--parallel", action="store_true",
                          help="Run all jobs in parallel")
    p_sc_cron = sc_subs.add_parser("crontab", help="Print crontab lines for all jobs")

    # ── config ────────────────────────────────────────────────────────────
    p_cfg = subs.add_parser("config", help="Show or validate configuration")
    grp = p_cfg.add_mutually_exclusive_group(required=True)
    grp.add_argument("--show",     action="store_true",
                     help="Print resolved configuration (redacts secrets)")
    grp.add_argument("--validate", action="store_true",
                     help="Validate that all required keys are present")
    grp.add_argument("--init",     action="store_true",
                     help="Create a starter config.ini at the default location")

    # ── client ────────────────────────────────────────────────────────────
    p_cl = subs.add_parser("client", help="Connector introspection and dynamic dispatch")
    cl_subs = p_cl.add_subparsers(dest="client_command", title="client commands",
                                   metavar="<client_command>")
    cl_subs.required = True

    p_cl_caps = cl_subs.add_parser("capabilities",
                                    help="List all operations available on a connector")
    p_cl_caps.add_argument("--platform", required=True, metavar="NAME",
                           help="Connector platform name (e.g. threatq, crowdstrike)")
    p_cl_caps.add_argument("--type", dest="cap_type", metavar="TYPE",
                           choices=["auth", "read", "write", "helper"],
                           help="Filter by operation type")
    p_cl_caps.add_argument("--platform-specific", action="store_true",
                           help="Show only platform-specific (non-standard) methods")

    p_cl_call = cl_subs.add_parser("call", help="Dynamically dispatch a connector method")
    p_cl_call.add_argument("--platform",    required=True, metavar="NAME")
    p_cl_call.add_argument("--method",      required=True, metavar="METHOD",
                           help="Method name (must appear in capabilities)")
    p_cl_call.add_argument("--args",        nargs="*", metavar="KEY=VALUE",
                           help="Method arguments as KEY=VALUE pairs")
    p_cl_call.add_argument("--allow-write", action="store_true",
                           help="Permit write operations (upsert_object, delete_object)")

    # ── nlq ───────────────────────────────────────────────────────────────
    p_nlq = subs.add_parser("nlq",
                             help="Natural-language threat-intel query")
    p_nlq.add_argument("query", metavar="QUERY",
                       help="Free-text query, e.g. \"APT28 IPs last 30 days\"")
    p_nlq.add_argument("--platform", dest="nlq_platform", default=None, metavar="NAME",
                       help="Connect to this platform and query it (optional)")
    p_nlq.add_argument("--backend",  default=None, choices=["builtin", "claude"],
                       help="Override NLP backend (default: from [nlp] config or builtin)")
    p_nlq.add_argument("--parse-only", action="store_true",
                       help="Print the parsed QuerySpec without querying any connector")
    p_nlq.add_argument("--limit", type=int, default=None, metavar="N",
                       help="Override result limit")

    # ── tui ───────────────────────────────────────────────────────────────
    p_tui = subs.add_parser("tui",
                            help="Launch interactive terminal UI (requires gnat[tui])")
    p_tui.add_argument("screen", nargs="?",
                       choices=["query", "library", "scheduler", "reports"],
                       default="query",
                       help="Screen to open on launch (default: query)")
    p_tui.add_argument("--backend", default=None, choices=["builtin", "claude"],
                       metavar="BACKEND",
                       help="NLP backend for the query screen")
    p_tui.add_argument("--platform", dest="tui_platform", default=None,
                       metavar="NAME",
                       help="Connector platform key to query")
    p_tui.add_argument("--reports-dir", default=None, metavar="DIR",
                       help="Directory to scan for generated reports")

    # ── serve ─────────────────────────────────────────────────────────────
    p_srv = subs.add_parser(
        "serve",
        help="Start web dashboard server (requires gnat[serve])",
        description=(
            "Launch the GNAT web dashboard — a browser-based interface for the "
            "Research Library, Reports, and Scheduler.  Binds to localhost by "
            "default; use nginx+TLS for external exposure."
        ),
    )
    p_srv.add_argument("--host", default="127.0.0.1", metavar="HOST",
                       help="Host/IP to bind to (default: 127.0.0.1)")
    p_srv.add_argument("--port", type=int, default=8088, metavar="PORT",
                       help="TCP port (default: 8088)")
    p_srv.add_argument("--api-key", default=None, metavar="KEY",
                       help="X-Api-Key secret; auto-generated if omitted")
    p_srv.add_argument("--reports-dir", default=None, metavar="DIR",
                       help="Directory to scan for generated reports")

    # ── taxii ─────────────────────────────────────────────────────────────
    p_tax = subs.add_parser(
        "taxii",
        help="Start TAXII 2.1 server (requires gnat[serve])",
        description=(
            "Launch a TAXII 2.1-compliant server that exposes GNAT workspaces "
            "as TAXII collections.  Each workspace becomes a collection under a "
            "single API root.  Requires FastAPI and uvicorn (gnat[serve])."
        ),
    )
    p_tax.add_argument("--host", default="127.0.0.1", metavar="HOST",
                       help="Host/IP to bind to (default: 127.0.0.1)")
    p_tax.add_argument("--port", type=int, default=8090, metavar="PORT",
                       help="TCP port (default: 8090)")
    p_tax.add_argument("--api-key", default=None, metavar="KEY",
                       help="X-Api-Key secret; auto-generated if omitted")
    p_tax.add_argument("--title", default="GNAT TAXII 2.1 Server", metavar="TITLE",
                       help="Server title shown in TAXII discovery response")
    p_tax.add_argument("--contact", default="", metavar="EMAIL",
                       help="Contact e-mail shown in TAXII discovery response")

    # ── health ────────────────────────────────────────────────────────────
    p_hlt = subs.add_parser(
        "health",
        help="Connector health check and schema drift detection",
        description=(
            "Run a one-shot health check on all configured connectors, "
            "or capture/reset a schema baseline for a specific platform."
        ),
    )
    hlt_subs = p_hlt.add_subparsers(
        dest="health_command", title="health commands", metavar="<command>"
    )

    p_hlt_chk = hlt_subs.add_parser(
        "check",
        help="Run health check on all (or selected) connectors",
    )
    p_hlt_chk.add_argument(
        "--platform", dest="health_platform", default=None, metavar="NAME",
        help="Restrict check to a single platform (default: all configured)",
    )
    p_hlt_chk.add_argument(
        "--no-schema", action="store_true",
        help="Skip schema sampling (faster, only tests connectivity)",
    )
    p_hlt_chk.add_argument(
        "--snapshot-dir", default=None, metavar="DIR",
        help="Directory for schema snapshots (default: ~/.gnat/snapshots)",
    )

    p_hlt_bl = hlt_subs.add_parser(
        "baseline",
        help="Capture or reset the schema baseline for a connector",
    )
    p_hlt_bl.add_argument("platform", metavar="PLATFORM",
                          help="Connector name (e.g. threatq)")
    p_hlt_bl.add_argument(
        "--snapshot-dir", default=None, metavar="DIR",
        help="Directory for schema snapshots",
    )

    # ── tenant ────────────────────────────────────────────────────────────
    p_tnt = subs.add_parser(
        "tenant",
        help="Manage tenants for multi-tenant MSP deployments",
        description=(
            "Register and manage tenants for multi-tenant GNAT deployments.  "
            "Each tenant gets an isolated workspace namespace.  Use "
            "'gnat tenant create <id>' to register a tenant, then use "
            "'WorkspaceManager.for_tenant(id)' or 'TenantWorkspaceManager' "
            "in Python to scope workspace operations."
        ),
    )
    tnt_subs = p_tnt.add_subparsers(
        dest="tenant_command", title="tenant commands", metavar="<command>"
    )

    p_tnt_lst = tnt_subs.add_parser("list", help="List all registered tenants")
    p_tnt_lst.add_argument("--registry", default=None, metavar="PATH",
                           help="Path to tenants.json registry (default: ~/.gnat/tenants.json)")

    p_tnt_crt = tnt_subs.add_parser("create", help="Register a new tenant")
    p_tnt_crt.add_argument("tenant_id", metavar="ID",
                           help="Unique tenant ID (lowercase alphanumeric, hyphens, underscores)")
    p_tnt_crt.add_argument("--display-name", default="", metavar="NAME",
                           help="Human-readable display name")
    p_tnt_crt.add_argument("--description", default="", metavar="DESC",
                           help="Optional description")
    p_tnt_crt.add_argument("--config", dest="tenant_config", default=None, metavar="PATH",
                           help="Path to tenant-specific gnat.ini config file")
    p_tnt_crt.add_argument("--registry", default=None, metavar="PATH",
                           help="Path to tenants.json registry")

    p_tnt_del = tnt_subs.add_parser("delete", help="Remove a tenant from the registry")
    p_tnt_del.add_argument("tenant_id", metavar="ID", help="Tenant ID to delete")
    p_tnt_del.add_argument("--yes", action="store_true",
                           help="Skip confirmation prompt")
    p_tnt_del.add_argument("--registry", default=None, metavar="PATH",
                           help="Path to tenants.json registry")

    p_tnt_inf = tnt_subs.add_parser("info", help="Show details for a tenant")
    p_tnt_inf.add_argument("tenant_id", metavar="ID", help="Tenant ID")
    p_tnt_inf.add_argument("--registry", default=None, metavar="PATH",
                           help="Path to tenants.json registry")

    p_tnt_ws = tnt_subs.add_parser("workspaces", help="List workspaces for a tenant")
    p_tnt_ws.add_argument("tenant_id", metavar="ID", help="Tenant ID")
    p_tnt_ws.add_argument("--registry", default=None, metavar="PATH",
                          help="Path to tenants.json registry")

    # ── validate ──────────────────────────────────────────────────────────
    p_val = subs.add_parser(
        "validate",
        help="Validate STIX 2.1 patterns or bundles",
        description=(
            "Validate STIX 2.1 Indicator pattern syntax.  "
            "Use 'gnat validate pattern' for a single pattern string or "
            "'gnat validate bundle' to validate all indicator patterns in a "
            "STIX bundle JSON file.  Install gnat[stix-validate] for full "
            "ANTLR grammar support."
        ),
    )
    val_subs = p_val.add_subparsers(
        dest="validate_command", title="validate commands", metavar="<command>"
    )

    p_val_pat = val_subs.add_parser(
        "pattern",
        help="Validate a single STIX 2.1 pattern string",
    )
    p_val_pat.add_argument("pattern_string", metavar="PATTERN",
                           help="STIX 2.1 pattern to validate (quote it: \"[ipv4-addr:value = '1.2.3.4']\")")
    p_val_pat.add_argument("--strict", action="store_true",
                           help="Use stix2-patterns ANTLR grammar if installed (pip install 'gnat[stix-validate]')")

    p_val_bnd = val_subs.add_parser(
        "bundle",
        help="Validate all indicator patterns in a STIX bundle JSON file",
    )
    p_val_bnd.add_argument("file", metavar="FILE",
                           help="Path to a STIX bundle JSON file")
    p_val_bnd.add_argument("--strict", action="store_true",
                           help="Use stix2-patterns ANTLR grammar if installed")
    p_val_bnd.add_argument("--fail-fast", action="store_true",
                           help="Stop at first invalid pattern")

    # ── contribute ────────────────────────────────────────────────────────
    p_ctr = subs.add_parser(
        "contribute",
        help="Submit a connector as a draft PR to the upstream repository",
        description=(
            "Opt-in pipeline: validates compliance, runs tests, creates a "
            "branch, commits connector files, pushes to your fork, and "
            "optionally opens a draft PR on github.com/wrhalpin/GNAT.  "
            "Requires [contribute] enabled = true in config.ini."
        ),
    )
    p_ctr.add_argument(
        "--connector", required=True, metavar="NAME",
        help="Connector platform name (must match a CLIENT_REGISTRY key)",
    )
    p_ctr.add_argument(
        "--message", default=None, metavar="MSG",
        help="Commit / PR title (default: 'feat(connectors): add <name> connector')",
    )
    p_ctr.add_argument(
        "--no-pr", action="store_true",
        help="Skip PR creation (push branch only)",
    )
    p_ctr.add_argument(
        "--no-tests", action="store_true",
        help="Skip running the test suite (not recommended)",
    )
    p_ctr.add_argument(
        "--dry-run", action="store_true",
        help="Show what would happen without making any git changes",
    )

    return parser


# ── Command handlers ───────────────────────────────────────────────────────

def _cmd_ping(args: argparse.Namespace) -> int:
    from gnat.client import GNATClient
    _info(args, f"Pinging {_bold(args.target)} …")
    try:
        cli = GNATClient(config_path=args.config)
        cli.connect(target=args.target)
        ok = cli.ping()
        if ok:
            print(_green(f"✓  {args.target} is reachable"))
            return 0
        else:
            print(_red(f"✗  {args.target} did not respond"))
            return 1
    except Exception as exc:
        print(_red(f"✗  {exc}"))
        return 1


def _cmd_query(args: argparse.Namespace) -> int:
    from gnat.client import GNATClient
    _info(args, f"Querying {_bold(args.target)} for {args.type} {_dim(args.id)} …")
    try:
        cli = GNATClient(config_path=args.config)
        cli.connect(target=args.target)
        raw = cli.client.get_object(args.type, args.id)
        stix = cli.client.to_stix(raw)
        _output(args, stix)
        return 0
    except Exception as exc:
        print(_red(f"Error: {exc}"), file=sys.stderr)
        return 1


def _cmd_list(args: argparse.Namespace) -> int:
    from gnat.client import GNATClient
    _info(args, f"Listing {args.type} from {_bold(args.target)} …")
    try:
        cli = GNATClient(config_path=args.config)
        cli.connect(target=args.target)
        filters: Dict[str, str] = {}
        for kv in (args.filters or []):
            if "=" in kv:
                k, _, v = kv.partition("=")
                filters[k] = v
        rows = cli.client.list_objects(
            args.type, filters=filters or None,
            page=args.page, page_size=args.limit
        )
        stix_rows = [cli.client.to_stix(r) for r in rows]
        if args.output == "table":
            _print_table(stix_rows, fields=["id", "name", "type", "created"])
        elif args.output == "json":
            _print_json(stix_rows)
        else:
            for obj in stix_rows:
                _print_stix(obj)
        _info(args, f"{_dim(str(len(stix_rows)))} objects returned")
        return 0
    except Exception as exc:
        print(_red(f"Error: {exc}"), file=sys.stderr)
        return 1


def _cmd_ingest(args: argparse.Namespace) -> int:
    from gnat.client import GNATClient
    from gnat.ingest import IngestPipeline
    from gnat.ingest.sources import (
        PlainTextReader, CSVReader, JSONReader, JSONLReader,
        STIXBundleReader, MISPReader,
    )
    from gnat.ingest.mappers import (
        FlatIOCMapper, CSVIndicatorMapper, STIXPassthroughMapper,
        MISPAttributeMapper, NVDCVEMapper,
    )

    fmt = args.format
    src = args.source
    mapper_kwargs = dict(tlp_marking=args.tlp, confidence=args.confidence)

    _info(args, f"Ingesting {_bold(fmt)} from {_dim(src)} → {_bold(args.target)} …")

    try:
        # Build reader
        if fmt == "plaintext":
            reader = PlainTextReader(src)
            mapper = FlatIOCMapper(**mapper_kwargs)
        elif fmt == "csv":
            reader = CSVReader(src, value_col=args.value_col, type_col=args.type_col)
            mapper = CSVIndicatorMapper(value_field=args.value_col, **mapper_kwargs)
        elif fmt == "json":
            reader = JSONReader(src, records_key=args.records_key)
            mapper = FlatIOCMapper(**mapper_kwargs)
        elif fmt == "jsonl":
            reader = JSONLReader(src)
            mapper = FlatIOCMapper(**mapper_kwargs)
        elif fmt == "stix-bundle":
            reader = STIXBundleReader(src)
            mapper = STIXPassthroughMapper(**mapper_kwargs)
        elif fmt == "misp":
            reader = MISPReader(src)
            mapper = MISPAttributeMapper(**mapper_kwargs)
        elif fmt == "nvd":
            reader = JSONReader(src, records_key=args.records_key or "CVE_Items")
            mapper = NVDCVEMapper(**mapper_kwargs)
        else:
            print(_red(f"Unsupported format: {fmt}"), file=sys.stderr)
            return 1

        pipeline = (
            IngestPipeline(f"cli-ingest-{fmt}")
            .read_from(reader)
            .map_with(mapper)
        )
        if args.deduplicate:
            pipeline.deduplicate(key_fields=["name"])

        if args.dry_run:
            _info(args, _yellow("Dry-run mode — objects will not be written"))
            objs = list(pipeline.iter_objects())
            if args.output == "json":
                _print_json([o.to_dict() for o in objs])
            elif args.output == "stix":
                for o in objs:
                    _print_stix(o)
            else:
                _print_table(
                    [{"id": o.id, "type": o.stix_type,
                      "name": getattr(o, "name", ""), "tlp": getattr(o, "x_tlp", "")}
                     for o in objs]
                )
            print(_yellow(f"Dry-run: {len(objs)} objects would be written"))
            return 0

        cli = GNATClient(config_path=args.config)
        cli.connect(target=args.target)
        pipeline.write_to(cli)
        result = pipeline.run()

        print(_green(f"✓  Ingest complete: {result}"))
        if result.errors:
            for e in result.errors[:5]:
                print(_yellow(f"  ⚠  {e}"))
            if len(result.errors) > 5:
                print(_dim(f"  … and {len(result.errors)-5} more errors"))
        return 0 if not result.errors else 2

    except Exception as exc:
        print(_red(f"Error: {exc}"), file=sys.stderr)
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


def _cmd_codegen(args: argparse.Namespace) -> int:
    if args.codegen_command == "openapi":
        from gnat.codegen.openapi_generator import generate_connector
        _info(args, f"Generating connector {_bold(args.name)} from {_dim(args.spec)} …")
        try:
            generate_connector(
                spec_path=args.spec,
                connector_name=args.name,
                auth_type=args.auth,
                out_dir=args.out_dir,
                test_dir=args.test_dir,
                overwrite=args.overwrite,
            )
            return 0
        except Exception as exc:
            print(_red(f"Error: {exc}"), file=sys.stderr)
            return 1

    elif args.codegen_command == "xsoar":
        from gnat.codegen.xsoar_generator import generate_xsoar_pack
        _info(args, f"Generating XSOAR pack for {_bold(args.connector)} …")
        try:
            zip_path = generate_xsoar_pack(
                connector_name=args.connector,
                output_dir=args.output,
                version=args.version,
                auth_type=args.auth,
                overwrite=args.overwrite,
            )
            print(_green(f"✓  Pack written: {zip_path}"))
            return 0
        except KeyError as exc:
            print(_red(f"Unknown connector: {exc}"), file=sys.stderr)
            return 1
        except FileExistsError as exc:
            print(_red(f"File exists: {exc}"), file=sys.stderr)
            return 1
        except Exception as exc:
            print(_red(f"Error: {exc}"), file=sys.stderr)
            if args.debug:
                import traceback
                traceback.print_exc()
            return 1

    return 0


def _cmd_config(args: argparse.Namespace) -> int:
    from gnat.config import GNATConfig

    _REQUIRED_KEYS = {
        "threatq":       {"host", "client_id", "client_secret"},
        "crowdstrike":   {"host", "client_id", "client_secret"},
        "proofpoint":    {"host", "service_principal", "secret"},
        "netskope":      {"host", "api_token"},
        "xsoar":         {"host", "api_key"},
        "recordedfuture": {"host", "api_token"},
    }
    _SECRET_KEYS = {"client_secret", "secret", "api_key", "api_token", "password"}

    if args.init:
        default_path = Path.home() / ".gnat" / "config.ini"
        default_path.parent.mkdir(parents=True, exist_ok=True)
        example = Path(__file__).parent.parent.parent / "config" / "config.ini.example"
        if example.exists():
            import shutil
            shutil.copy(example, default_path)
            print(_green(f"✓  Created {default_path}"))
            print(_dim("  Edit it to add your credentials."))
        else:
            print(_red("Could not find config.ini.example in the package."))
            return 1
        return 0

    try:
        cfg = GNATConfig(args.config)
    except FileNotFoundError as exc:
        print(_red(f"Config not found: {exc}"))
        print(_dim("  Run: gnat config --init"))
        return 1

    if args.show:
        print(_bold(f"Config: {cfg.config_path}"))
        print(_bold(f"Sections: {', '.join(cfg.sections)}"))
        print()
        for section in cfg.sections:
            print(_bold(f"[{section}]"))
            for k, v in cfg.get(section).items():
                if k in _SECRET_KEYS:
                    v = "*" * 8
                print(f"  {k} = {v}")
            print()
        return 0

    if args.validate:
        all_ok = True
        for target in cfg.sections:
            required = _REQUIRED_KEYS.get(target, set())
            present  = set(cfg.get(target).keys())
            missing  = required - present
            if missing:
                print(_red(f"✗  [{target}] missing: {', '.join(sorted(missing))}"))
                all_ok = False
            else:
                print(_green(f"✓  [{target}]"))
        return 0 if all_ok else 1

    return 0


# ── Helpers ────────────────────────────────────────────────────────────────

def _info(args: argparse.Namespace, msg: str) -> None:
    if not args.quiet:
        print(msg)


def _output(args: argparse.Namespace, data: Any) -> None:
    if args.output == "json":
        _print_json(data)
    elif args.output == "stix":
        _print_stix(data)
    else:
        if isinstance(data, dict):
            _print_table([data])
        elif isinstance(data, list):
            _print_table(data)
        else:
            print(data)


# ── Entry point ────────────────────────────────────────────────────────────

def _cmd_viz(args: argparse.Namespace) -> int:
    from gnat.context import WorkspaceManager
    from gnat.viz import TabularView, GraphView, PowerBIExporter, save_grafana_dashboard

    viz_cmd = getattr(args, "viz_command", None)

    if viz_cmd == "table":
        manager = WorkspaceManager.default(config_path=args.config)
        try:
            ws = manager.open(args.workspace)
        except KeyError as e:
            print(_red(str(e))); return 1
        view = TabularView(ws)
        if args.file:
            ext = Path(args.file).suffix.lower()
            if ext in (".html", ".htm"):
                view.to_html(args.file, stix_type=args.type, top=args.top)
            elif ext == ".csv":
                view.to_csv(args.file, stix_type=args.type, top=args.top)
            elif ext in (".xlsx", ".xls"):
                view.to_excel(args.file, top=args.top)
            else:
                view.to_html(args.file, top=args.top)
            print(_green(f"✓  Saved to {args.file}"))
        else:
            view.show(stix_type=args.type, sort_by=args.sort, top=args.top)
        return 0

    if viz_cmd == "graph":
        manager = WorkspaceManager.default(config_path=args.config)
        try:
            ws = manager.open(args.workspace)
        except KeyError as e:
            print(_red(str(e))); return 1
        from gnat.viz import GraphView
        gv = GraphView(ws)
        if args.file:
            gv.to_html(args.file, stix_types=args.types)
            print(_green(f"✓  Graph saved to {args.file}"))
        else:
            _info(args, f"Opening 3D graph for {_bold(args.workspace)} …")
            gv.show(stix_types=args.types)
        return 0

    if viz_cmd == "serve":
        from gnat.context import WorkspaceManager
        from gnat.viz.grafana.server import GrafanaServer
        manager = WorkspaceManager.default(config_path=args.config)
        search_index = None
        if getattr(args, "with_solr", False):
            try:
                from gnat.config import GNATConfig
                from gnat.search import build_search_index
                cfg = GNATConfig(config_path=args.config)
                search_index = build_search_index(cfg)
                print(_dim("  Solr search index mounted at /solr/"))
            except Exception as _exc:  # noqa: BLE001
                print(_yellow(f"Warning: could not load search index: {_exc}"), file=sys.stderr)
        server = GrafanaServer(manager, host=args.host, port=args.port,
                               search_index=search_index)
        print(_green(f"✓  Grafana datasource: {server.url()}"))
        if search_index is not None:
            print(_dim(f"  Solr endpoints:      {server.url()}/solr/"))
        print(_dim("  Configure in Grafana: Add data source → SimpleJSON → URL above"))
        server.run()
        return 0

    if viz_cmd == "dashboard":
        manager = WorkspaceManager.default(config_path=args.config)
        save_grafana_dashboard(args.workspace, args.file, args.datasource)
        print(_green(f"✓  Dashboard JSON saved to {args.file}"))
        return 0

    if viz_cmd == "solr-dashboard":
        from gnat.viz.export import save_solr_dashboard
        save_solr_dashboard(args.file, args.datasource, args.title)
        return 0

    if viz_cmd == "powerbi":
        manager = WorkspaceManager.default(config_path=args.config)
        try:
            ws = manager.open(args.workspace)
        except KeyError as e:
            print(_red(str(e))); return 1
        PowerBIExporter(ws).to_xlsx(args.file)
        print(_green(f"✓  Power BI workbook saved to {args.file}"))
        return 0

    return 1


def _cmd_report(args) -> int:
    """report subcommand — run, list."""
    report_cmd = getattr(args, "report_command", None)

    if report_cmd == "list":
        try:
            from gnat.config import GNATConfig
            cfg = GNATConfig(getattr(args, "config_path", None))
            profiles = [
                s[len("report."):] for s in cfg._parser.sections()
                if s.startswith("report.")
            ]
            if not profiles:
                _info(args, "No [report.<name>] sections found in config.")
                return 0
            rows = [{"profile": p} for p in sorted(profiles)]
            _print_table(rows, fields=["profile"])
            return 0
        except FileNotFoundError as exc:
            print(_red(f"Config not found: {exc}"), file=sys.stderr)
            return 1

    if report_cmd == "run":
        profile = args.report_config
        try:
            from gnat.config import GNATConfig
            from gnat.reports import ReportConfig, ReportGenerator, AIMode
            from gnat.context.workspace import WorkspaceManager

            cfg_path = getattr(args, "config_path", None)
            manager  = WorkspaceManager.default(config_path=cfg_path)
            report_cfg = ReportConfig.from_ini(
                section=f"report.{profile}",
                config_path=cfg_path,
            )

            if args.no_ai:
                report_cfg = ReportConfig(
                    **{**report_cfg.__dict__, "ai_mode": AIMode.DISABLED}
                )
            if args.output_dir:
                report_cfg = ReportConfig(
                    **{**report_cfg.__dict__, "output_dir": args.output_dir}
                )
            if args.formats:
                fmt_list = [f.strip() for f in args.formats.split(",") if f.strip()]
                report_cfg = ReportConfig(
                    **{**report_cfg.__dict__, "formats": fmt_list}
                )

            _info(args, f"Running report: {profile}")
            result = ReportGenerator(manager, report_cfg).run()

            if result.success:
                print(_green(f"Report generated: {result.title}"))
                for path in result.files_written:
                    print(f"  {_dim('→')} {path}")
            else:
                print(_yellow(f"Report completed with errors: {result.title}"))
                for err in result.errors:
                    print(_red(f"  ✗ {err}"), file=sys.stderr)
                for path in result.files_written:
                    print(f"  {_dim('→')} {path}")
                return 2
            return 0

        except FileNotFoundError as exc:
            print(_red(f"Config not found: {exc}"), file=sys.stderr)
            return 1
        except KeyError as exc:
            print(_red(f"Report profile not found in config: {exc}"), file=sys.stderr)
            return 1
        except ImportError as exc:
            print(_red(f"Missing dependency: {exc}"), file=sys.stderr)
            return 1

    return 0


def _cmd_schedule(args) -> int:
    """schedule subcommand — list, run, crontab."""
    # Scheduler must be defined in the user's project; here we show a stub
    # that reads job definitions from a Python module specified in config.
    schedule_cmd = getattr(args, "schedule_command", None)
    if schedule_cmd == "list":
        _info(args, "No scheduler configured. Define jobs in your project and "
              "call scheduler.statuses() to list them.")
        return 0
    if schedule_cmd == "crontab":
        _info(args, "No scheduler configured.")
        return 0
    return 0


def _cmd_client(args) -> int:
    """client subcommand — capabilities, call."""
    from gnat.client import GNATClient
    from gnat.clients.base import GNATClientError

    try:
        cli = GNATClient(config_path=args.config)
        cli.connect(target=args.platform)
        connector = cli.client
    except Exception as exc:
        print(_red(f"Error connecting to '{args.platform}': {exc}"), file=sys.stderr)
        return 1

    if args.client_command == "capabilities":
        caps = connector.capabilities()

        # Apply filters
        if getattr(args, "cap_type", None):
            caps = {k: v for k, v in caps.items() if v["type"] == args.cap_type}
        if getattr(args, "platform_specific", False):
            caps = {k: v for k, v in caps.items() if v["platform_specific"]}

        if not caps:
            print(_dim("No capabilities match the given filters."))
            return 0

        if args.format == "json":
            import json
            print(json.dumps(caps, indent=2))
            return 0

        # Table output
        col_name = max(len(n) for n in caps) + 2
        header = (
            f"{'Method':<{col_name}}  {'Type':<8}  {'Sig':<40}  Doc"
        )
        print(_bold(f"\nCapabilities: {args.platform}"))
        print(_dim("─" * min(len(header) + 4, 120)))
        print(_bold(header))
        print(_dim("─" * min(len(header) + 4, 120)))
        for name, meta in sorted(caps.items()):
            type_label = meta["type"]
            type_colored = {
                "auth":   _bold(type_label),
                "read":   _green(type_label),
                "write":  _red(type_label),
                "helper": _dim(type_label),
            }.get(type_label, type_label)

            ps_flag = " *" if meta["platform_specific"] else "  "
            sig = meta["signature"]
            if len(sig) > 38:
                sig = sig[:35] + "..."
            doc = meta["doc"]
            if len(doc) > 60:
                doc = doc[:57] + "..."
            print(f"{name + ps_flag:<{col_name}}  {type_colored:<8}  {sig:<40}  {_dim(doc)}")

        print(_dim(f"\n  * = platform-specific method   "
                   f"{len(caps)} method(s) shown"))
        return 0

    elif args.client_command == "call":
        # Parse KEY=VALUE args into a kwargs dict
        kwargs: Dict[str, Any] = {}
        for kv in (getattr(args, "args", None) or []):
            if "=" in kv:
                k, v = kv.split("=", 1)
                # Basic type coercion
                if v.isdigit():
                    kwargs[k] = int(v)
                elif v.lower() in ("true", "false"):
                    kwargs[k] = v.lower() == "true"
                else:
                    kwargs[k] = v
            else:
                print(_red(f"Argument '{kv}' is not in KEY=VALUE format"), file=sys.stderr)
                return 1

        allow_write = getattr(args, "allow_write", False)
        _info(args, f"Calling {_bold(args.method)} on {_bold(args.platform)} …")
        try:
            result = connector.call(args.method, allow_write=allow_write, **kwargs)
            _output(args, result)
            return 0
        except ValueError as exc:
            print(_red(f"Error: {exc}"), file=sys.stderr)
            return 1
        except GNATClientError as exc:
            print(_red(f"API error: {exc}"), file=sys.stderr)
            return 1

    return 0


def _cmd_nlq(args) -> int:
    """nlq subcommand — natural-language threat-intel query."""
    from gnat.nlp.parser import NLPQueryEngine

    # Build engine
    backend = getattr(args, "backend", None) or "builtin"
    if backend == "claude":
        try:
            from gnat.config import GNATConfig
            from gnat.agents.base import AgentConfig
            cfg = GNATConfig(args.config)
            agent_cfg = AgentConfig.from_config(cfg._parser)
            engine = NLPQueryEngine(backend="claude", claude_config=agent_cfg)
        except Exception as exc:
            print(_yellow(f"Claude backend unavailable ({exc}); using builtin"), file=sys.stderr)
            engine = NLPQueryEngine(backend="builtin")
    else:
        engine = NLPQueryEngine(backend="builtin")

    # Override limit if given
    query = args.query
    spec = engine.parse(query)
    if getattr(args, "limit", None):
        spec.limit = args.limit

    if args.parse_only:
        _output(args, spec.to_dict())
        return 0

    _info(args, f"Parsing: {_dim(query)}")
    _info(args, f"  entities:  {spec.entities or '(none)'}")
    _info(args, f"  ioc_types: {spec.ioc_types or '(all)'}")
    _info(args, f"  since:     {spec.since or '(any)'}")
    _info(args, f"  platforms: {spec.platforms or '(all)'}")
    _info(args, f"  limit:     {spec.limit}")

    platform = getattr(args, "nlq_platform", None)
    if not platform:
        # No live connector — just return the parsed spec
        print(_dim("\nNo --platform specified; showing parsed query spec only."))
        _output(args, spec.to_dict())
        return 0

    try:
        from gnat.client import GNATClient
        cli = GNATClient(config_path=args.config)
        cli.connect(target=platform)
        _info(args, f"Querying {_bold(platform)} …")
        results = cli.natural_language_query(query)
        if not results:
            print(_dim("No results."))
            return 0
        _output(args, results)
        return 0
    except Exception as exc:
        print(_red(f"Error: {exc}"), file=sys.stderr)
        return 1


def _cmd_tui(args) -> int:
    """tui subcommand — launch the interactive Textual terminal UI."""
    try:
        from gnat.tui.app import run as _tui_run
    except ImportError:
        print(
            _red("Error: Textual is not installed.  "
                 "Run: pip install \"gnat[tui]\""),
            file=sys.stderr,
        )
        return 1

    screen      = getattr(args, "screen", "query") or "query"
    nlp_backend = getattr(args, "backend", None)
    platform    = getattr(args, "tui_platform", None)
    reports_dir = getattr(args, "reports_dir", None)
    config_path = getattr(args, "config", None)

    _tui_run(
        config_path=config_path,
        initial_tab=screen,
        nlp_backend=nlp_backend,
        nlp_platform=platform,
        reports_dir=reports_dir,
    )
    return 0


def _cmd_contribute(args) -> int:
    """contribute subcommand — submit a connector as a draft PR."""
    from gnat.codegen.contribute import (
        ComplianceMatrix,
        ContributeConfig,
        ContributionPipeline,
    )

    connector    = args.connector
    config_path  = getattr(args, "config", None) or ""
    no_pr        = getattr(args, "no_pr", False)
    no_tests     = getattr(args, "no_tests", False)
    dry_run      = getattr(args, "dry_run", False)
    message      = (
        getattr(args, "message", None)
        or f"feat(connectors): add {connector} connector"
    )

    # Load config
    try:
        config = ContributeConfig.from_ini(config_path)
    except Exception as exc:
        print(_red(f"Config error: {exc}"), file=sys.stderr)
        return 1

    if not config.enabled and not dry_run:
        print(
            _red(
                "Contribution pipeline is disabled.  "
                "Set [contribute] enabled = true in config.ini to opt in."
            ),
            file=sys.stderr,
        )
        return 1

    # Always show compliance report first
    print(_bold(f"Checking compliance for {_bold(connector)} …"))
    compliance = ComplianceMatrix.check(connector)
    for s in compliance.method_statuses:
        mark = _green("✓") if s.implemented else _red("✗")
        print(f"  {mark}  {s.name}" + (f"  {_dim(s.note)}" if s.note else ""))
    test_mark = _green("✓") if compliance.has_tests else _red("✗")
    print(f"  {test_mark}  unit tests")
    print()

    if not compliance.passed:
        print(_red("Compliance check FAILED — fix the issues above before contributing."))
        return 1
    print(_green("✓  Compliance check passed"))

    if dry_run:
        print(_dim("\n[dry-run] Would run tests, create branch, commit, push, open PR."))
        return 0

    # Run pipeline
    pipeline = ContributionPipeline()

    if no_tests:
        # Monkey-patch the test runner for --no-tests
        pipeline._run_tests = lambda: (True, "skipped")  # type: ignore[method-assign]

    result = pipeline.run(
        connector_name = connector,
        message        = message,
        config         = config,
        create_pr      = not no_pr,
    )

    if not result.success:
        print(_red(f"\nContribution failed:\n{result.error}"), file=sys.stderr)
        return 1

    print(_green(f"\n✓  Branch:   {_bold(result.branch)}"))
    if result.pr_url:
        print(_green(f"✓  Draft PR: {_bold(result.pr_url)}"))
    else:
        print(_dim("   (No PR created — either --no-pr or no github_token configured)"))
    return 0


def _cmd_health(args) -> int:
    """health subcommand — connector health check and schema drift detection."""
    from gnat.agents.health_monitor import (
        ConnectorHealthJob,
        _try_sample_schema,
        save_snapshot,
    )

    health_cmd   = getattr(args, "health_command", None)
    config_path  = getattr(args, "config", None)
    snapshot_dir = getattr(args, "snapshot_dir", None)

    if health_cmd == "check" or health_cmd is None:
        platform = getattr(args, "health_platform", None)
        no_schema = getattr(args, "no_schema", False)
        platforms = [platform] if platform else None

        try:
            job = ConnectorHealthJob.from_config(
                config_path  = config_path or "",
                platforms    = platforms,
                sample_schema = not no_schema,
                snapshot_dir = snapshot_dir,
            )
        except FileNotFoundError as exc:
            print(_red(f"Error: {exc}"), file=sys.stderr)
            return 1

        if not job._connectors:
            print(
                _yellow("No connectors found in config — nothing to check."),
                file=sys.stderr,
            )
            return 0

        print(_bold(f"Checking {len(job._connectors)} connector(s) …"))
        run = job._run_health_checks()

        any_problem = False
        for c in run.checks:
            icon   = _green("✓") if c.reachable else _red("✗")
            ms_str = f"{c.response_ms:.0f} ms"
            line   = f"  {icon}  {_bold(c.connector):<20} {ms_str}"
            if not c.reachable and c.error:
                line += f"  {_dim(c.error[:60])}"
            elif c.drift and c.drift.is_significant:
                line += f"  {_yellow(c.drift.summary())}"
            print(line)
            if not c.reachable or (c.drift and c.drift.is_significant):
                any_problem = True

        total = len(run.checks)
        healthy = run.healthy_count
        print()
        status_line = (
            f"{_green(str(healthy))} / {total} healthy"
            if healthy == total
            else f"{_red(str(total - healthy))} unreachable, "
                 f"{_green(str(healthy))} healthy"
        )
        if run.drift_count:
            status_line += f", {_yellow(str(run.drift_count))} drift"
        print(status_line)
        return 1 if any_problem else 0

    elif health_cmd == "baseline":
        platform = args.platform
        try:
            from gnat.client import GNATClient
            sak = GNATClient(config_path=config_path).connect(platform)
            connector = sak.client
        except Exception as exc:
            print(_red(f"Error connecting to {platform!r}: {exc}"), file=sys.stderr)
            return 1

        print(f"Sampling schema from {_bold(platform)} …")
        fingerprint = _try_sample_schema(connector)
        if not fingerprint:
            print(
                _yellow(
                    f"Could not sample schema from {platform!r} — "
                    "list_objects() returned no objects."
                ),
                file=sys.stderr,
            )
            return 1

        save_snapshot(platform, fingerprint, snapshot_dir)
        print(_green(f"✓  Baseline saved for {_bold(platform)} ({len(fingerprint)} fields)"))
        return 0

    else:
        # No sub-subcommand — print help
        print("Usage: gnat health check | gnat health baseline PLATFORM")
        return 1


def _cmd_tenant(args) -> int:
    """tenant subcommand — manage multi-tenant workspace namespaces."""
    from gnat.context.tenant import TenantRegistry, TenantWorkspaceManager

    sub          = getattr(args, "tenant_command", None)
    registry_path = getattr(args, "registry", None)
    registry     = TenantRegistry(registry_path)

    if sub == "list":
        tenants = registry.list()
        if not tenants:
            print(_yellow("No tenants registered.  Use: gnat tenant create <id>"),
                  file=sys.stderr)
            return 0
        print(f"{'ID':<20} {'Display Name':<30} {'Config':<20} {'Created'}")
        print("-" * 90)
        for t in tenants:
            cfg  = t.config_path or "(global)"
            date = t.created_at[:10] if t.created_at else ""
            print(f"{t.tenant_id:<20} {t.display_name:<30} {cfg:<20} {date}")
        return 0

    elif sub == "create":
        tenant_id   = args.tenant_id
        display     = getattr(args, "display_name", "") or ""
        description = getattr(args, "description", "") or ""
        cfg_path    = getattr(args, "tenant_config", None)
        try:
            tenant = registry.register(
                tenant_id,
                display_name=display,
                description=description,
                config_path=cfg_path,
            )
        except ValueError as exc:
            print(_red(f"Error: {exc}"), file=sys.stderr)
            return 1
        print(_green(f"✓  Tenant {_bold(tenant_id)!r} registered."), file=sys.stderr)
        print(f"   Display name : {tenant.display_name}", file=sys.stderr)
        if cfg_path:
            print(f"   Config       : {cfg_path}", file=sys.stderr)
        print(
            f"\nWorkspaces for this tenant are namespaced as: "
            f"{_bold(tenant_id + '::workspace-name')}",
            file=sys.stderr,
        )
        return 0

    elif sub == "delete":
        tenant_id = args.tenant_id
        tenant    = registry.get(tenant_id)
        if tenant is None:
            print(_red(f"Error: Tenant {tenant_id!r} not found."), file=sys.stderr)
            return 1

        if not getattr(args, "yes", False):
            print(
                _yellow(
                    f"Warning: This removes the tenant metadata record.  "
                    f"Workspace data is NOT deleted automatically.  "
                    f"Use 'gnat tenant workspaces {tenant_id}' first to "
                    f"review existing workspaces."
                ),
                file=sys.stderr,
            )
            try:
                confirm = input(f"Delete tenant {tenant_id!r}? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                confirm = ""
            if confirm not in ("y", "yes"):
                print("Aborted.", file=sys.stderr)
                return 0

        registry.delete(tenant_id)
        print(_green(f"✓  Tenant {tenant_id!r} deleted from registry."), file=sys.stderr)
        return 0

    elif sub == "info":
        tenant_id = args.tenant_id
        tenant    = registry.get(tenant_id)
        if tenant is None:
            print(_red(f"Error: Tenant {tenant_id!r} not found."), file=sys.stderr)
            return 1

        print(f"  Tenant ID    : {_bold(tenant.tenant_id)}")
        print(f"  Display name : {tenant.display_name}")
        print(f"  Description  : {tenant.description or '(none)'}")
        print(f"  Config path  : {tenant.config_path or '(global)'}")
        print(f"  Created      : {tenant.created_at}")

        # Show workspace count if possible
        config_path = getattr(args, "config", None)
        try:
            twm = TenantWorkspaceManager.default(tenant_id, config_path=config_path)
            workspaces = twm.list()
            print(f"  Workspaces   : {len(workspaces)}")
        except Exception as exc:  # noqa: BLE001
            print(f"  Workspaces   : (unavailable — {exc})")
        return 0

    elif sub == "workspaces":
        tenant_id   = args.tenant_id
        config_path = getattr(args, "config", None)
        try:
            twm = TenantWorkspaceManager.default(tenant_id, config_path=config_path)
            workspaces = twm.list()
        except ValueError as exc:
            print(_red(f"Error: {exc}"), file=sys.stderr)
            return 1

        if not workspaces:
            print(_yellow(f"No workspaces for tenant {tenant_id!r}."), file=sys.stderr)
            return 0
        print(f"{'Name':<30} {'Objects':>8}  {'Description'}")
        print("-" * 70)
        for ws in workspaces:
            print(f"{ws['name']:<30} {ws.get('object_count', '?'):>8}  "
                  f"{ws.get('description', '')}")
        return 0

    else:
        print(
            "Usage:\n"
            "  gnat tenant list\n"
            "  gnat tenant create <id> [--display-name NAME] [--description DESC] "
            "[--config PATH]\n"
            "  gnat tenant delete <id> [--yes]\n"
            "  gnat tenant info <id>\n"
            "  gnat tenant workspaces <id>\n",
            file=sys.stderr,
        )
        return 0


def _cmd_validate(args) -> int:
    """validate subcommand — validate STIX 2.1 patterns."""
    from gnat.stix.pattern_validator import validate_pattern

    sub = getattr(args, "validate_command", None)
    strict = getattr(args, "strict", False)

    if sub == "pattern":
        pattern = args.pattern_string
        result = validate_pattern(pattern, strict=strict)
        if result.valid:
            tier = "strict (stix2-patterns)" if result.strict else "pure-python"
            print(_green(f"✓  Pattern is valid [{tier}]"), file=sys.stderr)
            return 0
        else:
            print(_red("✗  Pattern is INVALID"), file=sys.stderr)
            for err in result.errors:
                print(f"   {_red('Error:')} {err}", file=sys.stderr)
            for warn in result.warnings:
                print(f"   {_yellow('Warning:')} {warn}", file=sys.stderr)
            return 1

    elif sub == "bundle":
        bundle_path = Path(args.file)
        if not bundle_path.exists():
            print(_red(f"Error: file not found: {bundle_path}"), file=sys.stderr)
            return 1

        try:
            import json as _json
            data = _json.loads(bundle_path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            print(_red(f"Error reading bundle: {exc}"), file=sys.stderr)
            return 1

        objects = data.get("objects") or []
        indicators = [o for o in objects if o.get("type") == "indicator"
                      and o.get("pattern_type", "stix") == "stix"
                      and o.get("pattern")]

        if not indicators:
            print(_yellow("No STIX-type indicator patterns found in bundle."), file=sys.stderr)
            return 0

        fail_fast = getattr(args, "fail_fast", False)
        invalid_count = 0
        for ind in indicators:
            pattern = ind["pattern"]
            obj_id  = ind.get("id", "<unknown>")
            result  = validate_pattern(pattern, strict=strict)
            if result.valid:
                tier = "strict" if result.strict else "pure-python"
                print(f"  {_green('✓')} {obj_id}  [{tier}]")
            else:
                invalid_count += 1
                print(f"  {_red('✗')} {obj_id}")
                for err in result.errors:
                    print(f"      {_red('Error:')} {err}")
                if fail_fast:
                    break

        total = len(indicators)
        valid_count = total - invalid_count
        summary = f"{valid_count}/{total} patterns valid"
        if invalid_count == 0:
            print(_green(f"\n✓  {summary}"), file=sys.stderr)
            return 0
        else:
            print(_red(f"\n✗  {summary} ({invalid_count} invalid)"), file=sys.stderr)
            return 1

    else:
        # No subcommand — print help
        print(
            "Usage:\n"
            "  gnat validate pattern \"[ipv4-addr:value = '1.2.3.4']\"\n"
            "  gnat validate bundle   indicators.json\n"
            "\nOptions:\n"
            "  --strict      Use stix2-patterns ANTLR grammar (pip install 'gnat[stix-validate]')\n"
            "  --fail-fast   (bundle only) stop at first invalid pattern\n",
            file=sys.stderr,
        )
        return 0


def _cmd_serve_taxii(args) -> int:
    """taxii subcommand — start the GNAT TAXII 2.1 server."""
    try:
        from gnat.serve.taxii import run_taxii_server
    except ImportError:
        print(
            _red("Error: FastAPI/uvicorn is not installed.  "
                 "Run: pip install \"gnat[serve]\""),
            file=sys.stderr,
        )
        return 1

    import secrets

    host        = getattr(args, "host", "127.0.0.1") or "127.0.0.1"
    port        = getattr(args, "port", 8090) or 8090
    api_key     = getattr(args, "api_key", None)
    title       = getattr(args, "title", "GNAT TAXII 2.1 Server")
    contact     = getattr(args, "contact", "")
    config_path = getattr(args, "config", None)

    if not api_key:
        api_key = secrets.token_hex(16)
        print(
            _yellow("No API key supplied — generated a random key:"),
            file=sys.stderr,
        )
        print(f"  X-Api-Key: {_bold(api_key)}", file=sys.stderr)
        print("  Store this value — it will not be shown again.\n", file=sys.stderr)

    from gnat.context import WorkspaceManager
    manager = WorkspaceManager.default(config_path=config_path)

    url = f"http://{host}:{port}"
    print(_green(f"✓  GNAT TAXII 2.1 Server: {_bold(url)}"), file=sys.stderr)
    print(_dim("   Discovery: " + url + "/taxii2/"), file=sys.stderr)
    print(_dim("   Press Ctrl+C to stop."), file=sys.stderr)

    run_taxii_server(
        manager=manager,
        host=host,
        port=port,
        api_key=api_key,
        title=title,
        contact=contact,
    )
    return 0


def _cmd_serve(args) -> int:
    """serve subcommand — start the GNAT web dashboard."""
    try:
        from gnat.serve.app import run as _serve_run
    except ImportError:
        print(
            _red("Error: FastAPI/uvicorn is not installed.  "
                 "Run: pip install \"gnat[serve]\""),
            file=sys.stderr,
        )
        return 1

    import secrets

    host        = getattr(args, "host", "127.0.0.1") or "127.0.0.1"
    port        = getattr(args, "port", 8088) or 8088
    api_key     = getattr(args, "api_key", None)
    reports_dir = getattr(args, "reports_dir", None)
    config_path = getattr(args, "config", None)

    if not api_key:
        api_key = secrets.token_hex(16)
        print(
            _yellow("No API key supplied — generated a random key:"),
            file=sys.stderr,
        )
        print(f"  X-Api-Key: {_bold(api_key)}", file=sys.stderr)
        print("  Store this value — it will not be shown again.\n", file=sys.stderr)

    # Optionally resolve reports_dir from INI when not given on CLI
    if not reports_dir and config_path:
        from gnat.serve.config import WebUIConfig
        cfg = WebUIConfig.from_ini(config_path)
        reports_dir = cfg.reports_dir

    url = f"http://{host}:{port}"
    print(_green(f"✓  GNAT Web Dashboard: {_bold(url)}"), file=sys.stderr)
    print(_dim("   Press Ctrl+C to stop."), file=sys.stderr)

    _serve_run(
        api_key=api_key,
        host=host,
        port=port,
        reports_dir=reports_dir,
    )
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """
    Main CLI entry point.

    Parameters
    ----------
    argv : list of str, optional
        Argument list (defaults to ``sys.argv[1:]``).

    Returns
    -------
    int
        Exit code (0 = success, 1 = error, 2 = partial success with warnings).
    """
    global _NO_COLOR

    parser = _build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "no_color", False):
        _NO_COLOR = True

    if getattr(args, "debug", False):
        logging.basicConfig(level=logging.DEBUG,
                            format="%(name)s %(levelname)s %(message)s")
    elif not getattr(args, "quiet", False):
        logging.basicConfig(level=logging.WARNING)

    handlers = {
        "ping":     _cmd_ping,
        "viz":      _cmd_viz,
        "report":   _cmd_report,
        "schedule": _cmd_schedule,
        "query":    _cmd_query,
        "list":     _cmd_list,
        "ingest":   _cmd_ingest,
        "codegen":  _cmd_codegen,
        "config":   _cmd_config,
        "client":   _cmd_client,
        "nlq":      _cmd_nlq,
        "tui":      _cmd_tui,
        "tenant":   _cmd_tenant,
        "validate": _cmd_validate,
        "serve":    _cmd_serve,
        "taxii":    _cmd_serve_taxii,
        "health":      _cmd_health,
        "contribute":  _cmd_contribute,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
