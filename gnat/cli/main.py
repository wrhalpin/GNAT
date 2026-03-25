"""
ctm_sak.cli.main
=================

CTM-SAK command-line interface.

Entry point: ``ctm-sak`` (installed via ``pyproject.toml`` scripts).

Sub-commands
------------

.. code-block:: text

    ctm-sak ping      --target threatq
    ctm-sak query     --target threatq --type indicator --id indicator--abc
    ctm-sak list      --target crowdstrike --type indicator --limit 20
    ctm-sak ingest    --target threatq --source iocs.txt --format plaintext
    ctm-sak ingest    --target threatq --source feed.json --format stix-bundle
    ctm-sak ingest    --target threatq --source export.csv --format csv
    ctm-sak ingest    --target threatq --source events.json --format misp
    ctm-sak codegen   --spec openapi.json --name myplatform --auth oauth2
    ctm-sak config    --show
    ctm-sak config    --validate

Global flags
------------

.. code-block:: text

    --config PATH      Path to config.ini  (default: ~/.ctm_sak/config.ini)
    --output FORMAT    Output format: json | table | stix  (default: table)
    --quiet            Suppress informational output
    --no-color         Disable ANSI color output
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ctm_sak.cli")


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
        prog="ctm-sak",
        description=_bold("CTM-SAK — Cybersecurity Threat Management Swiss Army Knife"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              ctm-sak ping   --target threatq
              ctm-sak query  --target crowdstrike --type indicator --id indicator--abc
              ctm-sak list   --target xsoar --type indicator --limit 50
              ctm-sak ingest --target threatq --source iocs.txt --format plaintext
              ctm-sak ingest --target threatq --source bundle.json --format stix-bundle
              ctm-sak codegen --spec openapi.json --name myplatform --auth oauth2
              ctm-sak config --validate
        """),
    )

    # Global flags
    parser.add_argument("--config",   metavar="PATH",
                        help="Path to config.ini (default: ~/.ctm_sak/config.ini)")
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
    p_cg = subs.add_parser("codegen",
                            help="Generate a connector from an OpenAPI spec")
    p_cg.add_argument("--spec",     required=True, metavar="PATH",
                      help="OpenAPI spec file (JSON or YAML)")
    p_cg.add_argument("--name",     required=True, metavar="NAME",
                      help="Connector name (snake_case)")
    p_cg.add_argument("--auth",     default="oauth2",
                      choices=["oauth2", "api_key", "basic"])
    p_cg.add_argument("--out-dir",  default="./ctm_sak/connectors",
                      metavar="DIR")
    p_cg.add_argument("--test-dir", default="./tests/unit/connectors",
                      metavar="DIR")
    p_cg.add_argument("--overwrite", action="store_true")

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
    p_vs.add_argument("--host",  default="0.0.0.0")

    p_vd = viz_subs.add_parser("dashboard", help="Export Grafana dashboard JSON")
    p_vd.add_argument("--workspace", required=True, metavar="NAME")
    p_vd.add_argument("--file",      default="dashboard.json")
    p_vd.add_argument("--datasource", default="CTM-SAK")

    p_vpb = viz_subs.add_parser("powerbi", help="Export workspace to Power BI Excel")
    p_vpb.add_argument("--workspace", required=True, metavar="NAME")
    p_vpb.add_argument("--file",      default="workspace.xlsx")

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

    return parser


# ── Command handlers ───────────────────────────────────────────────────────

def _cmd_ping(args: argparse.Namespace) -> int:
    from ctm_sak.client import SAKClient
    _info(args, f"Pinging {_bold(args.target)} …")
    try:
        cli = SAKClient(config_path=args.config)
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
    from ctm_sak.client import SAKClient
    _info(args, f"Querying {_bold(args.target)} for {args.type} {_dim(args.id)} …")
    try:
        cli = SAKClient(config_path=args.config)
        cli.connect(target=args.target)
        raw = cli.client.get_object(args.type, args.id)
        stix = cli.client.to_stix(raw)
        _output(args, stix)
        return 0
    except Exception as exc:
        print(_red(f"Error: {exc}"), file=sys.stderr)
        return 1


def _cmd_list(args: argparse.Namespace) -> int:
    from ctm_sak.client import SAKClient
    _info(args, f"Listing {args.type} from {_bold(args.target)} …")
    try:
        cli = SAKClient(config_path=args.config)
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
    from ctm_sak.client import SAKClient
    from ctm_sak.ingest import IngestPipeline
    from ctm_sak.ingest.sources import (
        PlainTextReader, CSVReader, JSONReader, JSONLReader,
        STIXBundleReader, MISPReader,
    )
    from ctm_sak.ingest.mappers import (
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

        cli = SAKClient(config_path=args.config)
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
    from ctm_sak.codegen.openapi_generator import generate_connector
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


def _cmd_config(args: argparse.Namespace) -> int:
    from ctm_sak.config import SAKConfig

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
        default_path = Path.home() / ".ctm_sak" / "config.ini"
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
        cfg = SAKConfig(args.config)
    except FileNotFoundError as exc:
        print(_red(f"Config not found: {exc}"))
        print(_dim("  Run: ctm-sak config --init"))
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
    from ctm_sak.context import WorkspaceManager
    from ctm_sak.viz import TabularView, GraphView, PowerBIExporter, save_grafana_dashboard

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
        from ctm_sak.viz import GraphView
        gv = GraphView(ws)
        if args.file:
            gv.to_html(args.file, stix_types=args.types)
            print(_green(f"✓  Graph saved to {args.file}"))
        else:
            _info(args, f"Opening 3D graph for {_bold(args.workspace)} …")
            gv.show(stix_types=args.types)
        return 0

    if viz_cmd == "serve":
        from ctm_sak.context import WorkspaceManager
        from ctm_sak.viz.grafana.server import GrafanaServer
        manager = WorkspaceManager.default(config_path=args.config)
        server  = GrafanaServer(manager, host=args.host, port=args.port)
        print(_green(f"✓  Grafana datasource: {server.url()}"))
        print(_dim("  Configure in Grafana: Add data source → SimpleJSON → URL above"))
        server.run()
        return 0

    if viz_cmd == "dashboard":
        manager = WorkspaceManager.default(config_path=args.config)
        save_grafana_dashboard(args.workspace, args.file, args.datasource)
        print(_green(f"✓  Dashboard JSON saved to {args.file}"))
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


def _cmd_schedule(args) -> int:
    """schedule subcommand — list, run, crontab."""
    from ctm_sak.schedule import FeedScheduler
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
        "ping":    _cmd_ping,
        "viz":     _cmd_viz,
        "schedule": _cmd_schedule,
        "query":   _cmd_query,
        "list":    _cmd_list,
        "ingest":  _cmd_ingest,
        "codegen": _cmd_codegen,
        "config":  _cmd_config,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
