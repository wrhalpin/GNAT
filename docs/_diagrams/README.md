# GNAT Diagram Sources

This directory contains Python scripts that generate the architectural PNG diagrams
included in [`docs/explanation/architecture/img/`](../explanation/architecture/img/).

The scripts use the [`diagrams`](https://diagrams.mingrammer.com/) Python library which
builds on Graphviz. Generated images are committed to the repository so that the docs
are self-contained without requiring Graphviz to be installed by every reader.

## Regenerating Diagrams

Install dependencies (one-time setup):

```bash
sudo apt-get install graphviz   # or: brew install graphviz
pip install diagrams
```

Regenerate all diagrams from the repo root:

```bash
python docs/_diagrams/generate_all.py
```

Or regenerate a single diagram:

```bash
python docs/_diagrams/generate_system_overview.py
python docs/_diagrams/generate_connector_arch.py
python docs/_diagrams/generate_ai_agents.py
python docs/_diagrams/generate_ingest_pipeline.py
```

## Editing in Grafly

The Graphviz DOT files that back these diagrams can be imported into
[Grafly](https://grafly.io/) for visual editing:

1. Run a generation script — this also produces a `.dot` intermediate file.
2. Open [grafly.io](https://grafly.io/) → *File → Import → Graphviz DOT*.
3. Edit visually, then export back to DOT or PNG.

Mermaid-based workflow diagrams (in
[`workflow-diagrams.md`](../explanation/architecture/workflow-diagrams.md))
can be imported into Grafly via *File → Import → Mermaid*.

## Scripts

| Script | Output | Description |
|--------|--------|-------------|
| `generate_system_overview.py` | `img/system_overview.png` | All GNAT layers end-to-end |
| `generate_connector_arch.py` | `img/connector_architecture.png` | ConnectorMixin / CLIENT_REGISTRY |
| `generate_ai_agents.py` | `img/ai_agent_layer.png` | LLMClient + specialist agents |
| `generate_ingest_pipeline.py` | `img/ingest_pipeline.png` | Ingest pipeline from sources to ORM |
| `generate_all.py` | all of the above | Convenience runner |
