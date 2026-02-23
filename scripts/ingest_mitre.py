#!/usr/bin/env python3
"""MITRE ATT&CK STIX ingestion CLI script.

Downloads the enterprise-attack STIX bundle, parses all objects,
and loads them into the Neo4j knowledge graph.

Usage:
    # Download from GitHub and load (first run — creates schema + data)
    python scripts/ingest_mitre.py --source github --clear

    # Re-run with local cache (skip download)
    python scripts/ingest_mitre.py --source local

    # Point to a specific local file
    python scripts/ingest_mitre.py --source local --file path/to/enterprise-attack.json

    # Skip schema creation (indexes/constraints already exist)
    python scripts/ingest_mitre.py --source local --skip-schema
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

# Add project root to path so `src` is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.config import get_settings
from src.graph.connection import Neo4jConnection
from src.graph.loader import load_all_nodes, load_all_relationships
from src.graph.queries import (
    COUNT_NODES_BY_LABEL,
    COUNT_RELATIONSHIPS_BY_TYPE,
    SAMPLE_CREDENTIAL_ACCESS,
)
from src.graph.schema import clear_graph, setup_schema
from src.layers.layer1_ingestion import (
    DEFAULT_CACHE_PATH,
    download_stix_bundle,
    load_stix_store,
    parse_campaigns,
    parse_data_sources,
    parse_intrusion_sets,
    parse_malware,
    parse_mitigations,
    parse_relationships,
    parse_subtechniques,
    parse_tactic_technique_links,
    parse_tactics,
    parse_techniques,
    parse_tools,
)

console = Console()


def setup_logging(level: str = "INFO") -> None:
    """Configure logging with Rich handler."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


@click.command()
@click.option(
    "--source",
    type=click.Choice(["github", "local"], case_sensitive=False),
    default="github",
    help="Data source: 'github' to download, 'local' to use cached file.",
)
@click.option(
    "--file",
    "file_path",
    type=click.Path(exists=False),
    default=None,
    help="Path to local STIX JSON file (default: src/data/mitre/enterprise-attack.json).",
)
@click.option(
    "--clear",
    is_flag=True,
    default=False,
    help="Clear existing graph before loading.",
)
@click.option(
    "--skip-schema",
    is_flag=True,
    default=False,
    help="Skip index/constraint creation (for re-runs).",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default="INFO",
    help="Logging level.",
)
def main(
    source: str,
    file_path: str | None,
    clear: bool,
    skip_schema: bool,
    log_level: str,
) -> None:
    """Ingest MITRE ATT&CK STIX data into Neo4j knowledge graph."""
    setup_logging(log_level)
    logger = logging.getLogger("ingest_mitre")

    settings = get_settings()
    start_time = time.time()

    console.rule("[bold blue]MITRE ATT&CK Knowledge Graph Ingestion[/bold blue]")

    # ── Step 1: Connect to Neo4j ───────────────────────────
    console.print("\n[bold]Step 1:[/bold] Connecting to Neo4j ...")
    try:
        conn = Neo4jConnection()
    except Exception as e:
        console.print(f"[red]Failed to connect to Neo4j: {e}[/red]")
        raise SystemExit(1)

    try:
        # ── Step 2: Schema setup ──────────────────────────
        if clear:
            console.print("\n[bold]Step 2a:[/bold] Clearing existing graph ...")
            deleted = clear_graph(conn)
            console.print(f"  Deleted {deleted} nodes.")

        if not skip_schema:
            console.print("\n[bold]Step 2b:[/bold] Creating schema (indexes + constraints) ...")
            schema_stats = setup_schema(conn)
            console.print(
                f"  Created {schema_stats['constraints']} constraints, "
                f"{schema_stats['indexes']} indexes."
            )
        else:
            console.print("\n[bold]Step 2:[/bold] Skipping schema creation (--skip-schema).")

        # ── Step 3: Download / load STIX bundle ───────────
        console.print("\n[bold]Step 3:[/bold] Loading STIX bundle ...")
        if file_path:
            stix_path = Path(file_path)
            if not stix_path.exists():
                console.print(f"[red]File not found: {stix_path}[/red]")
                raise SystemExit(1)
        elif source == "github":
            stix_path = download_stix_bundle()
        else:
            stix_path = DEFAULT_CACHE_PATH
            if not stix_path.exists():
                console.print(
                    f"[red]Cached file not found at {stix_path}. "
                    f"Use --source github for first run.[/red]"
                )
                raise SystemExit(1)

        stix_store = load_stix_store(stix_path)

        # ── Step 4: Parse all STIX objects ─────────────────
        console.print("\n[bold]Step 4:[/bold] Parsing STIX objects ...")
        parse_start = time.time()

        tactics = parse_tactics(stix_store)
        techniques = parse_techniques(stix_store)
        subtechniques = parse_subtechniques(stix_store)
        intrusion_sets = parse_intrusion_sets(stix_store)
        tools = parse_tools(stix_store)
        malware_list = parse_malware(stix_store)
        data_sources = parse_data_sources(stix_store)
        mitigations = parse_mitigations(stix_store)
        campaigns = parse_campaigns(stix_store)
        grouped_rels = parse_relationships(stix_store)
        tactic_links = parse_tactic_technique_links(stix_store, tactics)

        parse_elapsed = time.time() - parse_start

        # Show parsed counts
        parse_table = Table(title="Parsed STIX Objects", show_lines=True)
        parse_table.add_column("Type", style="cyan")
        parse_table.add_column("Count", justify="right", style="green")
        for label, items in [
            ("Tactics", tactics),
            ("Techniques", techniques),
            ("SubTechniques", subtechniques),
            ("IntrusionSets", intrusion_sets),
            ("Tools", tools),
            ("Malware", malware_list),
            ("DataSources", data_sources),
            ("Mitigations", mitigations),
            ("Campaigns", campaigns),
        ]:
            parse_table.add_row(label, str(len(items)))
        parse_table.add_row("─" * 20, "─" * 5)
        total_nodes = sum(
            len(x) for x in [tactics, techniques, subtechniques, intrusion_sets,
                              tools, malware_list, data_sources, mitigations, campaigns]
        )
        parse_table.add_row("[bold]Total Nodes[/bold]", f"[bold]{total_nodes}[/bold]")
        parse_table.add_row("", "")
        for rel_type, rels in sorted(grouped_rels.items()):
            parse_table.add_row(f"Rel: {rel_type}", str(len(rels)))
        parse_table.add_row("Tactic Links", str(len(tactic_links)))

        console.print(parse_table)
        console.print(f"  Parsing took {parse_elapsed:.1f}s")

        # ── Step 5: Load nodes ─────────────────────────────
        console.print("\n[bold]Step 5:[/bold] Loading nodes into Neo4j ...")
        load_start = time.time()

        parsed_data = {
            "tactics": tactics,
            "techniques": techniques,
            "subtechniques": subtechniques,
            "intrusion_sets": intrusion_sets,
            "tools": tools,
            "malware": malware_list,
            "data_sources": data_sources,
            "mitigations": mitigations,
            "campaigns": campaigns,
        }
        node_stats = load_all_nodes(conn, parsed_data)

        node_elapsed = time.time() - load_start
        console.print(f"  Loaded {sum(node_stats.values())} nodes in {node_elapsed:.1f}s")

        # ── Step 6: Load relationships ─────────────────────
        console.print("\n[bold]Step 6:[/bold] Loading relationships into Neo4j ...")
        rel_start = time.time()

        rel_stats = load_all_relationships(conn, grouped_rels, tactic_links)

        rel_elapsed = time.time() - rel_start
        console.print(f"  Loaded {sum(rel_stats.values())} relationships in {rel_elapsed:.1f}s")

        # ── Step 7: Verification ───────────────────────────
        console.print("\n[bold]Step 7:[/bold] Verifying loaded data ...")

        # Node counts
        node_counts = conn.run_query(COUNT_NODES_BY_LABEL)
        verify_table = Table(title="Neo4j Node Counts", show_lines=True)
        verify_table.add_column("Label", style="cyan")
        verify_table.add_column("Count", justify="right", style="green")
        for row in node_counts:
            verify_table.add_row(row["label"], str(row["count"]))
        console.print(verify_table)

        # Relationship counts
        rel_counts = conn.run_query(COUNT_RELATIONSHIPS_BY_TYPE)
        rel_table = Table(title="Neo4j Relationship Counts", show_lines=True)
        rel_table.add_column("Type", style="cyan")
        rel_table.add_column("Count", justify="right", style="green")
        for row in rel_counts:
            rel_table.add_row(row["type"], str(row["count"]))
        console.print(rel_table)

        # Sample query
        sample = conn.run_query(SAMPLE_CREDENTIAL_ACCESS)
        if sample:
            sample_table = Table(
                title="Sample: Credential Access Techniques (first 10)",
                show_lines=True,
            )
            sample_table.add_column("ATT&CK ID", style="cyan")
            sample_table.add_column("Name", style="white")
            for row in sample:
                sample_table.add_row(row["attack_id"], row["name"])
            console.print(sample_table)

        # ── Summary ────────────────────────────────────────
        total_elapsed = time.time() - start_time
        console.rule("[bold green]Ingestion Complete[/bold green]")
        console.print(f"  Total time: {total_elapsed:.1f}s")
        console.print(f"  Nodes: {sum(node_stats.values())}")
        console.print(f"  Relationships: {sum(rel_stats.values())}")
        console.print(f"  STIX source: {stix_path}")

    finally:
        conn.close()


if __name__ == "__main__":
    main()
