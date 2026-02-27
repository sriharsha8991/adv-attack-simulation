"""CLI: Batch-generate abilities for all MITRE ATT&CK techniques.

Usage:
    python scripts/generate_all.py --dry-run          # preview manifest
    python scripts/generate_all.py                    # full sweep
    python scripts/generate_all.py --category credential_access
    python scripts/generate_all.py --resume           # skip finished categories
    python scripts/generate_all.py --concurrency 50   # limit parallelism
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import click
from rich.console import Console
from rich.logging import RichHandler

console = Console()


def setup_logging(level: str) -> None:
    """Configure rich-formatted logging."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


@click.command()
@click.option(
    "--category",
    type=str,
    default=None,
    help="Generate for a single category only (e.g. 'credential_access').",
)
@click.option(
    "--resume",
    is_flag=True,
    default=False,
    help="Skip categories that already have output files.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Discover targets and print the manifest without generating.",
)
@click.option(
    "--concurrency",
    type=int,
    default=None,
    help="Max parallel LLM calls (default: 100 from config).",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default="INFO",
    help="Logging level.",
)
def main(
    category: str | None,
    resume: bool,
    dry_run: bool,
    concurrency: int | None,
    log_level: str,
) -> None:
    """Batch-generate adversary simulation abilities for all ATT&CK techniques.

    Queries the knowledge graph for every technique + sub-technique,
    enriches each directly, and composes one ability per technique×platform
    at up to 100 concurrent LLM calls (Gemini tier-3).
    """
    setup_logging(log_level)
    logger = logging.getLogger("generate_all")

    categories = [category] if category else None

    from src.services.batch_generator import BatchGenerator

    try:
        with BatchGenerator(concurrency=concurrency) as gen:
            stats = gen.run(
                categories=categories,
                resume=resume,
                dry_run=dry_run,
            )
    except KeyboardInterrupt:
        logger.warning("Interrupted by user.")
        sys.exit(1)
    except Exception as exc:
        logger.error("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)

    if not dry_run:
        console.print(
            f"\n[bold green]Done![/] "
            f"{stats.generated} generated, "
            f"{stats.blocked} blocked, "
            f"{stats.failed} failed "
            f"in {stats.elapsed_seconds:.1f}s",
        )

    sys.exit(0 if stats.failed == 0 else 1)


if __name__ == "__main__":
    main()
