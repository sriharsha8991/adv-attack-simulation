"""Neo4j connection wrapper with context manager support.

Usage:
    from src.graph.connection import Neo4jConnection

    with Neo4jConnection() as conn:
        results = conn.run_query("MATCH (n) RETURN count(n) AS cnt")
        print(results[0]["cnt"])
"""

from __future__ import annotations

import logging
from typing import Any

from neo4j import GraphDatabase

from src.config import get_settings

logger = logging.getLogger(__name__)


class Neo4jConnection:
    """Wrapper around the Neo4j Python driver.

    Provides simplified query/write methods and context manager support.
    Reads connection parameters from Settings (loaded from .env).
    """

    def __init__(
        self,
        uri: str | None = None,
        username: str | None = None,
        password: str | None = None,
        database: str | None = None,
    ) -> None:
        settings = get_settings()
        self._uri = uri or settings.neo4j_uri
        self._username = username or settings.neo4j_username
        self._password = password or settings.neo4j_password
        self._database = database or settings.neo4j_database

        if not self._uri:
            raise ValueError(
                "NEO4J_URI is not set. Check your .env file or pass uri= explicitly."
            )

        logger.info("Connecting to Neo4j at %s", self._uri)

        # Build driver kwargs — handle SSL for Aura (neo4j+s://)
        driver_kwargs: dict[str, Any] = {
            "auth": (self._username, self._password),
        }

        # If using neo4j+s:// (Aura) and SSL verification fails (e.g. corporate
        # proxy), fall back to neo4j+ssc:// which accepts self-signed certs.
        if self._uri.startswith("neo4j+s://"):
            try:
                self._driver = GraphDatabase.driver(self._uri, **driver_kwargs)
                self._driver.verify_connectivity()
                logger.info("Neo4j connection verified successfully (strict SSL).")
                return
            except Exception:
                logger.warning(
                    "Strict SSL connection failed. "
                    "Retrying with self-signed cert support (neo4j+ssc://) ..."
                )
                try:
                    self._driver.close()
                except Exception:
                    pass
                ssc_uri = self._uri.replace("neo4j+s://", "neo4j+ssc://", 1)
                self._driver = GraphDatabase.driver(ssc_uri, **driver_kwargs)
                self._driver.verify_connectivity()
                logger.info("Neo4j connection verified (self-signed cert mode).")
                return

        self._driver = GraphDatabase.driver(self._uri, **driver_kwargs)
        self._driver.verify_connectivity()
        logger.info("Neo4j connection verified successfully.")

    # --- Context manager ---

    def __enter__(self) -> Neo4jConnection:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    # --- Query methods ---

    def run_query(
        self, cypher: str, params: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """Execute a read query and return list of record dicts."""
        params = params or {}
        records, _, _ = self._driver.execute_query(
            cypher,
            parameters_=params,
            database_=self._database,
        )
        return [record.data() for record in records]

    def run_write(
        self, cypher: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Execute a write query and return summary counters."""
        params = params or {}
        _, summary, _ = self._driver.execute_query(
            cypher,
            parameters_=params,
            database_=self._database,
        )
        counters = summary.counters
        return {
            "nodes_created": counters.nodes_created,
            "nodes_deleted": counters.nodes_deleted,
            "relationships_created": counters.relationships_created,
            "relationships_deleted": counters.relationships_deleted,
            "properties_set": counters.properties_set,
        }

    def clear_all(self) -> int:
        """Delete all nodes and relationships in batched transactions.

        Returns total number of nodes deleted. Uses LIMIT to avoid
        transaction size limits on Neo4j Aura.
        """
        total_deleted = 0
        while True:
            result = self.run_write(
                "MATCH (n) WITH n LIMIT 10000 DETACH DELETE n RETURN count(n) AS deleted"
            )
            deleted = result.get("nodes_deleted", 0)
            if deleted == 0:
                break
            total_deleted += deleted
            logger.info("Deleted batch of %d nodes (total: %d)", deleted, total_deleted)
        logger.info("Graph cleared. Total nodes deleted: %d", total_deleted)
        return total_deleted

    def is_active(self) -> bool:
        """Check whether the Neo4j connection is active and responsive."""
        try:
            self._driver.verify_connectivity()
            return True
        except Exception:
            return False

    def close(self) -> None:
        """Close the driver connection."""
        self._driver.close()
        logger.info("Neo4j connection closed.")
