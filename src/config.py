"""Central configuration — loads from .env via pydantic-settings.

Usage:
    from src.config import get_settings
    settings = get_settings()
    print(settings.neo4j_uri)
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    # --- LLM Provider ---
    llm_provider: str = "gemini"
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3-flash-preview"
    groq_api_key: str = ""
    groq_model: str = "qwen/qwen3-32b"
    ollama_model: str = "qwen3:32b"
    ollama_base_url: str = "http://localhost:11434/v1"

    # --- Neo4j ---
    neo4j_uri: str = ""
    neo4j_username: str = "neo4j"
    neo4j_password: str = ""
    neo4j_database: str = "neo4j"

    # --- Safety & Generation ---
    max_abilities_per_batch: int = 20
    enable_api_submission: bool = False
    backend_api_url: str = ""

    # --- Logging ---
    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # Ignore unrecognized env vars (e.g. AURA_INSTANCEID)
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return singleton Settings instance (cached after first call)."""
    return Settings()
