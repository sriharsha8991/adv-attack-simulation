"""LLM provider integrations — factory pattern for provider switching.

Usage:
    from src.llm import create_llm_client
    from src.config import get_settings

    llm = create_llm_client(get_settings())
    result = llm.generate([{"role": "user", "content": "Hello"}])
"""

from src.config import Settings
from src.llm.base import GenerateResult, LLMClient
from src.llm.gemini_client import GeminiClient


def create_llm_client(settings: Settings) -> LLMClient:
    """Create LLM client based on provider setting.

    Args:
        settings: Application settings with provider config.

    Returns:
        Configured LLMClient instance.

    Raises:
        ValueError: If settings.llm_provider is not recognized.
    """
    match settings.llm_provider:
        case "gemini":
            return GeminiClient(
                api_key=settings.gemini_api_key,
                model=settings.gemini_model,
            )
        case "groq":
            from src.llm.openai_compat import OpenAICompatClient
            return OpenAICompatClient(
                api_key=settings.groq_api_key,
                base_url=settings.groq_base_url,
                model=settings.groq_model,
            )
        case "ollama":
            from src.llm.openai_compat import OpenAICompatClient
            return OpenAICompatClient(
                api_key="ollama",
                base_url=settings.ollama_base_url,
                model=settings.ollama_model,
            )
        case _:
            raise ValueError(f"Unknown LLM provider: {settings.llm_provider}")


__all__ = [
    "create_llm_client",
    "LLMClient",
    "GenerateResult",
    "GeminiClient",
]
