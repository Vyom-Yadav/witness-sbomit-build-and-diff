from pydantic import SecretStr
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "SBOMIT_", "env_file": ".env"}

    # LLM (OpenRouter)
    openrouter_api_key: SecretStr = SecretStr("")
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_model: str = "openai/gpt-4o-mini"

    # Classifier model (can be different, more capable)
    classifier_model: str = "openai/gpt-4o-mini"

    # Build environment (base image with all binaries pre-installed)
    build_base_image: str = "sbomit-analyzer:base"

    # Discovery agent
    max_tool_calls: int = 4
    min_confidence: float = 0.5

    # Storage
    db_path: str = "data/analysis.db"

    # Temporal
    temporal_address: str = "localhost:7233"
    temporal_task_queue: str = "sbomit-analyzer"


settings = Settings()
