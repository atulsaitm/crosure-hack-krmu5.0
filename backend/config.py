from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://crosure:crosure_secret@localhost:5432/crosure"

    # Ollama
    OLLAMA_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "dolphin-mistral"

    # OpenRouter (free cloud LLM — get key at https://openrouter.ai)
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_MODEL: str = "qwen/qwen3-coder:free"

    # ChromaDB
    CHROMADB_PATH: str = "./chromadb_data"

    # Scanner
    MAX_CRAWL_PAGES: int = 50
    CRAWL_TIMEOUT: int = 30
    MAX_CONCURRENT_REQUESTS: int = 10
    SCAN_REQUEST_TIMEOUT: int = 15

    # OAST
    OAST_POLL_INTERVAL: int = 10

    # App
    APP_NAME: str = "Crosure"
    DEBUG: bool = True

    class Config:
        env_file = ".env"


settings = Settings()
