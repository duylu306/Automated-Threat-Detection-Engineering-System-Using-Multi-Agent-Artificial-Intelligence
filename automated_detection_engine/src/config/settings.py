"""
src/config/settings.py
Config trung tam dung Pydantic Settings.
"""
from enum import Enum
from pathlib import Path
from functools import lru_cache
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    GOOGLE = "google"  


class VectorDB(str, Enum):
    CHROMADB = "chromadb"
    QDRANT = "qdrant"


class AppEnv(str, Enum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # LLM
    openai_api_key: str = Field(default="")
    anthropic_api_key: str = Field(default="")
    google_api_key: str = Field(default="")  
    llm_provider: LLMProvider = Field(default=LLMProvider.OPENAI)
    llm_model: str = Field(default="gpt-4o-mini")
    llm_temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    llm_max_tokens: int = Field(default=4096, ge=256)
    ollama_base_url: str = Field(default="http://localhost:11434")
    ollama_model: str = Field(default="llama3.1:8b")

    # Vector DB
    vector_db: VectorDB = Field(default=VectorDB.CHROMADB)
    chroma_persist_dir: str = Field(default="./data/chroma_storage")
    qdrant_url: str = Field(default="http://localhost:6333")
    qdrant_api_key: str = Field(default="")
    embedding_model: str = Field(default="BAAI/bge-small-en-v1.5")
    reranker_model: str = Field(default="BAAI/bge-reranker-base")

    # DB & Redis
    database_url: str = Field(default="sqlite:///./data/detection_engine.db")
    redis_url: str = Field(default="redis://localhost:6379/0")

    # App
    app_env: AppEnv = Field(default=AppEnv.DEVELOPMENT)
    log_level: str = Field(default="INFO")
    max_validation_retries: int = Field(default=5, ge=1, le=20)
    rag_top_k_retrieve: int = Field(default=20, ge=5)
    rag_top_k_rerank: int = Field(default=5, ge=1)

    # Paths
    data_dir: str = Field(default="./data")
    raw_cti_dir: str = Field(default="./data/raw_cti")
    evtx_samples_dir: str = Field(default="./data/evtx_samples")
    sigmahq_rules_dir: str = Field(default="./data/sigmahq_rules")

    @property
    def is_development(self) -> bool:
        return self.app_env == AppEnv.DEVELOPMENT

    @property
    def sigmahq_path(self) -> Path:
        return Path(self.sigmahq_rules_dir)

    def get_llm_api_key(self) -> str:
        if self.llm_provider == LLMProvider.OPENAI:
            return self.openai_api_key
        elif self.llm_provider == LLMProvider.ANTHROPIC:
            return self.anthropic_api_key
        elif self.llm_provider == LLMProvider.GOOGLE:  # Thêm 2 dòng này
            return self.google_api_key
        return ""

    def ensure_dirs(self) -> None:
        for d in [self.data_dir, self.raw_cti_dir, self.evtx_samples_dir,
                  self.sigmahq_rules_dir, self.chroma_persist_dir]:
            Path(d).mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
