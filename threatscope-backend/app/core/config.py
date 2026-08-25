"""
Application configuration loaded from environment variables.

Uses pydantic-settings to parse .env files and environment variables
into a strongly-typed Settings object. All secrets and tunables live
here — never hardcode sensitive values in application code.
"""

import logging

from typing import Any
from pydantic import field_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Application settings sourced from .env and environment variables."""

    # ── Database ─────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://threatscope:password@db:5432/threatscope"

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def validate_database_url(cls, v: Any) -> Any:
        if isinstance(v, str):
            # Replace sslmode query parameter with ssl for asyncpg
            if "sslmode=" in v:
                v = v.replace("sslmode=require", "ssl=require")
                v = v.replace("sslmode=disable", "ssl=disable")
                v = v.replace("sslmode=allow", "ssl=allow")
                v = v.replace("sslmode=prefer", "ssl=prefer")
            # Strip channel_binding which is unsupported by asyncpg
            if "channel_binding=" in v:
                import re
                v = re.sub(r'[&?]channel_binding=[^&]*', '', v)
                # Fix trailing question mark if query parameters are empty
                if v.endswith("?"):
                    v = v[:-1]
                # Fix potential double ampersands
                v = v.replace("?&", "?").replace("&&", "&")

            # Normalise standard cloud PostgreSQL URLs to use asyncpg
            if v.startswith("postgres://"):
                v = v.replace("postgres://", "postgresql+asyncpg://", 1)
            elif v.startswith("postgresql://") and "asyncpg" not in v:
                v = v.replace("postgresql://", "postgresql+asyncpg://", 1)
        return v

    # ── Redis ────────────────────────────────
    REDIS_URL: str = "redis://redis:6379/0"

    # ── MinIO Object Storage ─────────────────
    MINIO_ENDPOINT: str = "minio:9000"
    MINIO_ACCESS_KEY: str = "minioadmin"
    MINIO_SECRET_KEY: str = "minioadmin"
    MINIO_BUCKET: str = "threatscope-files"
    MINIO_SECURE: bool = False
    MINIO_REGION: str = "us-east-005"
    MINIO_PUBLIC_URL: str = "http://localhost:9000"

    # ── External APIs ────────────────────────
    VIRUSTOTAL_API_KEY: str = "your-vt-key-here"
    ABUSEIPDB_API_KEY: str = ""
    SHODAN_API_KEY: str = ""
    URLSCAN_API_KEY: str = ""

    # ── Yara Repos ───────────────────────────
    YARA_REPO_1_URL: str = "https://github.com/Yara-Rules/rules.git"
    YARA_REPO_2_URL: str = "https://github.com/Neo23x0/signature-base.git"
    YARA_BASE_DIR: str = "/app/yara_rules/repos"
    COMPILED_RULES_PATH: str = "/app/yara_rules/compiled.yarc"

    # ── App Settings ─────────────────────────
    MAX_FILE_SIZE_MB: int = 50
    RATE_LIMIT_PER_HOUR: int = 10
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [x.strip() for x in v.split(",") if x.strip()]
        return v

    @field_validator("YARA_BASE_DIR", mode="before")
    @classmethod
    def validate_yara_base_dir(cls, v: Any) -> Any:
        if isinstance(v, str):
            import os
            is_windows_path = ":" in v or "\\" in v
            is_nonexistent_app = v.startswith("/app") and not os.path.exists("/app")
            if is_windows_path or is_nonexistent_app:
                return "yara_rules/repos"
        return v

    @field_validator("COMPILED_RULES_PATH", mode="before")
    @classmethod
    def validate_compiled_rules_path(cls, v: Any) -> Any:
        if isinstance(v, str):
            import os
            is_windows_path = ":" in v or "\\" in v
            is_nonexistent_app = v.startswith("/app") and not os.path.exists("/app")
            if is_windows_path or is_nonexistent_app:
                return "yara_rules/compiled.yarc"
        return v

    # ── Ollama (Local LLM) ──────────────────
    OLLAMA_URL: str = "http://ollama:11434/api/generate"
    OLLAMA_MODEL: str = "mistral"

    # ── Sentry Error Tracking ───────────────
    SENTRY_DSN: str = ""

    model_config = {
        "env_file": ".env",
        "extra": "ignore",
    }


settings = Settings()
