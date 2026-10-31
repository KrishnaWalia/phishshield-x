"""PhishShield X - Application Configuration

Central configuration loaded via Pydantic Settings.
Reads from environment variables and backend/.env file.
"""

from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application Settings for PhishShield X Backend."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Database Configuration (Neon PostgreSQL)
    DATABASE_URL: str = Field(
        default="postgresql+psycopg://postgres:postgres@localhost:5432/phishshield",
        description="Neon pooled connection string for normal application queries",
    )
    DIRECT_URL: Optional[str] = Field(
        default=None,
        description="Neon direct connection string for Alembic schema migrations",
    )

    # Groq AI Service Configuration
    PHISHSHIELD_GROQ_API_KEY: Optional[str] = Field(
        default=None,
        description="Groq API key for semantic analysis (optional)",
    )
    PHISHSHIELD_GROQ_MODEL: str = Field(
        default="llama-3.3-70b-versatile",
        description="Groq model name to use for semantic analysis",
    )
    PHISHSHIELD_AI_ENABLED: bool = Field(
        default=True,
        description="Enable or disable Groq AI enhancement layer",
    )

    # Server Settings
    PHISHSHIELD_HOST: str = Field(default="127.0.0.1", description="Server host")
    PHISHSHIELD_PORT: int = Field(default=8000, description="Server port")
    PHISHSHIELD_DEBUG: bool = Field(default=False, description="Debug mode")

    # Client Integration Base URLs (for reference / documentation)
    NEXT_PUBLIC_PHISHSHIELD_API_BASE_URL: str = Field(
        default="http://127.0.0.1:8000",
        description="Dashboard API Base URL",
    )
    PHISHSHIELD_EXTENSION_API_BASE_URL: str = Field(
        default="http://127.0.0.1:8000",
        description="Extension API Base URL",
    )

    # CORS Configuration
    CORS_ORIGINS: List[str] = Field(
        default=[
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ],
        description="Allowed CORS origins",
    )

    @staticmethod
    def _normalize_driver(url: Optional[str]) -> Optional[str]:
        """Ensure postgresql connection string uses postgresql+psycopg driver."""
        if not url:
            return url
        url_str = str(url).strip()
        if url_str.startswith("postgres://"):
            return "postgresql+psycopg://" + url_str[len("postgres://"):]
        if url_str.startswith("postgresql://"):
            return "postgresql+psycopg://" + url_str[len("postgresql://"):]
        return url_str

    @property
    def sqlalchemy_database_url(self) -> str:
        """Returns the application DATABASE_URL normalized for SQLAlchemy with psycopg 3."""
        normalized = self._normalize_driver(self.DATABASE_URL)
        return normalized or self.DATABASE_URL

    @property
    def sqlalchemy_direct_url(self) -> str:
        """Returns DIRECT_URL for Alembic migrations, falling back to DATABASE_URL."""
        target = self.DIRECT_URL or self.DATABASE_URL
        normalized = self._normalize_driver(target)
        return normalized or target


# Singleton settings instance
settings = Settings()
