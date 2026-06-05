"""Configuration de l'application avec variables d'environnement."""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Paramètres de configuration chargés depuis les variables d'environnement."""

    # MongoDB
    MONGO_URI: str = Field(default="mongodb://localhost:27017", alias="MONGODB_URI")
    MONGO_DB_NAME: str = Field(default="networkrecon", alias="MONGODB_DATABASE")

    # Application
    APP_ENV: str = Field(default="development", alias="APP_ENV")
    DEBUG: bool = Field(default=True, alias="DEBUG")
    API_HOST: str = Field(default="0.0.0.0", alias="API_HOST")
    API_PORT: int = Field(default=8000, alias="API_PORT")

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Scan
    SCAN_TIMEOUT: int = Field(default=300, alias="SCAN_TIMEOUT")
    MAX_CONCURRENT_SCANS: int = Field(default=5, alias="MAX_CONCURRENT_SCANS")

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
