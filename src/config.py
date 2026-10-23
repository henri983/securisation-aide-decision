"""
Configuration centrale et variables d'environnement.
"""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "Sécurisation Systèmes d'Aide à la Décision"
    APP_ENV: str = "development"
    LOG_LEVEL: str = "INFO"

    # Clé maître cryptographique (256-bit AES-GCM hex)
    DECISION_MASTER_KEY_HEX: str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

    # Clé HMAC de scellement des décisions
    DECISION_SIGNATURE_KEY_HEX: str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

    # Paramètres du Disjoncteur Décisionnel (Circuit Breaker)
    CIRCUIT_BREAKER_CONFIDENCE_THRESHOLD: float = 0.65
    PROACTIVE_POISON_THRESHOLD: float = 0.75
    MAX_STATISTICAL_ZSCORE_DEVIATION: float = 3.5

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
