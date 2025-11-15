"""Application configuration classes."""

from __future__ import annotations

import os
from dataclasses import dataclass


 codex/design-and-implement-reconpanel-web-app-c5u9lc
DEFAULT_DB_PATH = "sqlite:////data/db/reconpanel.db"

DEFAULT_DB_PATH = "sqlite:////data/reconpanel.db"
 main
DEFAULT_WORDLIST_DIR = "/data/wordlists"
DEFAULT_LOG_DIR = "/data/logs"
DEFAULT_TMP_DIR = "/tmp/reconpanel"
DEFAULT_TEMPLATE_DIR = "/nuclei-templates"


@dataclass
class BaseConfig:
    """Base configuration shared by the Flask and Celery apps."""

    SECRET_KEY: str = os.environ.get("RECONPANEL_SECRET_KEY", "change-me")
    SQLALCHEMY_DATABASE_URI: str = os.environ.get("DATABASE_URL", DEFAULT_DB_PATH)
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    CELERY_BROKER_URL: str = os.environ.get("CELERY_BROKER_URL", "redis://redis:6379/0")
    CELERY_RESULT_BACKEND: str = os.environ.get("CELERY_RESULT_BACKEND", "redis://redis:6379/0")
    WORDLIST_DIRECTORY: str = os.environ.get("RECONPANEL_WORDLIST_DIR", DEFAULT_WORDLIST_DIR)
    LOG_DIRECTORY: str = os.environ.get("RECONPANEL_LOG_DIR", DEFAULT_LOG_DIR)
    TMP_DIRECTORY: str = os.environ.get("RECONPANEL_TMP_DIR", DEFAULT_TMP_DIR)
    NUCLEI_TEMPLATE_DIRECTORY: str = os.environ.get(
        "RECONPANEL_TEMPLATE_DIR", DEFAULT_TEMPLATE_DIR
    )
    RECONPANEL_ADMIN_USERNAME: str | None = os.environ.get("RECONPANEL_ADMIN_USERNAME")
    RECONPANEL_ADMIN_PASSWORD: str | None = os.environ.get("RECONPANEL_ADMIN_PASSWORD")
    SESSION_COOKIE_SECURE: bool = False
    REMEMBER_COOKIE_SECURE: bool = False

    @property
    def CELERY(self) -> dict[str, str]:
        return {
            "broker_url": self.CELERY_BROKER_URL,
            "result_backend": self.CELERY_RESULT_BACKEND,
        }


class TestingConfig(BaseConfig):
    TESTING: bool = True
