"""ReconPanel package initialization."""

from .celery_app import celery_app  # noqa: F401  # re-export for Celery CLI

__all__ = ["celery_app"]
