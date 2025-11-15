"""Entry point for running Celery workers."""

from __future__ import annotations

from .app import create_app
from .tasks import celery


flask_app = create_app()
celery_app = celery

__all__ = ["celery_app"]
