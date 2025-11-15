"""Database models for ReconPanel."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, Optional

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db, login_manager


class User(UserMixin, db.Model):
    """Authenticated user capable of accessing the ReconPanel UI."""

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id: str) -> Optional["User"]:
    return db.session.get(User, int(user_id))


class ScanTask(db.Model):
    """Represents a scan request submitted by a user."""

    __tablename__ = "scan_tasks"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), default="pending", nullable=False)
    wordlist_path = db.Column(db.String(255), nullable=False)
    wordlist_lines_used = db.Column(db.Integer, nullable=False)
    subfinder_args = db.Column(db.Text, nullable=False)
    nuclei_args = db.Column(db.Text, nullable=False)
    subfinder_output_path = db.Column(db.String(255))
    log_path = db.Column(db.String(255))
    error_message = db.Column(db.Text)

    findings = db.relationship("Finding", backref="scan", lazy=True, cascade="all, delete-orphan")

    def _load_args(self, value: str) -> Dict[str, Any]:
        try:
            return json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return {}

    @property
    def subfinder_options(self) -> Dict[str, Any]:
        return self._load_args(self.subfinder_args)

    @property
    def nuclei_options(self) -> Dict[str, Any]:
        return self._load_args(self.nuclei_args)


class Finding(db.Model):
    """Stores findings discovered by nuclei for a scan."""

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_tasks.id"), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    template_id = db.Column(db.String(255))
    severity = db.Column(db.String(20))
    raw_line = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
