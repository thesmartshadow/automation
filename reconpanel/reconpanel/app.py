"""Flask application factory for ReconPanel."""

from __future__ import annotations

from flask import Flask
from flask_wtf.csrf import CSRFProtect

from . import config as config_module
from .auth import auth_bp
from .extensions import db, login_manager
from .models import User
from .tasks import init_celery
from .views import main_bp


csrf = CSRFProtect()


def create_app(config_class: type[config_module.BaseConfig] = config_module.BaseConfig) -> Flask:
    """Create and configure the Flask application."""

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(config_class())

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    with app.app_context():
        db.create_all()
        _ensure_admin_user()

    init_celery(app)

    return app


def _ensure_admin_user() -> None:
    """Create the initial admin user if configured via environment variables."""

    from flask import current_app

    username = current_app.config.get("RECONPANEL_ADMIN_USERNAME")
    password = current_app.config.get("RECONPANEL_ADMIN_PASSWORD")
    if not username or not password:
        return

    if not User.query.filter_by(username=username).first():
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
