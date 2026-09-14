import logging
import os
from logging.handlers import RotatingFileHandler

from flask import Flask

from app.config import Config
from app.extensions import init_extensions


def create_app(config_class=Config):
    """
    Application Factory.

    Centralizes application creation and initialization.
    Security-sensitive logic is kept in dedicated modules.
    """

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    app.config.from_object(config_class)

    os.makedirs(app.config["LOG_DIR"], exist_ok=True)
    os.makedirs(app.config["ENCRYPTED_STORAGE_DIR"], exist_ok=True)
    os.makedirs(app.config["KEY_DIR"], exist_ok=True)

    init_extensions(app)

    _configure_security_logging(app)

    @app.after_request
    def apply_security_headers(response):
        """
        Add configured security headers to every response.
        """

        for header, value in app.config["SECURITY_HEADERS"].items():
            response.headers[header] = value

        return response

    from app.auth.auth_routes import auth_bp
    from app.routes.dashboard_routes import dashboard_bp
    from app.routes.evidence_routes import evidence_bp
    from app.routes.admin_routes import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(evidence_bp)
    app.register_blueprint(admin_bp)

    try:
        from app.audit.audit_logger import audit_bp

        app.register_blueprint(audit_bp)

    except ImportError:
        # Audit routes may be unavailable during early development.
        pass

    with app.app_context():
        from app.extensions import db

        # Import models so SQLAlchemy registers all tables.
        from app import models  # noqa: F401

        db.create_all()

    return app


def _configure_security_logging(app):
    """
    Configure the rotating security log.

    Security events are written by authentication,
    authorization, evidence, admin, and audit modules.
    """

    logger = logging.getLogger("security")

    logger.setLevel(logging.INFO)
    logger.propagate = False

    log_file = app.config["SECURITY_LOG_FILE"]

    # Prevent duplicate handlers.
    if not logger.handlers:
        handler = RotatingFileHandler(
            log_file,
            maxBytes=app.config["LOG_MAX_BYTES"],
            backupCount=app.config["LOG_BACKUP_COUNT"],
            encoding="utf-8",
        )

        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s"
        )

        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # Make the logger available through Flask.
    app.extensions["security_logger"] = logger
