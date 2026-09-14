from flask_argon2 import Argon2
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect


db = SQLAlchemy()


login_manager = LoginManager()


@login_manager.user_loader
def load_user(user_id):
    """
    Load the authenticated user from the database using
    the ID stored in the Flask-Login session.

    A07: Identification and Authentication Failures
    """
    from app.models import User

    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


login_manager.login_view = "auth.login"

login_manager.login_message = (
    "Please log in to access this page."
)

login_manager.login_message_category = "warning"

login_manager.session_protection = "strong"

argon2 = Argon2()

csrf = CSRFProtect()


server_session = Session()


limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[
        "200 per day",
        "50 per hour",
    ],
)


def init_extensions(app):
    """
    Initialize all Flask extensions.

    Extensions are initialized through the application factory
    so the project remains modular and easier to test.
    """

    # Database
    db.init_app(app)

    # Flask-Login
    login_manager.init_app(app)

    # Argon2 password hashing
    argon2.init_app(app)

    # CSRF protection
    csrf.init_app(app)

    # Server-side sessions
    server_session.init_app(app)

    # Rate limiting
    limiter.init_app(app)
