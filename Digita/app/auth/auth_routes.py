import logging
import re
from datetime import timedelta

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import (
    current_user,
    login_required,
    login_user,
    logout_user,
)
from sqlalchemy.exc import IntegrityError

from app.extensions import argon2, db, limiter
from app.models import AuditLog, User, utc_now


auth_bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/auth",
)


# ============================================================
# Validation Rules
# ============================================================

USERNAME_PATTERN = re.compile(
    r"^[A-Za-z0-9_.-]{3,30}$"
)

ALLOWED_REQUESTED_ROLES = {
    "investigator",
    "officer",
    "auditor",
}


def _normalize_username(username):
    """
    Normalize usernames before database lookup/storage.
    """

    return username.strip().lower()


def _is_valid_username(username):
    """
    Server-side username validation.
    """

    return bool(USERNAME_PATTERN.fullmatch(username))


def _is_valid_password(password):
    """
    Server-side password validation.
    """

    if not isinstance(password, str):
        return False

    if not 8 <= len(password) <= 128:
        return False

    # Reject control characters.
    if any(ord(character) < 32 for character in password):
        return False

    return True


# ============================================================
# Security / Audit Helpers
# ============================================================

def _security_logger():
    """
    Return the configured security logger.
    """

    return logging.getLogger("security")


def _client_ip():
    """
    Return the direct client address.

    X-Forwarded-For is intentionally not trusted.
    """

    return request.remote_addr or "unknown"


def _write_audit_log(
    *,
    user=None,
    evidence_id=None,
    action,
    result,
    details="",
):
    """
    Record an authentication/security event.

    Passwords and authentication secrets are never logged.
    """

    safe_details = details[:1000] if details else None

    audit_entry = AuditLog(
        user_id=user.id if user else None,
        evidence_id=evidence_id,
        action=action,
        result=result,
        ip_address=_client_ip(),
        details=safe_details,
    )

    db.session.add(audit_entry)

    logger = _security_logger()

    logger.info(
        "action=%s result=%s user=%s ip=%s details=%s",
        action,
        result,
        user.username if user else "anonymous",
        _client_ip(),
        details[:500] if details else "",
    )


# ============================================================
# Login
# ============================================================

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(
    lambda: current_app.config["LOGIN_RATE_LIMIT"],
    methods=["POST"],
)
def login():
    """
    Authenticate an approved active user.

    Security controls:
    - Authentication
    - Rate limiting
    - Account lockout after configured failures
    - Argon2 password verification
    - Session regeneration
    - Account status verification
    """

    if current_user.is_authenticated:
        return redirect(
            url_for("dashboard.dashboard")
        )

    if request.method == "GET":
        return render_template("login.html")

    # --------------------------------------------------------
    # Input validation
    # --------------------------------------------------------

    username = _normalize_username(
        request.form.get("username", "")
    )

    password = request.form.get(
        "password",
        ""
    )

    if not username or not password:
        flash(
            "Invalid username or password.",
            "danger",
        )

        return render_template(
            "login.html"
        ), 400

    if not _is_valid_username(username):
        flash(
            "Invalid username or password.",
            "danger",
        )

        return render_template(
            "login.html"
        ), 400

    # --------------------------------------------------------
    # User lookup
    # --------------------------------------------------------

    user = db.session.scalar(
        db.select(User).where(
            User.username == username
        )
    )

    if user is None:
        _write_audit_log(
            action="LOGIN",
            result="FAILED",
            details="Authentication failed.",
        )

        db.session.commit()

        flash(
            "Invalid username or password.",
            "danger",
        )

        return render_template(
            "login.html"
        ), 401

    # --------------------------------------------------------
    # Account status
    # --------------------------------------------------------

    if user.account_status == "pending":
        _write_audit_log(
            user=user,
            action="LOGIN",
            result="DENIED",
            details="Pending account attempted login.",
        )

        db.session.commit()

        flash(
            "Your account is waiting for administrator approval.",
            "warning",
        )

        return render_template(
            "login.html"
        ), 403

    if user.account_status == "rejected":
        _write_audit_log(
            user=user,
            action="LOGIN",
            result="DENIED",
            details="Rejected account attempted login.",
        )

        db.session.commit()

        flash(
            "This account is not approved.",
            "danger",
        )

        return render_template(
            "login.html"
        ), 403

    if user.account_status == "suspended":
        _write_audit_log(
            user=user,
            action="LOGIN",
            result="DENIED",
            details="Suspended account attempted login.",
        )

        db.session.commit()

        flash(
            "This account is currently unavailable.",
            "danger",
        )

        return render_template(
            "login.html"
        ), 403

    if not user.is_active:
        _write_audit_log(
            user=user,
            action="LOGIN",
            result="DENIED",
            details="Inactive account attempted login.",
        )

        db.session.commit()

        flash(
            "This account is currently unavailable.",
            "danger",
        )

        return render_template(
            "login.html"
        ), 403

    # --------------------------------------------------------
    # Account lockout
    # --------------------------------------------------------

    user.clear_expired_lock()

    if user.is_locked():
        _write_audit_log(
            user=user,
            action="LOGIN",
            result="DENIED",
            details="Account temporarily locked.",
        )

        db.session.commit()

        flash(
            "Invalid username or password.",
            "danger",
        )

        return render_template(
            "login.html"
        ), 403

    # --------------------------------------------------------
    # Password verification
    # --------------------------------------------------------

    try:
        password_valid = argon2.check_password_hash(
            user.password_hash,
            password,
        )

    except Exception:
        current_app.logger.exception(
            "Password verification error."
        )

        db.session.rollback()

        _write_audit_log(
            user=user,
            action="LOGIN",
            result="ERROR",
            details="Password verification error.",
        )

        db.session.commit()

        flash(
            "Unable to process the login request.",
            "danger",
        )

        return render_template(
            "login.html"
        ), 500

    # --------------------------------------------------------
    # Failed authentication
    # --------------------------------------------------------

    if not password_valid:
        user.failed_login_attempts += 1

        if (
            user.failed_login_attempts
            >= current_app.config[
                "MAX_FAILED_LOGIN_ATTEMPTS"
            ]
        ):
            user.locked_until = (
                utc_now()
                + timedelta(
                    minutes=current_app.config[
                        "ACCOUNT_LOCKOUT_MINUTES"
                    ]
                )
            )

            audit_result = "LOCKED"
            details = "Account locked after repeated failures."

        else:
            audit_result = "FAILED"
            details = "Invalid credentials."

        _write_audit_log(
            user=user,
            action="LOGIN",
            result=audit_result,
            details=details,
        )

        db.session.commit()

        flash(
            "Invalid username or password.",
            "danger",
        )

        return render_template(
            "login.html"
        ), 401

    # --------------------------------------------------------
    # Successful authentication
    # --------------------------------------------------------

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = utc_now()

    try:
        # Clear previous session data.
        session.clear()

        # Regenerate the server-side session identifier.
        current_app.session_interface.regenerate(
            session
        )

        login_user(
            user,
            remember=False,
            fresh=True,
        )

        _write_audit_log(
            user=user,
            action="LOGIN",
            result="SUCCESS",
            details="User authenticated successfully.",
        )

        db.session.commit()

    except Exception:
        db.session.rollback()

        current_app.logger.exception(
            "Unable to establish authenticated session."
        )

        logout_user()
        session.clear()

        flash(
            "Unable to complete the login.",
            "danger",
        )

        return render_template(
            "login.html"
        ), 500

    return redirect(
        url_for("dashboard.dashboard")
    )


# ============================================================
# Signup
# ============================================================

@auth_bp.route("/signup", methods=["GET", "POST"])
@limiter.limit(
    "3 per hour",
    methods=["POST"],
)
def signup():
    """
    Register a new account.

    The applicant may request:
    - investigator
    - officer
    - auditor

    The requested role is NOT the final authorization role.

    New accounts are created as:
    - account_status = pending
    - is_active = False

    The administrator must approve the account and assign
    the final role.
    """

    if current_user.is_authenticated:
        return redirect(
            url_for("dashboard.dashboard")
        )

    if request.method == "GET":
        return render_template(
            "signup.html"
        )

    # --------------------------------------------------------
    # Read submitted data
    # --------------------------------------------------------

    username = _normalize_username(
        request.form.get("username", "")
    )

    password = request.form.get(
        "password",
        ""
    )

    confirm_password = request.form.get(
        "confirm_password",
        ""
    )

    requested_role = (
        request.form.get(
            "requested_role",
            ""
        )
        .strip()
        .lower()
    )

    # --------------------------------------------------------
    # Validate username
    # --------------------------------------------------------

    if not _is_valid_username(username):
        flash(
            "Username must contain 3–30 valid characters.",
            "danger",
        )

        return render_template(
            "signup.html"
        ), 400

    # --------------------------------------------------------
    # Validate password
    # --------------------------------------------------------

    if not _is_valid_password(password):
        flash(
            "Password must contain between 8 and 128 characters.",
            "danger",
        )

        return render_template(
            "signup.html"
        ), 400

    if password != confirm_password:
        flash(
            "Passwords do not match.",
            "danger",
        )

        return render_template(
            "signup.html"
        ), 400

    # --------------------------------------------------------
    # Validate requested role
    # --------------------------------------------------------

    if requested_role not in ALLOWED_REQUESTED_ROLES:
        flash(
            "Please select a valid requested role.",
            "danger",
        )

        return render_template(
            "signup.html"
        ), 400

    # --------------------------------------------------------
    # Prevent public admin requests
    # --------------------------------------------------------

    if requested_role == "admin":
        flash(
            "Invalid account role.",
            "danger",
        )

        return render_template(
            "signup.html"
        ), 400

    # --------------------------------------------------------
    # Duplicate account prevention
    # --------------------------------------------------------

    existing_user = db.session.scalar(
        db.select(User).where(
            User.username == username
        )
    )

    if existing_user is not None:
        flash(
            "Unable to create this account.",
            "danger",
        )

        return render_template(
            "signup.html"
        ), 409

    # --------------------------------------------------------
    # Create pending account
    # --------------------------------------------------------

    try:
        password_hash = argon2.generate_password_hash(
            password
        )

        user = User(
            username=username,
            password_hash=password_hash,

            # Final role is kept at a safe default until
            # the administrator approves the request.
            role="investigator",

            # Store the role requested by the applicant.
            requested_role=requested_role,

            # New registration requires administrator approval.
            account_status="pending",
            is_active=False,

            failed_login_attempts=0,
            locked_until=None,

            approved_at=None,
            approved_by_id=None,
        )

        db.session.add(user)

        db.session.flush()

        _write_audit_log(
            user=user,
            action="SIGNUP",
            result="PENDING",
            details=(
                f"New registration request created. "
                f"Requested role='{requested_role}'."
            ),
        )

        db.session.commit()

    except IntegrityError:
        db.session.rollback()

        flash(
            "Unable to create this account.",
            "danger",
        )

        return render_template(
            "signup.html"
        ), 409

    except Exception:
        db.session.rollback()

        current_app.logger.exception(
            "Account registration error."
        )

        flash(
            "Unable to create the account.",
            "danger",
        )

        return render_template(
            "signup.html"
        ), 500

    flash(
        "Account request submitted. Please wait for administrator approval.",
        "success",
    )

    return redirect(
        url_for("auth.login")
    )


# ============================================================
# Logout
# ============================================================

@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """
    End the authenticated session.

    POST + CSRF is required because logout changes
    authentication state.
    """

    user = current_user

    try:
        _write_audit_log(
            user=user,
            action="LOGOUT",
            result="SUCCESS",
            details="User logged out.",
        )

        db.session.commit()

        logout_user()

        session.clear()

    except Exception:
        db.session.rollback()

        current_app.logger.exception(
            "Logout processing error."
        )

        logout_user()
        session.clear()

    flash(
        "You have been logged out.",
        "success",
    )

    return redirect(
        url_for("auth.login")
    )
