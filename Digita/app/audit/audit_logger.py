import logging

from flask import Blueprint, abort, request, render_template
from flask_login import login_required

from app.extensions import db
from app.models import AuditLog
from app.security.access_control import require_auditor


audit_bp = Blueprint(
    "audit",
    __name__,
)


# ============================================================
# Security Logger
#
# A09: Security Logging and Monitoring Failures
#
# Security events are stored in:
# 1. Database -> AuditLog
# 2. logs/security.log -> rotating application log
#
# Passwords, session IDs, encryption keys, and other secrets
# must never be written to the audit log.
# ============================================================


def _get_security_logger():
    """
    Return the configured security logger.
    """
    return logging.getLogger("security")


def _get_client_ip():
    """
    Return the direct client IP address.

    X-Forwarded-For is not trusted because it can be forged
    unless a trusted reverse proxy is explicitly configured.
    """
    return request.remote_addr or "unknown"


def log_security_event(
    action,
    result,
    user=None,
    evidence_id=None,
    details=None,
):
    """
    Record a security/audit event.

    Parameters:
        action:
            Operation such as LOGIN, LOGOUT, UPLOAD, UPDATE,
            DELETE, VERIFY, ACCESS_DENIED.

        result:
            SUCCESS, FAILED, DENIED, ERROR, TAMPERED, etc.

        user:
            User object when available.

        evidence_id:
            Related evidence ID when applicable.

        details:
            Non-sensitive descriptive information.

    Returns:
        AuditLog object added to the current database session.
    """

    # Limit audit details to avoid oversized log entries.
    if details:
        details = str(details)[:1000]

    audit_entry = AuditLog(
        user_id=user.id if user else None,
        evidence_id=evidence_id,
        action=str(action)[:100],
        result=str(result)[:30],
        ip_address=_get_client_ip(),
        details=details,
    )

    db.session.add(audit_entry)

    logger = _get_security_logger()

    logger.info(
        "action=%s | result=%s | user=%s | evidence_id=%s | ip=%s | details=%s",
        str(action)[:100],
        str(result)[:30],
        user.username if user else "anonymous",
        evidence_id if evidence_id is not None else "-",
        _get_client_ip(),
        details or "",
    )

    return audit_entry


# ============================================================
# Audit Logs - Read Only
#
# A01: Broken Access Control
# A09: Security Logging and Monitoring
# ============================================================


@audit_bp.route(
    "/audit-logs",
    methods=["GET"],
)
@login_required
def audit_logs():
    """
    Display security audit logs.

    Only authenticated auditors can access this endpoint.

    Audit logs are read-only through the web application.
    """

    # Centralized RBAC check.
    require_auditor()

    audit_entries = db.session.scalars(
        db.select(AuditLog)
        .order_by(
            AuditLog.timestamp.desc()
        )
    ).all()

    return render_template(
        "audit_logs.html",
        audit_logs=audit_entries,
    )
