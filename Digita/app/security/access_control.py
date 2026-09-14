from flask import abort
from flask_login import current_user


# ============================================================
# Role-Based Access Control
#
# A01: Broken Access Control
#
# All authorization decisions are enforced server-side.
# Client-controlled role values are never trusted.
# ============================================================


# ============================================================
# Application Roles
# ============================================================

ADMIN_ROLE = "admin"
INVESTIGATOR_ROLE = "investigator"
OFFICER_ROLE = "officer"
AUDITOR_ROLE = "auditor"

ALL_ROLES = {
    ADMIN_ROLE,
    INVESTIGATOR_ROLE,
    OFFICER_ROLE,
    AUDITOR_ROLE,
}


# ============================================================
# Account Authorization
# ============================================================

def require_authenticated_user():
    """
    Require an authenticated user.
    """

    if not current_user.is_authenticated:
        abort(401)


def require_role(role):
    """
    Allow access only to an authenticated user with
    the required role.

    Example:
        require_role("investigator")
    """

    require_authenticated_user()

    if current_user.role != role:
        abort(403)


def require_any_role(*roles):
    """
    Allow access when the authenticated user has one of
    the specified roles.
    """

    require_authenticated_user()

    if current_user.role not in roles:
        abort(403)


def require_admin():
    """
    Allow access only to administrators.

    Administrator permissions are enforced entirely on the server.
    """

    require_role(ADMIN_ROLE)


def require_active_account():
    """
    Require the authenticated account to be approved and active.

    This provides an additional server-side authorization check
    for protected application functionality.
    """

    require_authenticated_user()

    if current_user.account_status != "approved":
        abort(403)

    if not current_user.is_active:
        abort(403)


# ============================================================
# Evidence Ownership
#
# A01: Broken Access Control
# IDOR protection
# ============================================================

def is_evidence_owner(evidence):
    """
    Return True only when the current investigator owns
    the requested evidence record.
    """

    if not current_user.is_authenticated:
        return False

    return evidence.uploaded_by_id == current_user.id


def require_evidence_owner(evidence):
    """
    Require the current authenticated user to own the evidence.
    """

    require_authenticated_user()

    if evidence.uploaded_by_id != current_user.id:
        abort(403)


# ============================================================
# Evidence Permissions
# ============================================================

def can_view_evidence(evidence):
    """
    Check whether the current user can view evidence.

    Investigator:
        Can view their own evidence.

    Officer:
        Can view all evidence.

    Admin:
        Can view all evidence.

    Auditor:
        Evidence access is not granted through this function.
    """

    if not current_user.is_authenticated:
        return False

    if current_user.role in {
        OFFICER_ROLE,
        ADMIN_ROLE,
    }:
        return True

    if current_user.role == INVESTIGATOR_ROLE:
        return is_evidence_owner(evidence)

    return False


def require_view_evidence(evidence):
    """
    Enforce evidence viewing authorization.
    """

    require_active_account()

    if not can_view_evidence(evidence):
        abort(403)


# ============================================================
# Evidence Modification
# ============================================================

def can_modify_evidence(evidence):
    """
    Check whether the current user can modify evidence metadata.

    Only the owning investigator can update evidence metadata.
    """

    if not current_user.is_authenticated:
        return False

    return (
        current_user.role == INVESTIGATOR_ROLE
        and is_evidence_owner(evidence)
    )


def require_modify_evidence(evidence):
    """
    Enforce evidence update authorization.
    """

    require_active_account()

    if not can_modify_evidence(evidence):
        abort(403)


# ============================================================
# Evidence Deletion
# ============================================================

def can_delete_evidence(evidence):
    """
    Check whether the current user can delete evidence.

    Only the owning investigator can delete their evidence.
    """

    if not current_user.is_authenticated:
        return False

    return (
        current_user.role == INVESTIGATOR_ROLE
        and is_evidence_owner(evidence)
    )


def require_delete_evidence(evidence):
    """
    Enforce evidence deletion authorization.
    """

    require_active_account()

    if not can_delete_evidence(evidence):
        abort(403)


# ============================================================
# Evidence Upload
# ============================================================

def require_evidence_upload_permission():
    """
    Only approved and active investigators can upload evidence.
    """

    require_active_account()

    if current_user.role != INVESTIGATOR_ROLE:
        abort(403)


# ============================================================
# Evidence Verification
# ============================================================

def can_verify_evidence(evidence):
    """
    Check whether the current user can verify evidence.

    Investigator:
        Can verify their own evidence.

    Officer:
        Can verify all evidence.

    Admin:
        Can verify all evidence.

    Auditor:
        Verification is not granted through this function.
    """

    if not current_user.is_authenticated:
        return False

    if current_user.role in {
        OFFICER_ROLE,
        ADMIN_ROLE,
    }:
        return True

    if current_user.role == INVESTIGATOR_ROLE:
        return is_evidence_owner(evidence)

    return False


def require_verify_evidence(evidence):
    """
    Enforce evidence verification authorization.
    """

    require_active_account()

    if not can_verify_evidence(evidence):
        abort(403)


# ============================================================
# Audit Log Access
#
# A01: Broken Access Control
# A09: Security Logging and Monitoring
# ============================================================

def require_auditor():
    """
    Only auditors can access the audit log interface.
    """

    require_active_account()

    if current_user.role != AUDITOR_ROLE:
        abort(403)


# ============================================================
# Admin User Management
#
# A01: Broken Access Control
# ============================================================

def can_manage_users():
    """
    Return True only for administrators.
    """

    if not current_user.is_authenticated:
        return False

    return (
        current_user.role == ADMIN_ROLE
        and current_user.account_status == "approved"
        and current_user.is_active
    )


def require_user_management():
    """
    Require administrator permission for user management.
    """

    require_admin()

    if current_user.account_status != "approved":
        abort(403)

    if not current_user.is_active:
        abort(403)


# ============================================================
# Admin Registration Requests
# ============================================================

def require_registration_request_management():
    """
    Require administrator permission to manage
    pending registration requests.
    """

    require_user_management()


# ============================================================
# Role Validation
# ============================================================

def is_valid_role(role):
    """
    Return True when the supplied role is an allowed
    application role.
    """

    if not isinstance(role, str):
        return False

    return role.strip().lower() in ALL_ROLES


def is_valid_requested_role(role):
    """
    Return True when the role may be requested by a
    public registration.

    Admin cannot be requested through public signup.
    """

    if not isinstance(role, str):
        return False

    return role.strip().lower() in {
        INVESTIGATOR_ROLE,
        OFFICER_ROLE,
        AUDITOR_ROLE,
    }
