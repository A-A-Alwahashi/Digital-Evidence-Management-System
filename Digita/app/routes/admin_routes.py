from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy.exc import IntegrityError

from app.audit.audit_logger import log_security_event
from app.extensions import argon2, db
from app.models import User, utc_now
from app.security.access_control import require_admin


admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/dashboard/admin",
)


# ============================================================
# Constants
# ============================================================

ALLOWED_ROLES = {
    "admin",
    "investigator",
    "officer",
    "auditor",
}

PUBLIC_REQUESTED_ROLES = {
    "investigator",
    "officer",
    "auditor",
}


# ============================================================
# Admin User Management
# ============================================================

@admin_bp.route("/users", methods=["GET"])
@login_required
def users():
    """
    Display all user accounts.
    """

    require_admin()

    users_list = (
        User.query
        .order_by(User.created_at.desc())
        .all()
    )

    total_users = len(users_list)

    pending_count = (
        User.query
        .filter_by(account_status="pending")
        .count()
    )

    active_count = (
        User.query
        .filter_by(
            account_status="approved",
            is_active=True,
        )
        .count()
    )

    suspended_count = (
        User.query
        .filter_by(account_status="suspended")
        .count()
    )

    return render_template(
        "admin_users.html",
        users=users_list,
        total_users=total_users,
        pending_count=pending_count,
        active_count=active_count,
        suspended_count=suspended_count,
        current_user=current_user,
    )


# ============================================================
# Registration Requests
# ============================================================

@admin_bp.route("/requests", methods=["GET"])
@login_required
def registration_requests():
    """
    Display pending registration requests.
    """

    require_admin()

    requests_list = (
        User.query
        .filter_by(account_status="pending")
        .order_by(User.created_at.asc())
        .all()
    )

    return render_template(
        "admin_requests.html",
        requests=requests_list,
        current_user=current_user,
    )


# ============================================================
# Approve Registration Request
# ============================================================

@admin_bp.route(
    "/requests/<int:user_id>/approve",
    methods=["POST"],
)
@login_required
def approve_request(user_id):
    """
    Approve a pending registration request and assign
    the final application role.
    """

    require_admin()

    user = db.session.get(User, user_id)

    if user is None:
        abort(404)

    if user.account_status != "pending":
        flash(
            "This registration request is no longer pending.",
            "warning",
        )

        return redirect(
            url_for("admin.registration_requests")
        )

    selected_role = (
        request.form.get("role", "")
        .strip()
        .lower()
    )

    if selected_role not in PUBLIC_REQUESTED_ROLES:
        flash(
            "Invalid account role.",
            "danger",
        )

        return redirect(
            url_for("admin.registration_requests")
        )

    try:
        user.role = selected_role
        user.account_status = "approved"
        user.is_active = True

        user.approved_at = utc_now()
        user.approved_by_id = current_user.id

        user.failed_login_attempts = 0
        user.locked_until = None

        log_security_event(
            action="ADMIN_APPROVE_REGISTRATION",
            result="SUCCESS",
            user=current_user,
            details=(
                f"Approved user id={user.id}, "
                f"username='{user.username}', "
                f"role='{selected_role}'."
            ),
        )

        db.session.commit()

        flash(
            "Registration request approved successfully.",
            "success",
        )

    except Exception:
        db.session.rollback()

        try:
            log_security_event(
                action="ADMIN_APPROVE_REGISTRATION",
                result="FAILED",
                user=current_user,
                details=(
                    f"Failed to approve user id={user_id}."
                ),
            )

            db.session.commit()

        except Exception:
            db.session.rollback()

        flash(
            "Unable to approve this registration request.",
            "danger",
        )

    return redirect(
        url_for("admin.registration_requests")
    )


# ============================================================
# Reject Registration Request
# ============================================================

@admin_bp.route(
    "/requests/<int:user_id>/reject",
    methods=["POST"],
)
@login_required
def reject_request(user_id):
    """
    Reject a pending registration request.
    """

    require_admin()

    user = db.session.get(User, user_id)

    if user is None:
        abort(404)

    if user.account_status != "pending":
        flash(
            "This registration request is no longer pending.",
            "warning",
        )

        return redirect(
            url_for("admin.registration_requests")
        )

    try:
        user.account_status = "rejected"
        user.is_active = False

        log_security_event(
            action="ADMIN_REJECT_REGISTRATION",
            result="SUCCESS",
            user=current_user,
            details=(
                f"Rejected user id={user.id}, "
                f"username='{user.username}'."
            ),
        )

        db.session.commit()

        flash(
            "Registration request rejected.",
            "success",
        )

    except Exception:
        db.session.rollback()

        try:
            log_security_event(
                action="ADMIN_REJECT_REGISTRATION",
                result="FAILED",
                user=current_user,
                details=(
                    f"Failed to reject user id={user_id}."
                ),
            )

            db.session.commit()

        except Exception:
            db.session.rollback()

        flash(
            "Unable to reject this registration request.",
            "danger",
        )

    return redirect(
        url_for("admin.registration_requests")
    )


# ============================================================
# Create User
# ============================================================

@admin_bp.route(
    "/users/create",
    methods=["GET", "POST"],
)
@login_required
def create_user():
    """
    Allow an administrator to create an already-approved account.
    """

    require_admin()

    if request.method == "GET":
        return render_template(
            "admin_user_edit.html",
            user=None,
            current_user=current_user,
        )

    username = (
        request.form.get("username", "")
        .strip()
        .lower()
    )

    password = request.form.get(
        "password",
        "",
    )

    confirm_password = request.form.get(
        "confirm_password",
        "",
    )

    role = (
        request.form.get("role", "")
        .strip()
        .lower()
    )

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    if not 3 <= len(username) <= 30:
        flash(
            "Username must be between 3 and 30 characters.",
            "danger",
        )

        return redirect(
            url_for("admin.create_user")
        )

    if any(ord(char) < 32 for char in username):
        flash(
            "Invalid username.",
            "danger",
        )

        return redirect(
            url_for("admin.create_user")
        )

    if not 8 <= len(password) <= 128:
        flash(
            "Password must contain between 8 and 128 characters.",
            "danger",
        )

        return redirect(
            url_for("admin.create_user")
        )

    if any(ord(char) < 32 for char in password):
        flash(
            "Invalid password.",
            "danger",
        )

        return redirect(
            url_for("admin.create_user")
        )

    if password != confirm_password:
        flash(
            "Passwords do not match.",
            "danger",
        )

        return redirect(
            url_for("admin.create_user")
        )

    if role not in ALLOWED_ROLES:
        flash(
            "Invalid account role.",
            "danger",
        )

        return redirect(
            url_for("admin.create_user")
        )

    existing_user = User.query.filter_by(
        username=username
    ).first()

    if existing_user:
        flash(
            "Username is already in use.",
            "danger",
        )

        return redirect(
            url_for("admin.create_user")
        )

    # --------------------------------------------------------
    # Create Account
    # --------------------------------------------------------

    try:
        password_hash = argon2.generate_password_hash(
            password
        )

        user = User(
            username=username,
            password_hash=password_hash,
            role=role,
            requested_role=role,
            account_status="approved",
            is_active=True,
            failed_login_attempts=0,
            locked_until=None,
            approved_at=utc_now(),
            approved_by_id=current_user.id,
        )

        db.session.add(user)

        log_security_event(
            action="ADMIN_CREATE_USER",
            result="SUCCESS",
            user=current_user,
            details=(
                f"Created user username='{username}', "
                f"role='{role}'."
            ),
        )

        db.session.commit()

        flash(
            "User created successfully.",
            "success",
        )

    except IntegrityError:
        db.session.rollback()

        flash(
            "Unable to create this user.",
            "danger",
        )

    except Exception:
        db.session.rollback()

        flash(
            "An error occurred while creating the user.",
            "danger",
        )

    return redirect(
        url_for("admin.users")
    )


# ============================================================
# Edit User
# ============================================================

@admin_bp.route(
    "/users/<int:user_id>/edit",
    methods=["GET", "POST"],
)
@login_required
def edit_user(user_id):
    """
    Update an existing user account.
    """

    require_admin()

    user = db.session.get(User, user_id)

    if user is None:
        abort(404)

    if request.method == "GET":
        return render_template(
            "admin_user_edit.html",
            user=user,
            current_user=current_user,
        )

    username = (
        request.form.get("username", "")
        .strip()
        .lower()
    )

    role = (
        request.form.get("role", "")
        .strip()
        .lower()
    )

    password = request.form.get(
        "password",
        "",
    )

    confirm_password = request.form.get(
        "confirm_password",
        "",
    )

    is_active = (
        request.form.get("is_active") == "1"
    )

    # --------------------------------------------------------
    # Prevent Self Lockout
    # --------------------------------------------------------

    if user.id == current_user.id:

        if role != "admin":
            flash(
                "You cannot remove your own admin role.",
                "danger",
            )

            return redirect(
                url_for(
                    "admin.edit_user",
                    user_id=user.id,
                )
            )

        if not is_active:
            flash(
                "You cannot deactivate your own account.",
                "danger",
            )

            return redirect(
                url_for(
                    "admin.edit_user",
                    user_id=user.id,
                )
            )

    # --------------------------------------------------------
    # Validate Username
    # --------------------------------------------------------

    if not 3 <= len(username) <= 30:
        flash(
            "Username must be between 3 and 30 characters.",
            "danger",
        )

        return redirect(
            url_for(
                "admin.edit_user",
                user_id=user.id,
            )
        )

    if any(ord(char) < 32 for char in username):
        flash(
            "Invalid username.",
            "danger",
        )

        return redirect(
            url_for(
                "admin.edit_user",
                user_id=user.id,
            )
        )

    # --------------------------------------------------------
    # Validate Role
    # --------------------------------------------------------

    if role not in ALLOWED_ROLES:
        flash(
            "Invalid account role.",
            "danger",
        )

        return redirect(
            url_for(
                "admin.edit_user",
                user_id=user.id,
            )
        )

    # --------------------------------------------------------
    # Unique Username
    # --------------------------------------------------------

    duplicate_user = (
        User.query
        .filter(
            User.username == username,
            User.id != user.id,
        )
        .first()
    )

    if duplicate_user:
        flash(
            "Username is already in use.",
            "danger",
        )

        return redirect(
            url_for(
                "admin.edit_user",
                user_id=user.id,
            )
        )

    # --------------------------------------------------------
    # Optional Password
    # --------------------------------------------------------

    if password or confirm_password:

        if not 8 <= len(password) <= 128:
            flash(
                "Password must contain between 8 and 128 characters.",
                "danger",
            )

            return redirect(
                url_for(
                    "admin.edit_user",
                    user_id=user.id,
                )
            )

        if any(ord(char) < 32 for char in password):
            flash(
                "Invalid password.",
                "danger",
            )

            return redirect(
                url_for(
                    "admin.edit_user",
                    user_id=user.id,
                )
            )

        if password != confirm_password:
            flash(
                "Passwords do not match.",
                "danger",
            )

            return redirect(
                url_for(
                    "admin.edit_user",
                    user_id=user.id,
                )
            )

    # --------------------------------------------------------
    # Protect Last Active Administrator
    # --------------------------------------------------------

    if (
        user.role == "admin"
        and user.is_active
        and (
            role != "admin"
            or not is_active
        )
    ):
        active_admin_count = (
            User.query
            .filter_by(
                role="admin",
                account_status="approved",
                is_active=True,
            )
            .count()
        )

        if active_admin_count <= 1:
            flash(
                "The last active administrator cannot be removed or deactivated.",
                "danger",
            )

            return redirect(
                url_for(
                    "admin.edit_user",
                    user_id=user.id,
                )
            )

    # --------------------------------------------------------
    # Update User
    # --------------------------------------------------------

    try:
        old_role = user.role
        old_status = user.account_status
        old_active = user.is_active

        user.username = username
        user.role = role
        user.is_active = is_active
        user.requested_role = role

        if is_active:
            user.account_status = "approved"

        else:
            user.account_status = "suspended"

        if password:
            user.password_hash = (
                argon2.generate_password_hash(
                    password
                )
            )

            user.failed_login_attempts = 0
            user.locked_until = None

        log_security_event(
            action="ADMIN_UPDATE_USER",
            result="SUCCESS",
            user=current_user,
            details=(
                f"Updated user id={user.id}; "
                f"username='{user.username}'; "
                f"role '{old_role}' -> '{user.role}'; "
                f"status '{old_status}' -> "
                f"'{user.account_status}'; "
                f"active {old_active} -> {user.is_active}."
            ),
        )

        db.session.commit()

        flash(
            "User updated successfully.",
            "success",
        )

    except IntegrityError:
        db.session.rollback()

        flash(
            "Unable to update this user.",
            "danger",
        )

    except Exception:
        db.session.rollback()

        flash(
            "An error occurred while updating the user.",
            "danger",
        )

    return redirect(
        url_for("admin.users")
    )


# ============================================================
# Suspend / Activate User
# ============================================================

@admin_bp.route(
    "/users/<int:user_id>/toggle",
    methods=["POST"],
)
@login_required
def toggle_user(user_id):
    """
    Suspend or activate a user.
    """

    require_admin()

    user = db.session.get(User, user_id)

    if user is None:
        abort(404)

    if user.id == current_user.id:
        flash(
            "You cannot change your own account status.",
            "danger",
        )

        return redirect(
            url_for("admin.users")
        )

    # --------------------------------------------------------
    # Protect Last Active Administrator
    # --------------------------------------------------------

    if (
        user.role == "admin"
        and user.account_status == "approved"
        and user.is_active
    ):
        active_admin_count = (
            User.query
            .filter_by(
                role="admin",
                account_status="approved",
                is_active=True,
            )
            .count()
        )

        if active_admin_count <= 1:
            flash(
                "The last active administrator cannot be suspended.",
                "danger",
            )

            return redirect(
                url_for("admin.users")
            )

    try:

        if (
            user.account_status == "suspended"
            or not user.is_active
        ):
            user.account_status = "approved"
            user.is_active = True

            action = "ADMIN_ACTIVATE_USER"

        else:
            user.account_status = "suspended"
            user.is_active = False

            action = "ADMIN_SUSPEND_USER"

        log_security_event(
            action=action,
            result="SUCCESS",
            user=current_user,
            details=(
                f"Changed account status for user "
                f"id={user.id}, "
                f"username='{user.username}', "
                f"status='{user.account_status}'."
            ),
        )

        db.session.commit()

        flash(
            "Account status updated.",
            "success",
        )

    except Exception:
        db.session.rollback()

        flash(
            "Unable to update the account status.",
            "danger",
        )

    return redirect(
        url_for("admin.users")
    )


# ============================================================
# Unlock User
# ============================================================

@admin_bp.route(
    "/users/<int:user_id>/unlock",
    methods=["POST"],
)
@login_required
def unlock_user(user_id):
    """
    Clear login lockout state.
    """

    require_admin()

    user = db.session.get(User, user_id)

    if user is None:
        abort(404)

    try:
        user.failed_login_attempts = 0
        user.locked_until = None

        log_security_event(
            action="ADMIN_UNLOCK_USER",
            result="SUCCESS",
            user=current_user,
            details=(
                f"Unlocked user id={user.id}, "
                f"username='{user.username}'."
            ),
        )

        db.session.commit()

        flash(
            "User account unlocked.",
            "success",
        )

    except Exception:
        db.session.rollback()

        flash(
            "Unable to unlock the user.",
            "danger",
        )

    return redirect(
        url_for("admin.users")
    )


# ============================================================
# Delete User
# ============================================================

@admin_bp.route(
    "/users/<int:user_id>/delete",
    methods=["POST"],
)
@login_required
def delete_user(user_id):
    """
    Delete a user account.

    The current administrator cannot delete their own account.
    The last active administrator cannot be deleted.
    """

    require_admin()

    user = db.session.get(User, user_id)

    if user is None:
        abort(404)

    if user.id == current_user.id:
        flash(
            "You cannot delete your own account.",
            "danger",
        )

        return redirect(
            url_for("admin.users")
        )

    # --------------------------------------------------------
    # Protect Last Active Administrator
    # --------------------------------------------------------

    if (
        user.role == "admin"
        and user.account_status == "approved"
        and user.is_active
    ):
        active_admin_count = (
            User.query
            .filter_by(
                role="admin",
                account_status="approved",
                is_active=True,
            )
            .count()
        )

        if active_admin_count <= 1:
            flash(
                "The last active administrator cannot be deleted.",
                "danger",
            )

            return redirect(
                url_for("admin.users")
            )

    username = user.username

    try:
        db.session.delete(user)

        log_security_event(
            action="ADMIN_DELETE_USER",
            result="SUCCESS",
            user=current_user,
            details=(
                f"Deleted user id={user.id}, "
                f"username='{username}'."
            ),
        )

        db.session.commit()

        flash(
            "User deleted successfully.",
            "success",
        )

    except IntegrityError:
        db.session.rollback()

        flash(
            "This user cannot be deleted because related records exist.",
            "danger",
        )

    except Exception:
        db.session.rollback()

        flash(
            "Unable to delete the user.",
            "danger",
        )

    return redirect(
        url_for("admin.users")
    )
