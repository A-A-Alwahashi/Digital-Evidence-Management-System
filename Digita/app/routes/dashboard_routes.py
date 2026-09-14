from flask import Blueprint, abort, redirect, render_template, url_for
from flask_login import current_user, login_required


dashboard_bp = Blueprint(
    "dashboard",
    __name__,
)


# ============================================================
# Root
# ============================================================

@dashboard_bp.route("/", methods=["GET"])
def home():
    """
    Redirect the root URL to the login page.
    """

    return redirect(
        url_for("auth.login")
    )


# ============================================================
# Main Dashboard
# ============================================================

@dashboard_bp.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    """
    Main dashboard for authenticated users.
    """

    return render_template(
        "dashboard.html",
        current_user=current_user,
    )


# ============================================================
# Investigator Dashboard
# ============================================================

@dashboard_bp.route(
    "/dashboard/investigator",
    methods=["GET"],
)
@login_required
def investigator_dashboard():
    """
    Investigator-only dashboard.
    """

    if current_user.role != "investigator":
        abort(403)

    return render_template(
        "dashboard.html",
        current_user=current_user,
    )


# ============================================================
# Officer Dashboard
# ============================================================

@dashboard_bp.route(
    "/dashboard/officer",
    methods=["GET"],
)
@login_required
def officer_dashboard():
    """
    Officer-only dashboard.
    """

    if current_user.role != "officer":
        abort(403)

    return render_template(
        "dashboard.html",
        current_user=current_user,
    )


# ============================================================
# Auditor Dashboard
# ============================================================

@dashboard_bp.route(
    "/dashboard/auditor",
    methods=["GET"],
)
@login_required
def auditor_dashboard():
    """
    Auditor-only dashboard.
    """

    if current_user.role != "auditor":
        abort(403)

    return render_template(
        "dashboard.html",
        current_user=current_user,
    )


# ============================================================
# Admin Dashboard
# ============================================================

@dashboard_bp.route(
    "/dashboard/admin",
    methods=["GET"],
)
@login_required
def admin_dashboard():
    """
    Administrator-only dashboard.

    The admin dashboard provides access to:
    - Registration requests
    - User management
    - Account status management
    - Role management
    """

    if current_user.role != "admin":
        abort(403)

    return render_template(
        "dashboard.html",
        current_user=current_user,
    )
