import hashlib
import os
import secrets

import bleach

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required

from app.audit.audit_logger import log_security_event
from app.extensions import db, limiter
from app.models import Evidence


evidence_bp = Blueprint(
    "evidence",
    __name__,
)


# ============================================================
# Helper Functions
# ============================================================

def _allowed_file(filename):
    """
    Validate the file extension on the server.

    The filename itself is never used as the storage filename.
    """

    if not filename or "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()

    return extension in current_app.config[
        "ALLOWED_EVIDENCE_EXTENSIONS"
    ]


def _safe_original_filename(filename):
    """
    Store only a clean display filename.

    The original user-controlled filename is never used to build
    a filesystem path.
    """

    filename = os.path.basename(filename or "")

    # Remove control characters.
    filename = "".join(
        character
        for character in filename
        if ord(character) >= 32
    )

    filename = filename.strip()

    if not filename:
        return "evidence"

    return filename[:255]


def _safe_note(value):
    """
    Sanitize evidence notes before storing them.

    Jinja autoescaping remains the primary XSS defense when
    rendering notes in templates.
    """

    if not value:
        return ""

    value = value[:current_app.config["MAX_EVIDENCE_NOTE_LENGTH"]]

    return bleach.clean(
        value,
        tags=[],
        attributes={},
        strip=True,
    )


def _owns_evidence(evidence):
    """
    Verify that the currently authenticated investigator owns
    the evidence.

    A01: Broken Access Control / IDOR
    """

    return evidence.uploaded_by_id == current_user.id


def _get_evidence_or_404(evidence_id):
    """
    Retrieve an evidence record by numeric ID.

    Invalid/nonexistent IDs are treated as not found.
    """

    if not isinstance(evidence_id, int) or evidence_id <= 0:
        abort(404)

    evidence = db.session.get(
        Evidence,
        evidence_id,
    )

    if evidence is None:
        abort(404)

    return evidence


def _investigator_only():
    """
    Server-side RBAC check.

    The role shown in HTML is never trusted for authorization.
    """

    if current_user.role != "investigator":
        log_security_event(
            action="ACCESS_DENIED",
            result="DENIED",
            user=current_user,
            details="Investigator-only evidence operation.",
        )
        db.session.commit()
        abort(403)


def _officer_or_investigator(evidence):
    """
    Authorization for viewing/verifying evidence.

    Investigator:
        Can access owned evidence.

    Officer:
        Can access all evidence.
    """

    if current_user.role == "officer":
        return

    if current_user.role == "investigator":
        if _owns_evidence(evidence):
            return

        log_security_event(
            action="ACCESS_DENIED",
            result="DENIED",
            user=current_user,
            evidence_id=evidence.id,
            details="Attempt to access evidence owned by another investigator.",
        )
        db.session.commit()
        abort(403)

    log_security_event(
        action="ACCESS_DENIED",
        result="DENIED",
        user=current_user,
        evidence_id=evidence.id,
        details="Role is not authorized to access evidence.",
    )
    db.session.commit()

    abort(403)


def _generate_storage_name(extension):
    """
    Generate an unpredictable server-side storage filename.

    User-controlled filenames are never used as storage names.
    """

    return f"{secrets.token_hex(32)}.{extension}"


def _storage_path(filename):
    """
    Resolve a storage filename under the configured evidence directory.

    Path Traversal protection:
    - only the generated server-side filename is accepted
    - the resulting path must remain inside the configured directory
    """

    storage_dir = os.path.realpath(
        current_app.config["ENCRYPTED_STORAGE_DIR"]
    )

    candidate = os.path.realpath(
        os.path.join(
            storage_dir,
            filename,
        )
    )

    if not (
        candidate == storage_dir
        or candidate.startswith(storage_dir + os.sep)
    ):
        abort(400)

    return candidate


def _calculate_sha256(file_bytes):
    """
    Calculate SHA-256 of the original evidence bytes.

    A08: Software and Data Integrity Failures
    """

    return hashlib.sha256(file_bytes).hexdigest()


# ============================================================
# CREATE
# ============================================================

@evidence_bp.route(
    "/evidence/upload",
    methods=["GET", "POST"],
)
@login_required
@limiter.limit(
    "10 per hour",
    methods=["POST"],
)
def upload():
    """
    Create a new digital evidence record.

    Investigator only.

    Security controls:
    - A01: RBAC
    - A02: Encryption
    - A03: Input validation / sanitization
    - A04: Secure upload design
    - A08: SHA-256 + digital signature
    - A09: Security auditing
    """

    _investigator_only()

    if request.method == "GET":
        return render_template("upload.html")

    uploaded_file = request.files.get("file")

    note = _safe_note(
        request.form.get("note", "")
    )

    if uploaded_file is None:
        flash(
            "Please select an evidence file.",
            "danger",
        )
        return redirect(
            url_for("evidence.upload")
        )

    original_filename = _safe_original_filename(
        uploaded_file.filename
    )

    if not _allowed_file(original_filename):
        flash(
            "This file type is not allowed.",
            "danger",
        )
        return redirect(
            url_for("evidence.upload")
        )

    file_bytes = uploaded_file.read()

    if not file_bytes:
        flash(
            "The uploaded file is empty.",
            "danger",
        )
        return redirect(
            url_for("evidence.upload")
        )

    max_size = current_app.config["MAX_CONTENT_LENGTH"]

    if len(file_bytes) > max_size:
        flash(
            "The uploaded file is too large.",
            "danger",
        )
        return redirect(
            url_for("evidence.upload")
        )

    extension = original_filename.rsplit(
        ".",
        1,
    )[1].lower()

    stored_filename = _generate_storage_name(
        extension
    )

    encrypted_path = _storage_path(
        stored_filename
    )

    try:
        from app.security.crypto_utils import (
            encrypt_evidence,
            sign_hash,
        )

        sha256_hash = _calculate_sha256(
            file_bytes
        )

        signature = sign_hash(
            sha256_hash
        )

        encrypted_data, nonce = encrypt_evidence(
            file_bytes
        )

        with open(
            encrypted_path,
            "wb",
        ) as encrypted_file:
            encrypted_file.write(
                encrypted_data
            )

        evidence = Evidence(
            uploaded_by_id=current_user.id,
            original_filename=original_filename,
            stored_filename=stored_filename,
            mime_type=(
                uploaded_file.mimetype
                or "application/octet-stream"
            ),
            file_size=len(file_bytes),
            note=note,
            encrypted_path=encrypted_path,
            encryption_nonce=nonce,
            sha256_hash=sha256_hash,
            signature=signature,
            verification_status="valid",
        )

        db.session.add(evidence)

        # Get the database ID before creating the audit entry.
        db.session.flush()

        log_security_event(
            action="UPLOAD",
            result="SUCCESS",
            user=current_user,
            evidence_id=evidence.id,
            details=(
                f"Evidence uploaded: {original_filename}"
            ),
        )

        db.session.commit()

        flash(
            "Evidence uploaded successfully.",
            "success",
        )

        return redirect(
            url_for("evidence.my_evidence")
        )

    except Exception:
        db.session.rollback()

        try:
            if os.path.exists(encrypted_path):
                os.remove(encrypted_path)
        except OSError:
            current_app.logger.exception(
                "Unable to remove orphaned encrypted evidence file."
            )

        current_app.logger.exception(
            "Evidence upload failed."
        )

        flash(
            "Unable to process the evidence.",
            "danger",
        )

        return redirect(
            url_for("evidence.upload")
        )


# ============================================================
# READ - MY EVIDENCE
# ============================================================

@evidence_bp.route(
    "/evidence/my",
    methods=["GET"],
)
@login_required
def my_evidence():
    """
    Display evidence owned by the current investigator.

    A01: Ownership enforced server-side.
    """

    _investigator_only()

    evidence_items = db.session.scalars(
        db.select(Evidence)
        .where(
            Evidence.uploaded_by_id == current_user.id
        )
        .order_by(
            Evidence.created_at.desc()
        )
    ).all()

    return render_template(
        "my_evidence.html",
        evidence_items=evidence_items,
    )


# ============================================================
# READ - ALL EVIDENCE
# ============================================================

@evidence_bp.route(
    "/evidence/all",
    methods=["GET"],
)
@login_required
def all_evidence():
    """
    Display all evidence for authorized officers.

    Investigators cannot use this endpoint to bypass ownership.
    """

    if current_user.role != "officer":
        log_security_event(
            action="ACCESS_DENIED",
            result="DENIED",
            user=current_user,
            details="Unauthorized attempt to access all evidence.",
        )
        db.session.commit()
        abort(403)

    evidence_items = db.session.scalars(
        db.select(Evidence)
        .order_by(
            Evidence.created_at.desc()
        )
    ).all()

    return render_template(
        "all_evidence.html",
        evidence_items=evidence_items,
    )


# ============================================================
# READ - SINGLE EVIDENCE
# ============================================================

@evidence_bp.route(
    "/evidence/<int:evidence_id>",
    methods=["GET"],
)
@login_required
def view_evidence(evidence_id):
    """
    View evidence metadata.

    Investigator:
        Own evidence only.

    Officer:
        Can view all evidence.

    Auditor:
        Uses the audit interface.
    """

    evidence = _get_evidence_or_404(
        evidence_id
    )

    _officer_or_investigator(
        evidence
    )

    log_security_event(
        action="VIEW",
        result="SUCCESS",
        user=current_user,
        evidence_id=evidence.id,
        details="Evidence metadata viewed.",
    )

    db.session.commit()

    return render_template(
        "evidence_view.html",
        evidence=evidence,
    )


# ============================================================
# READ - DOWNLOAD / DECRYPT
# ============================================================

@evidence_bp.route(
    "/evidence/<int:evidence_id>/download",
    methods=["GET"],
)
@login_required
def download_evidence(evidence_id):
    """
    Decrypt and send evidence to an authorized user.

    The encrypted file is never exposed directly through a
    public static directory.

    A01: Access Control
    A02: Cryptographic Failures
    A08: Integrity
    """

    evidence = _get_evidence_or_404(
        evidence_id
    )

    _officer_or_investigator(
        evidence
    )

    encrypted_path = _storage_path(
        evidence.stored_filename
    )

    if encrypted_path != os.path.realpath(
        evidence.encrypted_path
    ):
        log_security_event(
            action="DOWNLOAD",
            result="DENIED",
            user=current_user,
            evidence_id=evidence.id,
            details="Evidence storage path validation failed.",
        )
        db.session.commit()
        abort(403)

    if not os.path.isfile(encrypted_path):
        log_security_event(
            action="DOWNLOAD",
            result="FILE_MISSING",
            user=current_user,
            evidence_id=evidence.id,
            details="Encrypted evidence file is missing.",
        )
        db.session.commit()
        abort(404)

    try:
        from app.security.crypto_utils import (
            decrypt_evidence,
            verify_signature,
        )

        with open(
            encrypted_path,
            "rb",
        ) as encrypted_file:
            encrypted_data = encrypted_file.read()

        original_bytes = decrypt_evidence(
            encrypted_data,
            evidence.encryption_nonce,
        )

        current_hash = _calculate_sha256(
            original_bytes
        )

        if current_hash != evidence.sha256_hash:
            evidence.verification_status = "tampered"

            log_security_event(
                action="DOWNLOAD",
                result="TAMPERED",
                user=current_user,
                evidence_id=evidence.id,
                details="SHA-256 integrity verification failed.",
            )

            db.session.commit()

            abort(409)

        if not verify_signature(
            current_hash,
            evidence.signature,
        ):
            evidence.verification_status = "tampered"

            log_security_event(
                action="DOWNLOAD",
                result="TAMPERED",
                user=current_user,
                evidence_id=evidence.id,
                details="Digital signature verification failed.",
            )

            db.session.commit()

            abort(409)

        evidence.verification_status = "valid"

        log_security_event(
            action="DOWNLOAD",
            result="SUCCESS",
            user=current_user,
            evidence_id=evidence.id,
            details="Evidence decrypted and downloaded.",
        )

        db.session.commit()

        from io import BytesIO

        return send_file(
            BytesIO(original_bytes),
            mimetype=evidence.mime_type,
            as_attachment=True,
            download_name=evidence.original_filename,
        )

    except Exception:
        db.session.rollback()

        current_app.logger.exception(
            "Evidence download/decryption failed."
        )

        log_security_event(
            action="DOWNLOAD",
            result="ERROR",
            user=current_user,
            evidence_id=evidence.id,
            details="Evidence download/decryption operation failed.",
        )

        db.session.commit()

        abort(500)


# ============================================================
# UPDATE
# ============================================================

@evidence_bp.route(
    "/evidence/<int:evidence_id>/update",
    methods=["GET", "POST"],
)
@login_required
def update_evidence(evidence_id):
    """
    Update evidence metadata only.

    The original evidence bytes, SHA-256 hash, and digital
    signature are immutable after creation.

    A01: Ownership / RBAC
    A03: Input sanitization
    A08: Evidence integrity
    """

    _investigator_only()

    evidence = _get_evidence_or_404(
        evidence_id
    )

    if not _owns_evidence(evidence):
        log_security_event(
            action="ACCESS_DENIED",
            result="DENIED",
            user=current_user,
            evidence_id=evidence.id,
            details="Attempt to update evidence owned by another investigator.",
        )
        db.session.commit()
        abort(403)

    if request.method == "GET":
        return render_template(
            "evidence_view.html",
            evidence=evidence,
            edit_mode=True,
        )

    note = _safe_note(
        request.form.get("note", "")
    )

    evidence.note = note

    try:
        log_security_event(
            action="UPDATE",
            result="SUCCESS",
            user=current_user,
            evidence_id=evidence.id,
            details="Evidence metadata updated.",
        )

        db.session.commit()

        flash(
            "Evidence metadata updated successfully.",
            "success",
        )

    except Exception:
        db.session.rollback()

        current_app.logger.exception(
            "Evidence update failed."
        )

        flash(
            "Unable to update the evidence.",
            "danger",
        )

    return redirect(
        url_for(
            "evidence.view_evidence",
            evidence_id=evidence.id,
        )
    )


# ============================================================
# DELETE
# ============================================================

@evidence_bp.route(
    "/evidence/<int:evidence_id>/delete",
    methods=["POST"],
)
@login_required
def delete_evidence(evidence_id):
    """
    Delete evidence.

    Only the owning investigator can delete evidence.

    POST is required because deletion changes server state.

    Flask-WTF CSRF protection applies to this request.
    """

    _investigator_only()

    evidence = _get_evidence_or_404(
        evidence_id
    )

    if not _owns_evidence(evidence):
        log_security_event(
            action="ACCESS_DENIED",
            result="DENIED",
            user=current_user,
            evidence_id=evidence.id,
            details="Attempt to delete evidence owned by another investigator.",
        )
        db.session.commit()
        abort(403)

    encrypted_path = _storage_path(
        evidence.stored_filename
    )

    if encrypted_path != os.path.realpath(
        evidence.encrypted_path
    ):
        log_security_event(
            action="DELETE",
            result="DENIED",
            user=current_user,
            evidence_id=evidence.id,
            details="Evidence storage path validation failed.",
        )
        db.session.commit()
        abort(403)

    evidence_id_value = evidence.id

    try:
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)

        log_security_event(
            action="DELETE",
            result="SUCCESS",
            user=current_user,
            evidence_id=evidence_id_value,
            details="Evidence deleted.",
        )

        db.session.delete(evidence)
        db.session.commit()

        flash(
            "Evidence deleted successfully.",
            "success",
        )

    except Exception:
        db.session.rollback()

        current_app.logger.exception(
            "Evidence deletion failed."
        )

        flash(
            "Unable to delete the evidence.",
            "danger",
        )

    return redirect(
        url_for("evidence.my_evidence")
    )


# ============================================================
# VERIFY
# ============================================================

@evidence_bp.route(
    "/evidence/<int:evidence_id>/verify",
    methods=["GET", "POST"],
)
@login_required
def verify_evidence(evidence_id):
    """
    Verify evidence integrity.

    Investigator:
        Own evidence.

    Officer:
        Any evidence.

    Verification:
        Decrypt -> SHA-256 -> RSA signature verification.
    """

    evidence = _get_evidence_or_404(
        evidence_id
    )

    _officer_or_investigator(
        evidence
    )

    if request.method == "GET":
        return render_template(
            "verify_evidence.html",
            evidence=evidence,
        )

    encrypted_path = _storage_path(
        evidence.stored_filename
    )

    if encrypted_path != os.path.realpath(
        evidence.encrypted_path
    ):
        log_security_event(
            action="VERIFY",
            result="DENIED",
            user=current_user,
            evidence_id=evidence.id,
            details="Evidence storage path validation failed.",
        )
        db.session.commit()
        abort(403)

    if not os.path.isfile(encrypted_path):
        evidence.verification_status = "missing"

        log_security_event(
            action="VERIFY",
            result="FILE_MISSING",
            user=current_user,
            evidence_id=evidence.id,
            details="Encrypted evidence file is missing.",
        )

        db.session.commit()

        return render_template(
            "verify_evidence.html",
            evidence=evidence,
            verification_result={
                "valid": False,
                "status": "missing",
                "message": "Encrypted evidence file is missing.",
            },
        )

    try:
        from app.security.crypto_utils import (
            decrypt_evidence,
            verify_signature,
        )

        with open(
            encrypted_path,
            "rb",
        ) as encrypted_file:
            encrypted_data = encrypted_file.read()

        original_bytes = decrypt_evidence(
            encrypted_data,
            evidence.encryption_nonce,
        )

        calculated_hash = _calculate_sha256(
            original_bytes
        )

        hash_valid = (
            calculated_hash == evidence.sha256_hash
        )

        signature_valid = False

        if hash_valid:
            signature_valid = verify_signature(
                calculated_hash,
                evidence.signature,
            )

        verification_valid = (
            hash_valid and signature_valid
        )

        evidence.verification_status = (
            "valid"
            if verification_valid
            else "tampered"
        )

        log_security_event(
            action="VERIFY",
            result=(
                "VERIFIED"
                if verification_valid
                else "TAMPERED"
            ),
            user=current_user,
            evidence_id=evidence.id,
            details=(
                "Evidence integrity and signature verification completed."
            ),
        )

        db.session.commit()

        return render_template(
            "verify_evidence.html",
            evidence=evidence,
            verification_result={
                "valid": verification_valid,
                "status": evidence.verification_status,
                "hash_valid": hash_valid,
                "signature_valid": signature_valid,
                "calculated_hash": calculated_hash,
            },
        )

    except Exception:
        db.session.rollback()

        current_app.logger.exception(
            "Evidence verification failed."
        )

        try:
            log_security_event(
                action="VERIFY",
                result="ERROR",
                user=current_user,
                evidence_id=evidence.id,
                details="Evidence verification operation failed.",
            )
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception(
                "Unable to write evidence verification audit event."
            )

        return render_template(
            "verify_evidence.html",
            evidence=evidence,
            verification_result={
                "valid": False,
                "status": "error",
                "message": "Unable to verify the evidence.",
            },
        ), 500
