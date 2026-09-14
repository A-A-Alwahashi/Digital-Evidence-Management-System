from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import safe_join

from app.extensions import db


def utc_now():
    """
    Return the current UTC time as a naive datetime.

    Naive UTC values are used consistently because SQLite commonly
    returns DateTime values without timezone information.
    """
    return datetime.utcnow()


class User(UserMixin, db.Model):
    """
    Application user.

    Roles:
    - admin
    - investigator
    - officer
    - auditor

    Account statuses:
    - pending
    - approved
    - rejected
    - suspended

    A new public registration starts with:
    - account_status = pending
    - is_active = False

    The requested role is stored separately from the final role.
    The administrator decides the final role before approval.

    Security areas:
    - A01: Broken Access Control
    - A04: Insecure Design
    - A07: Identification and Authentication Failures
    - A09: Security Logging and Monitoring Failures
    """

    __tablename__ = "users"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    username = db.Column(
        db.String(30),
        unique=True,
        nullable=False,
        index=True,
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False,
    )

    role = db.Column(
        db.String(20),
        nullable=False,
        default="investigator",
        index=True,
    )

    requested_role = db.Column(
        db.String(20),
        nullable=False,
        default="investigator",
        index=True,
    )

    account_status = db.Column(
        db.String(20),
        nullable=False,
        default="pending",
        index=True,
    )

    is_active = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
    )

    failed_login_attempts = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    locked_until = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
    )

    approved_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
    )

    approved_by_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    last_login_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
    )

    evidence_items = db.relationship(
        "Evidence",
        back_populates="uploaded_by",
        foreign_keys="Evidence.uploaded_by_id",
        lazy="select",
    )

    audit_logs = db.relationship(
        "AuditLog",
        back_populates="user",
        foreign_keys="AuditLog.user_id",
        lazy="select",
    )

    approved_by = db.relationship(
        "User",
        remote_side=[id],
        foreign_keys=[approved_by_id],
        backref=db.backref(
            "approved_users",
            lazy="select",
        ),
    )

    def get_id(self):
        """
        Flask-Login uses the database ID as the authenticated
        identity stored in the session.
        """
        return str(self.id)

    @property
    def is_admin(self):
        return self.role == "admin"

    @property
    def is_investigator(self):
        return self.role == "investigator"

    @property
    def is_officer(self):
        return self.role == "officer"

    @property
    def is_auditor(self):
        return self.role == "auditor"

    @property
    def is_pending(self):
        return self.account_status == "pending"

    @property
    def is_approved(self):
        return self.account_status == "approved"

    @property
    def is_rejected(self):
        return self.account_status == "rejected"

    @property
    def is_suspended(self):
        return self.account_status == "suspended"

    def is_locked(self):
        """
        Check the server-side account lockout state.
        """

        if not self.locked_until:
            return False

        locked_until = self.locked_until

        if locked_until.tzinfo is not None:
            locked_until = locked_until.astimezone(
                timezone.utc
            ).replace(
                tzinfo=None
            )

        return utc_now() < locked_until

    def clear_expired_lock(self):
        """
        Clear an expired account lockout.

        Normalizes timezone-aware values to UTC-naive datetime
        before comparison so SQLite values remain compatible.
        """

        if not self.locked_until:
            return

        locked_until = self.locked_until

        if locked_until.tzinfo is not None:
            locked_until = locked_until.astimezone(
                timezone.utc
            ).replace(
                tzinfo=None
            )

        if utc_now() >= locked_until:
            self.locked_until = None
            self.failed_login_attempts = 0


class Evidence(db.Model):
    """
    Digital evidence record.

    The original evidence bytes are stored encrypted on the server.
    Metadata can be updated, but the original evidence content should
    remain immutable after creation.

    Security areas:
    - A01: Broken Access Control
    - A02: Cryptographic Failures
    - A03: Injection
    - A04: Insecure Design
    - A08: Software and Data Integrity Failures
    """

    __tablename__ = "evidence"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    uploaded_by_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    uploaded_by = db.relationship(
        "User",
        back_populates="evidence_items",
        foreign_keys=[uploaded_by_id],
    )

    original_filename = db.Column(
        db.String(255),
        nullable=False,
    )

    stored_filename = db.Column(
        db.String(255),
        unique=True,
        nullable=False,
    )

    mime_type = db.Column(
        db.String(100),
        nullable=False,
    )

    file_size = db.Column(
        db.BigInteger,
        nullable=False,
    )

    note = db.Column(
        db.Text,
        nullable=True,
    )

    encrypted_path = db.Column(
        db.String(500),
        nullable=False,
    )

    encryption_nonce = db.Column(
        db.String(64),
        nullable=False,
    )

    sha256_hash = db.Column(
        db.String(64),
        nullable=False,
        index=True,
    )

    signature = db.Column(
        db.Text,
        nullable=False,
    )

    verification_status = db.Column(
        db.String(20),
        nullable=False,
        default="pending",
        index=True,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    def safe_storage_path(self, storage_directory):
        """
        Return a safe path confined to the configured storage directory.

        A01 / Path Traversal protection:
        the stored filename is resolved under the intended directory.
        """

        safe_path = safe_join(
            storage_directory,
            self.stored_filename,
        )

        if safe_path is None:
            raise ValueError("Invalid evidence storage path.")

        return safe_path


class AuditLog(db.Model):
    """
    Security audit trail.

    Audit records are append-oriented and should not be modified from
    ordinary user-facing CRUD operations.

    Security area:
    - A09: Security Logging and Monitoring Failures
    """

    __tablename__ = "audit_logs"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    evidence_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "evidence.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    action = db.Column(
        db.String(100),
        nullable=False,
        index=True,
    )

    result = db.Column(
        db.String(30),
        nullable=False,
        index=True,
    )

    ip_address = db.Column(
        db.String(45),
        nullable=True,
    )

    details = db.Column(
        db.Text,
        nullable=True,
    )

    timestamp = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        index=True,
    )

    user = db.relationship(
        "User",
        back_populates="audit_logs",
        foreign_keys=[user_id],
    )

    evidence = db.relationship(
        "Evidence",
        foreign_keys=[evidence_id],
    )
