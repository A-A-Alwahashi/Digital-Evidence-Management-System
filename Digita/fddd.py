from getpass import getpass

from app import create_app
from app.extensions import db, argon2
from app.models import User


app = create_app()


with app.app_context():
    username = input("Admin username: ").strip()
    password = getpass("Admin password: ")
    confirm = getpass("Confirm password: ")

    if not username:
        print("Error: username is required.")
        raise SystemExit(1)

    if password != confirm:
        print("Error: passwords do not match.")
        raise SystemExit(1)

    if len(password) < 8 or len(password) > 128:
        print("Error: password must be between 8 and 128 characters.")
        raise SystemExit(1)

    existing_user = db.session.scalar(
        db.select(User).where(User.username == username)
    )

    if existing_user:
        print(f"Error: user '{username}' already exists.")
        raise SystemExit(1)

    admin = User(
        username=username,
        password_hash=argon2.generate_password_hash(password),
        role="admin",
        requested_role="admin",
        account_status="approved",
        is_active=True,
        failed_login_attempts=0,
        locked_until=None,
        approved_at=None,
        approved_by_id=None,
    )

    db.session.add(admin)
    db.session.commit()

    print()
    print("================================")
    print("Admin account created successfully")
    print("Username:", username)
    print("Role: admin")
    print("Status: approved")
    print("================================")
