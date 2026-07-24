from __future__ import annotations

import base64
import hashlib
import re
import sqlite3
import uuid
from datetime import datetime, timedelta
from typing import Optional, Tuple
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet
from flask import current_app, g
from werkzeug.security import check_password_hash, generate_password_hash

BRUSSELS_TZ = ZoneInfo("Europe/Brussels")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    phone TEXT,
    address TEXT,
    date_of_birth TEXT,
    terms_accepted_at TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    email_verified INTEGER NOT NULL DEFAULT 0,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    account_locked_until TEXT,
    last_login TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL,
    role_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    iban TEXT NOT NULL UNIQUE,
    account_number TEXT NOT NULL UNIQUE,
    account_type TEXT NOT NULL,
    currency TEXT NOT NULL DEFAULT 'EUR',
    balance NUMERIC NOT NULL DEFAULT 0,
    daily_transfer_limit NUMERIC NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Frozen', 'Closed')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS credit_cards (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    encrypted_card_number TEXT NOT NULL,
    last_four_digits CHAR(4) NOT NULL,
    expiry_month INTEGER NOT NULL,
    expiry_year INTEGER NOT NULL,
    card_type TEXT NOT NULL,
    credit_limit NUMERIC NOT NULL DEFAULT 0,
    available_credit NUMERIC NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Blocked')),
    issued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE,
    UNIQUE (account_id)
);

CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    sender_account_id TEXT,
    receiver_account_id TEXT,
    amount NUMERIC NOT NULL,
    currency TEXT NOT NULL,
    transaction_type TEXT NOT NULL CHECK (transaction_type IN ('Transfer', 'Deposit', 'Withdrawal')),
    status TEXT NOT NULL CHECK (status IN ('Pending', 'Completed', 'Failed')),
    description TEXT,
    reference TEXT UNIQUE,
    fee NUMERIC NOT NULL DEFAULT 0,
    ip_address TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_account_id) REFERENCES accounts (id) ON DELETE SET NULL,
    FOREIGN KEY (receiver_account_id) REFERENCES accounts (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS beneficiaries (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    beneficiary_name TEXT NOT NULL,
    iban TEXT NOT NULL,
    nickname TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    notification_type TEXT NOT NULL CHECK (notification_type IN ('Security', 'Transaction')),
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS login_history (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    login_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    logout_time TEXT,
    ip_address TEXT,
    user_agent TEXT,
    success INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    description TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    source_ip TEXT,
    target_resource TEXT,
    description TEXT NOT NULL,
    detected_by TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('Open', 'Investigating', 'Closed')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts (user_id);
CREATE INDEX IF NOT EXISTS idx_transactions_sender_account_id ON transactions (sender_account_id);
CREATE INDEX IF NOT EXISTS idx_transactions_receiver_account_id ON transactions (receiver_account_id);
CREATE INDEX IF NOT EXISTS idx_beneficiaries_user_id ON beneficiaries (user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications (user_id);
CREATE INDEX IF NOT EXISTS idx_login_history_user_id ON login_history (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events (user_id);

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    otp TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        database_path = current_app.config["DATABASE"]
        connection = sqlite3.connect(database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        g.db = connection
    return g.db


def close_db(_exception: Optional[BaseException] = None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_app(app) -> None:
    app.teardown_appcontext(close_db)


def init_db() -> None:
    database = get_db()
    database.executescript(SCHEMA_SQL)
    _run_migrations(database)
    seed_reference_data(database)
    database.commit()


def _run_migrations(database: sqlite3.Connection) -> None:
    """Add columns introduced after a database file already existed.

    CREATE TABLE IF NOT EXISTS in SCHEMA_SQL only creates tables that are
    missing -- it never alters an existing table, so new columns need an
    explicit, idempotent ALTER TABLE here.
    """
    existing_columns = {row["name"] for row in database.execute("PRAGMA table_info(users)")}
    if "terms_accepted_at" not in existing_columns:
        database.execute("ALTER TABLE users ADD COLUMN terms_accepted_at TEXT")

    token_columns = {row["name"] for row in database.execute("PRAGMA table_info(email_verification_tokens)")}
    if "purpose" not in token_columns:
        # Existing rows predate purpose-scoping; 'login' is a harmless
        # default since they're already expired/used from earlier testing.
        database.execute("ALTER TABLE email_verification_tokens ADD COLUMN purpose TEXT NOT NULL DEFAULT 'login'")


def seed_reference_data(database: sqlite3.Connection) -> None:
    for role_name in ("Customer", "Admin", "Support", "Auditor"):
        database.execute(
            "INSERT OR IGNORE INTO roles (role_name) VALUES (?)",
            (role_name,),
        )


def _utc_now() -> str:
    return datetime.now(BRUSSELS_TZ).strftime("%Y-%m-%d %H:%M:%S")


def now_timestamp() -> str:
    """Public wrapper for callers (e.g. templates) comparing against
    account_locked_until without duplicating the timezone logic."""
    return _utc_now()


def _utc_in(minutes: int) -> str:
    return (datetime.now(BRUSSELS_TZ) + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")


def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=BRUSSELS_TZ)
    except ValueError:
        return None


def _generate_uuid() -> str:
    return str(uuid.uuid4())

# Validate email format
EMAIL_REGEX = re.compile(
    r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)

def valid_email(email: str) -> bool:
    return bool(EMAIL_REGEX.fullmatch(email.strip()))

COMMON_PASSWORDS = {
    "password123!",
    "Password123!",
    "qwerty123!",
}

def valid_password(password: str) -> bool:

    if password in COMMON_PASSWORDS:
        return False

    return (
        len(password) >= 12
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"\d", password)
        and re.search(r"[!@#$%^&*]", password)
    )


def valid_date_of_birth(date_of_birth: str) -> bool:
    try:
        dob = datetime.strptime(date_of_birth, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return False

    today = datetime.now(BRUSSELS_TZ).date()
    if dob > today:
        return False

    age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
    return age >= 18


def max_date_of_birth() -> str:
    """Latest date of birth that still makes someone 18 today, as YYYY-MM-DD."""
    today = datetime.now(BRUSSELS_TZ).date()
    try:
        return today.replace(year=today.year - 18).isoformat()
    except ValueError:
        # today is Feb 29 in a leap year and (year - 18) isn't a leap year.
        return today.replace(month=2, day=28, year=today.year - 18).isoformat()


def _generate_username(email: str, database: sqlite3.Connection) -> str:
    base = re.sub(r"[^a-z0-9._-]", "", email.split("@", 1)[0].strip().lower())
    if not base:
        base = "user"

    candidate = base
    suffix = 1
    while database.execute(
        "SELECT 1 FROM users WHERE username = ?",
        (candidate,),
    ).fetchone():
        candidate = f"{base}{suffix}"
        suffix += 1

    return candidate


def _generate_account_number(database: sqlite3.Connection) -> str:
    while True:
        candidate = f"{uuid.uuid4().int % 10**12:012d}"
        if not database.execute(
            "SELECT 1 FROM accounts WHERE account_number = ?",
            (candidate,),
        ).fetchone():
            return candidate


def _generate_iban(database: sqlite3.Connection) -> str:
    while True:
        candidate = f"BE{uuid.uuid4().int % 10**14:014d}"
        if not database.execute(
            "SELECT 1 FROM accounts WHERE iban = ?",
            (candidate,),
        ).fetchone():
            return candidate


def _luhn_checksum(number: str) -> int:
    digits = [int(d) for d in number]
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for digit in even_digits:
        doubled = digit * 2
        total += doubled - 9 if doubled > 9 else doubled
    return total % 10


def _generate_card_number(database: sqlite3.Connection) -> str:
    # 16-digit Visa-style card number (starts with 4) with a valid Luhn
    # check digit, matching the format real card issuers use.
    while True:
        body = f"4{uuid.uuid4().int % 10**14:014d}"
        checksum = _luhn_checksum(body + "0")
        check_digit = (10 - checksum) % 10
        candidate = f"{body}{check_digit}"
        if not database.execute(
            "SELECT 1 FROM credit_cards WHERE last_four_digits = ?",
            (candidate[-4:],),
        ).fetchone():
            return candidate


def get_user_by_email(email: str):
    return get_db().execute(
        "SELECT * FROM users WHERE email = ? ",
        (email.strip().lower(),),
    ).fetchone()


def get_user_by_id(user_id: str):
    return get_db().execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def update_user_profile(
    user_id: str,
    first_name: str,
    last_name: str,
    username: str,
    phone: Optional[str] = None,
    address: Optional[str] = None,
    date_of_birth: Optional[str] = None,
):
    if date_of_birth and not valid_date_of_birth(date_of_birth):
        return None, "You must be at least 18 years old, and the date of birth cannot be in the future."

    database = get_db()
    normalized_username = username.strip().lower()
    username_owner = database.execute(
        "SELECT id FROM users WHERE username = ?",
        (normalized_username,),
    ).fetchone()

    if username_owner is not None and username_owner["id"] != user_id:
        return None, "Username is already taken."

    database.execute(
        """
        UPDATE users
        SET first_name = ?,
            last_name = ?,
            username = ?,
            phone = ?,
            address = ?,
            date_of_birth = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            first_name.strip(),
            last_name.strip(),
            normalized_username,
            phone.strip() if phone else None,
            address.strip() if address else None,
            date_of_birth or None,
            _utc_now(),
            user_id,
        ),
    )

    record_audit_log(
        user_id,
        "PROFILE_UPDATED",
        "users",
        "User updated profile details.",
    )
    database.commit()
    return get_user_by_id(user_id), None


def get_role_id(role_name: str) -> Optional[int]:
    role = get_db().execute(
        "SELECT id FROM roles WHERE role_name = ?",
        (role_name,),
    ).fetchone()
    return role["id"] if role else None


def get_user_roles(user_id: str) -> list[str]:
    rows = get_db().execute(
        """
        SELECT r.role_name
        FROM roles r
        JOIN user_roles ur ON ur.role_id = r.id
        WHERE ur.user_id = ?
        """,
        (user_id,),
    ).fetchall()
    return [row["role_name"] for row in rows]


def user_has_role(user_id: str, role_name: str) -> bool:
    return role_name in get_user_roles(user_id)


def record_audit_log(
    user_id: Optional[str],
    action: str,
    resource: str,
    description: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    get_db().execute(
        """
        INSERT INTO audit_logs (
            id, user_id, action, resource, description, ip_address, user_agent, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _generate_uuid(),
            user_id,
            action,
            resource,
            description,
            ip_address,
            user_agent,
            _utc_now(),
        ),
    )


def record_login_history(
    user_id: Optional[str],
    success: bool,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    logout_time: Optional[str] = None,
) -> None:
    get_db().execute(
        """
        INSERT INTO login_history (
            id, user_id, login_time, logout_time, ip_address, user_agent, success
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _generate_uuid(),
            user_id,
            _utc_now(),
            logout_time,
            ip_address,
            user_agent,
            1 if success else 0,
        ),
    )


def record_security_event(
    user_id: Optional[str],
    event_type: str,
    severity: str,
    source_ip: Optional[str],
    target_resource: str,
    description: str,
    detected_by: str,
    status: str = "Open",
) -> None:
    get_db().execute(
        """
        INSERT INTO security_events (
            id, user_id, event_type, severity, source_ip, target_resource,
            description, detected_by, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _generate_uuid(),
            user_id,
            event_type,
            severity,
            source_ip,
            target_resource,
            description,
            detected_by,
            status,
            _utc_now(),
        ),
    )


def record_logout(user_id: str, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> None:
    database = get_db()
    latest_login = database.execute(
        """
        SELECT id
        FROM login_history
        WHERE user_id = ? AND logout_time IS NULL
        ORDER BY login_time DESC
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()

    if latest_login is not None:
        database.execute(
            "UPDATE login_history SET logout_time = ? WHERE id = ?",
            (_utc_now(), latest_login["id"]),
        )

    record_audit_log(
        user_id,
        "LOGOUT",
        "session",
        "User logged out of the banking portal.",
        ip_address,
        user_agent,
    )
    database.commit()


def _card_cipher() -> Fernet:
    key_material = hashlib.sha256(current_app.config["SECRET_KEY"].encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key_material))


def create_credit_card(account_id: str, credit_limit: float = 2500) -> str:
    database = get_db()
    card_number = _generate_card_number(database)
    card_id = _generate_uuid()
    issued = datetime.now(BRUSSELS_TZ)
    try:
        expiry = issued.replace(year=issued.year + 4)
    except ValueError:
        expiry = issued.replace(month=2, day=28, year=issued.year + 4)

    database.execute(
        """
        INSERT INTO credit_cards (
            id, account_id, encrypted_card_number, last_four_digits,
            expiry_month, expiry_year, card_type, credit_limit,
            available_credit, status, issued_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Active', ?)
        """,
        (
            card_id,
            account_id,
            _card_cipher().encrypt(card_number.encode()).decode(),
            card_number[-4:],
            expiry.month,
            expiry.year,
            "Visa Debit",
            credit_limit,
            credit_limit,
            _utc_now(),
        ),
    )
    return card_id


def get_account_cards(account_id: str):
    return get_db().execute(
        "SELECT * FROM credit_cards WHERE account_id = ? ORDER BY issued_at DESC",
        (account_id,),
    ).fetchall()


def ensure_account_card(account_id: str) -> None:
    """Backfill a card for accounts opened before cards were auto-issued.

    New accounts get a card immediately in create_default_account, so this
    only ever does real work for legacy accounts. The UNIQUE constraint on
    credit_cards.account_id backstops the check-then-insert below against
    two concurrent requests for the same account both trying to backfill it.
    """
    if get_account_cards(account_id):
        return
    try:
        create_credit_card(account_id)
    except sqlite3.IntegrityError:
        pass


def get_user_cards(user_id: str):
    return get_db().execute(
        """
        SELECT c.*, a.account_type, a.iban
        FROM credit_cards c
        JOIN accounts a ON c.account_id = a.id
        WHERE a.user_id = ? AND a.status = 'Active'
        ORDER BY c.issued_at DESC
        """,
        (user_id,),
    ).fetchall()


def get_account_by_iban(iban: str):
    normalized = (iban or "").strip().upper().replace(" ", "")
    return get_db().execute(
        """
        SELECT a.*, u.first_name AS owner_first_name, u.last_name AS owner_last_name
        FROM accounts a
        JOIN users u ON u.id = a.user_id
        WHERE a.iban = ? AND a.status = 'Active'
        """,
        (normalized,),
    ).fetchone()


def create_default_account(user_id: str, account_type: str, daily_transfer_limit: float = 5000) -> str:
    database = get_db()
    account_id = _generate_uuid()
    database.execute(
        """
        INSERT INTO accounts (
            id, user_id, iban, account_number, account_type, currency,
            balance, daily_transfer_limit, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'EUR', 0, ?, 'Active', ?, ?)
        """,
        (
            account_id,
            user_id,
            _generate_iban(database),
            _generate_account_number(database),
            account_type,
            daily_transfer_limit,
            _utc_now(),
            _utc_now(),
        ),
    )
    create_credit_card(account_id)
    return account_id


def assign_role(user_id: str, role_name: str = "Customer") -> None:
    database = get_db()
    role_id = get_role_id(role_name)
    if role_id is None:
        return

    database.execute(
        "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
        (user_id, role_id),
    )


def create_user(
    first_name: str,
    last_name: str,
    email: str,
    password: str,
    username: Optional[str] = None,
    phone: Optional[str] = None,
    address: Optional[str] = None,
    date_of_birth: Optional[str] = None,
    account_type: str = "Savings",
    daily_transfer_limit: float = 5000,
    role: str = "Customer",
    open_default_account: bool = True,
    terms_accepted: bool = False,
):
    database = get_db()
    normalized_email = email.strip().lower()
    if not valid_email(normalized_email):
        return None, "Invalid email address"

    if not valid_password(password):
        return None, (
            "Password must contain at least 12 characters, "
            "one uppercase letter, one lowercase letter, "
            "one number, and one special character."
    )

    if date_of_birth and not valid_date_of_birth(date_of_birth):
        return None, "You must be at least 18 years old to register, and the date of birth cannot be in the future."

    if not terms_accepted:
        return None, "You must agree to the Terms & Conditions and Privacy Policy to create an account."

    existing_user = database.execute(
        "SELECT id FROM users WHERE email = ?",
        (normalized_email,),
    ).fetchone()
    if existing_user is not None:
        return None, "Email address is already registered."

    user_id = _generate_uuid()
    if username and username.strip():
        normalized_username = username.strip().lower()
        username_exists = database.execute(
            "SELECT id FROM users WHERE username = ?",
            (normalized_username,),
        ).fetchone()
        if username_exists is not None:
            return None, "Username is already taken."
    else:
        normalized_username = _generate_username(normalized_email, database)

    database.execute(
        """
        INSERT INTO users (
            id, username, email, password_hash, first_name, last_name,
            phone, address, date_of_birth, terms_accepted_at, is_active,
            email_verified, mfa_enabled, failed_login_attempts,
            account_locked_until, last_login, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 0, 0, NULL, NULL, ?, ?)
        """,
        (
            user_id,
            normalized_username,
            normalized_email,
            generate_password_hash(password),
            first_name.strip(),
            last_name.strip(),
            phone.strip() if phone else None,
            address.strip() if address else None,
            date_of_birth,
            _utc_now(),
            _utc_now(),
            _utc_now(),
        ),
    )
    assign_role(user_id, role)
    if open_default_account:
        create_default_account(user_id, account_type, daily_transfer_limit)
    record_audit_log(
        user_id,
        "REGISTER",
        "users",
        "New customer account created." if open_default_account else "New user created without a bank account.",
    )
    database.commit()

    return get_user_by_id(user_id), None


def authenticate_user(email: str, password: str, ip_address: Optional[str] = None, user_agent: Optional[str] = None):
    database = get_db()
    normalized_email = email.strip().lower()
    user = database.execute(
        "SELECT * FROM users WHERE email = ?",
        (normalized_email,),
    ).fetchone()

    if user is None:
        record_login_history(None, False, ip_address, user_agent)
        record_audit_log(None, "LOGIN_FAILED", "users", f"Failed login attempt for {normalized_email}.", ip_address, user_agent)
        database.commit()
        return None, "Invalid email or password."

    if not user["is_active"]:
        record_login_history(user["id"], False, ip_address, user_agent)
        record_security_event(
            user["id"],
            "Deactivated Account Login Attempt",
            "Medium",
            ip_address,
            "login",
            "Login blocked because the account has been deactivated.",
            "Application",
            "Open",
        )
        database.commit()
        return None, "Your account has been deactivated. Contact support."

    if not user["email_verified"]:
        record_login_history(user["id"], False, ip_address, user_agent)
        database.commit()
        return None, "Please verify your email before logging in."

    locked_until = _parse_timestamp(user["account_locked_until"])
    now = datetime.now(BRUSSELS_TZ)
    if locked_until is not None and locked_until > now:
        record_login_history(user["id"], False, ip_address, user_agent)
        record_security_event(
            user["id"],
            "Account Locked",
            "High",
            ip_address,
            "login",
            "Login blocked because the account is temporarily locked.",
            "Application",
            "Open",
        )
        database.commit()
        return None, "Your account is temporarily locked. Try again later."

    if not check_password_hash(user["password_hash"], password):
        failed_attempts = int(user["failed_login_attempts"] or 0) + 1
        lock_until = None
        message = "Invalid email or password."

        if failed_attempts >= 5:
            lock_until = _utc_in(15)
            message = "Too many failed attempts. Your account is locked for 15 minutes."
            record_security_event(
                user["id"],
                "Brute Force",
                "High",
                ip_address,
                "login",
                "Multiple failed password attempts triggered the account lockout policy.",
                "Application",
                "Open",
            )

        database.execute(
            """
            UPDATE users
            SET failed_login_attempts = ?,
                account_locked_until = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (failed_attempts, lock_until, _utc_now(), user["id"]),
        )
        record_login_history(user["id"], False, ip_address, user_agent)
        record_audit_log(user["id"], "LOGIN_FAILED", "users", "Password verification failed.", ip_address, user_agent)
        database.commit()
        return None, message

    database.execute(
        """
        UPDATE users
        SET failed_login_attempts = 0,
            account_locked_until = NULL,
            last_login = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (_utc_now(), _utc_now(), user["id"]),
    )
    record_login_history(user["id"], True, ip_address, user_agent)
    record_audit_log(user["id"], "LOGIN_SUCCESS", "users", "User logged in successfully.", ip_address, user_agent)
    database.commit()

    return user, None


def get_previous_login(user_id: str):
    """Return the user's last successful login before their current session.

    The row for the *current* session's login is already the most recent
    entry in login_history by the time the dashboard renders, so we skip it
    (OFFSET 1) to show the genuine previous "Last Login" instead of just
    re-displaying the login that's happening right now.
    """
    return get_db().execute(
        """
        SELECT login_time, ip_address
        FROM login_history
        WHERE user_id = ? AND success = 1
        ORDER BY login_time DESC
        LIMIT 1 OFFSET 1
        """,
        (user_id,),
    ).fetchone()


def get_user_accounts(user_id: str):
    return get_db().execute(
        "SELECT * FROM accounts WHERE user_id = ? AND status = 'Active'",
        (user_id,),
    ).fetchall()


def get_user_account_types(user_id: str) -> set[str]:
    rows = get_db().execute(
        "SELECT account_type FROM accounts WHERE user_id = ? AND status = 'Active'",
        (user_id,),
    ).fetchall()
    return {row["account_type"] for row in rows}


def get_account_by_id(account_id: str):
    return get_db().execute(
        "SELECT * FROM accounts WHERE id = ?",
        (account_id,),
    ).fetchone()


def get_recent_user_transactions(user_id: str, limit: int = 5):
    return get_db().execute(
        """
        SELECT t.*
        FROM transactions t
        LEFT JOIN accounts a ON t.sender_account_id = a.id
        LEFT JOIN accounts ra ON t.receiver_account_id = ra.id
        WHERE a.user_id = ? OR ra.user_id = ?
        ORDER BY t.created_at DESC
        LIMIT ?
        """,
        (user_id, user_id, limit),
    ).fetchall()


def get_todays_transfer_total(user_id: str) -> float:
    """Sum of EUR already sent today via Transfer transactions, across all
    of the user's own accounts. Deposits are intentionally excluded (both
    by the transaction_type filter and because deposits have no
    sender_account_id to join on), so they stay unlimited."""
    today = datetime.now(BRUSSELS_TZ).strftime("%Y-%m-%d")
    row = get_db().execute(
        """
        SELECT COALESCE(SUM(t.amount), 0) AS total
        FROM transactions t
        JOIN accounts a ON a.id = t.sender_account_id
        WHERE a.user_id = ?
          AND t.transaction_type = 'Transfer'
          AND t.status = 'Completed'
          AND substr(t.created_at, 1, 10) = ?
        """,
        (user_id, today),
    ).fetchone()
    return float(row["total"] or 0)


def get_all_user_transactions(user_id: str):
    return get_db().execute(
        """
        SELECT t.*
        FROM transactions t
        LEFT JOIN accounts a ON t.sender_account_id = a.id
        LEFT JOIN accounts ra ON t.receiver_account_id = ra.id
        WHERE a.user_id = ? OR ra.user_id = ?
        ORDER BY t.created_at DESC
        """,
        (user_id, user_id),
    ).fetchall()


def update_account_balance(account_id: str, amount: float) -> None:
    database = get_db()
    database.execute(
        "UPDATE accounts SET balance = balance + ?, updated_at = ? WHERE id = ?",
        (amount, _utc_now(), account_id),
    )
    database.commit()


def create_transaction(
    sender_account_id: Optional[str],
    receiver_account_id: Optional[str],
    amount: float,
    currency: str,
    transaction_type: str,
    status: str,
    description: Optional[str] = None,
    reference: Optional[str] = None,
    fee: float = 0,
    ip_address: Optional[str] = None,
) -> None:
    database = get_db()
    database.execute(
        """
        INSERT INTO transactions (
            id, sender_account_id, receiver_account_id, amount, currency,
            transaction_type, status, description, reference, fee, ip_address, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _generate_uuid(),
            sender_account_id,
            receiver_account_id,
            amount,
            currency,
            transaction_type,
            status,
            description,
            reference,
            fee,
            ip_address,
            _utc_now(),
        ),
    )
    database.commit()

import secrets

# Distinct flows sharing the same OTP table -- generating a new code for one
# purpose must never invalidate a different purpose's pending code for the
# same user (e.g. logging in shouldn't kill an in-progress password reset).
OTP_PURPOSE_REGISTRATION = "registration"
OTP_PURPOSE_LOGIN = "login"
OTP_PURPOSE_PASSWORD_RESET = "password_reset"

MAX_OTP_ATTEMPTS = 5

def generate_otp():
    return f"{secrets.randbelow(1000000):06d}"

def create_email_otp(user_id, purpose):
    otp = generate_otp()
    database = get_db()

    database.execute(
        """
        UPDATE email_verification_tokens
        SET used = 1
        WHERE user_id = ? AND purpose = ? AND used = 0
        """,
        (user_id, purpose),
    )

    database.execute(
        """
        INSERT INTO email_verification_tokens
        (id, user_id, purpose, otp, expires_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            _generate_uuid(),
            user_id,
            purpose,
            otp,
            _utc_in(10),  # expires in 10 minutes
        ),
    )

    database.commit()

    return otp


def validate_email_otp(user_id: str, otp: str, purpose: str) -> tuple[bool, str]:
    database = get_db()
    row = database.execute(
        """
        SELECT id, otp, expires_at, attempts
        FROM email_verification_tokens
        WHERE user_id = ? AND purpose = ? AND used = 0
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (user_id, purpose),
    ).fetchone()

    if row is None:
        return False, "Invalid or expired verification code. Please request a new one."

    if _parse_timestamp(row["expires_at"]) is None or _parse_timestamp(row["expires_at"]) < datetime.now(BRUSSELS_TZ):
        return False, "This verification code has expired. Please request a new one."

    if row["attempts"] >= MAX_OTP_ATTEMPTS:
        database.execute("UPDATE email_verification_tokens SET used = 1 WHERE id = ?", (row["id"],))
        database.commit()
        return False, "Too many incorrect attempts. Please request a new code."

    if row["otp"] != otp:
        database.execute(
            "UPDATE email_verification_tokens SET attempts = attempts + 1 WHERE id = ?",
            (row["id"],),
        )
        database.commit()
        return False, "Invalid verification code."

    database.execute(
        """
        UPDATE email_verification_tokens
        SET used = 1,
            attempts = attempts + 1
        WHERE id = ?
        """,
        (row["id"],),
    )
    database.commit()
    return True, ""


def mark_email_verified(user_id: str) -> None:
    database = get_db()
    database.execute(
        """
        UPDATE users
        SET email_verified = 1,
            updated_at = ?
        WHERE id = ?
        """,
        (_utc_now(), user_id),
    )
    database.commit()


# ---------------------------------------------------------------------------
# SOC (Security Operations Center) dashboard queries
# ---------------------------------------------------------------------------

VALID_SEVERITIES = ("Low", "Medium", "High", "Critical")
VALID_EVENT_STATUSES = ("Open", "Investigating", "Closed")


def _security_events_filter(severity: Optional[str], status: Optional[str]):
    conditions = []
    params: list = []

    if severity in VALID_SEVERITIES:
        conditions.append("se.severity = ?")
        params.append(severity)

    if status in VALID_EVENT_STATUSES:
        conditions.append("se.status = ?")
        params.append(status)

    return conditions, params


def get_security_events(
    limit: int = 200,
    offset: int = 0,
    severity: Optional[str] = None,
    status: Optional[str] = None,
) -> list:
    conditions, params = _security_events_filter(severity, status)

    query = """
        SELECT se.*, u.email AS user_email
        FROM security_events se
        LEFT JOIN users u ON u.id = se.user_id
    """
    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY se.created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    return get_db().execute(query, params).fetchall()


def count_security_events(severity: Optional[str] = None, status: Optional[str] = None) -> int:
    conditions, params = _security_events_filter(severity, status)

    query = "SELECT COUNT(*) AS c FROM security_events se"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    return get_db().execute(query, params).fetchone()["c"]


def count_open_security_events_for_user(user_id: str) -> int:
    row = get_db().execute(
        "SELECT COUNT(*) AS c FROM security_events WHERE user_id = ? AND status = 'Open'",
        (user_id,),
    ).fetchone()
    return row["c"] if row else 0


def get_security_event_by_id(event_id: str):
    return get_db().execute(
        "SELECT * FROM security_events WHERE id = ?",
        (event_id,),
    ).fetchone()


def update_security_event_status(event_id: str, status: str) -> bool:
    if status not in VALID_EVENT_STATUSES:
        return False

    database = get_db()
    database.execute(
        "UPDATE security_events SET status = ? WHERE id = ?",
        (status, event_id),
    )
    database.commit()
    return True


def get_audit_logs(limit: int = 200, offset: int = 0) -> list:
    return get_db().execute(
        """
        SELECT al.*, u.email AS user_email
        FROM audit_logs al
        LEFT JOIN users u ON u.id = al.user_id
        ORDER BY al.created_at DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    ).fetchall()


def count_audit_logs() -> int:
    return get_db().execute("SELECT COUNT(*) AS c FROM audit_logs").fetchone()["c"]


def get_login_history(limit: int = 200, offset: int = 0, success: Optional[bool] = None) -> list:
    query = """
        SELECT lh.*, u.email AS user_email
        FROM login_history lh
        LEFT JOIN users u ON u.id = lh.user_id
    """
    params: list = []

    if success is not None:
        query += " WHERE lh.success = ?"
        params.append(1 if success else 0)

    query += " ORDER BY lh.login_time DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    return get_db().execute(query, params).fetchall()


def count_login_history(success: Optional[bool] = None) -> int:
    query = "SELECT COUNT(*) AS c FROM login_history lh"
    params: list = []

    if success is not None:
        query += " WHERE lh.success = ?"
        params.append(1 if success else 0)

    return get_db().execute(query, params).fetchone()["c"]


def _user_search_filter(search: Optional[str]) -> Tuple[list, list]:
    if not search:
        return [], []
    like = f"%{search.strip()}%"
    condition = "(u.email LIKE ? OR u.username LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ?)"
    return [condition], [like, like, like, like]


def get_users(limit: int = 200, offset: int = 0, search: Optional[str] = None) -> list:
    conditions, params = _user_search_filter(search)

    query = """
        SELECT u.*, GROUP_CONCAT(r.role_name) AS roles
        FROM users u
        LEFT JOIN user_roles ur ON ur.user_id = u.id
        LEFT JOIN roles r ON r.id = ur.role_id
    """
    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += """
        GROUP BY u.id
        ORDER BY u.created_at DESC
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    return get_db().execute(query, params).fetchall()


def count_users(search: Optional[str] = None) -> int:
    conditions, params = _user_search_filter(search)

    query = "SELECT COUNT(*) AS c FROM users u"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    return get_db().execute(query, params).fetchone()["c"]


def set_user_active(user_id: str, active: bool) -> bool:
    database = get_db()
    cursor = database.execute(
        "UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?",
        (1 if active else 0, _utc_now(), user_id),
    )
    database.commit()
    return cursor.rowcount > 0


def unlock_user_login(user_id: str) -> bool:
    database = get_db()
    cursor = database.execute(
        """
        UPDATE users
        SET account_locked_until = NULL, failed_login_attempts = 0, updated_at = ?
        WHERE id = ?
        """,
        (_utc_now(), user_id),
    )
    database.commit()
    return cursor.rowcount > 0


def set_user_mfa_enabled(user_id: str, enabled: bool) -> bool:
    """Toggle a user's own login MFA (email OTP) preference.

    Off by default for every new account (schema default 0) -- this is
    the self-service switch a user flips from their profile page. It's
    independent of the one-time email verification required at signup.
    """
    database = get_db()
    cursor = database.execute(
        "UPDATE users SET mfa_enabled = ?, updated_at = ? WHERE id = ?",
        (1 if enabled else 0, _utc_now(), user_id),
    )
    database.commit()
    return cursor.rowcount > 0


def get_soc_summary() -> dict:
    database = get_db()
    cutoff_24h = (datetime.now(BRUSSELS_TZ) - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")

    open_events = database.execute(
        "SELECT COUNT(*) AS c FROM security_events WHERE status = 'Open'"
    ).fetchone()["c"]

    critical_open_events = database.execute(
        """
        SELECT COUNT(*) AS c FROM security_events
        WHERE severity IN ('High', 'Critical') AND status != 'Closed'
        """
    ).fetchone()["c"]

    failed_logins_24h = database.execute(
        "SELECT COUNT(*) AS c FROM login_history WHERE success = 0 AND login_time >= ?",
        (cutoff_24h,),
    ).fetchone()["c"]

    locked_accounts = database.execute(
        """
        SELECT COUNT(*) AS c FROM users
        WHERE account_locked_until IS NOT NULL AND account_locked_until >= ?
        """,
        (_utc_now(),),
    ).fetchone()["c"]

    total_users = database.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]

    # Honeypot hits are always logged with detected_by = 'Honeypot' (see
    # routes/honeypot.py) so they're trivially distinguishable from real
    # application security events for the SOC's own alert banner.
    honeypot_hits_total = database.execute(
        "SELECT COUNT(*) AS c FROM security_events WHERE detected_by = 'Honeypot'"
    ).fetchone()["c"]

    honeypot_hits_open = database.execute(
        "SELECT COUNT(*) AS c FROM security_events WHERE detected_by = 'Honeypot' AND status = 'Open'"
    ).fetchone()["c"]

    return {
        "open_events": open_events,
        "critical_open_events": critical_open_events,
        "failed_logins_24h": failed_logins_24h,
        "locked_accounts": locked_accounts,
        "total_users": total_users,
        "honeypot_hits_total": honeypot_hits_total,
        "honeypot_hits_open": honeypot_hits_open,
    }


def reset_user_password(user_id: str, new_password: str) -> bool:
    """Reset a user's password (used by the forgot-password flow)."""
    database = get_db()
    password_hash = generate_password_hash(new_password)

    database.execute(
        """
        UPDATE users
        SET password_hash = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (password_hash, _utc_now(), user_id),
    )
    database.commit()
    return True


def change_user_password(user_id: str, current_password: str, new_password: str) -> Tuple[bool, str]:
    """Change a logged-in user's own password (used by the profile page).

    Unlike reset_user_password (forgot-password flow, where OTP possession
    is already the proof of identity), this requires the current password.
    """
    database = get_db()
    user = database.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if user is None:
        return False, "User not found."

    if not check_password_hash(user["password_hash"], current_password):
        return False, "Current password is incorrect."

    if not valid_password(new_password):
        return False, (
            "New password must contain at least 12 characters, "
            "one uppercase letter, one lowercase letter, "
            "one number, and one special character."
        )

    if check_password_hash(user["password_hash"], new_password):
        return False, "New password must be different from your current password."

    database.execute(
        "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
        (generate_password_hash(new_password), _utc_now(), user_id),
    )
    record_audit_log(
        user_id,
        "PASSWORD_CHANGED",
        "users",
        "User changed their password from the profile page.",
    )
    database.commit()
    return True, ""
