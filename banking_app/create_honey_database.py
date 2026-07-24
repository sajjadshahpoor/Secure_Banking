import random
import sqlite3
import uuid
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "instance" / "bank_archive_2025.sqlite3"
SCHEMA_PATH = APP_DIR / "honeypot_seed" / "fake_bank_schema.sql"

RANDOM = random.Random(2026)


def new_id() -> str:
    return str(uuid.uuid4())


def ensure_schema(connection: sqlite3.Connection) -> None:
    users_table_exists = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table' AND name = 'users'
        """
    ).fetchone()

    if users_table_exists is not None:
        return

    if not SCHEMA_PATH.exists():
        raise FileNotFoundError(
            f"Schema file not found: {SCHEMA_PATH}"
        )

    connection.executescript(
        SCHEMA_PATH.read_text(encoding="utf-8")
    )


def clear_honey_data(connection: sqlite3.Connection) -> None:
    # Delete child records before parent records to preserve foreign-key integrity.
    tables = [
        "user_roles",
        "roles",
        "email_verification_tokens",
        "notifications",
        "security_events",
        "audit_logs",
        "login_history",
        "credit_cards",
        "transactions",
        "beneficiaries",
        "accounts",
        "users",
    ]

    for table in tables:
        connection.execute(f"DELETE FROM {table}")


def populate_honey_database() -> None:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.execute("PRAGMA foreign_keys = ON")

    try:
        ensure_schema(connection)
        clear_honey_data(connection)

        # Generate a realistic mix of ordinary retail-banking customers.
        people = [
            ("marc.delvaux", "Marc", "Delvaux", "1978-04-16"),
            ("sophie.lambert", "Sophie", "Lambert", "1985-09-03"),
            ("isabelle.dupont", "Isabelle", "Dupont", "1976-11-24"),
            ("thomas.vermeulen", "Thomas", "Vermeulen", "1982-02-19"),
            ("emma.janssens", "Emma", "Janssens", "1991-07-12"),
            ("luc.desmet", "Luc", "De Smet", "1969-05-30"),
            ("sarah.peeters", "Sarah", "Peeters", "1988-10-08"),
            ("julien.leclercq", "Julien", "Leclercq", "1993-03-21"),
            ("claire.dubois", "Claire", "Dubois", "1984-12-14"),
            ("nicolas.maes", "Nicolas", "Maes", "1974-06-09"),
            ("amelie.leroy", "Amélie", "Leroy", "1990-01-27"),
            ("laura.vandenberg", "Laura", "Vandenberg", "1987-04-04"),
            ("pierre.martin", "Pierre", "Martin", "1971-11-16"),
            ("nathalie.gerard", "Nathalie", "Gérard", "1994-02-25"),
            ("olivier.simon", "Olivier", "Simon", "1983-08-07"),
            ("helene.francois", "Hélène", "François", "1989-05-13"),
            ("antoine.lemaire", "Antoine", "Lemaire", "1986-10-02"),
            ("camille.renard", "Camille", "Renard", "1992-06-18"),
            ("benoit.michel", "Benoît", "Michel", "1977-01-29"),
            ("elise.vanacker", "Élise", "Van Acker", "1995-03-08"),
        ]

        users = []

        for index, (username, first_name, last_name, dob) in enumerate(
            people,
            start=1,
        ):
            user = {
                "id": new_id(),
                "username": username,
                "email": f"{username}@bankofbelgium.test",
                "first_name": first_name,
                "last_name": last_name,
                "phone": f"+32 47{index % 10} {10 + index:02d} "
                         f"{20 + index:02d} {30 + index:02d}",
                "address": (
                    f"{10 + index} Avenue Centrale, "
                    f"{1000 + index} Brussels"
                ),
                "date_of_birth": dob,
            }
            users.append(user)

            connection.execute(
                """
                INSERT INTO users (
                    id,
                    username,
                    email,
                    password_hash,
                    first_name,
                    last_name,
                    phone,
                    address,
                    date_of_birth,
                    is_active,
                    email_verified,
                    mfa_enabled,
                    failed_login_attempts,
                    last_login
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user["id"],
                    user["username"],
                    user["email"],
                    "scrypt:fake-honey-password-hash",
                    user["first_name"],
                    user["last_name"],
                    user["phone"],
                    user["address"],
                    user["date_of_birth"],
                    1,
                    1,
                    1 if index % 3 == 0 else 0,
                    0,
                    f"2026-07-{(index % 20) + 1:02d} "
                    f"{8 + index % 10:02d}:15:00",
                ),
            )

        accounts = []

        for index, user in enumerate(users, start=1):
            # Keep most balances ordinary, with only a few premium customers.
            if user["username"] in {
                "marc.delvaux",
                "isabelle.dupont",
                "thomas.vermeulen",
            }:
                balance = round(RANDOM.uniform(180_000, 620_000), 2)
                transfer_limit = RANDOM.choice([25_000, 50_000])
            elif index % 5 == 0:
                balance = round(RANDOM.uniform(45_000, 140_000), 2)
                transfer_limit = 25_000
            else:
                balance = round(RANDOM.uniform(1_250, 38_000), 2)
                transfer_limit = RANDOM.choice(
                    [2_500, 5_000, 10_000, 15_000]
                )

            account = {
                "id": new_id(),
                "user_id": user["id"],
                "iban": f"BE{70 + index:02d}09612345{index:04d}",
                "account_number": f"11004200{index:04d}",
                "account_type": (
                    "checking" if index % 2 else "savings"
                ),
                "balance": balance,
                "daily_transfer_limit": transfer_limit,
            }
            accounts.append(account)

            connection.execute(
                """
                INSERT INTO accounts (
                    id,
                    user_id,
                    iban,
                    account_number,
                    account_type,
                    currency,
                    balance,
                    daily_transfer_limit,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    account["id"],
                    account["user_id"],
                    account["iban"],
                    account["account_number"],
                    account["account_type"],
                    "EUR",
                    account["balance"],
                    account["daily_transfer_limit"],
                    "Active",
                ),
            )

        # Create normal personal and business beneficiaries.
        for index, user in enumerate(users):
            target = users[(index + 3) % len(users)]

            connection.execute(
                """
                INSERT INTO beneficiaries (
                    id,
                    user_id,
                    beneficiary_name,
                    iban,
                    nickname
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    new_id(),
                    user["id"],
                    f"{target['first_name']} {target['last_name']}",
                    accounts[(index + 3) % len(accounts)]["iban"],
                    RANDOM.choice(
                        [
                            "Family",
                            "Landlord",
                            "Savings",
                            "Electricity provider",
                            "Insurance",
                            "Work",
                        ]
                    ),
                ),
            )

        # Create tokenized cards with believable consumer product names.
        for index, account in enumerate(accounts[:15], start=1):
            connection.execute(
                """
                INSERT INTO credit_cards (
                    id,
                    account_id,
                    encrypted_card_number,
                    last_four_digits,
                    expiry_month,
                    expiry_year,
                    card_type,
                    credit_limit,
                    available_credit,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id(),
                    account["id"],
                    f"HONEY-TOKEN-CARD-{index:04d}",
                    f"{4000 + index:04d}",
                    (index % 12) + 1,
                    2028 + (index % 4),
                    RANDOM.choice(
                        [
                            "Visa Debit",
                            "Visa Classic",
                            "Mastercard Debit",
                            "Mastercard Gold",
                            "Business Visa",
                        ]
                    ),
                    RANDOM.choice(
                        [2_500, 5_000, 7_500, 10_000, 15_000]
                    ),
                    RANDOM.choice(
                        [1_850, 3_900, 6_200, 8_400, 12_750]
                    ),
                    "Active",
                ),
            )

        # Create mostly ordinary retail-banking transactions.
        for index in range(1, 61):
            sender_index = RANDOM.randrange(len(accounts))
            receiver_index = RANDOM.randrange(len(accounts))

            while receiver_index == sender_index:
                receiver_index = RANDOM.randrange(len(accounts))

            if index <= 52:
                amount = round(RANDOM.uniform(8, 4_500), 2)
            else:
                amount = round(RANDOM.uniform(8_000, 85_000), 2)

            connection.execute(
                """
                INSERT INTO transactions (
                    id,
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
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id(),
                    accounts[sender_index]["id"],
                    accounts[receiver_index]["id"],
                    amount,
                    "EUR",
                    RANDOM.choice(
                        [
                            "Transfer",
                            "Transfer",
                            "Transfer",
                            "Deposit",
                            "Withdrawal",
                        ]
                    ),
                    RANDOM.choice(
                        ["Completed", "Completed", "Completed", "Pending"]
                    ),
                    RANDOM.choice(
                        [
                            "Salary payment",
                            "Rent payment",
                            "Grocery purchase",
                            "Utility bill",
                            "Insurance payment",
                            "Savings transfer",
                            "Loan repayment",
                            "Online purchase",
                            "Restaurant payment",
                            "Mobile subscription",
                            "Business invoice",
                            "Investment contribution",
                        ]
                    ),
                    f"BOB-2026-{index:06d}",
                    (
                        0.0
                        if amount < 5_000
                        else round(amount * 0.0005, 2)
                    ),
                    f"10.20.{index % 15}.{20 + index % 200}",
                    (
                        f"2026-07-{(index % 23) + 1:02d} "
                        f"{8 + index % 12:02d}:{index % 60:02d}:00"
                    ),
                ),
            )

        # Assign simple customer tiers without obvious administrative bait.
        roles = ["Customer", "Premium"]

        role_ids = {}

        for role_name in roles:
            cursor = connection.execute(
                """
                INSERT INTO roles (role_name)
                VALUES (?)
                """,
                (role_name,),
            )
            role_ids[role_name] = cursor.lastrowid

        for user in users:
            if user["username"] in {
                "marc.delvaux",
                "isabelle.dupont",
                "thomas.vermeulen",
            }:
                role = "Premium"
            else:
                role = "Customer"

            connection.execute(
                """
                INSERT INTO user_roles (user_id, role_id)
                VALUES (?, ?)
                """,
                (user["id"], role_ids[role]),
            )

        # Add realistic notifications, login history, and audit activity.
        for index, user in enumerate(users, start=1):
            connection.execute(
                """
                INSERT INTO notifications (
                    id,
                    user_id,
                    title,
                    message,
                    notification_type,
                    is_read
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id(),
                    user["id"],
                    RANDOM.choice(
                        [
                            "Monthly statement available",
                            "Transfer completed",
                            "Card payment approved",
                            "Direct debit processed",
                            "New beneficiary added",
                            "New device sign-in",
                        ]
                    ),
                    RANDOM.choice(
                        [
                            "Your latest banking activity is now available.",
                            "The requested operation was completed successfully.",
                            "Please review this activity in your account.",
                        ]
                    ),
                    RANDOM.choice(
                        ["Transaction", "Security"]
                    ),
                    index % 2,
                ),
            )

            connection.execute(
                """
                INSERT INTO login_history (
                    id,
                    user_id,
                    login_time,
                    logout_time,
                    ip_address,
                    user_agent,
                    success
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id(),
                    user["id"],
                    f"2026-07-{(index % 20) + 1:02d} 09:10:00",
                    f"2026-07-{(index % 20) + 1:02d} 10:45:00",
                    f"10.10.2.{30 + index}",
                    RANDOM.choice(
                        [
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)",
                            "Mozilla/5.0 (Linux; Android 15)",
                        ]
                    ),
                    1,
                ),
            )

            connection.execute(
                """
                INSERT INTO audit_logs (
                    id,
                    user_id,
                    action,
                    resource,
                    description,
                    ip_address,
                    user_agent
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id(),
                    user["id"],
                    RANDOM.choice(
                        [
                            "VIEW_ACCOUNT",
                            "EXPORT_STATEMENT",
                            "UPDATE_BENEFICIARY",
                            "AUTHORIZE_TRANSFER",
                        ]
                    ),
                    RANDOM.choice(
                        [
                            "accounts",
                            "transactions",
                            "beneficiaries",
                            "reports",
                        ]
                    ),
                    "Routine account activity recorded by the banking platform.",
                    f"10.30.5.{40 + index}",
                    RANDOM.choice(
                        [
                            "Web-Banking/3.4",
                            "Mobile-Banking/5.1",
                            "Customer-Portal/2.9",
                        ]
                    ),
                ),
            )

        # Keep security events believable and mostly low-severity.
        security_event_data = [
            (
                "NEW_DEVICE_LOGIN",
                "Low",
                "Account accessed from a previously unseen device.",
            ),
            (
                "PASSWORD_CHANGED",
                "Low",
                "The customer changed the online-banking password.",
            ),
            (
                "LARGE_TRANSFER",
                "Medium",
                "A transfer exceeded the customer's usual amount.",
            ),
            (
                "FAILED_LOGIN",
                "Medium",
                "Several unsuccessful login attempts were recorded.",
            ),
            (
                "NEW_BENEFICIARY",
                "Low",
                "A new beneficiary was added to the account.",
            ),
            (
                "CARD_PAYMENT_REVIEW",
                "Medium",
                "A card payment was selected for an additional review.",
            ),
        ]

        for index, (event_type, severity, description) in enumerate(
            security_event_data
        ):
            connection.execute(
                """
                INSERT INTO security_events (
                    id,
                    user_id,
                    event_type,
                    severity,
                    source_ip,
                    target_resource,
                    description,
                    detected_by,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id(),
                    users[index % len(users)]["id"],
                    event_type,
                    severity,
                    f"10.99.0.{50 + index}",
                    RANDOM.choice(
                        [
                            "/login",
                            "/accounts",
                            "/transfer",
                            "/profile",
                        ]
                    ),
                    description,
                    "Bank-Security-Monitor",
                    RANDOM.choice(
                        ["Open", "Investigating", "Closed"]
                    ),
                ),
            )

        connection.commit()

        print("Honey database expanded successfully.")
        print(f"Database: {DATABASE_PATH}")
        print(f"Users: {len(users)}")
        print(f"Accounts: {len(accounts)}")
        print("Transactions: 60")
        print("Cards: 15")
        print("Security events: 6")

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


if __name__ == "__main__":
    populate_honey_database() 