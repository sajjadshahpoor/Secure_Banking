"""Create (or promote) an Admin user so they can access the SOC dashboard.

Usage (run inside the running app container so it shares the same database):

    docker compose exec app python banking_app/create_admin.py

    # or non-interactively:
    docker compose exec app python banking_app/create_admin.py \
        --email admin@bank.com --password "Str0ngPass!" \
        --first-name Ada --last-name Admin \
        --phone "+32 2 555 0100" --address "1 Rue de la Banque, Brussels" \
        --dob 1990-01-01

Any optional field left out (either as a flag or at the interactive
prompt) is simply stored as empty, same as an optional field on the
public registration form. If the email already belongs to an existing
user, that user is promoted to the Admin role rather than creating a
duplicate account, and their existing profile is left untouched.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from banking_app.app import create_app
from banking_app.db import assign_role, create_user, get_db, get_user_by_email, mark_email_verified


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", help="Admin email address")
    parser.add_argument("--password", help="Admin password (prefer the interactive prompt on shared shells)")
    parser.add_argument("--first-name", help="First name")
    parser.add_argument("--last-name", help="Last name")
    parser.add_argument("--username", help="Username (auto-generated from email if omitted)")
    parser.add_argument("--phone", help="Phone number (optional)")
    parser.add_argument("--address", help="Mailing address (optional)")
    parser.add_argument("--dob", help="Date of birth, YYYY-MM-DD (optional)")
    parser.add_argument("--account-type", default="Current", help="Default account type to open (only used with --with-account)")
    parser.add_argument(
        "--with-account",
        action="store_true",
        help="Also open a normal bank account for this admin, the same way a customer registration would. "
             "Omit this flag (the default) to create an Admin who can only sign in to the SOC dashboard.",
    )
    return parser.parse_args()


def prompt_required(label: str) -> str:
    value = input(f"{label}: ").strip()
    if not value:
        print(f"{label} is required.")
        sys.exit(1)
    return value


def prompt_optional(label: str) -> str | None:
    value = input(f"{label} (optional, press Enter to skip): ").strip()
    return value or None


def prompt_password() -> str:
    password = getpass.getpass("Admin password: ")
    confirm = getpass.getpass("Confirm password: ")

    if password != confirm:
        print("Passwords do not match.")
        sys.exit(1)

    if len(password) < 8:
        print("Password must be at least 8 characters.")
        sys.exit(1)

    return password


def main() -> None:
    args = parse_args()

    email = args.email or prompt_required("Admin email")

    app = create_app()

    with app.app_context():
        existing_user = get_user_by_email(email)

        if existing_user is not None:
            assign_role(existing_user["id"], "Admin")
            get_db().commit()
            print(f"'{email}' already existed and has been granted the Admin role.")
            return

        # Only collect a full profile when we're actually creating a new
        # user -- promoting an existing one (above) leaves their profile
        # untouched.
        password = args.password or prompt_password()
        first_name = args.first_name or prompt_required("First name")
        last_name = args.last_name or prompt_required("Last name")
        phone = args.phone or prompt_optional("Phone")
        address = args.address or prompt_optional("Address")
        dob = args.dob or prompt_optional("Date of birth (YYYY-MM-DD)")

        user, error = create_user(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=password,
            username=args.username,
            phone=phone,
            address=address,
            date_of_birth=dob,
            account_type=args.account_type,
            role="Admin",
            open_default_account=args.with_account,
            # Internal staff provisioning, not the public self-service
            # signup flow -- there's no customer consent screen to gate on.
            terms_accepted=True,
        )

        if user is None:
            print(f"Could not create user: {error}")
            sys.exit(1)

        # Internal staff provisioning, not the public self-service signup
        # flow -- there's no inbox for this account to click a link in, so
        # mark it verified directly instead of leaving it permanently
        # locked out by the email-verification requirement.
        mark_email_verified(user["id"])

        get_db().commit()

        print(f"Admin user created: {email}")
        if args.with_account:
            print("A bank account was also opened for this admin, same as a regular customer.")
        print("They can now log in at /login and land directly on the SOC dashboard at /soc")


if __name__ == "__main__":
    main()
