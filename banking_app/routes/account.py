import csv
import io
import re
from datetime import datetime

from flask import Blueprint, Response, abort, flash, redirect, render_template, request, session, url_for
from flask_login import login_required, current_user

from ..db import (
    change_user_password,
    count_open_security_events_for_user,
    create_default_account,
    create_email_otp,
    create_transaction,
    ensure_account_card,
    get_account_by_iban,
    get_account_by_id,
    get_all_user_transactions,
    get_db,
    get_previous_login,
    get_todays_transfer_total,
    get_user_accounts,
    get_user_account_types,
    get_recent_user_transactions,
    get_user_by_id,
    get_user_cards,
    max_date_of_birth,
    record_audit_log,
    record_security_event,
    set_user_mfa_enabled,
    update_account_balance,
    update_user_profile,
    user_has_role,
    validate_email_otp,
)

account_bp = Blueprint(
    "account",
    __name__
)

# The only account types customers can self-serve open from the dashboard.
# Keep this in sync with the choices on the registration form.
OPENABLE_ACCOUNT_TYPES = ["Savings", "Current"]

# Matches the IBAN format this bank actually issues (see _generate_iban in
# db.py): 2-letter country code followed by 14 digits. Used to reject
# obviously malformed input before we even hit the database.
IBAN_FORMAT_RE = re.compile(r"^[A-Z]{2}\d{14}$")

# Per-user daily cap on outgoing transfers, matching the default
# accounts.daily_transfer_limit set in db.py. Deposits are never subject
# to this limit.
DAILY_TRANSFER_LIMIT = 5000.0


def _normalize_name(name: str) -> str:
    """Collapse whitespace and case so name comparisons aren't tripped up
    by extra spaces or capitalization differences."""
    return " ".join((name or "").split()).casefold()


@account_bp.route("/dashboard")
@login_required
def dashboard():
    accounts = get_user_accounts(current_user.id)

    # Admins are SOC users by default and don't get a bank account
    # automatically. If one hasn't opened an account (see /accounts to open
    # one, same as any other user), send them back to their real home page
    # instead of showing an empty "pretend" bank dashboard.
    if not accounts and user_has_role(current_user.id, "Admin"):
        flash("Your admin login doesn't have a bank account. Open one from the Accounts page if you need one.", "info")
        return redirect(url_for("soc.dashboard"))

    total_balance = sum(float(account["balance"]) for account in accounts)
    recent_transactions = get_recent_user_transactions(current_user.id, limit=5)

    # Accounts opened before cards were auto-issued won't have one yet --
    # backfill so existing test accounts pick one up instead of showing
    # an empty card panel. New accounts already get one in
    # create_default_account, so this is a no-op for them.
    for account in accounts:
        ensure_account_card(account["id"])
    get_db().commit()
    cards = get_user_cards(current_user.id)

    existing_types = get_user_account_types(current_user.id)
    available_account_types = [t for t in OPENABLE_ACCOUNT_TYPES if t not in existing_types]

    user_row = get_user_by_id(current_user.id)
    mfa_enabled = bool(user_row["mfa_enabled"]) if user_row else False

    member_since = "-"
    if user_row and user_row["created_at"]:
        try:
            member_since = datetime.strptime(
                user_row["created_at"], "%Y-%m-%d %H:%M:%S"
            ).strftime("%B %Y")
        except (TypeError, ValueError):
            member_since = user_row["created_at"]

    open_alerts_count = count_open_security_events_for_user(current_user.id)

    previous_login = get_previous_login(current_user.id)
    if previous_login:
        try:
            last_login_display = datetime.strptime(
                previous_login["login_time"], "%Y-%m-%d %H:%M:%S"
            ).strftime("%d %B %Y %H:%M")
        except (TypeError, ValueError):
            last_login_display = previous_login["login_time"]
    else:
        last_login_display = "This is your first login"

    return render_template(
        "dashboard.html",
        username=current_user.first_name,
        total_balance=total_balance,
        recent_transactions=recent_transactions,
        accounts=accounts,
        cards=cards,
        available_account_types=available_account_types,
        mfa_enabled=mfa_enabled,
        member_since=member_since,
        open_alerts_count=open_alerts_count,
        last_login_display=last_login_display,
        owned_account_ids={account["id"] for account in accounts},
    )


@account_bp.route("/transactions")
@login_required
def transactions():
    accounts = get_user_accounts(current_user.id)
    all_transactions = get_all_user_transactions(current_user.id)

    return render_template(
        "transactions.html",
        transactions=all_transactions,
        owned_account_ids={account["id"] for account in accounts},
    )


@account_bp.route("/accounts/<account_id>")
@login_required
def view_account(account_id):
    """
    ================================================================
    [CTF-VULN #1 - EASY] Insecure Direct Object Reference (IDOR)
    ================================================================
    This endpoint fetches an account purely by the id in the URL and
    never checks that the account belongs to current_user -- any
    authenticated user can view ANY other user's balance, IBAN, and
    account number just by changing the id in the address bar.

    HOW TO TRIGGER:
      1. Log in as any two test users (User A and User B) in two
         browsers/sessions, each with at least one open account.
      2. As User A, open the browser dev tools / view page source on
         /dashboard and copy one of User A's own account ids (e.g.
         from the "Copy" button's data-iban, or from a network
         request -- account ids are UUIDs like
         3a91f526-5132-473d-9cb6-70745ddd39bf).
      3. As User B, visit /accounts/<User A's account id>.
         -> User B now sees User A's real balance, IBAN, and account
            number, despite it not being their own account.

    THE FIX (not applied here on purpose): check
      `if account["user_id"] != current_user.id: abort(403)`
    before rendering, the same way every other account-scoped route
    in this file already does via the owned_account_ids / next(...)
    ownership pattern.
    ================================================================
    """
    account = get_account_by_id(account_id)
    if account is None:
        abort(404)

    is_owner = account["user_id"] == current_user.id

    # [SOC DETECTION for CTF-VULN #1] The vulnerable code above already
    # fetched and is about to render someone else's account -- this is
    # the exact moment a real IDOR would be caught: the requesting user
    # doesn't own the resource they're viewing. Logged as Critical so
    # it stands out from routine activity on the SOC dashboard.
    if not is_owner:
        record_security_event(
            current_user.id,
            "IDOR Exploit Detected - Unauthorized Account Access",
            "Critical",
            request.remote_addr,
            f"account:{account_id}",
            (
                f"User {current_user.email} viewed account {account_id} "
                f"(IBAN {account['iban']}) belonging to a different user "
                f"via GET /accounts/<id> without any ownership check. "
                f"CTF-VULN #1 (IDOR) was triggered."
            ),
            "IDOR-Detector",
            "Open",
        )
        get_db().commit()

    owner = get_user_by_id(account["user_id"])

    return render_template(
        "account_details.html",
        account=account,
        owner=owner,
        is_owner=is_owner,
    )


@account_bp.route("/accounts/open", methods=["POST"])
@login_required
def open_account():
    account_type = (request.form.get("account_type") or "").strip()

    if account_type not in OPENABLE_ACCOUNT_TYPES:
        flash("Please choose a valid account type to open.", "danger")
        return redirect(url_for("account.dashboard"))

    existing_types = get_user_account_types(current_user.id)
    if account_type in existing_types:
        flash(f"You already have a {account_type} account.", "info")
        return redirect(url_for("account.dashboard"))

    create_default_account(current_user.id, account_type)
    get_db().commit()

    flash(f"Your new {account_type} account has been opened.", "success")
    return redirect(url_for("account.dashboard"))


@account_bp.route("/statement/download")
@login_required
def download_statement():
    transactions = get_all_user_transactions(current_user.id)
    owned_account_ids = {a["id"] for a in get_user_accounts(current_user.id)}

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Date", "Description", "Type", "Direction", "Amount (EUR)", "Status"])

    for txn in transactions:
        direction = "Debit" if txn["sender_account_id"] in owned_account_ids else "Credit"
        writer.writerow(
            [
                txn["created_at"],
                txn["description"] or txn["transaction_type"],
                txn["transaction_type"],
                direction,
                f"{float(txn['amount']):.2f}",
                txn["status"],
            ]
        )

    filename = f"statement_{current_user.id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@account_bp.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    accounts = get_user_accounts(current_user.id)
    recent_transactions = get_recent_user_transactions(current_user.id, limit=5)
    owned_account_ids = {account["id"] for account in accounts}

    if request.method == "POST":
        account_id = request.form.get("from_account")
        recipient_iban_raw = request.form.get("account_number", "")
        recipient_iban = recipient_iban_raw.strip().upper().replace(" ", "")
        recipient_name = (request.form.get("recipient") or "").strip()
        description = (request.form.get("description") or "").strip()

        # [SOC DETECTION for CTF-VULN #2] The description below is stored
        # as-is (no sanitization -- that's intentional, see the |safe
        # filter in transactions.html marked CTF-VULN #2) and later
        # rendered unescaped, so anyone who views this transaction has the
        # payload execute in their browser. This check doesn't block or
        # clean the input -- it only raises the alert a real SOC would
        # generate on observing a payload like this in transit.
        if description and re.search(r"<script|onerror\s*=|onload\s*=|javascript:|<iframe|<img[^>]+onerror", description, re.IGNORECASE):
            record_security_event(
                current_user.id,
                "Stored XSS Payload Detected in Transfer Description",
                "High",
                request.remote_addr,
                "transfer",
                (
                    f"Transaction memo submitted by {current_user.email} contains a likely "
                    f"XSS payload and will be stored unsanitized: {description[:200]!r}. "
                    f"CTF-VULN #2 (Stored XSS) was triggered."
                ),
                "XSS-Detector",
                "Open",
            )
            get_db().commit()

        try:
            amount = round(float(request.form.get("amount", 0)), 2)
        except ValueError:
            amount = 0

        # The chosen "from" account must actually belong to the signed-in
        # user -- never trust the posted id on its own.
        sender_account = next((a for a in accounts if a["id"] == account_id), None)

        error = None
        if sender_account is None:
            error = "Please choose a valid account to transfer from."
        elif not recipient_name:
            error = "Please enter the recipient's full name."
        elif not IBAN_FORMAT_RE.match(recipient_iban):
            error = "Please enter a valid IBAN (2 letters followed by 14 digits, e.g. BE00 0000 0000 0000)."
        elif amount <= 0:
            error = "Enter an amount greater than €0.00."
        elif float(sender_account["balance"]) <= 0:
            error = "That account has a zero balance, so there's nothing to transfer."
        elif float(sender_account["balance"]) < amount:
            error = "Insufficient balance for this transfer."

        # Daily transfer limit (deposits are never subject to this check).
        if error is None:
            already_sent_today = get_todays_transfer_total(current_user.id)
            if already_sent_today + amount > DAILY_TRANSFER_LIMIT:
                remaining = max(DAILY_TRANSFER_LIMIT - already_sent_today, 0)
                error = (
                    f"This transfer would exceed your daily transfer limit of "
                    f"€{DAILY_TRANSFER_LIMIT:,.2f}. You have €{remaining:,.2f} left to send today."
                )
                record_security_event(
                    current_user.id,
                    "Daily Transfer Limit Exceeded",
                    "Medium",
                    request.remote_addr,
                    "transfer",
                    (
                        f"User {current_user.first_name} {current_user.last_name} "
                        f"(username: {current_user.username}, email: {current_user.email}) "
                        f"attempted to transfer €{amount:.2f} from account {sender_account['iban']}, "
                        f"which would exceed the €{DAILY_TRANSFER_LIMIT:,.2f} daily transfer limit "
                        f"(already sent €{already_sent_today:,.2f} today)."
                    ),
                    "Application",
                    "Open",
                )
                get_db().commit()

        receiver_account = None
        if error is None:
            receiver_account = get_account_by_iban(recipient_iban)
            if receiver_account is None:
                error = "We couldn't find an active account with that IBAN."
            elif receiver_account["id"] == sender_account["id"]:
                error = "You can't transfer to the same account."
            else:
                owner_name = f"{receiver_account['owner_first_name']} {receiver_account['owner_last_name']}"
                if _normalize_name(owner_name) != _normalize_name(recipient_name):
                    error = "The recipient name doesn't match the account holder for that IBAN. Please check both and try again."

        if error:
            flash(error, "danger")
            return render_template(
                "transfer.html",
                accounts=accounts,
                recent_transactions=recent_transactions,
                owned_account_ids=owned_account_ids,
                form=request.form,
            )

        # ================================================================
        # [CTF-VULN #3 - HARD] Business logic flaw: self-transfer money
        # duplication.
        # ================================================================
        # When sender and receiver are two DIFFERENT accounts owned by the
        # SAME user (a legitimate feature -- see the "between your
        # accounts" labels in dashboard.html/transactions.html), this
        # branch treats it as "just moving money between your own
        # pockets" and skips debiting the sender, on the flawed
        # assumption that no money is leaving the bank. The receiving
        # account still gets credited, so repeating this between two of
        # your own accounts creates money out of nowhere.
        #
        # HOW TO TRIGGER:
        #   1. Open a Savings AND a Current account on the same profile
        #      (dashboard -> "+ Open New Account").
        #   2. Note your total balance (Savings + Current).
        #   3. Transfer any amount from Savings to Current using its
        #      IBAN and your own name as recipient.
        #   4. Reload the dashboard -- your TOTAL balance went UP by the
        #      transferred amount instead of staying the same. Repeat to
        #      keep duplicating funds (capped only by the existing daily
        #      transfer limit, since these still count as sent Transfers).
        #
        # THE FIX (not applied here on purpose): always debit the sender,
        # i.e. delete the `if not is_internal_self_transfer:` guard below
        # and unconditionally call update_account_balance(sender, -amount).
        # ================================================================
        is_internal_self_transfer = receiver_account["user_id"] == sender_account["user_id"]

        if not is_internal_self_transfer:
            update_account_balance(sender_account["id"], -amount)
        else:
            # [SOC DETECTION for CTF-VULN #3] A legitimate internal
            # transfer is balance-neutral for the user overall, so every
            # occurrence of this path is logged -- the Blue Team can
            # correlate a stream of these events against a user's total
            # balance climbing to confirm the flaw is being actively
            # abused, rather than just used for its intended purpose.
            record_security_event(
                current_user.id,
                "Self-Transfer Detected - Verify Balance Integrity",
                "Medium",
                request.remote_addr,
                "transfer",
                (
                    f"User {current_user.email} transferred EUR {amount:.2f} between their own "
                    f"accounts ({sender_account['iban']} -> {receiver_account['iban']}). The sender "
                    f"account was NOT debited due to the intentional CTF business-logic flaw "
                    f"(CTF-VULN #3) -- repeated use of this path duplicates funds."
                ),
                "BusinessLogic-Detector",
                "Open",
            )
            get_db().commit()

        update_account_balance(receiver_account["id"], amount)

        create_transaction(
            sender_account_id=sender_account["id"],
            receiver_account_id=receiver_account["id"],
            amount=amount,
            currency="EUR",
            transaction_type="Transfer",
            status="Completed",
            description=description or f"Transfer to {recipient_name}".strip(),
            ip_address=request.remote_addr,
        )

        flash("Transfer completed successfully.", "success")
        return redirect(url_for("account.dashboard"))

    return render_template(
        "transfer.html",
        accounts=accounts,
        recent_transactions=recent_transactions,
        owned_account_ids=owned_account_ids,
        form=request.form,
    )



@account_bp.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    accounts = get_user_accounts(current_user.id)

    if request.method == "POST":
        account_id = request.form.get("account_id")
        deposit_method = (request.form.get("deposit_method") or "").strip()
        reference = (request.form.get("reference") or "").strip()

        try:
            amount = round(float(request.form.get("amount", 0)), 2)
        except ValueError:
            amount = 0

        # The chosen account must actually belong to the signed-in user --
        # never trust the posted id on its own (it would otherwise let
        # anyone deposit funds into an arbitrary account by id).
        account = next((a for a in accounts if a["id"] == account_id), None)

        error = None
        if account is None:
            error = "Please choose a valid account to deposit into."
        elif amount <= 0:
            error = "Enter an amount greater than €0.00."

        if error:
            flash(error, "danger")
            return render_template("deposit.html", accounts=accounts, form=request.form)

        assert account is not None
        update_account_balance(account["id"], amount)

        description = f"{deposit_method} deposit" if deposit_method else "Deposit"
        if reference:
            description = f"{description} — {reference}"

        create_transaction(
            sender_account_id=None,
            receiver_account_id=account["id"],
            amount=amount,
            currency="EUR",
            transaction_type="Deposit",
            status="Completed",
            description=description,
            ip_address=request.remote_addr,
        )

        flash("Deposit completed successfully.", "success")
        return redirect(url_for("account.dashboard"))

    return render_template("deposit.html", accounts=accounts, form=request.form)


@account_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        first_name = (request.form.get("firstname") or "").strip()
        last_name = (request.form.get("lastname") or "").strip()
        username = (request.form.get("username") or "").strip()
        phone = request.form.get("phone")
        address = request.form.get("address")
        date_of_birth = request.form.get("dob") or None

        if not first_name or not last_name or not username:
            return render_template(
                "profile.html",
                error="First name, last name, and username are required.",
                max_dob=max_date_of_birth(),
                mfa_enabled=bool(get_user_by_id(current_user.id)["mfa_enabled"]),
            )

        updated_user, error = update_user_profile(
            current_user.id,
            first_name,
            last_name,
            username,
            phone=phone,
            address=address,
            date_of_birth=date_of_birth,
        )

        if error:
            return render_template(
                "profile.html",
                error=error,
                max_dob=max_date_of_birth(),
                mfa_enabled=bool(get_user_by_id(current_user.id)["mfa_enabled"]),
            )

        # Redirect (rather than re-render) so the page reloads current_user
        # fresh from the database -- otherwise the page would keep showing
        # the pre-update values for this request.
        flash("Your profile has been updated.", "success")
        return redirect(url_for("account.profile"))

    return render_template(
        "profile.html",
        max_dob=max_date_of_birth(),
        mfa_enabled=bool(get_user_by_id(current_user.id)["mfa_enabled"]),
    )


@account_bp.route("/profile/password", methods=["POST"])
@login_required
def change_password():
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_new_password = request.form.get("confirm_new_password", "")

    if not current_password or not new_password or not confirm_new_password:
        flash("Please fill in all three password fields.", "danger")
        return redirect(url_for("account.profile"))

    if new_password != confirm_new_password:
        flash("New passwords do not match.", "danger")
        return redirect(url_for("account.profile"))

    success, error = change_user_password(current_user.id, current_password, new_password)

    if not success:
        flash(error, "danger")
        return redirect(url_for("account.profile"))

    flash("Your password has been changed successfully.", "success")
    return redirect(url_for("account.profile"))


@account_bp.route("/profile/mfa", methods=["POST"])
@login_required
def update_mfa():
    enabled = request.form.get("mfa_enabled") == "on"

    set_user_mfa_enabled(current_user.id, enabled)
    record_audit_log(
        current_user.id,
        "MFA_ENABLED" if enabled else "MFA_DISABLED",
        "users",
        f"User {'enabled' if enabled else 'disabled'} email OTP for login.",
        request.remote_addr,
        request.headers.get("User-Agent", ""),
    )
    get_db().commit()

    flash(
        "Multi-Factor Authentication (Email OTP) is now Enabled." if enabled
        else "Multi-Factor Authentication (Email OTP) is now Disabled.",
        "success",
    )
    return redirect(url_for("account.profile"))