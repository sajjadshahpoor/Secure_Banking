from flask import Blueprint, flash, render_template, request, redirect, url_for, session
from flask_login import login_user, logout_user, current_user, login_required
from ..extentions import limiter
from ..email_utils import send_login_otp, send_password_reset_otp, send_registration_otp

from ..models import User
from ..db import (
    OTP_PURPOSE_LOGIN,
    OTP_PURPOSE_PASSWORD_RESET,
    OTP_PURPOSE_REGISTRATION,
    authenticate_user,
    create_email_otp,
    create_user,
    get_db,
    get_user_by_email,
    get_user_by_id,
    mark_email_verified,
    max_date_of_birth,
    reset_user_password,
    validate_email_otp,
    record_audit_log,
    record_logout,
    record_security_event,
    user_has_role,
)


auth_bp = Blueprint(
    "auth",
    __name__
)


def _complete_login(user, mfa_verified: bool):
    """Establish the authenticated session once all required checks have
    passed -- password only (MFA off), or password + OTP (MFA on)."""
    session.clear()
    session.permanent = True

    login_user(User(user))
    session["user_id"] = user["id"]
    session["user_name"] = f"{user['first_name']} {user['last_name']}"

    record_audit_log(
        user["id"],
        "LOGIN_MFA_VERIFIED" if mfa_verified else "LOGIN_SUCCESS_NO_MFA",
        "users",
        "User completed the email verification code at login."
        if mfa_verified else
        "User logged in with MFA disabled (password only).",
        request.remote_addr,
        request.headers.get("User-Agent", ""),
    )
    get_db().commit()

    if user_has_role(user["id"], "Admin"):
        return redirect(url_for("soc.dashboard"))

    return redirect(url_for("account.dashboard"))


@auth_bp.route("/login", methods=["GET","POST"])
@limiter.limit("5 per minute")
def login():

    if request.method == "POST":

        user, error = authenticate_user(
            request.form["login"],
            request.form["password"],
            request.remote_addr,
            request.headers.get("User-Agent")
        )

        if user:
            if not user["mfa_enabled"]:
                # MFA is off for this account -- password alone is enough.
                return _complete_login(user, mfa_verified=False)

            # MFA is on: credentials are valid, but the session isn't
            # established yet -- a login verification code is still required.
            otp = create_email_otp(user["id"], OTP_PURPOSE_LOGIN)
            sent = send_login_otp(user["email"], otp)
            session.clear()
            session["pending_login_user_id"] = user["id"]

            if sent:
                flash("We've sent a verification code to your email to finish signing in.", "info")
            else:
                flash(
                    "We couldn't email your verification code (mail isn't configured). "
                    "Check the application logs for the code in development.",
                    "warning",
                )
            return redirect(url_for("auth.login_verify"))

        return render_template(
            "login.html",
            error=error
        )


    return render_template("login.html")


@auth_bp.route("/login/verify", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login_verify():
    user_id = session.get("pending_login_user_id")
    if not user_id:
        flash("Please log in again.", "info")
        return redirect(url_for("auth.login"))

    user = get_user_by_id(user_id)
    if user is None:
        session.pop("pending_login_user_id", None)
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()

        if not otp:
            return render_template("login_verify.html", error="Please enter the verification code.", email=user["email"])

        is_valid, error_msg = validate_email_otp(user_id, otp, OTP_PURPOSE_LOGIN)

        if not is_valid:
            record_security_event(
                user_id,
                "Failed Login Verification Code",
                "Medium",
                request.remote_addr,
                "login",
                f"Incorrect or expired login verification code entered for {user['email']}.",
                "Application",
                "Open",
            )
            get_db().commit()
            return render_template("login_verify.html", error=error_msg, email=user["email"])

        # Code confirmed -- now (and only now) actually establish the session.
        return _complete_login(user, mfa_verified=True)

    return render_template("login_verify.html", email=user["email"])


@auth_bp.route("/login/verify/resend", methods=["POST"])
@limiter.limit("3 per minute")
def login_resend_otp():
    user_id = session.get("pending_login_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = get_user_by_id(user_id)
    if user is None:
        session.pop("pending_login_user_id", None)
        return redirect(url_for("auth.login"))

    otp = create_email_otp(user_id, OTP_PURPOSE_LOGIN)
    send_login_otp(user["email"], otp)
    flash("A new verification code has been sent to your email.", "success")
    return redirect(url_for("auth.login_verify"))

@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():

    if request.method == "POST":

        firstname = request.form["firstname"]
        lastname = request.form["lastname"]
        username = request.form.get("username")
        email = request.form["email"].strip().lower()
        phone = request.form.get("phone")
        address = request.form.get("address")
        date_of_birth = request.form.get("dob")
        account_type = request.form["account_type"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        terms_accepted = request.form.get("terms_accepted") == "on"

        if password != confirm_password:
            return render_template("register.html", error="Passwords do not match.", max_dob=max_date_of_birth())

        if not terms_accepted:
            return render_template(
                "register.html",
                error="You must agree to the Terms & Conditions and Privacy Policy to create an account.",
                max_dob=max_date_of_birth(),
            )

        user, error = create_user(
            firstname,
            lastname,
            email,
            password,
            username=username,
            phone=phone,
            address=address,
            date_of_birth=date_of_birth,
            account_type=account_type,
            terms_accepted=terms_accepted,
        )

        if user is None:
            return render_template("register.html", error=error, max_dob=max_date_of_birth())

        otp = create_email_otp(user["id"], OTP_PURPOSE_REGISTRATION)
        sent = send_registration_otp(user["email"], otp)
        session["pending_verification_user_id"] = user["id"]

        if sent:
            flash("We've sent a 6-digit verification code to your email.", "info")
        else:
            flash(
                "Account created, but we couldn't email your verification code "
                "(mail isn't configured). Check the application logs for the code in development.",
                "warning",
            )
        return redirect(url_for("auth.verify_email"))

    return render_template("register.html", max_dob=max_date_of_birth())


@auth_bp.route("/verify-email", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def verify_email():
    user_id = session.get("pending_verification_user_id")
    if not user_id:
        flash("Please register or log in first.", "info")
        return redirect(url_for("auth.login"))

    user = get_user_by_id(user_id)
    if user is None:
        session.pop("pending_verification_user_id", None)
        return redirect(url_for("auth.register"))

    if user["email_verified"]:
        session.pop("pending_verification_user_id", None)
        flash("Your email is already verified. You can log in.", "success")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()

        if not otp:
            return render_template("verify_email.html", error="Please enter the verification code.", email=user["email"])

        is_valid, error_msg = validate_email_otp(user_id, otp, OTP_PURPOSE_REGISTRATION)

        if not is_valid:
            return render_template("verify_email.html", error=error_msg, email=user["email"])

        mark_email_verified(user_id)
        session.pop("pending_verification_user_id", None)

        flash("Your email has been verified. You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("verify_email.html", email=user["email"])


@auth_bp.route("/verify-email/resend", methods=["POST"])
@limiter.limit("3 per minute")
def resend_verification():
    user_id = session.get("pending_verification_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = get_user_by_id(user_id)
    if user is None or user["email_verified"]:
        return redirect(url_for("auth.login"))

    otp = create_email_otp(user_id, OTP_PURPOSE_REGISTRATION)
    send_registration_otp(user["email"], otp)
    flash("A new verification code has been sent to your email.", "success")
    return redirect(url_for("auth.verify_email"))


@auth_bp.route("/logout")
@login_required
def logout():
    user_id = session.get("user_id")
    if user_id:
        record_logout(
            user_id,
            request.headers.get("X-Forwarded-For", request.remote_addr),
            request.headers.get("User-Agent", ""),
        )
        logout_user()
    session.clear()
    return redirect(url_for("main.home"))

@auth_bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = get_user_by_email(email)

        if user:
            otp = create_email_otp(user["id"], OTP_PURPOSE_PASSWORD_RESET)
            send_password_reset_otp(user["email"], otp)
            session["reset_user_id"] = user["id"]
            # A fresh reset request must never inherit a stale "verified"
            # flag from an earlier completed/abandoned flow.
            session.pop("reset_verified", None)
            flash("A reset code has been sent to your email. Please check your inbox.", "success")
            return render_template("forgot_password.html", step="verify")
        else:
            flash("If this email exists in our system, you will receive a reset code.", "info")
            return render_template("forgot_password.html")

    return render_template("forgot_password.html")


@auth_bp.route("/forgot-password/verify", methods=["POST"])
@limiter.limit("5 per minute")
def forgot_password_verify():
    user_id = session.get("reset_user_id")
    if not user_id:
        flash("Session expired. Please start over.", "error")
        return redirect(url_for("auth.forgot_password"))

    otp = request.form.get("otp", "").strip()

    if not otp:
        return render_template("forgot_password.html", step="verify", error="Please enter the reset code.")

    is_valid, error_msg = validate_email_otp(user_id, otp, OTP_PURPOSE_PASSWORD_RESET)

    if not is_valid:
        return render_template("forgot_password.html", step="verify", error=error_msg)

    # Only this flag, set only here on a confirmed code, may unlock the
    # actual password change in forgot_password_reset() below.
    session["reset_verified"] = True
    return render_template("forgot_password.html", step="reset")


@auth_bp.route("/forgot-password/reset", methods=["POST"])
@limiter.limit("5 per minute")
def forgot_password_reset():
    user_id = session.get("reset_user_id")

    # reset_user_id alone is NOT proof of identity -- it's set the moment a
    # reset is requested, before any code is entered. Only forgot_password_
    # verify() sets reset_verified, and only after a correct OTP. Without
    # this check, anyone who knows a victim's email could skip straight to
    # this endpoint and set their password with no code at all.
    if not user_id or not session.get("reset_verified"):
        flash("Please verify your reset code before choosing a new password.", "error")
        return redirect(url_for("auth.forgot_password"))

    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not password or not confirm_password:
        return render_template("forgot_password.html", step="reset", error="Please enter a password.")

    if password != confirm_password:
        return render_template("forgot_password.html", step="reset", error="Passwords do not match.")

    if len(password) < 8:
        return render_template("forgot_password.html", step="reset", error="Password must be at least 8 characters long.")

    reset_user_password(user_id, password)
    record_audit_log(
        user_id,
        "PASSWORD_RESET_VIA_EMAIL",
        "users",
        "User reset their password via the forgot-password email code flow.",
        request.remote_addr,
        request.headers.get("User-Agent", ""),
    )
    get_db().commit()
    session.pop("reset_user_id", None)
    session.pop("reset_verified", None)

    flash("Your password has been reset successfully. You can now log in.", "success")
    return redirect(url_for("auth.login"))
