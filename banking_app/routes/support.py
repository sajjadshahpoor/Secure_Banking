from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from ..db import get_db, record_audit_log, valid_email
from ..email_utils import send_support_message


support_bp = Blueprint(
    "support",
    __name__
)


@support_bp.route("/support", methods=["GET", "POST"])
def support():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        subject = (request.form.get("subject") or "").strip()
        message_body = (request.form.get("message") or "").strip()

        if not name or not email or not subject or not message_body:
            flash("Please fill in every field before sending your message.", "danger")
            return render_template("support.html", form=request.form)

        if not valid_email(email):
            flash("Please enter a valid email address.", "danger")
            return render_template("support.html", form=request.form)

        recipient = current_app.config.get("SUPPORT_NOTIFICATION_EMAIL", "no-reply@bank.com")
        sent = send_support_message(recipient, name, email, subject, message_body)

        # Recorded regardless of email delivery, so a submission is never
        # lost purely because SMTP isn't configured -- it's still visible
        # in the audit log.
        record_audit_log(
            None,
            "SUPPORT_MESSAGE_SUBMITTED",
            "support",
            f"Contact form message from {name} <{email}>: {subject}",
            request.remote_addr,
            request.headers.get("User-Agent", ""),
        )
        get_db().commit()

        if sent:
            flash("Thanks for reaching out -- we've received your message and will respond within 24 hours.", "success")
        else:
            flash(
                "Your message was received, but we couldn't email our support team right now "
                "(mail isn't configured). We'll still follow up as soon as possible.",
                "warning",
            )
        return redirect(url_for("support.support"))

    return render_template("support.html", form=request.form)