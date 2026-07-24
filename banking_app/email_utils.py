import smtplib
from email.message import EmailMessage

from flask import current_app


def send_email(recipient: str, subject: str, body: str, reply_to: str | None = None) -> bool:
    app = current_app._get_current_object()
    sender = app.config.get("EMAIL_FROM", "no-reply@bank.com")
    smtp_host = app.config.get("SMTP_HOST")
    smtp_port = app.config.get("SMTP_PORT", 587)
    smtp_username = app.config.get("SMTP_USERNAME")
    smtp_password = app.config.get("SMTP_PASSWORD")
    use_tls = app.config.get("SMTP_USE_TLS", True)

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = recipient
    if reply_to:
        message["Reply-To"] = reply_to
    message.set_content(body)

    if not smtp_host:
        # No mail server configured (e.g. local dev without SMTP set up) --
        # log the actual content so the OTP is still retrievable, instead of
        # just noting that nothing was sent.
        app.logger.warning(
            "SMTP_HOST is not configured. Email to %s was not sent. Subject: %s\n%s",
            recipient, subject, body,
        )
        return False

    try:
        app.logger.info("Sending OTP email to %s with subject %s", recipient, subject)
        if use_tls:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
                smtp.starttls()
                if smtp_username and smtp_password:
                    smtp.login(smtp_username, smtp_password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as smtp:
                if smtp_username and smtp_password:
                    smtp.login(smtp_username, smtp_password)
                smtp.send_message(message)
        return True
    except Exception as exc:
        app.logger.error("Failed to send OTP email to %s: %s", recipient, exc)
        return False


def send_registration_otp(recipient: str, otp: str) -> bool:
    subject = "Your Bank Account Verification Code"
    body = (
        "Welcome to Bank of Belgium!\n\n"
        f"Code: {otp}\n\n"
        "The code expires in 10 minutes."
    )
    return send_email(recipient, subject, body)


def send_transfer_otp(recipient: str, otp: str, amount: float, recipient_name: str, recipient_account: str) -> bool:
    subject = "Bank Transfer Authorization Code"
    body = (
        "A transfer from your bank account requires authorization.\n\n"
        f"Recipient: {recipient_name}\n"
        f"Account number: {recipient_account}\n"
        f"Amount: €{amount:.2f}\n\n"
        f"Code: {otp}\n\n"
        "The code expires in 10 minutes."
    )
    return send_email(recipient, subject, body)


def send_login_otp(recipient: str, otp: str) -> bool:
    subject = "Your Login Verification Code"
    body = (
        "Someone (hopefully you) is signing in to your Bank of Belgium account.\n\n"
        f"Code: {otp}\n\n"
        "The code expires in 10 minutes. If this wasn't you, do not share this "
        "code and consider changing your password."
    )
    return send_email(recipient, subject, body)


def send_password_reset_otp(recipient: str, otp: str) -> bool:
    subject = "Your Password Reset Code"
    body = (
        "A password reset was requested for your Bank of Belgium account.\n\n"
        f"Code: {otp}\n\n"
        "The code expires in 10 minutes. If you didn't request this, you can "
        "safely ignore this email."
    )
    return send_email(recipient, subject, body)


def send_support_message(recipient: str, name: str, sender_email: str, subject: str, body_text: str) -> bool:
    """Forward a "Send Us A Message" contact-form submission to the admin
    inbox. Reply-To is set to the customer's own address, so replying to the
    notification email goes straight back to them."""
    subject_line = f"[Support] {subject}"
    body = (
        f"New message from the contact form.\n\n"
        f"Name: {name}\n"
        f"Email: {sender_email}\n"
        f"Subject: {subject}\n\n"
        f"{body_text}"
    )
    return send_email(recipient, subject_line, body, reply_to=sender_email)
