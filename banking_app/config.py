import os
from datetime import timedelta

class Config:
    # Falls back to a dev key locally so the app can boot without a .env
    # file, but you should always set a real SECRET_KEY via environment
    # variable / .env for anything beyond your own machine.
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    DATABASE = "instance/banking.sqlite3"

    EMAIL_FROM = os.environ.get("EMAIL_FROM", "no-reply@bank.com")
    # Where "Send Us A Message" contact-form submissions get forwarded.
    # Defaults to the same mailbox the app sends OTPs from, since that's the
    # one address already known to be configured and checked.
    SUPPORT_NOTIFICATION_EMAIL = os.environ.get("SUPPORT_NOTIFICATION_EMAIL", os.environ.get("EMAIL_FROM", "no-reply@bank.com"))
    # Where SOC alert emails get sent whenever record_security_event() fires.
    # Leave blank to disable email alerting (events still show up on /soc).
    SECURITY_ALERT_EMAIL = os.environ.get("SECURITY_ALERT_EMAIL")
    SMTP_HOST = os.environ.get("SMTP_HOST")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
    SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
    SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() in ("1", "true", "yes")

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Secure cookies are only ever sent over HTTPS. Hardcoding this to True
    # silently breaks login whenever the app is served over plain HTTP (e.g.
    # http://localhost:5000 in the lab). Default to False for local/lab use;
    # set SESSION_COOKIE_SECURE=true in the environment once the app sits
    # behind HTTPS.
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() in ("1", "true", "yes")

# Session expires after 5 minutes
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=5)
