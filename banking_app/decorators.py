"""Reusable route decorators."""

from functools import wraps

from flask import abort, request
from flask_login import current_user

from .db import get_db, record_audit_log, record_security_event, user_has_role


def admin_required(view_func):
    """Restrict a view to authenticated users holding the Admin role.

    Unauthenticated users get Flask-Login's normal redirect-to-login
    behaviour (this decorator assumes @login_required already ran, or
    is combined with it). Authenticated non-admins get a 403, and the
    attempt is logged as a security event so the SOC page shows
    privilege-escalation attempts against itself.
    """

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(403)

        if not user_has_role(current_user.id, "Admin"):
            record_security_event(
                current_user.id,
                "Unauthorized Admin Access",
                "High",
                request.remote_addr,
                request.path,
                f"User {current_user.email} attempted to access an admin-only resource without the Admin role.",
                "Application",
                "Open",
            )
            record_audit_log(
                current_user.id,
                "ACCESS_DENIED",
                request.path,
                "Attempted to access an admin-only resource.",
                request.remote_addr,
                request.headers.get("User-Agent", ""),
            )
            get_db().commit()
            abort(403)

        return view_func(*args, **kwargs)

    return wrapped


__all__ = ["admin_required"]
