from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..db import (
    VALID_EVENT_STATUSES,
    VALID_SEVERITIES,
    count_audit_logs,
    count_login_history,
    count_security_events,
    count_users,
    get_audit_logs,
    get_db,
    get_login_history,
    get_security_event_by_id,
    get_security_events,
    get_soc_summary,
    get_user_account_types,
    get_user_accounts,
    get_user_by_id,
    get_users,
    now_timestamp,
    record_audit_log,
    set_user_active,
    unlock_user_login,
    update_security_event_status,
)
from ..decorators import admin_required
from .account import OPENABLE_ACCOUNT_TYPES


soc_bp = Blueprint(
    "soc",
    __name__,
    url_prefix="/soc",
)

# Once an event is Closed, the UI hides its status form entirely -- treat
# that as a one-way transition server-side too, not just in the template.
EVENT_STATUS_TRANSITIONS = {
    "Open": {"Investigating", "Closed"},
    "Investigating": {"Closed"},
    "Closed": set(),
}

PAGE_SIZE = 20


def _page_from_args(param_name: str) -> int:
    try:
        page = int(request.args.get(param_name, 1))
    except ValueError:
        page = 1
    return max(page, 1)


def _total_pages(total: int) -> int:
    return max(1, -(-total // PAGE_SIZE))


@soc_bp.route("/")
@login_required
@admin_required
def dashboard():
    severity = request.args.get("severity") or None
    status = request.args.get("status") or None

    has_bank_account = bool(get_user_accounts(current_user.id))
    available_account_types = []
    if not has_bank_account:
        existing_types = get_user_account_types(current_user.id)
        available_account_types = [t for t in OPENABLE_ACCOUNT_TYPES if t not in existing_types]

    events_page = _page_from_args("events_page")
    audit_page = _page_from_args("audit_page")
    login_page = _page_from_args("login_page")
    users_page = _page_from_args("users_page")
    user_search = request.args.get("user_search") or None

    events_total = count_security_events(severity=severity, status=status)
    audit_total = count_audit_logs()
    login_total = count_login_history()
    users_total = count_users(search=user_search)

    return render_template(
        "soc.html",
        summary=get_soc_summary(),
        security_events=get_security_events(
            limit=PAGE_SIZE,
            offset=(events_page - 1) * PAGE_SIZE,
            severity=severity,
            status=status,
        ),
        audit_logs=get_audit_logs(limit=PAGE_SIZE, offset=(audit_page - 1) * PAGE_SIZE),
        login_history=get_login_history(limit=PAGE_SIZE, offset=(login_page - 1) * PAGE_SIZE),
        users=get_users(limit=PAGE_SIZE, offset=(users_page - 1) * PAGE_SIZE, search=user_search),
        severities=VALID_SEVERITIES,
        statuses=VALID_EVENT_STATUSES,
        selected_severity=severity,
        selected_status=status,
        has_bank_account=has_bank_account,
        available_account_types=available_account_types,
        events_page=events_page,
        events_total_pages=_total_pages(events_total),
        audit_page=audit_page,
        audit_total_pages=_total_pages(audit_total),
        login_page=login_page,
        login_total_pages=_total_pages(login_total),
        users_page=users_page,
        users_total_pages=_total_pages(users_total),
        user_search=user_search,
        now=now_timestamp(),
    )


@soc_bp.route("/events/<event_id>/status", methods=["POST"])
@login_required
@admin_required
def update_event_status(event_id):
    new_status = request.form.get("status")

    if new_status not in VALID_EVENT_STATUSES:
        abort(400)

    event = get_security_event_by_id(event_id)
    if event is None:
        abort(404)

    if new_status not in EVENT_STATUS_TRANSITIONS.get(event["status"], set()):
        flash(f"Can't move an event from {event['status']} to {new_status}.", "danger")
        return redirect(url_for("soc.dashboard"))

    update_security_event_status(event_id, new_status)
    record_audit_log(
        current_user.id,
        "SECURITY_EVENT_STATUS_UPDATED",
        "security_events",
        f"Security event {event_id} marked as {new_status}.",
        request.headers.get("X-Forwarded-For", request.remote_addr),
        request.headers.get("User-Agent", ""),
    )
    get_db().commit()

    flash(f"Event marked as {new_status}.", "success")
    return redirect(url_for("soc.dashboard"))


@soc_bp.route("/users/<user_id>/deactivate", methods=["POST"])
@login_required
@admin_required
def deactivate_user(user_id):
    if user_id == current_user.id:
        flash("You can't deactivate your own account.", "danger")
        return redirect(url_for("soc.dashboard"))

    target = get_user_by_id(user_id)
    if target is None:
        abort(404)

    set_user_active(user_id, False)
    record_audit_log(
        current_user.id,
        "USER_DEACTIVATED",
        "users",
        f"Deactivated account {target['email']}.",
        request.headers.get("X-Forwarded-For", request.remote_addr),
        request.headers.get("User-Agent", ""),
    )
    get_db().commit()

    flash(f"{target['email']} has been deactivated.", "success")
    return redirect(url_for("soc.dashboard"))


@soc_bp.route("/users/<user_id>/reactivate", methods=["POST"])
@login_required
@admin_required
def reactivate_user(user_id):
    target = get_user_by_id(user_id)
    if target is None:
        abort(404)

    set_user_active(user_id, True)
    record_audit_log(
        current_user.id,
        "USER_REACTIVATED",
        "users",
        f"Reactivated account {target['email']}.",
        request.headers.get("X-Forwarded-For", request.remote_addr),
        request.headers.get("User-Agent", ""),
    )
    get_db().commit()

    flash(f"{target['email']} has been reactivated.", "success")
    return redirect(url_for("soc.dashboard"))


@soc_bp.route("/users/<user_id>/unlock", methods=["POST"])
@login_required
@admin_required
def unlock_user(user_id):
    target = get_user_by_id(user_id)
    if target is None:
        abort(404)

    unlock_user_login(user_id)
    record_audit_log(
        current_user.id,
        "USER_UNLOCKED",
        "users",
        f"Cleared the brute-force lockout on {target['email']}.",
        request.headers.get("X-Forwarded-For", request.remote_addr),
        request.headers.get("User-Agent", ""),
    )
    get_db().commit()

    flash(f"{target['email']} has been unlocked.", "success")
    return redirect(url_for("soc.dashboard"))
