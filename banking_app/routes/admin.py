from pathlib import Path

from flask import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    render_template,
    request,
    send_file,
)

from .argus import record_event


admin_bp = Blueprint(
    "admin",
    __name__,
)


@admin_bp.route("/admin", methods=["GET", "POST"])
def fake_admin():
    if request.method == "GET":
        record_event(
            event_type="ADMIN_HONEYPOT_VISIT",
            request=request,
            threat_score=20,
        )

        return render_template("admin_login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    record_event(
        event_type="ADMIN_HONEYPOT_LOGIN",
        request=request,
        threat_score=40,
        details={
            "username": username,
            "password_length": len(password),
        },
    )

    return (
        render_template(
            "admin_login.html",
            error=(
                "Additional verification required. "
                "Please contact your system administrator."
            ),
        ),
        401,
    )


@admin_bp.route("/config.json")
def fake_config():
    record_event(
        event_type="CONFIG_HONEYPOT_ACCESS",
        request=request,
        threat_score=30,
    )

    return jsonify(
        {
            "application": "Bank of Belgium Internal Services",
            "environment": "production",
            "database_host": "db-core.internal.local",
            "database": "customer_accounts",
            "database_user": "svc_backup",
            "database_password": "B0B-Vault-Prod-2026!",
            "internal_api": "/api/internal/accounts",
            "backup_path": "/backup/database.sqlite3",
        }
    )


@admin_bp.route("/backup/database.sqlite3")
def download_honey_database():
    database_path = (
        Path(current_app.root_path).parent
        / "instance"
        / "bank_archive_2025.sqlite3"
    )

    record_event(
        event_type="DATABASE_HONEYPOT_DOWNLOAD",
        request=request,
        threat_score=60,
        details={
            "file": "bank_archive_2025.sqlite3",
            "exists": database_path.exists(),
        },
    )

    if not database_path.exists():
        abort(404)

    return send_file(
        database_path,
        as_attachment=True,
        download_name="customer_accounts_backup_2025.sqlite3",
        mimetype="application/vnd.sqlite3",
    )
