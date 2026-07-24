import os
from pathlib import Path

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix


def load_local_env() -> None:
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


load_local_env()

from .config import Config
from .extentions import csrf, login_manager, limiter, talisman

from .db import init_app, init_db, get_user_by_id, user_has_role
from .models import User


def create_app():

    app = Flask(__name__)

    # docker-compose puts exactly one reverse proxy (nginx) in front of the
    # app. ProxyFix trusts only that single hop's X-Forwarded-For/-Proto
    # headers and rewrites request.remote_addr/request.scheme accordingly,
    # so the rest of the app can trust those values directly instead of
    # reading X-Forwarded-For itself -- which a client could otherwise set
    # to any value they like and have it recorded as-is in security/audit
    # logs.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0, x_port=0, x_prefix=0)

    app.config.from_object(Config)

    # SESSION_COOKIE_SECURE=true is this app's own signal that it's running
    # somewhere beyond local/lab use (see config.py). The default SECRET_KEY
    # is public (it's committed in .env.example) and also derives the key
    # that encrypts stored card numbers, so refuse to boot with it in that
    # case rather than silently running with a well-known secret.
    if app.config.get("SESSION_COOKIE_SECURE") and app.config.get("SECRET_KEY") == "dev-secret-change-me":
        raise RuntimeError(
            "SESSION_COOKIE_SECURE is enabled but SECRET_KEY is still the default "
            "'dev-secret-change-me'. Set a real, random SECRET_KEY in the environment "
            "before running this app anywhere beyond local/lab use."
        )

    csrf.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    limiter.init_app(app)
    talisman.init_app(app,
    force_https=False,
    content_security_policy={
        "default-src": "'self'",
        "style-src": [
            "'self'",
            "https://cdn.jsdelivr.net"
        ],
        # No 'unsafe-inline' -- every inline <script> block in the
        # templates now carries a per-request nonce (via {{ csp_nonce() }})
        # instead, so only scripts the server itself emitted can run.
        # (Browsers that understand nonce-source ignore 'unsafe-inline'
        # when both are present anyway, so leaving it out is also just
        # the honest description of what's actually enforced.)
        "script-src": [
            "'self'",
            "https://cdn.jsdelivr.net"
        ],
        "img-src": [
            "'self'",
            "data:"
        ],
        "font-src": [
            "'self'"
        ]
    },
    content_security_policy_nonce_in=["script-src"],
)


    init_app(app)

    with app.app_context():
        init_db()

        # (Re)seeds instance/bank_archive_2025.sqlite3 with realistic-looking
        # fake customer data on every boot (deterministic, same data each
        # time). The schema lives in banking_app/honeypot_seed/, not the
        # gitignored instance/ folder, so it travels with the repo.
        from .create_honey_database import populate_honey_database
        populate_honey_database()


    @login_manager.user_loader
    def load_user(user_id):
        user = get_user_by_id(user_id)

        # A deactivated account's existing session is invalidated on its
        # very next request, not just blocked at the next login attempt.
        if user and user["is_active"]:
            return User(user)

        return None


    from .routes.auth import auth_bp
    from .routes.main import main_bp
    from .routes.account import account_bp
    from .routes.banking import banking_bp
    from .routes.support import support_bp
    from .routes.soc import soc_bp
    from .routes.argus import argus_bp
    from .routes.admin import admin_bp


    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(account_bp)
    app.register_blueprint(banking_bp)
    app.register_blueprint(support_bp)
    app.register_blueprint(soc_bp)
    # Deception routes (CTF honeypot: ARGUS) -- see routes/argus.py and
    # routes/admin.py. Exempted from CSRF on purpose: a genuinely insecure
    # "unsupported legacy" panel wouldn't have modern CSRF protection, and
    # exempting it means non-browser tooling (curl, scripts) can interact
    # with it too, without needing to first fetch a token.
    app.register_blueprint(argus_bp)
    app.register_blueprint(admin_bp)
    csrf.exempt(argus_bp)
    csrf.exempt(admin_bp)

    #print(app.url_map)


    @app.context_processor
    def inject_is_admin():
        from flask_login import current_user

        if current_user.is_authenticated:
            return {"is_admin": user_has_role(current_user.id, "Admin")}
        return {"is_admin": False}


    return app


#app = create_app()


if __name__ == "__main__":
    create_app().run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )