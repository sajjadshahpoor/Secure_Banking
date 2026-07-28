from flask_wtf import CSRFProtect
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta

try:
    from flask_talisman import Talisman
except ModuleNotFoundError:
    class Talisman:
        def init_app(self, app, *args, **kwargs):
            return app


csrf = CSRFProtect()

login_manager = LoginManager()
login_manager.session_protection = "strong"

limiter = Limiter(
    key_func=get_remote_address,
    # Raised from 200/day, 50/hour -- the 50/hour default was blocking
    # normal red-team/blue-team testing traffic. The per-route limits on
    # sensitive endpoints (login, register, OTP, password reset, etc.,
    # each decorated individually in routes/auth.py) are unaffected by
    # this and still apply.
    default_limits=["200000 per day", "10000 per hour"]
)

talisman = Talisman()