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
    default_limits=["200 per day", "50 per hour"]
)

talisman = Talisman()