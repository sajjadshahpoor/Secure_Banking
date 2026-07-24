"""import os

from flask import Flask, redirect, render_template, request, session, url_for
from flask_wtf import CSRFProtect
from flask_login import LoginManager, login_user,logout_user,login_required
from models import User

from db import authenticate_user, create_user, get_user_by_id,init_app, init_db,record_logout,update_user_profile


app = Flask(__name__)
csrf = CSRFProtect(app)

app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

app.config["DATABASE"] = os.path.join(app.instance_path, "banking.sqlite3")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # True when using HTTPS
)

app.debug = True

os.makedirs(app.instance_path, exist_ok=True)
init_app(app)

with app.app_context():
    init_db()

login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    user = get_user_by_id(user_id)

    if user:
        return User(user)

    return None



@app.route("/")
def home():
    return render_template("home.html")

@app.route("/security")
def security():
    return render_template("security.html")


@limiter.limit("5 per minute")
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        login = request.form["login"]
        password = request.form["password"]

        user, error = authenticate_user(
            login,
            password,
            request.headers.get("X-Forwarded-For", request.remote_addr),
            request.headers.get("User-Agent", ""),
        )

        if user is not None:
            user_obj = User(user)
            login_user(user_obj)
            session["logged_in"] = True
            session["user_id"] = user["id"]
            session["user"] = user["email"]
            session["user_name"] = f"{user['first_name']} {user['last_name']}"

            return redirect(url_for("dashboard"))

        return render_template("login.html", error=error)

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        firstname = request.form["firstname"]
        lastname = request.form["lastname"]
        username = request.form.get("username")
        email = request.form["email"]
        phone = request.form.get("phone")
        address = request.form.get("address")
        date_of_birth = request.form.get("dob")
        account_type = request.form["account_type"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            return render_template("register.html", error="Passwords do not match.")

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
        )

        if user is None:
            return render_template("register.html", error=error)

        session["registered_username"] = username or user["username"]
        return redirect(url_for("login"))


    return render_template("register.html")

@app.route("/accounts")
def accounts():
    return render_template("accounts.html")

@app.route("/investment")
def investment():
    return render_template("investment.html")

@app.route("/support")
def support():
    return render_template("support.html")

@app.route("/loan")
def loan():
    return render_template("loan.html")

@app.route("/dashboard")
@login_required
def dashboard():

    return render_template(
        "dashboard.html",
        username=session.get("user_name", session.get("user", "Customer"))
    )


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    if not user_id:
        session.clear()
        return redirect(url_for("login"))

    user = get_user_by_id(user_id)
    if user is None:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        updated_user, error = update_user_profile(
            user_id=user_id,
            first_name=request.form["firstname"],
            last_name=request.form["lastname"],
            username=request.form["username"],
            phone=request.form.get("phone"),
            address=request.form.get("address"),
            date_of_birth=request.form.get("dob"),
        )

        if updated_user is None:
            return render_template("profile.html", user=user, error=error)

        session["user_name"] = f"{updated_user['first_name']} {updated_user['last_name']}"
        return render_template("profile.html", user=updated_user, success="Profile updated successfully.")

    return render_template("profile.html", user=user)

@app.route("/transfer")
@login_required
def transfer():
    return render_template("transfer.html")

@app.route("/logout")
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
    return redirect(url_for("home"))




if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
"""