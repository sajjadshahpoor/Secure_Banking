from flask import Blueprint, render_template


main_bp = Blueprint(
    "main",
    __name__
)


@main_bp.route("/")
def home():
    return render_template("home.html")


@main_bp.route("/security")
def security():
    return render_template("security.html")


@main_bp.route("/terms")
def terms():
    return render_template("terms.html")


@main_bp.route("/privacy")
def privacy():
    return render_template("privacy.html")