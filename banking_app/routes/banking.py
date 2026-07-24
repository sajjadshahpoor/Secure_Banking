
from flask import Blueprint, render_template


banking_bp = Blueprint(
    "banking",
    __name__
)
@banking_bp.route("/account")
def account():
    return render_template("accounts.html")


@banking_bp.route("/investment")
def investment():
    return render_template("investment.html")

@banking_bp.route("/loan")
def loan():
    return render_template("loan.html")