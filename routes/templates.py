from flask import render_template, Blueprint

from utils.session import login_required, is_logged_in

main_blueprint = Blueprint("main", __name__)


@main_blueprint.route("/", methods=["GET"])
def home():
    return render_template("index.html", is_logged_in=is_logged_in())


@main_blueprint.route("/register", methods=["GET"])
def register():
    return render_template("register.html")


@main_blueprint.route("/confirm_email", methods=["GET"])
def confirm_email():
    return render_template("confirm-email.html")


@main_blueprint.route("/login", methods=["GET"])
def login():
    return render_template("login.html")


@main_blueprint.route("/settings", methods=["GET"])
@login_required
def settings():
    return render_template("settings.html")


@main_blueprint.route("/change_password", methods=["GET"])
@login_required
def change_password():
    return render_template("change-password.html")


@main_blueprint.route("/enable_totp", methods=["GET"])
@login_required
def enable_totp():
    return render_template("enable-totp.html")


@main_blueprint.route("/disable_totp", methods=["GET"])
@login_required
def disable_totp():
    return render_template("disable-totp.html")


@main_blueprint.route("/profile/<username>", methods=["GET"])
def profile(username):
    return render_template("profile.html", username=username, is_logged_in=is_logged_in())


@main_blueprint.route("/request_reset_password", methods=["GET"])
def request_reset_password():
    return render_template("request-reset-password.html")


@main_blueprint.route("/reset_password/<username>/<reset_secret>", methods=["GET"])
def reset_password(username, reset_secret):
    return render_template("reset-password.html", username=username, reset_secret=reset_secret)
