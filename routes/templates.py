from flask import render_template


def home():
    return render_template("index.html")


def register():
    return render_template("register.html")


def confirm_email():
    return render_template("confirm-email.html")


def login():
    return render_template("login.html")


def settings():
    return render_template("settings.html")


def change_password():
    return render_template("change-password.html")


def enable_totp():
    return render_template("enable-totp.html")


def disable_totp():
    return render_template("disable-totp.html")
