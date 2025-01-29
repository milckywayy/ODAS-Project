import logging

from flask import Flask

from extensions import init_extensions
from routes.auth import auth_blueprint
from routes.account import account_blueprint
from routes.templates import login, register, home, confirm_email, settings, change_password, enable_totp, disable_totp

log_format = "%(asctime)s - %(levelname)s - %(funcName)s - %(message)s"

logging.basicConfig(
    level=logging.DEBUG,
    format=log_format,
    datefmt="%Y-%m-%d %H:%M:%S"
)


def create_app():
    flask_app = Flask(__name__)
    flask_app.config.from_object("config.Config")

    init_extensions(flask_app)

    flask_app.register_blueprint(auth_blueprint, url_prefix="/auth")
    flask_app.register_blueprint(account_blueprint, url_prefix="/account")

    flask_app.add_url_rule("/", view_func=home, methods=["GET"])
    flask_app.add_url_rule("/register", view_func=register, methods=["GET"])
    flask_app.add_url_rule("/confirm_email", view_func=confirm_email, methods=["GET"])
    flask_app.add_url_rule("/login", view_func=login, methods=["GET"])
    flask_app.add_url_rule("/settings", view_func=settings, methods=["GET"])
    flask_app.add_url_rule("/change-password", view_func=change_password, methods=["GET"])
    flask_app.add_url_rule("/enable-totp", view_func=enable_totp, methods=["GET"])
    flask_app.add_url_rule("/disable-totp", view_func=disable_totp, methods=["GET"])

    return flask_app


if __name__ == "__main__":
    app = create_app()
    # app.run()
    app.run(debug=True)
