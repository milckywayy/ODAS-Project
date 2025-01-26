import logging

from flask import Flask

from extensions import init_extensions
from routes.auth import auth_blueprint


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

    return flask_app


if __name__ == "__main__":
    app = create_app()
    # app.run()
    app.run(debug=True)
