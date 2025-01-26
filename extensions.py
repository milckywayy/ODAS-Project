import firebase_admin
from firebase_admin import credentials, firestore
from flask_redis import FlaskRedis
from flask_session import Session

from config import Config

redis_client = FlaskRedis()

cred = credentials.Certificate("credentials/firestore.json")
firebase_admin.initialize_app(cred)
db = firestore.client()


def init_extensions(app):
    redis_client.init_app(app)

    app.config["REDIS_URL"] = "redis://localhost:6379/0"  # Redis on localhost
    app.config["SESSION_TYPE"] = "redis"  # Use Redis as the session backend
    app.config["SESSION_PERMANENT"] = False  # Session expires when the browser is closed
    app.config["SESSION_USE_SIGNER"] = True  # Sign session IDs
    app.config["SESSION_KEY_PREFIX"] = "session:"  # Prefix for session keys in Redis
    app.config["SESSION_REDIS"] = redis_client  # Link Redis to session management
    app.config["SECRET_KEY"] = Config.SECRET_KEY  # Key for signing cookies

    # Initialize Redis and Flask-Session
    redis_client.init_app(app)
    Session(app)
