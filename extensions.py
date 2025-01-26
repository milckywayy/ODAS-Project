import firebase_admin
from firebase_admin import credentials, firestore

from config import Config


cred = credentials.Certificate("credentials/firestore.json")
firebase_admin.initialize_app(cred)
db = firestore.client()


def init_extensions(app):
    app.config["SECRET_KEY"] = Config.SECRET_KEY
