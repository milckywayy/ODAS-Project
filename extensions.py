import firebase_admin
from firebase_admin import credentials, firestore

from config import Config
from utils.cache import Cache

cred = credentials.Certificate("credentials/firestore.json")
firebase_admin.initialize_app(cred)
db = firestore.client()
cache = Cache()


def init_extensions(app):
    app.config["SECRET_KEY"] = Config.SECRET_KEY
    app.config['STORAGE'] = cache
