from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import session, jsonify

from config import Config


def is_logged_in():
    return session.get('username')


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            return jsonify({"error": "Unauthorized", "message": "User not logged in"}), 401
        return f(*args, **kwargs)
    return decorated_function


def store_verification_token(verification_token):
    session['verification_token'] = {
        "token": verification_token,
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=Config.VERIFICATION_TOKEN_TTL)).isoformat()
    }


def get_verification_token():
    token_data = session.get('verification_token')
    if not token_data:
        return None
    expires_at = datetime.fromisoformat(token_data.get("expires_at"))
    if datetime.now(timezone.utc) > expires_at:
        remove_verification_token()
        return None
    return token_data.get("token")


def remove_verification_token():
    session.pop('verification_token', None)
