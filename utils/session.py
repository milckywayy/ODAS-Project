from functools import wraps

from flask import request, session, jsonify
from redis import RedisError

from extensions import redis_client
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
    session_id = request.cookies.get('session')
    if session_id:
        redis_client.set(
            f"{session_id}:verification_token",
            verification_token,
            ex=Config.VERIFICATION_TOKEN_TTL
        )

def get_verification_token():
    try:
        session_id = request.cookies.get('session')
        if not session_id:
            return None
        token = redis_client.get(f"{session_id}:verification_token")
        return token.decode("utf-8") if token else None
    except RedisError:
        return None

def remove_verification_token():
    session_id = request.cookies.get('session')
    if session_id:
        redis_client.delete(f"{session_id}:verification_token")
