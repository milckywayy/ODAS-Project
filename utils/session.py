from functools import wraps

from flask import session, jsonify

from utils.database import check_if_user_exist_by_username


def is_logged_in():
    username = session.get('username')
    if username is not None:
        if check_if_user_exist_by_username(username):
            return True
    return False


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            return jsonify({"error": "Unauthorized", "message": "User not logged in"}), 401
        return f(*args, **kwargs)
    return decorated_function
