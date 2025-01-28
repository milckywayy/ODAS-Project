import logging

from flask import request, session, jsonify, Blueprint

from utils.database import get_password, check_if_totp_active, delete_user, check_if_user_exist_by_username
from utils.security import check_password
from utils.session import login_required
from utils.totp import verify_totp

account_blueprint = Blueprint("account", __name__)


@account_blueprint.route("/delete_account", methods=["DELETE"])
@login_required
def delete_account():
    data = request.get_json()

    username = session.get('username')
    password = data.get('password')
    totp_code = data.get('totp_code')

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    if not check_if_user_exist_by_username(username):
        logging.info(f"Account deletion requested for nonexistent user: {username}")
        return jsonify({"message": "Invalid credentials"}), 400

    stored_password = get_password(username)
    if not check_password(password, stored_password):
        logging.info(f"User {username} provided invalid password for account deletion")
        return jsonify({"message": "Invalid credentials"}), 400

    totp_secret = check_if_totp_active(username)
    if totp_secret:
        if not totp_code:
            return jsonify({"message": "TOTP code is required"}), 400

        if not verify_totp(totp_code, totp_secret):
            return jsonify({"message": "Invalid TOTP code"}), 400

    try:
        delete_user(username)
        session.pop('username', None)
        logging.info(f"Account for user {username} successfully deleted")
        return jsonify({"message": "Account successfully deleted"}), 200
    except Exception as e:
        logging.error(f"Error deleting user {username}: {e}")
        return jsonify({"message": "An error occurred while deleting the account"}), 500
