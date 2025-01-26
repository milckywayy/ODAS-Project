import logging
from flask import Blueprint, request, jsonify, session, redirect
from utils.database import check_if_user_exist, add_pending_user, check_if_user_exist_by_username, \
    get_user_password_hash, \
    save_user_totp_secret, confirm_user, get_pending_user, remove_pending_user, \
    check_if_totp_active
from utils.mail import send_verification_mail
from utils.security import hash_password, check_password, generate_new_user_totp_secret
from utils.session import get_verification_token, login_required, store_verification_token, remove_verification_token
from utils.totp import verify_totp, generate_totp_uri
from utils.validation import is_valid_username, is_valid_email, is_valid_password

auth_blueprint = Blueprint("auth", __name__)


@auth_blueprint.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not is_valid_username(username):
        return jsonify({"message": "Invalid username"}), 400

    if not is_valid_email(email):
        return jsonify({"message": "Invalid email"}), 400

    if not is_valid_password(password):
        return jsonify({"message": "Invalid password"}), 400

    if check_if_user_exist(username, email, check_not_confirmed=True):
        logging.info(f"User {username} already exists")
        return jsonify({"message": "User already exists"}), 400

    verification_code = add_pending_user(username, email, hash_password(password))
    logging.info(f"User with username {username} has been saved and now is waiting for verification")

    send_verification_mail(email, verification_code)
    logging.info(f"Verification code {verification_code} sent to {email}")

    return jsonify({'message': 'User successfully registered. Check your mailbox for verification code'}), 200


@auth_blueprint.route("/confirm_email/<username>/<verification_token>", methods=["GET"])
def confirm_email(username, verification_token):
    if not username or not verification_token:
        return jsonify({"message": "No username or verification token were given"}), 400

    if not get_pending_user(username):
        logging.info(f"User {username} doesn't exist")
        return jsonify({"message": "Invalid data was given"}), 400

    correct_verification_token = get_verification_token()
    if not correct_verification_token:
        remove_pending_user(username)
        return jsonify({"message": "Verification token has expired"}), 400

    if verification_token != correct_verification_token:
        return jsonify({"message": "Invalid data was given"}), 400

    try:
        confirm_user(username)
    except ValueError as e:
        logging.error(e)
        return jsonify({"message": "Invalid data was given"}), 400

    return jsonify({"message": "Email successfully confirmed"}), 200


@auth_blueprint.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')
    totp_code = data.get('totp_code')

    if not username or not password:
        return jsonify({"message": "No username or password were given"}), 400

    if not check_if_user_exist_by_username(username):
        logging.info(f"User {username} does not exist")
        return jsonify({"message": "Invalid credentials were given"}), 400

    hashed_password = get_user_password_hash(username)

    # TODO Implement invalid login try latency

    if not check_password(password, hashed_password):
        logging.info(f'User {username} tried to login with invalid password')
        return jsonify({"message": "Invalid credentials were given"}), 400

    totp_secret = check_if_totp_active(username)
    if totp_secret:
        if not totp_code:
            return jsonify({"message": "TOTP code is required"}), 400

        if not verify_totp(totp_code, totp_secret):
            return jsonify({"message": "Invalid TOTP code"}), 400

    session['username'] = username
    return jsonify({"message": "Login successful"}), 200


@auth_blueprint.route("/logout", methods=["GET"])
@login_required
def logout():
    session.pop('username', None)
    return jsonify({"message": "Logout successful"}), 200


@auth_blueprint.route('/test_session', methods=["GET"])
@login_required
def test_session():
    return jsonify({"message": "You're authorized!"}), 200


@auth_blueprint.route("/generate-totp-code", methods=["POST"])
@login_required
def enable_totp():
    data = request.get_json()

    totp_code = data.get('totp_code')
    username = session.get('username')

    if check_if_totp_active(username):
        return jsonify({"message": "TOTP verification already active"}), 400

    if not totp_code or not get_verification_token():
        new_user_totp_secret = generate_new_user_totp_secret()
        store_verification_token(new_user_totp_secret)

        totp_uri = generate_totp_uri(new_user_totp_secret)

        return jsonify({"message": "TOTP uri has been generated", "totp_uri": totp_uri}), 200

    totp_secret = get_verification_token()
    if not verify_totp(totp_code, totp_secret):
        return jsonify({"message": "Invalid TOTP code"}), 400

    remove_verification_token()
    save_user_totp_secret(username, totp_secret)
    return jsonify({"message": "TOTP verification has been enabled"}), 200
