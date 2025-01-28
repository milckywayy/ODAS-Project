import logging
from flask import Blueprint, request, jsonify, session, current_app
from user_agents import parse

from config import Token, Event
from utils.database import check_if_user_exist, add_pending_user, check_if_user_exist_by_username, \
    save_user_totp_secret, confirm_user, get_pending_user, remove_pending_user, \
    check_if_totp_active, get_username_by_email, set_password, check_if_user_exist_by_email, get_password, delete_user, \
    log_user_event, check_if_device_used, save_user_device
from utils.mail import send_verification_mail, send_password_reset_mail
from utils.ratelimiter import limiter
from utils.security import hash_password, check_password, generate_new_user_totp_secret, generate_password_reset_token
from utils.session import login_required
from utils.totp import verify_totp, generate_totp_uri
from utils.useragent import get_device_info
from utils.validation import is_valid_username, is_valid_email, is_valid_password

auth_blueprint = Blueprint("auth", __name__)


@auth_blueprint.route("/register", methods=["POST"])
@limiter.limit("10 per 10 minutes")
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
@limiter.limit("15 per 10 minutes")
def confirm_email(username, verification_token):
    if not username or not verification_token:
        return jsonify({"message": "No username or verification token were given"}), 400

    if not get_pending_user(username):
        logging.info(f"User {username} doesn't exist")
        return jsonify({"message": "Invalid data was given"}), 400

    correct_verification_token = current_app.config['STORAGE'].get(username, Token.VERIFICATION.token_name)
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
@limiter.limit("15 per 10 minutes")
def login():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')
    totp_code = data.get('totp_code')

    user_agent_string = request.headers.get('User-Agent')
    user_agent = parse(user_agent_string)
    device_info = get_device_info(user_agent)

    if not username or not password:
        return jsonify({"message": "No username or password were given"}), 400

    if not check_if_user_exist_by_username(username):
        logging.info(f"User {username} does not exist")
        return jsonify({"message": "Invalid credentials were given"}), 400

    hashed_password = get_password(username)

    if not check_password(password, hashed_password):
        log_user_event(username, Event.FAILED_LOGIN_ATTEMPT, user_agent_string)

        logging.info(f'User {username} tried to login with invalid password')
        return jsonify({"message": "Invalid credentials were given"}), 400

    totp_secret = check_if_totp_active(username)
    if totp_secret:
        if not totp_code:
            return jsonify({"message": "TOTP code is required"}), 400

        if not verify_totp(totp_code, totp_secret):
            return jsonify({"message": "Invalid TOTP code"}), 400

    log_user_event(username, Event.SUCCESSFUL_LOGIN_ATTEMPT, user_agent_string)

    if not check_if_device_used(username, device_info):
        save_user_device(username, device_info)
        log_user_event(username, Event.LOGIN_FROM_NEW_DEVICE, user_agent_string)

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


@auth_blueprint.route("/enable_totp", methods=["POST"])
@limiter.limit("15 per 10 minutes")
@login_required
def enable_totp():
    data = request.get_json()

    totp_code = data.get('totp_code')
    username = session.get('username')

    user_agent_string = request.headers.get('User-Agent')

    if check_if_totp_active(username):
        return jsonify({"message": "TOTP verification already active"}), 400

    if not totp_code or not current_app.config['STORAGE'].get(username, Token.TOTP.token_name):
        new_user_totp_secret = generate_new_user_totp_secret()
        current_app.config['STORAGE'].set(
            username,
            Token.TOTP.token_name,
            new_user_totp_secret,
            ttl=Token.TOTP.ttl
        )

        totp_uri = generate_totp_uri(new_user_totp_secret)

        return jsonify({"message": "TOTP uri has been generated", "totp_uri": totp_uri}), 200

    totp_secret = current_app.config['STORAGE'].get(username, Token.TOTP.token_name)
    if not verify_totp(totp_code, totp_secret):
        return jsonify({"message": "Invalid TOTP code"}), 400

    log_user_event(username, Event.TOTP_VERIFICATION_ON, user_agent_string)
    logging.info(f'TOTP verification turned on for {username}')

    current_app.config['STORAGE'].delete(username, Token.TOTP.token_name)
    save_user_totp_secret(username, totp_secret)
    return jsonify({"message": "TOTP verification has been enabled"}), 200


@auth_blueprint.route("/disable_totp", methods=["POST"])
@limiter.limit("15 per 10 minutes")
@login_required
def disable_totp():
    data = request.get_json()

    username = session.get('username')
    password = data.get('password')
    totp_code = data.get('totp_code')

    user_agent_string = request.headers.get('User-Agent')

    if not username or not password:
        return jsonify({"message": "Password is required to disable TOTP"}), 400

    if not check_if_user_exist_by_username(username):
        logging.info(f"TOTP disable requested for nonexistent user: {username}")
        return jsonify({"message": "Invalid credentials"}), 400

    stored_password = get_password(username)
    if not check_password(password, stored_password):
        logging.info(f"User {username} provided an invalid password for disabling TOTP")
        return jsonify({"message": "Invalid credentials"}), 400

    totp_secret = check_if_totp_active(username)
    if totp_secret:
        if not totp_code:
            return jsonify({"message": "TOTP code is required"}), 400

        if not verify_totp(totp_code, totp_secret):
            return jsonify({"message": "Invalid TOTP code"}), 400

    log_user_event(username, Event.TOTP_VERIFICATION_OFF, user_agent_string)
    logging.info(f'TOTP verification turned off for {username}')

    save_user_totp_secret(username, None)
    logging.info(f"TOTP authentication disabled for user {username}")
    return jsonify({"message": "TOTP authentication successfully disabled"}), 200


@auth_blueprint.route("/change_password", methods=["POST"])
@limiter.limit("10 per 10 minutes")
@login_required
def change_password():
    data = request.get_json()

    username = session.get('username')
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    totp_code = data.get('totp_code')

    user_agent_string = request.headers.get('User-Agent')

    if not username or not current_password or not new_password:
        return jsonify({"message": "Username, current password, and new password are required"}), 400

    if not is_valid_password(new_password):
        return jsonify({"message": "Invalid new password"}), 400

    if not check_if_user_exist_by_username(username):
        logging.info(f"Password change requested for nonexistent user: {username}")
        return jsonify({"message": "Invalid credentials"}), 400

    stored_password = get_password(username)
    if not check_password(current_password, stored_password):
        return jsonify({"message": "Invalid credentials"}), 400

    totp_secret = check_if_totp_active(username)
    if totp_secret:
        if not totp_code:
            return jsonify({"message": "TOTP code is required"}), 400

        if not verify_totp(totp_code, totp_secret):
            return jsonify({"message": "Invalid TOTP code"}), 400

    set_password(username, hash_password(new_password))

    log_user_event(username, Event.PASSWORD_CHANGED, user_agent_string)
    logging.info(f"Password changed successfully for user {username}")

    return jsonify({"message": "Password changed successfully"}), 200


@auth_blueprint.route("/request_password_reset", methods=["POST"])
@limiter.limit("10 per 10 minutes")
def request_password_reset():
    data = request.get_json()

    email = data.get('email')
    token = data.get('token')
    new_password = data.get('new_password')
    totp_code = data.get('totp_code')

    user_agent_string = request.headers.get('User-Agent')

    if not is_valid_email(email):
        return jsonify({"message": "Invalid email"}), 400

    if not check_if_user_exist_by_email(email):
        logging.info(f"Password reset requested for nonexistent email: {email}")
        return jsonify({"message": "If the email exists, a reset link will be sent"}), 200

    username = get_username_by_email(email)

    if token and new_password:
        totp_secret = check_if_totp_active(username)
        if totp_secret:
            if not totp_code:
                return jsonify({"message": "TOTP code is required"}), 400

            if not verify_totp(totp_code, totp_secret):
                return jsonify({"message": "Invalid TOTP code"}), 400

        if not is_valid_password(new_password):
            return jsonify({"message": "Invalid password"}), 400

        correct_token = current_app.config['STORAGE'].get(username, Token.PASSWORD_RESET.token_name)

        if token != correct_token:
            return jsonify({"message": "Invalid token"}), 400

        set_password(username, hash_password(new_password))

        log_user_event(username, Event.PASSWORD_CHANGED, user_agent_string)
        logging.info(f"Password changed successfully for user {username}")

        return jsonify({"message": "Password reset successful"}), 200

    else:
        reset_token = generate_password_reset_token()
        logging.info(f"Generate password reset token {reset_token} for user {email}")

        current_app.config['STORAGE'].set(
            username,
            Token.PASSWORD_RESET.token_name,
            reset_token,
            ttl=Token.PASSWORD_RESET.ttl
        )
        logging.info(f"Password reset token generated for {email}")

        send_password_reset_mail(email, reset_token)
        logging.info(f"Password reset email sent to {email}")

        return jsonify({"message": "If the email exists, a reset link will be sent"}), 200
