from config import Token
from extensions import db
from utils.security import generate_verification_token

from flask import current_app


def add_pending_user(username, email, password):
    if check_if_user_exist(username, email):
        raise ValueError("Username or email is already taken.")

    doc_ref = db.collection("pending_users").document(username)

    doc_ref.set({
        "email": email,
        "password": password,
    })

    verification_token = generate_verification_token()
    current_app.config['STORAGE'].set(
        username,
        Token.VERIFICATION.token_name,
        verification_token,
        ttl=Token.VERIFICATION.ttl
    )

    print(current_app.config['STORAGE'].get(username, Token.VERIFICATION.token_name))

    return verification_token


def remove_pending_user(username):
    doc_ref = db.collection("pending_users").document(username)
    if not doc_ref.get().exists:
        return

    doc_ref.delete()
    current_app.config['STORAGE'].delete(username, Token.VERIFICATION.token_name)


def check_if_user_exist_by_username(username, check_not_confirmed=False):
    doc_ref = db.collection("users").document(username)
    doc = doc_ref.get()

    if doc.exists:
        return True

    if check_not_confirmed:
        pending_ref = db.collection("pending_users").document(username)
        pending_doc = pending_ref.get()

        if pending_doc.exists:
            verification_token = current_app.config['STORAGE'].get(username, Token.VERIFICATION.token_name)
            if not verification_token:
                remove_pending_user(username)
                return False
            else:
                return True

    return False


def check_if_user_exist_by_email(email, check_not_confirmed=False):
    users_ref = db.collection("users")
    query = users_ref.where("email", "==", email).stream()

    for _ in query:
        return True

    if check_not_confirmed:
        pending_ref = db.collection("pending_users")
        query_pending = pending_ref.where("email", "==", email).stream()

        for doc in query_pending:
            username = doc.to_dict().get("username")

            verification_token = current_app.config['STORAGE'].get(username, Token.VERIFICATION.token_name)
            if not verification_token:
                remove_pending_user(username)
                return False
            else:
                return True

    return False


def get_username_by_email(email, check_not_confirmed=False):
    users_ref = db.collection("users")
    query = users_ref.where("email", "==", email).stream()

    for doc in query:
        return doc.id

    if check_not_confirmed:
        pending_ref = db.collection("pending_users")
        query_pending = pending_ref.where("email", "==", email).stream()

        for doc in query_pending:
            username = doc.id

            verification_token = current_app.config['STORAGE'].get(username, Token.VERIFICATION.token_name)
            if not verification_token:
                remove_pending_user(username)
                return None
            else:
                return username

    return None


def set_password(username, password):
    user_ref = db.collection("users").document(username)
    user_doc = user_ref.get()

    if not user_doc.exists:
        raise ValueError("User does not exist.")

    user_ref.update({'password': password})


def get_password(username):
    user_ref = db.collection("users").document(username)
    user_doc = user_ref.get()

    if not user_doc.exists:
        raise ValueError("User does not exist.")

    return user_doc.get('password')


def check_if_user_exist(username, email, check_not_confirmed=False):
    return check_if_user_exist_by_username(username, check_not_confirmed) or check_if_user_exist_by_email(email, check_not_confirmed)


def get_user_password_hash(username):
    doc_ref = db.collection("users").document(username)
    doc = doc_ref.get()

    if not doc.exists:
        return None

    user_data = doc.to_dict()
    return user_data["password"]


def get_pending_user(username):
    user_ref = db.collection("pending_users").document(username)
    return user_ref


def confirm_user(username):
    doc_ref = db.collection("pending_users").document(username)

    doc = doc_ref.get()
    if not doc.exists:
        raise ValueError("Pending user not found.")

    doc_data = doc.to_dict()
    db.collection('users').document(username).set({
        'email': doc_data.get('email'),
        'password': doc_data.get('password')
    })

    remove_pending_user(username)


def check_if_totp_active(username):
    doc_ref = db.collection("users").document(username)
    doc = doc_ref.get()

    if not doc.exists:
        return None

    return doc.to_dict().get("totp_secret")


def save_user_totp_secret(username, totp_secret):
    doc_ref = db.collection("users").document(username)
    doc = doc_ref.get()

    if not doc.exists:
        raise ValueError("User does not exist")

    doc_ref.update({
        "totp_secret": totp_secret
    })
