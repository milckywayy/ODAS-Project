from datetime import datetime

from google.cloud import firestore
from google.cloud.firestore_v1 import FieldFilter

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


def delete_user(identifier):
    # identifier: The username or email of the user to delete.

    user_ref = db.collection("users").document(identifier)
    user_doc = user_ref.get()

    if not user_doc.exists:
        users_ref = db.collection("users")
        query = users_ref.where("email", "==", identifier).stream()

        user_found = None
        for doc in query:
            user_found = doc.id
            break

        if not user_found:
            raise ValueError("User does not exist.")

        user_ref = db.collection("users").document(user_found)
        identifier = user_found

    devices_ref = user_ref.collection("devices")
    devices_query = devices_ref.where("username", "==", identifier).stream()
    for device in devices_query:
        devices_ref.document(device.id).delete()

    events_ref = user_ref.collection("events")
    events_query = events_ref.where("username", "==", identifier).stream()
    for event in events_query:
        events_ref.document(event.id).delete()

    user_ref.delete()


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


def get_email_by_username(username, check_not_confirmed=False):
    users_ref = db.collection("users")
    query = users_ref.document(username).get()

    if query.exists:
        return query.to_dict().get("email")

    if check_not_confirmed:
        pending_ref = db.collection("pending_users")
        query_pending = pending_ref.document(username).get()

        if query_pending.exists:
            email = query_pending.to_dict().get("email")

            verification_token = current_app.config['STORAGE'].get(username, Token.VERIFICATION.token_name)
            if not verification_token:
                remove_pending_user(username)
                return None
            else:
                return email

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


def remove_user_totp_secret(username):
    doc_ref = db.collection("users").document(username)
    doc = doc_ref.get()

    if not doc.exists:
        raise ValueError("User does not exist")

    doc_ref.update({
        "totp_secret": firestore.DELETE_FIELD
    })


def log_user_event(username, event, details):
    event_data = {
        "username": username,
        "event_type": event.event_name,
        "details": details,
        "timestamp": datetime.now().strftime("%H:%M:%S %d-%m-%Y")
    }

    db.collection("users").document(username).collection('events').add(event_data)


def save_user_device(username, device_info):
    device_data = {
        "username": username,
        "device_info": device_info,
    }

    db.collection("users").document(username).collection("devices").add(device_data)


def check_if_device_used(username, device_info):
    devices_ref = db.collection("users").document(username).collection("devices")
    query = devices_ref.where("device_info", "==", device_info).stream()

    for _ in query:
        return True

    return False


def get_user_profile(username):
    user_ref = db.collection("users").document(username)
    user_doc = user_ref.get()

    if not user_doc.exists:
        return None

    user_data = user_doc.to_dict()

    user_data["username"] = user_doc.id
    user_data["email"] = user_data.get("email")
    user_data["totp_enabled"] = check_if_totp_active(username)

    for key, value in user_data.items():
        if isinstance(value, bytes):
            try:
                user_data[key] = value.decode("utf-8")
            except UnicodeDecodeError:
                user_data[key] = str(value)

    devices_ref = user_ref.collection("devices")
    devices = [device.to_dict() for device in devices_ref.stream()]
    user_data["devices"] = devices

    events_ref = user_ref.collection("events")
    events = [event.to_dict() for event in events_ref.stream()]
    user_data["events"] = events

    return user_data


def save_message(username, title, content, is_public):
    message_data = {
        "title": title,
        "content": content,
        "is_public": is_public,
        "timestamp": firestore.SERVER_TIMESTAMP
    }
    db.collection("users").document(username).collection("messages").add(message_data)


def get_user_messages(username, show_all=False):
    messages_ref = db.collection("users").document(username).collection("messages")
    if show_all:
        query = messages_ref.stream()
    else:
        query = messages_ref.where("is_public", "==", True).stream()

    return [{"id": msg.id, **msg.to_dict()} for msg in query]


def get_all_messages(show_all=False):
    users_ref = db.collection("users").stream()
    messages = []
    for user in users_ref:
        messages_ref = db.collection("users").document(user.id).collection("messages")
        if show_all:
            query = messages_ref.stream()
        else:
            query = messages_ref.where("is_public", "==", True).stream()

        messages.extend([{"id": msg.id, "username": user.id, **msg.to_dict()} for msg in query])

    return messages


def update_message(username, message_id, title, content, is_public):
    message_ref = db.collection("users").document(username).collection("messages").document(message_id)
    message_ref.update({
        "title": title,
        "content": content,
        "is_public": is_public,
        "timestamp": firestore.SERVER_TIMESTAMP
    })
