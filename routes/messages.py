import base64

import bleach
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, pss
from flask import Blueprint, request, jsonify, session, current_app
from utils.database import save_message, get_user_messages, get_all_messages, update_message, \
    get_public_key, check_if_user_exist_by_username
from utils.session import login_required, is_logged_in

messages_blueprint = Blueprint("messages", __name__)


@messages_blueprint.route("/add_message", methods=["POST"])
@login_required
def add_message():
    data = request.get_json()
    username = session.get("username")

    title = data.get("title")
    content = data.get("content")
    is_public = data.get("is_public", False)
    signature = data.get("signature")

    if not title or not content:
        return jsonify({"message": "Title and content are required"}), 400

    public_key_pem = get_public_key(username)
    if not public_key_pem:
        return jsonify({"message": "Public key not found"}), 400

    message_to_verify = title + content
    is_valid = verify_signature(public_key_pem, message_to_verify, signature)
    if not is_valid:
        return jsonify({"message": "Invalid signature"}), 400

    cleaned_content = bleach.clean(content, tags=current_app.config['ALLOWED_TAGS'], strip=True)

    save_message(username, title, cleaned_content, is_public, signature)
    return jsonify({"message": "Message added successfully"}), 201


@messages_blueprint.route("/get_user_messages/<username>", methods=["GET"])
def get_user_messages_endpoint(username):
    show_all = is_logged_in()
    user_messages = get_user_messages(username, show_all)

    return jsonify({"messages": user_messages}), 200


@messages_blueprint.route("/get_all_messages", methods=["GET"])
def get_all_messages_endpoint():
    show_all = is_logged_in()
    messages = get_all_messages(show_all)

    return jsonify({"messages": messages}), 200


@messages_blueprint.route("/edit_message/<message_id>", methods=["POST"])
@login_required
def edit_message(message_id):
    data = request.get_json()

    username = session.get("username")
    title = data.get("title")
    content = data.get("content")
    is_public = data.get("is_public", False)

    if not title or not content:
        return jsonify({"message": "Title and content are required"}), 400

    cleaned_content = bleach.clean(content, tags=current_app.config['ALLOWED_TAGS'], strip=True)
    update_message(username, message_id, title, cleaned_content, is_public)
    return jsonify({"message": "Message updated successfully"}), 200


def verify_signature(public_key_pem, message, signature):
    try:
        public_key = RSA.import_key(public_key_pem)
        message_hash = SHA256.new(message if isinstance(message, bytes) else message.encode())
        signature_bytes = base64.b64decode(signature)

        verifier = pss.new(public_key)
        verifier.verify(message_hash, signature_bytes)
        return True
    except (ValueError, TypeError) as e:
        print(f"Verification failed: {e}")
        return False


@messages_blueprint.route("/get_public_key/<username>", methods=["GET"])
def get_public_key_endpoint(username):
    if not check_if_user_exist_by_username(username):
        return jsonify({"message": "User not found"}), 404

    public_key = get_public_key(username)

    if not public_key:
        return jsonify({"message": "Public key not found"}), 404

    return jsonify({"username": username, "public_key": public_key}), 200
