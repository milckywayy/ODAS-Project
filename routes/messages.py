import bleach
from flask import Blueprint, request, jsonify, session, current_app
from utils.database import save_message, get_user_messages, get_all_messages, update_message
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

    if not title or not content:
        return jsonify({"message": "Title and content are required"}), 400

    cleaned_content = bleach.clean(content, tags=current_app.config['ALLOWED_TAGS'], strip=True)

    save_message(username, title, cleaned_content, is_public)
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
