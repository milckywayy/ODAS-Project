import base64
import re


def is_valid_username(username):
    # Min. 3 characters, maximum 30 characters. Only letters, numbers, and underscores
    if not username:
        return False
    return bool(re.fullmatch(r'^[a-zA-Z0-9_]{3,30}$', username))


def is_valid_email(email):
    # Function to check if the email is valid.
    if not email:
        return False
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.fullmatch(email_regex, email))


def is_valid_password(password):
    # Min 14 characters. At least one letter, one digit, and one special character
    if not password or len(password) < 14:
        return False
    return (
        any(char.isdigit() for char in password) and
        any(char.isalpha() for char in password) and
        any(char in '!@#$%^&*()-_=+[]{};:,<.>/?' for char in password)
    )


def is_valid_public_key(public_key):
    if not public_key:
        return False

    if not (public_key.startswith("-----BEGIN PUBLIC KEY-----") and
            public_key.endswith("-----END PUBLIC KEY-----")):
        return False

    return True
