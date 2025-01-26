import uuid
import pyotp
import bcrypt


def hash_password(password):
    # Returns password in bytes
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def check_password(password, hashed_password):
    # Takes hashed_password in bytes
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)


def generate_verification_token():
    return str(uuid.uuid4())


def generate_session_token():
    return str(uuid.uuid4())


def generate_new_user_totp_secret():
    return pyotp.random_base32()

