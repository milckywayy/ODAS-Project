import pyotp
import qrcode
from flask import current_app


def generate_totp_uri(totp_secret):
    totp_instance = pyotp.TOTP(totp_secret)
    totp_uri = totp_instance.provisioning_uri(name=current_app.config['APP_NAME'])

    qr = qrcode.make(totp_uri)
    qr.show()

    return totp_uri


def verify_totp(user_code, totp_secret):
    totp_instance = pyotp.TOTP(totp_secret)

    return totp_instance.verify(user_code, valid_window=1)
