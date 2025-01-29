import pyotp
import qrcode
import io
import base64
from flask import current_app


def generate_totp_uri_and_qr(totp_secret):
    totp_instance = pyotp.TOTP(totp_secret)
    totp_uri = totp_instance.provisioning_uri(name=current_app.config['APP_NAME'])

    qr = qrcode.make(totp_uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()

    return totp_uri, qr_base64


def verify_totp(user_code, totp_secret):
    totp_instance = pyotp.TOTP(totp_secret)

    return totp_instance.verify(user_code, valid_window=1)
