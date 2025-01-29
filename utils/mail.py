from flask import url_for


def send_verification_mail(to, username, verification_code):
    confirmation_link = url_for('main.confirm_email', username=username, verification_token=verification_code, _external=True)
    print(f"SEND MAIL: Sending verification email to {to}. Confirmation link: {confirmation_link}")


def send_password_reset_mail(to, username, password_reset_code):
    reset_link = url_for('main.reset_password', username=username, reset_secret=password_reset_code, _external=True)
    print(f'SEND MAIL: Password reset email sent to {to} with link {reset_link}')


def send_new_device_login_mail(to, device_info):
    print(f'SEND MAIL: Login from new device for user {to}: {device_info}')
