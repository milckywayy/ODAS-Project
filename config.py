from enum import Enum
import os


class Config:
    APP_NAME = "ODAS - Project"

    SECRET_KEY = os.getenv("SECRET_KEY", "jesiotr_syberyjski!")
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    VERIFICATION_TOKEN_TTL = 60 * 30  # 30 minutes
    TOTP_TOKEN_TTL = 60 * 30  # 30 minutes
    PASSWORD_RESET_TOKEN_TTL = 60 * 30  # 30 minutes

    ALLOWED_TAGS = ["b", "i", "strong", "em", "img"]


class Token(Enum):
    VERIFICATION = ("verification_token", 60 * 30)  # 30 minutes
    TOTP = ("totp_token", 60 * 30)  # 30 minutes
    PASSWORD_RESET = ("password_reset_token", 60 * 30)  # 30 minutes

    def __init__(self, token_name, ttl):
        self.token_name = token_name
        self.ttl = ttl


class Event(Enum):
    FAILED_LOGIN_ATTEMPT = 'Failed login attempt'
    SUCCESSFUL_LOGIN_ATTEMPT = 'Successful login attempt'
    LOGIN_FROM_NEW_DEVICE = 'Login from new device'
    PASSWORD_CHANGED = 'Password changed'
    TOTP_VERIFICATION_ON = 'TOTP verification turned on'
    TOTP_VERIFICATION_OFF = 'TOTP verification turned off'

    def __init__(self, event_name):
        self.event_name = event_name
