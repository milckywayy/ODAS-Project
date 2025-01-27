from enum import Enum
import os


class Config:
    APP_NAME = "ODAS - Project"

    SECRET_KEY = os.getenv("SECRET_KEY", "jesiotr_syberyjski!")
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    VERIFICATION_TOKEN_TTL = 60 * 30  # 30 minutes
    TOTP_TOKEN_TTL = 60 * 30  # 30 minutes
    PASSWORD_RESET_TOKEN_TTL = 60 * 30  # 30 minutes


class Token(Enum):
    VERIFICATION = ("verification_token", 60 * 30)  # 30 minutes
    TOTP = ("totp_token", 60 * 30)  # 30 minutes
    PASSWORD_RESET = ("password_reset_token", 60 * 30)  # 30 minutes

    def __init__(self, token_name, ttl):
        self.token_name = token_name
        self.ttl = ttl
