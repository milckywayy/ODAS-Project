import os


class Config:
    APP_NAME = "ODAS - Project"

    SECRET_KEY = os.getenv("SECRET_KEY", "jesiotr_syberyjski!")
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    VERIFICATION_TOKEN_TTL = 60 * 30 # 30 minutes
