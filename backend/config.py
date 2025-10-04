import os
from dotenv import load_dotenv

load_dotenv()




class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "carv-secret")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URI", "sqlite:///carv.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "carv-jwt")


    # Google OAuth
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
    # Distance limit for nearby restaurants (in km)
    RADIUS_LIMIT_KM = int(os.getenv("RADIUS_LIMIT_KM", 7))


    # Celery / Redis
    CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
    CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")


    # Payment (placeholder)
    PAYMENT_PROVIDER = os.getenv("PAYMENT_PROVIDER", "razorpay")
    RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "")
    RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "")

    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL","carv@food.com")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD","supersuperfast")