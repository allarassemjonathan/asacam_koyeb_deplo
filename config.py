import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # key for forms and sessions
    SECRET_KEY= os.environ.get('SECRET_KEY') or 'mysecret'

    # db config
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # stripe db
    STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY')
    STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')

    # openai key
    OPEN_AI_KEY = os.environ.get('OPEN_AI_KEY')

    # payment
    PAYMENT_AMOUNT = 100

    # Email configuration (using Gmail SMTP)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')  # App password, not regular password
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_USERNAME')

    # Verification code expiry (5 minutes)
    VERIFICATION_CODE_EXPIRY = 300


