from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timedelta
import bcrypt
import secrets
import string

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    
    # Email verification fields
    is_email_verified = db.Column(db.Boolean, default=False, nullable=False)
    verification_code = db.Column(db.String(6), nullable=True)
    verification_code_expires = db.Column(db.DateTime, nullable=True)
    
    # Payment fields
    has_paid = db.Column(db.Boolean, default=False, nullable=False)
    payment_date = db.Column(db.DateTime, nullable=True)
    stripe_customer_id = db.Column(db.String(100), nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        """Check password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def generate_verification_code(self):
        """Generate 6-digit verification code"""
        self.verification_code = ''.join(secrets.choice(string.digits) for _ in range(6))
        self.verification_code_expires = datetime.utcnow() + timedelta(minutes=5)
        return self.verification_code
    
    def is_verification_code_valid(self, code):
        """Check if verification code is valid and not expired"""
        if not self.verification_code or not self.verification_code_expires:
            return False
        
        if datetime.utcnow() > self.verification_code_expires:
            return False
            
        return self.verification_code == code
    
    def verify_email(self):
        """Mark email as verified and clear verification code"""
        self.is_email_verified = True
        self.verification_code = None
        self.verifiacation_code_expires = None
    
    def __repr__(self):
        return f'<User {self.email}>'