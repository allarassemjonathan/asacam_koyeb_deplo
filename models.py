from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timedelta
import bcrypt
import secrets
import string
import sqlite3
from contextlib import contextmanager

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
    
    # Subscription fields
    stripe_customer_id = db.Column(db.String(100), nullable=True)
    stripe_subscription_id = db.Column(db.String(100), nullable=True)
    subscription_status = db.Column(db.String(50), nullable=True)
    subscription_start_date = db.Column(db.DateTime, nullable=True)
    subscription_end_date = db.Column(db.DateTime, nullable=True)
    
    # Camera plan field (NEW)
    num_cameras = db.Column(db.Integer, default=1, nullable=False)
    
    # Keep old fields for compatibility
    has_paid = db.Column(db.Boolean, default=False, nullable=False)
    payment_date = db.Column(db.DateTime, nullable=True)
    
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
        self.verification_code_expires = None
    
    @property
    def has_active_subscription(self):
        """Check if user has an active subscription"""
        return self.subscription_status in ['active', 'incomplete']
    
    @property
    def monthly_cost(self):
        """Calculate monthly cost based on number of cameras"""
        return self.num_cameras * 1.00  # $1 per camera
    
    def __repr__(self):
        return f'<User {self.email}>'

import sqlite3

class CameraDatabase:
    def __init__(self, db_path='cameras.db'):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Initialize the database with the cameras table"""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS cameras (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    link TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
        finally:
            conn.close()
    
    def add_camera(self, name, link):
        """Add a new camera to the database"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute(
                'INSERT INTO cameras (name, link) VALUES (?, ?)',
                (name, link)
            )
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def get_all_cameras(self):
        """Get all cameras from the database"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute('SELECT * FROM cameras ORDER BY name')
            cameras = cursor.fetchall()
            return [dict(camera) for camera in cameras]
        finally:
            conn.close()
    
    def search_cameras(self, query):
        """Search cameras by name or link"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute(
                'SELECT * FROM cameras WHERE name LIKE ? OR link LIKE ? ORDER BY name',
                (f'%{query}%', f'%{query}%')
            )
            cameras = cursor.fetchall()
            return [dict(camera) for camera in cameras]
        finally:
            conn.close()
    
    def get_camera_by_id(self, camera_id):
        """Get a specific camera by ID"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute(
                'SELECT * FROM cameras WHERE id = ?',
                (camera_id,)
            )
            camera = cursor.fetchone()
            return dict(camera) if camera else None
        finally:
            conn.close()
    
    def update_camera(self, camera_id, name, link):
        """Update an existing camera"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute(
                'UPDATE cameras SET name = ?, link = ? WHERE id = ?',
                (name, link, camera_id)
            )
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def delete_camera(self, camera_id):
        """Delete a camera by ID"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute('DELETE FROM cameras WHERE id = ?', (camera_id,))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()