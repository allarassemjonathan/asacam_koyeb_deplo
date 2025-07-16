from flask import Flask, render_template, request, redirect, url_for, flash, session, current_app
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from models import db, User
from config import Config
import stripe
import secrets
import string
from datetime import datetime, timedelta
import openai
import os
from dotenv import load_dotenv
import redis
import json
import threading

from pathlib import Path
"""Basic connection example.
"""

import redis

redis_client = redis.Redis(
    host='redis-10368.c83.us-east-1-2.ec2.redns.redis-cloud.com',
    port=10368,
    decode_responses=True,
    username="default",
    password=os.environ.get('REDIS_PASS'),
)


redis_client.set('camera:url', 'None')
redis_client.set('camera:is_opened', 'False')
redis_client.set('camera:is_streaming', 'False')

load_dotenv()
# camera object to keep track of its state
class CameraState:
    is_streaming = False
    url = None
    camera = None

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
prompt="Act as a security monitor. Describe what you see and alert if anything dangerous is happening."
title='Security Monitoring'
triggers = 'danger, bad'
reporter = os.getenv('MAIL_USERNAME')

import cv2
print(cv2.getBuildInformation())

os.environ["OPENCV_FFMPEG_DEBUG"] = "1"
cap = cv2.VideoCapture("rtsp://...?...", cv2.CAP_FFMPEG)

# Initialize extensions
db.init_app(app)
mail = Mail(app)
api_key = app.config.get('OPEN_AI_KEY')
stripe.api_key = app.config.get('STRIPE_SECRET_KEY', 'placeholder')

def init_db():
    """Initialize database tables"""
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully")
        except Exception as e:
            print(f"Database initialization: {e}")
# Initialize database tables
init_db()

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_verification_code():
    """Generate 6-digit verification code"""
    return ''.join(secrets.choice(string.digits) for _ in range(6))

app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

def send_verification_email_for_registration(email, first_name, code):
    """Send verification code for registration"""
    msg = Message(
        subject='Verify Your Email - Registration Code',
        recipients=[email],
        body=f'''
Hello {first_name},

Your verification code is: {code}

This code will expire in 5 minutes.

If you didn't request this code, please ignore this email.

Best regards,
Your App Team
        '''
    )
    
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

@app.route('/api/prompt', methods=['POST'])
def update_prompt():
    global prompt, title, triggers, reporter
    
    try:
        # Get JSON data from the request
        data = request.get_json()
        
        # Check if data exists
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        
        # Extract mission title and prompt
        mission_title = data.get('mission_title', '').strip()
        mission_prompt = data.get('mission_prompt', '').strip()
        mission_triggers = data.get('mission_triggers', '').strip()
        mission_reporter = data.get('mission_reporter', '').strip()
        
        # Basic validation
        if not mission_title:
            return jsonify({
                'status': 'error',
                'message': 'Mission title is required'
            }), 400
            
        if not mission_prompt:
            return jsonify({
                'status': 'error',
                'message': 'Mission prompt is required'
            }), 400

        if not mission_triggers:
            return jsonify({
                'status': 'error',
                'message': 'Mission prompt is required'
            }), 400
        

        if not mission_reporter:
            return jsonify({
                'status': 'error',
                'message': 'Mission prompt is required'
            }), 400
        
        # Update global variables (modify this part based on your needs)
        current_mission_title = mission_title
        prompt = mission_prompt
        title = mission_title
        triggers = mission_triggers
        if mission_reporter and '@' in mission_reporter:
            reporter = mission_reporter

    
        # Log the received data (optional)
        print(f"Mission Title: {mission_title}")
        print(f"Mission Prompt: {mission_prompt}")
        print(f"Mission Triggers: {mission_triggers}")
        print(f"Mission Reporter: {mission_reporter}")

        # Return success response
        return jsonify({
            'status': 'success',
            'message': 'Mission created successfully',
            'data': {
                'mission_title': mission_title,
                'mission_prompt': mission_prompt,
                'mission_triggers': mission_triggers, 
                'mission_reporter': mission_reporter
            }
        }), 200
        
    except Exception as e:
        # Handle any errors
        print(f"Error in update_prompt: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500


@app.route('/')
def index():
    """Home page - redirects based on user status"""
    if current_user.is_authenticated:
        # All users in database are email verified, only check payment
        if current_user.has_paid or (hasattr(current_user, 'subscription_status') and current_user.subscription_status == 'active'):
    # Allow access
            return redirect(url_for('home'))
        else:
            return redirect(url_for('payment'))
    return redirect(url_for('login'))

@app.route('/mission')
@login_required
def mission():
    return render_template('mission.html', username=session.get('username'), prompt=prompt, date=datetime.now().strftime("%Y-%m-%d"), title=title, current_user=current_user)

# Add this near your other global variables
current_user_email = None
email_cooldown_time = 10
last_alert_email_time = 0

# Thread-safe email storage
user_email_storage = {}
user_email_lock = threading.Lock()
@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        email = request.form.get('email').lower().strip()
        password = request.form.get('password')
        
        if not email or not password:
            flash('Email and password are required.', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user)
            
            # DEBUG: Show user status
            print(f"=== LOGIN DEBUG ===")
            print(f"User: {user.email}")
            print(f"has_paid: {user.has_paid}")
            print(f"subscription_status: {getattr(user, 'subscription_status', 'NOT SET')}")
            
            # Check if user has canceled subscription FIRST
            if hasattr(user, 'subscription_status') and user.subscription_status == 'canceled':
                print("❌ User has canceled subscription - redirecting to reactivate")
                return redirect(url_for('reactivate_page'))
            
            # Check if user has paid or has active subscription
            has_access = (
                user.has_paid and 
                (not hasattr(user, 'subscription_status') or user.subscription_status in ['active', 'incomplete'])
            )
            
            print(f"has_access: {has_access}")
            
            if not has_access:
                print("❌ User has no access - redirecting to payment")
                return redirect(url_for('payment'))
            else:
                # Store in session manually
                session['username'] = user.first_name
                session['email'] = user.email
                
                # Store email for this session in thread-safe storage
                session_id = session.get('_id', str(time.time()))
                if '_id' not in session:
                    session['_id'] = session_id
                
                set_user_email_for_session(session_id, user.email)
                
                print(f"✅ User logged in successfully: {user.email}")
                return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html')

def send_alert_email_with_image(body, recipient_email, frame):
    """Send alert email to user with optional image attachment"""
    global reporter
    try:
        print('here x')
        print(reporter)
        # Create the MIME message
        msg = MIMEMultipart()
        msg['From'] = your_email
        msg['To'] = reporter
        msg['Subject'] = "🚨 SECURITY ALERT DETECTED"

        # Add an HTML body
        html = f"""
        <html>
        <body>
            <h2 style="color: black;"> Security Alert</h2>
            <p>We have reasons to believe that what you were monitoring for happened. In {email_cooldown_time} seconds we will send another email if the situation is not resolved</p>
            <p><strong>Alert Details:</strong></p>
            <div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 10px 0;">
                <p>{body}</p>
            </div>
            <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <br>
            {f'<p><strong>Alert Image:</strong> See attachment below</p>' if frame is not None else ''}
            <p>This alert was generated by ASACAM, your security monitoring system.</p>
        </body>
        </html>
        """
        print('here xx')
        msg.attach(MIMEText(html, 'html'))

        # Add image attachment if frame is provided
        if frame is not None:
            try:
                print('here xxx')
                # Encode frame as JPEG
                success, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 95])
                print('here xxxx')
                if success:
                    print('here xxxxx')
                    # Create image attachment
                    img_attachment = MIMEImage(buffer.tobytes())
                    img_attachment.add_header(
                        'Content-Disposition', 
                        f'attachment; filename="security_alert_{datetime.now().strftime("%Y%m%d_%H%M%S")}.jpg"'
                    )
                    msg.attach(img_attachment)
                    logger.info("📸 Image attached to alert email")
                else:
                    logger.warning("Failed to encode image for email attachment")
            except Exception as img_error:
                logger.error(f"Error attaching image to email: {img_error}")

        print('here xxxxxxxxx')
        # Connect to the SMTP server and send the email
        server = smtplib.SMTP(smtp_server, smtp_port)
        print('here xxxxxxxxx2')
        server.starttls()
        print('here xxxxxxxxx3')
        server.login(your_email, your_password)
        print('here xxxxxxxxx4')
        server.send_message(msg)
        print('here xxxxxxxxx5')
        server.quit()

        print(f"Alert email sent successfully to {recipient_email}")
        return True

    except Exception as e:
        print(f"Error sending alert email: {e}")
        return False

def send_alert_email(body, recipient_email):
    """Send alert email to user"""
    try:
        # Create the MIME message
        msg = MIMEMultipart()
        msg['From'] = your_email  # Use your_email instead of EMAIL_USER
        msg['To'] = recipient_email
        msg['Subject'] = "SECURITY ALERT DETECTED"

        # Add an HTML body
        html = f"""
        <html>
        <body>
            <h2>Security Alert</h2>
            <p><strong>Alert Details:</strong></p>
            <p>{body}</p>
            <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <br>
            <p>This alert was generated by your security monitoring system.</p>
        </body>
        </html>
        """
        msg.attach(MIMEText(html, 'html'))

        # Connect to the SMTP server and send the email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(your_email, your_password)
        server.send_message(msg)
        server.quit()

        print(f"Alert email sent successfully to {recipient_email}")
        return True

    except Exception as e:
        print(f"Error sending alert email: {e}")
        return False
    
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page - sends verification email first"""
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()
        
        # Validate input
        if not email or not password or not first_name or not last_name:
            flash('All fields are required', 'error')
            return render_template('register.html')
        
        # Check if user already exists in database
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('register.html')
        
        # Store registration data in session (NOT database)
        session['registration_data'] = {
            'email': email,
            'password': password,
            'first_name': first_name,
            'last_name': last_name
        }
        
        # Generate verification code
        verification_code = ''.join(secrets.choice(string.digits) for _ in range(6))
        session['verification_code'] = verification_code
        session['code_expires'] = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
        
        # Send verification email
        if send_verification_email_for_registration(email, first_name, verification_code):
            flash('Registration successful! Please check your email for the verification code.', 'success')
            return redirect(url_for('verify_email_for_payment'))
        else:
            flash('Failed to send verification email. Please try again.', 'error')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/verify-email-for-payment', methods=['GET', 'POST'])
def verify_email_for_payment():
    """Email verification before payment"""
    # Check if we have pending registration data
    if 'registration_data' not in session or 'verification_code' not in session:
        flash('No pending registration found. Please register again.', 'error')
        return redirect(url_for('register'))
    
    registration_data = session['registration_data']
    
    # Check if code has expired
    if 'code_expires' in session:
        code_expires = datetime.fromisoformat(session['code_expires'])
        if datetime.utcnow() > code_expires:
            # Clear expired session data
            session.pop('registration_data', None)
            session.pop('verification_code', None)
            session.pop('code_expires', None)
            flash('Verification code expired. Please register again.', 'error')
            return redirect(url_for('register'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'verify':
            entered_code = request.form.get('verification_code')
            
            if not entered_code:
                flash('Please enter the verification code.', 'error')
                return render_template('verify_email_for_payment.html', email=registration_data['email'])
            
            if entered_code == session['verification_code']:
                # Code is correct! Clear verification data and proceed to payment
                session.pop('verification_code', None)
                session.pop('code_expires', None)
                
                # Mark as verified in session
                session['email_verified'] = True
                
                flash('Email verified successfully! Please complete payment to create your account.', 'success')
                return redirect(url_for('payment'))
            else:
                flash('Invalid verification code.', 'error')
        
        elif action == 'resend':
            # Generate new code and send
            new_code = ''.join(secrets.choice(string.digits) for _ in range(6))
            
            if send_verification_email_for_registration(registration_data['email'], 
                                                       registration_data['first_name'], 
                                                       new_code):
                session['verification_code'] = new_code
                session['code_expires'] = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
                flash('New verification code sent!', 'success')
            else:
                flash('Failed to send new code. Please try again.', 'error')
    
    return render_template('verify_email_for_payment.html', email=registration_data['email'])


@app.route('/payment', methods=['GET', 'POST'])
def payment():
    """Payment page - creates user only after payment confirmation"""
    # Check if registration data exists in session
    if 'registration_data' not in session:
        flash('Please complete registration first.', 'error')
        return redirect(url_for('register'))
    
    # Check if email was verified
    if not session.get('email_verified'):
        flash('Please verify your email first.', 'error')
        return redirect(url_for('verify_email_for_payment'))
    
    registration_data = session['registration_data']
    
    if request.method == 'POST':
        try:
            # Create Stripe checkout session
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price': 'price_1Rkd2ZFr9wM1tN4f7UBbwR1y',  # Replace with your actual price_id
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=url_for('payment_success', _external=True),
                cancel_url=url_for('payment_cancel', _external=True),
                customer_email=registration_data['email'],
                metadata={
                    'registration_data': json.dumps(registration_data)
                }
            )
            
            return redirect(checkout_session.url, code=303)
            
        except stripe.error.StripeError as e:
            flash(f'Payment error: {str(e)}', 'error')
            return render_template('payment.html', user_data=registration_data)
    
    return render_template('payment.html', user_data=registration_data)

@app.route('/payment-success')
def payment_success():
    """Handle successful payment"""
    # Don't require login since user might not exist yet
    # Don't update user here - webhooks handle that
    flash('Subscription created successfully! Your account is being activated...', 'success')
    return render_template('payment_success.html')

@app.route('/payment-cancel')
@login_required
def payment_cancel():
    """Handle cancelled payment"""
    flash('Payment was cancelled. You can try again anytime.', 'info')
    return redirect(url_for('payment'))

@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    """Handle Stripe webhook events"""
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = json.loads(payload)
    except json.JSONDecodeError:
        return 'Invalid payload', 400
    
    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        handle_checkout_completed(session)
    
    elif event['type'] == 'customer.subscription.created':
        subscription = event['data']['object']
        handle_subscription_created(subscription)
    
    elif event['type'] == 'customer.subscription.updated':
        subscription = event['data']['object']
        handle_subscription_updated(subscription)
    
    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        handle_subscription_deleted(subscription)
    
    elif event['type'] == 'invoice.payment_succeeded':
        invoice = event['data']['object']
        handle_payment_succeeded(invoice)
    
    elif event['type'] == 'invoice.payment_failed':
        invoice = event['data']['object']
        handle_payment_failed(invoice)
    
    return 'Success', 200

def handle_checkout_completed(session):
    """Handle successful checkout - CREATE USER HERE"""
    print(f"=== CHECKOUT COMPLETED DEBUG ===")
    print(f"Session ID: {session.get('id')}")
    print(f"Customer ID: {session.get('customer')}")
    print(f"Session metadata: {session.get('metadata', {})}")
    
    if 'registration_data' in session.get('metadata', {}):
        try:
            # Get registration data from session metadata
            registration_data = json.loads(session['metadata']['registration_data'])
            print(f"Registration data found: {registration_data}")
            
            # Check if user already exists
            existing_user = User.query.filter_by(email=registration_data['email']).first()
            if existing_user:
                print(f"User already exists: {registration_data['email']}")
                return
            
            # Create the user in database ONLY after payment confirmation
            user = User(
                email=registration_data['email'],
                first_name=registration_data['first_name'],
                last_name=registration_data['last_name'],
                is_email_verified=True,  # Skip email verification since they paid
                stripe_customer_id=session['customer'],
                subscription_status='active',  # Set subscription status
                subscription_start_date=datetime.utcnow(),
                has_paid=True,  # IMPORTANT: Set has_paid to True
                payment_date=datetime.utcnow()
            )
            user.set_password(registration_data['password'])
            
            db.session.add(user)
            db.session.commit()
            
            print(f"✅ User created successfully: {user.email}")
            print(f"✅ has_paid: {user.has_paid}")
            print(f"✅ subscription_status: {user.subscription_status}")
            
        except Exception as e:
            print(f"❌ Error creating user after payment: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("❌ No registration_data found in session metadata")
        print(f"Available metadata keys: {list(session.get('metadata', {}).keys())}")

def handle_subscription_created(subscription):
    """Handle new subscription creation"""
    customer_id = subscription['customer']
    user = User.query.filter_by(stripe_customer_id=customer_id).first()
    
    if user:
        print(f"Updating user {user.email} with subscription ID: {subscription['id']}")
        user.stripe_subscription_id = subscription['id']
        user.subscription_status = subscription['status']
        user.subscription_start_date = datetime.fromtimestamp(subscription['created'])
        user.has_paid = True
        user.payment_date = datetime.fromtimestamp(subscription['created'])
        db.session.commit()
        print(f"✅ Subscription created for user {user.email}")
        print(f"✅ stripe_subscription_id: {user.stripe_subscription_id}")


def handle_subscription_updated(subscription):
    """Handle subscription status updates"""
    customer_id = subscription['customer']
    user = User.query.filter_by(stripe_customer_id=customer_id).first()
    
    if user:
        print(f"Subscription status changed to: {subscription['status']} for user: {user.email}")
        user.subscription_status = subscription['status']
        user.has_paid = (subscription['status'] in ['active', 'incomplete'])  # Update old field
        if subscription['status'] == 'canceled':
            user.subscription_end_date = datetime.fromtimestamp(subscription['canceled_at'])
        db.session.commit()
        print(f"✅ Subscription updated for user {user.email}: {subscription['status']}")

def handle_subscription_deleted(subscription):
    """Handle subscription cancellation"""
    customer_id = subscription['customer']
    user = User.query.filter_by(stripe_customer_id=customer_id).first()
    
    if user:
        user.subscription_status = 'canceled'
        user.has_paid = False  # Update old field
        user.subscription_end_date = datetime.fromtimestamp(subscription['canceled_at'])
        db.session.commit()
        print(f"✅ Subscription canceled for user {user.email}")

def handle_payment_succeeded(invoice):
    """Handle successful payment"""
    customer_id = invoice['customer']
    user = User.query.filter_by(stripe_customer_id=customer_id).first()
    
    if user:
        # Update subscription status if not already active
        if not hasattr(user, 'subscription_status') or user.subscription_status != 'active':
            user.subscription_status = 'active'
        user.has_paid = True  # Update old field
        user.payment_date = datetime.utcnow()
        db.session.commit()
        print(f"✅ Payment succeeded for user {user.email}")

def handle_payment_failed(invoice):
    """Handle failed payment"""
    customer_id = invoice['customer']
    user = User.query.filter_by(stripe_customer_id=customer_id).first()
    
    if user:
        if hasattr(user, 'subscription_status'):
            user.subscription_status = 'past_due'
        user.has_paid = False  # Update old field
        db.session.commit()
        print(f"✅ Payment failed for user {user.email}")

@app.route('/cancel-subscription', methods=['GET', 'POST'])
@login_required
def cancel_subscription():
    """Cancel user's subscription"""
    print(f"=== CANCEL SUBSCRIPTION DEBUG ===")
    print(f"User: {current_user.email}")
    print(f"has_paid: {current_user.has_paid}")
    print(f"subscription_status: {getattr(current_user, 'subscription_status', 'NOT SET')}")
    print(f"stripe_subscription_id: {getattr(current_user, 'stripe_subscription_id', 'NOT SET')}")
    print(f"stripe_customer_id: {getattr(current_user, 'stripe_customer_id', 'NOT SET')}")
    
    # Check if user has an active subscription (handle both old and new users)
    has_active_subscription = (
        current_user.has_paid or 
        (hasattr(current_user, 'subscription_status') and current_user.subscription_status in ['active', 'incomplete'])
    )
    
    if not has_active_subscription:
        print("❌ User does not have active subscription")
        flash('You do not have an active subscription to cancel.', 'error')
        return redirect(url_for('home'))
    
    # Find subscription ID if missing
    if not current_user.stripe_subscription_id and current_user.stripe_customer_id:
        try:
            print("Looking up subscription for customer...")
            subscriptions = stripe.Subscription.list(
                customer=current_user.stripe_customer_id,
                status='active'
            )
            
            if subscriptions.data:
                subscription_id = subscriptions.data[0].id
                print(f"Found subscription: {subscription_id}")
                
                # Update user with the subscription ID
                current_user.stripe_subscription_id = subscription_id
                db.session.commit()
            else:
                print("❌ No active subscriptions found")
                flash('No active subscription found to cancel.', 'error')
                return redirect(url_for('home'))
        except stripe.error.StripeError as e:
            print(f"❌ Error looking up subscription: {e}")
            flash('Error accessing subscription information.', 'error')
            return redirect(url_for('home'))
    
    # Check if subscription is already set to cancel at period end
    pending_cancellation = False
    if current_user.stripe_subscription_id:
        try:
            subscription = stripe.Subscription.retrieve(current_user.stripe_subscription_id)
            pending_cancellation = subscription.cancel_at_period_end
            print(f"Pending cancellation: {pending_cancellation}")
        except stripe.error.StripeError as e:
            print(f"Error checking subscription: {e}")
    
    if request.method == 'POST':
        action = request.form.get('action')
        print(f"POST request received - action: {action}")
        
        if not current_user.stripe_subscription_id:
            print("❌ No subscription ID available")
            flash('No subscription found to cancel.', 'error')
            return render_template('cancel_subscription.html', pending_cancellation=pending_cancellation)
        
        try:
            # Handle different actions
            if action == 'cancel_immediately':
                # Cancel immediately (whether it's first time or changing from period end)
                print(f"Canceling subscription immediately: {current_user.stripe_subscription_id}")
                
                subscription = stripe.Subscription.delete(current_user.stripe_subscription_id)
                print("✅ Subscription canceled immediately")
                
                # Update user in database
                current_user.subscription_status = 'canceled'
                current_user.subscription_end_date = datetime.utcnow()
                current_user.has_paid = False
                db.session.commit()
                
                flash('Your subscription has been canceled immediately. You can reactivate it anytime.', 'success')
                return redirect(url_for('reactivate_page'))
        
            elif action == 'cancel_at_period_end':
                # Cancel at end of period (first time only)
                print(f"Setting subscription to cancel at period end: {current_user.stripe_subscription_id}")
                
                subscription = stripe.Subscription.modify(
                    current_user.stripe_subscription_id,
                    cancel_at_period_end=True
                )
                print("✅ Subscription set to cancel at period end")
                
                # Update user in database
                current_user.subscription_status = 'active'  # Keep active until period end
                current_user.subscription_end_date = datetime.fromtimestamp(subscription['current_period_end'])
                current_user.has_paid = True  # Keep access until period end
                db.session.commit()
                
                end_date = datetime.fromtimestamp(subscription['current_period_end']).strftime('%B %d, %Y')
                flash(f'Your subscription will be canceled on {end_date}. You can reactivate anytime before then.', 'success')
                return redirect(url_for('home'))
        
            elif action == 'reactivate':
                # Reactivate subscription (remove pending cancellation)
                print(f"Reactivating subscription: {current_user.stripe_subscription_id}")
                
                subscription = stripe.Subscription.modify(
                    current_user.stripe_subscription_id,
                    cancel_at_period_end=False
                )
                print("✅ Subscription reactivated")
                
                # Update user in database
                current_user.subscription_status = 'active'
                current_user.subscription_end_date = None
                current_user.has_paid = True
                db.session.commit()
                
                flash('Your subscription has been reactivated! Welcome back!', 'success')
                return redirect(url_for('home'))
        
            elif action == 'keep_subscription':
                # Keep subscription as-is
                flash('Subscription kept active.', 'info')
                return redirect(url_for('home'))
                
        except stripe.error.StripeError as e:
            print(f"❌ Stripe error: {e}")
            flash(f'Error processing request: {str(e)}', 'error')
        except Exception as e:
            print(f"❌ General error: {e}")
            flash(f'Error: {str(e)}', 'error')
    
    print("Showing cancel subscription page")
    return render_template('cancel_subscription.html', pending_cancellation=pending_cancellation)

@app.route('/reactivate')
@login_required
def reactivate_page():
    """Page for reactivating subscription"""
    print(f"=== REACTIVATE PAGE DEBUG ===")
    print(f"User: {current_user.email}")
    print(f"subscription_status: {getattr(current_user, 'subscription_status', 'NOT SET')}")
    
    # Only show this page to users with canceled subscriptions
    if not (hasattr(current_user, 'subscription_status') and current_user.subscription_status == 'canceled'):
        print("❌ User does not have canceled subscription - redirecting to home")
        return redirect(url_for('home'))
    
    print("✅ Showing reactivate page")
    return render_template('reactivate_subscription.html')

@app.route('/reactivate-payment', methods=['GET', 'POST'])
@login_required
def reactivate_payment():
    """Payment page for reactivating subscription"""
    if not (hasattr(current_user, 'subscription_status') and current_user.subscription_status == 'canceled'):
        flash('You do not have a canceled subscription to reactivate.', 'error')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        try:
            # Create Stripe checkout session for reactivation
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price': 'price_1Rkd2ZFr9wM1tN4f7UBbwR1y',  # Your price ID
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=url_for('reactivate_success', _external=True),
                cancel_url=url_for('reactivate_page', _external=True),
                customer=current_user.stripe_customer_id,
            )
            
            return redirect(checkout_session.url, code=303)
            
        except stripe.error.StripeError as e:
            flash(f'Payment error: {str(e)}', 'error')
            return render_template('reactivate_payment.html')
    
    return render_template('reactivate_payment.html')

@app.route('/reactivate-success')
@login_required
def reactivate_success():
    """Handle successful reactivation payment"""
    flash('Your subscription has been reactivated successfully! Welcome back!', 'success')
    return redirect(url_for('home'))

@app.route('/reactivate-subscription', methods=['POST'])
@login_required
def reactivate_subscription():
    """Reactivate a canceled subscription"""
    action = request.form.get('action', 'reactivate')
    
    if not (hasattr(current_user, 'subscription_status') and current_user.subscription_status == 'canceled'):
        flash('You do not have a canceled subscription to reactivate.', 'error')
        return redirect(url_for('home'))
    
    if action == 'reactivate':
        try:
            print(f"=== REACTIVATE DEBUG ===")
            print(f"User: {current_user.email}")
            print(f"stripe_subscription_id: {current_user.stripe_subscription_id}")
            print(f"stripe_customer_id: {current_user.stripe_customer_id}")
            
            # First, try to reactivate existing subscription (for end-of-period cancellations)
            if current_user.stripe_subscription_id:
                try:
                    print("Attempting to reactivate existing subscription...")
                    subscription = stripe.Subscription.modify(
                        current_user.stripe_subscription_id,
                        cancel_at_period_end=False  # Remove the cancellation
                    )
                    
                    print("✅ Existing subscription reactivated successfully")
                    
                    # Update user in database
                    current_user.subscription_status = 'active'
                    current_user.subscription_end_date = None
                    current_user.has_paid = True
                    db.session.commit()
                    
                    flash('Your subscription has been reactivated! Welcome back!', 'success')
                    return redirect(url_for('home'))
                    
                except stripe.error.InvalidRequestError as e:
                    print(f"Cannot reactivate existing subscription: {e}")
                    print("Will create new subscription instead...")
                    # Fall through to create new subscription
                    
            # Create new subscription (for immediate cancellations or if reactivation failed)
            if current_user.stripe_customer_id:
                print("Creating new subscription...")
                
                try:
                    subscription = stripe.Subscription.create(
                        customer=current_user.stripe_customer_id,
                        items=[{
                            'price': 'price_1Rkd2ZFr9wM1tN4f7UBbwR1y',  # Your price ID
                        }],
                    )
                    
                    print(f"✅ New subscription created: {subscription.id}")
                    
                    # Update user in database
                    current_user.stripe_subscription_id = subscription.id
                    current_user.subscription_status = 'active'
                    current_user.subscription_start_date = datetime.fromtimestamp(subscription.created)
                    current_user.subscription_end_date = None
                    current_user.has_paid = True
                    db.session.commit()
                    
                    flash('Your subscription has been reactivated! Welcome back!', 'success')
                    return redirect(url_for('home'))
                    
                except stripe.error.InvalidRequestError as e:
                    if 'no attached payment source' in str(e).lower():
                        print("❌ No payment method - redirecting to checkout")
                        # No payment method - need to go through checkout again
                        flash('Please provide payment information to reactivate your subscription.', 'info')
                        return redirect(url_for('reactivate_payment'))
                    else:
                        raise e
            else:
                print("❌ No stripe_customer_id found")
                flash('No customer information found. Please contact support.', 'error')
                
        except stripe.error.CardError as e:
            print(f"❌ Card error: {e}")
            flash('Payment method issue. Please update your payment information and try again.', 'error')
        except stripe.error.StripeError as e:
            print(f"❌ Stripe error: {e}")
            flash(f'Error reactivating subscription: {str(e)}', 'error')
        except Exception as e:
            print(f"❌ General error: {e}")
            flash(f'Error: {str(e)}', 'error')
    
    elif action == 'stay_canceled':
        # User chose to stay canceled
        print(f"=== STAY CANCELED DEBUG ===")
        print(f"User: {current_user.email}")
        
        # Make sure user stays canceled
        current_user.subscription_status = 'canceled'
        current_user.has_paid = False
        db.session.commit()
        
        flash('You have chosen to keep your subscription canceled.', 'info')
        return redirect(url_for('logout'))
    
    return redirect(url_for('reactivate_page'))

@app.route('/home')
@login_required
def home():
    """Home page - only for users who have active subscriptions"""
    print(f"=== HOME ACCESS DEBUG ===")
    print(f"User: {current_user.email}")
    print(f"has_paid: {current_user.has_paid}")
    print(f"subscription_status: {getattr(current_user, 'subscription_status', 'NOT SET')}")
    
    # Check if user has canceled subscription
    if hasattr(current_user, 'subscription_status') and current_user.subscription_status == 'canceled':
        print("❌ Canceled user trying to access home - redirecting to reactivate")
        return redirect(url_for('reactivate_page'))
    
    # Check if user has paid or has active subscription
    has_access = (
        current_user.has_paid and 
        (not hasattr(current_user, 'subscription_status') or current_user.subscription_status in ['active', 'incomplete'])
    )
    
    print(f"has_access: {has_access}")
    
    if not has_access:
        print("❌ User has no access - redirecting to payment")
        return redirect(url_for('payment'))
    
    print("✅ User has access - showing home page")
    return render_template('home.html')

DATA_FILE = Path("static/data/cameras.json")

@app.route("/api/cameras", methods=["GET"])
def get_cameras():
    if DATA_FILE.exists():
        with open(DATA_FILE) as f:
            return jsonify(json.load(f))
    return jsonify([])

@app.route("/api/cameras", methods=["POST"])
def save_cameras():
    data = request.get_json()
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)
    return jsonify({"status": "success"})


@app.route('/cameras')
@login_required
def cameras():
    """Camera management page"""
    if not current_user.has_paid:
        return redirect(url_for('payment'))
    
    return render_template('cameras.html')

CAMERA_FILE = Path("static/data/cameras.json")
def load_cameras():
    if CAMERA_FILE.exists():
        with open(CAMERA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


@app.route('/logout')
@login_required
def logout():
    """User logout"""
    # Clear email storage for this session
    session_id = session.get('_id')
    if session_id:
        clear_user_email_for_session(session_id)
    
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Create database tables
# with app.app_context():
#     db.create_all()
if app.config.get("ENV") == "development":
    with app.app_context():
        db.create_all(checkfirst=True)

if __name__ == '__main__':
    app.run(threaded=True, debug=True)

 # TODO: Move to env vars later

import logging
import queue
import time
import requests
import base64
from flask import Response
from threading import Event
from flask_cors import CORS
from flask import jsonify



# Global AI Worker Variables (add these with your other globals)
ai_worker_running = False
ai_worker_thread = None
ai_processing = False
ai_queue = queue.Queue(maxsize=1)
ai_results_queue = queue.Queue(maxsize=5)
last_ai_call = 0
ai_cooldown = 3.0

# Add these global variables at the top with your other globals
camera_ready = Event()
initialization_thread = None
video_queue = queue.Queue(maxsize=10)
description_queue = queue.Queue(maxsize=50)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Enable CORS for all routes
CORS(app)

# Global variables for video processing
video_queue = queue.Queue(maxsize=10)
description_queue = queue.Queue(maxsize=50)

MAX_WAIT = 600  # seconds
LOG_INTERVAL = 5

def initialize_camera():
    """Robust camera initialization that allows long waits"""

    url = redis_client.get('camera:url')
    is_opened = redis_client.get('camera:is_opened')=='True'
    print(url, is_opened)
    try:
        if CameraState.camera is not None:
            CameraState.camera.release()

        if url == '0':
            url = 0

        print('RTSP link:', url)
        CameraState.camera = cv2.VideoCapture(url)

        start_time = time.time()
        last_log = 0

        while not CameraState.camera.isOpened():
            elapsed = time.time() - start_time
            if elapsed > MAX_WAIT:
                logger.error(f"Camera failed to open after {MAX_WAIT} seconds.")
                return False

            if int(elapsed) - last_log >= LOG_INTERVAL:
                logger.warning(f"Waiting for camera to open... ({int(elapsed)}s)")
                last_log = int(elapsed)

            time.sleep(1)

        redis_client.set('camera:is_opened', 'True')
        # Optional: Lower resolution to save memory
        CameraState.camera.set(cv2.CAP_PROP_FRAME_WIDTH, 320)
        CameraState.camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 240)

        ret, _ = CameraState.camera.read()
        if ret:
            logger.info("Camera initialized successfully.")
            print('camera is on', CameraState.camera)
            return True
        else:
            logger.error("Camera opened but cannot read frame.")
            CameraState.camera.release()
            CameraState.camera = None

            # no need to turn streaming back to False it was already like that
            redis_client.set('camera:is_opened', 'False')
            return False

    except Exception as e:
        logger.error(f"Exception during camera init: {e}")
        return False

def get_current_user_email():
    """Get current user's email safely, handling threading context"""
    try:
        # Try to get from Flask-Login current_user first
        if hasattr(current_user, 'email') and current_user.email:
            return current_user.email
        
        # Fallback to session
        if 'email' in session:
            return session['email']
        
        # Last resort: check if we have a user ID and query database
        if hasattr(current_user, 'id') and current_user.id:
            from models import User
            user = User.query.get(current_user.id)
            if user:
                return user.email
        
        return None
    except:
        # If we're in a thread without app context, return None
        return None

def set_user_email_for_session(session_id, email):
    """Store user email with session ID"""
    with user_email_lock:
        user_email_storage[session_id] = email
        print(f"📧 Stored email for session {session_id}: {email}")

def get_user_email_for_session(session_id):
    """Get user email for session ID"""
    with user_email_lock:
        return user_email_storage.get(session_id)

def clear_user_email_for_session(session_id):
    """Clear user email for session ID"""
    with user_email_lock:
        user_email_storage.pop(session_id, None)


@app.route('/get_descriptions')
def get_descriptions():
    """Get latest scene descriptions"""
    descriptions = []
    
    # Get all available descriptions from queue
    while not description_queue.empty():
        try:
            descriptions.append(description_queue.get_nowait())
        except queue.Empty:
            break
    
    return jsonify({"descriptions": descriptions})

def generate_frames():
    """Generate video frames for streaming"""
    
    while redis_client.get('camera:is_streaming'):
        if CameraState.camera is None or not redis_client.get('camera:is_opened'):
            break
            
        success, frame = CameraState.camera.read()
        if not success:
            logger.warning("Failed to read frame from camera")
            break
        
        # Add frame to queue for LLM processing (non-blocking)
        try:
            if not video_queue.full():
                video_queue.put(frame.copy(), block=False)
        except queue.Full:
            pass  # Skip if queue is full
        
        # Encode frame as JPEG
        ret, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
        if not ret:
            continue
            
        frame_bytes = buffer.tobytes()
        
        # Yield frame in the format expected by the browser
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
        
        time.sleep(0.033)  # ~30 FPS

@app.route('/video_feed')
@login_required
def video_feed():
    
    logger.info(f"[video_feed] is_streaming: {redis_client.get('camera:is_streaming')}, camera: { CameraState.camera}, url: {redis_client.get('camera:url')}")
    
    try:
        if not (redis_client.get('camera:is_streaming')=='True') or not (redis_client.get('camera:is_opened')=='True'):
            logger.warning("[video_feed] Stream not started")
            return "Stream not started. Click 'Start Stream' first.", 404

        if CameraState.camera is None:
            CameraState.camera = cv2.VideoCapture(redis_client.get('camera:url'))

            start_time = time.time()
            last_log = 0
            logger.warning("Camera", CameraState.camera, "open?:", redis_client.get('camera:is_opened'), 'url?', redis_client.get('camera:url'))
            while not CameraState.camera.isOpened():
                elapsed = time.time() - start_time
                if elapsed > MAX_WAIT:
                    logger.error(f"Camera failed to open after {MAX_WAIT} seconds.")
                    return False

                if int(elapsed) - last_log >= LOG_INTERVAL:
                    logger.warning(f"Waiting for camera to open... ({int(elapsed)}s)")
                    last_log = int(elapsed)

                time.sleep(1)

            redis_client.set('camera:is_opened', 'True')
            # Optional: Lower resolution to save memory
            CameraState.camera.set(cv2.CAP_PROP_FRAME_WIDTH, 320)
            CameraState.camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 240)

        return Response(
            generate_frames(),
            mimetype='multipart/x-mixed-replace; boundary=frame',
            headers={
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
        )
    except Exception as e:
        logger.error(f"Error in video feed: {str(e)}")
        return f"Video feed error: {str(e)}", 500

@app.route('/start_stream', methods=['POST'])
@login_required
def start_stream():
    """Start video streaming"""

    data =  request.get_json()
    url = CameraState.url = data.get('url')
    redis_client.set('camera:url', url)  
    is_streaming = redis_client.get('camera:is_streaming')=="True"
    
    print('RTSP link:', url)

    if not is_streaming:
        if initialize_camera():
            print('do we get here-1')
            redis_client.set('camera:is_streaming',"True")

            # Start the description processing thread
            description_thread = threading.Thread(target=enhanced_process_descriptions2, daemon=True)
            # description_thread = threading.Thread(target=enhanced_process_descriptions, daemon=True)
            description_thread.start()
            return jsonify({"status": "success", "message": "Stream started"})
        else:
            print('do we get here-2')
            return jsonify({"status": "error", "message": "Failed to initialize camera"}), 500
    else:
        print('do we get here-3')
        return jsonify({"status": "info", "message": "Stream already running"})

def cleanup_camera():
    """Clean up camera resources"""

    redis_client.set('camera:is_streaming', "False")
    if CameraState.camera is not None:
        CameraState.camera.release()
        CameraState.camera = None
        redis_client.set('camera:is_opened', 'False')
    logger.info("Camera resources cleaned up")


@app.route('/stop_stream', methods=['POST'])
@login_required
def stop_stream():
    """Stop video streaming"""
    cleanup_camera()
    return jsonify({"status": "success", "message": "Stream stopped"})


# OpenAI integration functions
def encode_image(frame):
    """Turns the frame into base64 so we can send it to OpenAI"""
    try:
        # Convert to JPEG first
        success, buffer = cv2.imencode('.jpg', frame)
        if not success:
            return None, "Failed to encode frame as JPEG"
        
        # Then to base64
        base64_image = base64.b64encode(buffer).decode('utf-8')
        return base64_image, None
    except Exception as e:
        return None, str(e)


def is_alert_response(ai_response):
    global triggers
    """Checks if the AI is actually alerting us about something serious"""
    print('triggers', triggers)
    keywords = triggers.split(', ')
    ai_words = ai_response.split(' ')
    
    # # Stuff we actually care about
    # positive_alerts = [
    #     'alert', 'danger', 'emergency', 'help needed', 'call for help',
    #     'fighting', 'violence', 'aggressive', 'attacking',
    #     'fire', 'smoke', 'medical emergency', 'injury', 'accident',
    #     'suspicious activity', 'intruder', 'break-in', 'theft', 'this', 'the'
    # ]
    
    # # Stuff that means everything's cool
    # negative_indicators = [
    #     'no danger', 'no alert', 'no emergency', 'no unusual', 'no suspicious',
    #     'safe environment', 'appears calm', 'normal activity', 'no threat',
    #     'no alerts necessary', 'no immediate concerns'
    # ]
    is_sent = any(word in keywords for word in ai_words)
    print('is_sent', is_sent)
    # Check for negative indicators first
    return is_sent
    
    # # Then check for positive alerts
    # return any(alert in response_lower for alert in positive_alerts)

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage

smtp_server = os.environ.get('SMTP_SERVER')
smtp_port = os.environ.get('SMTP_PORT')
your_email = os.environ.get('MAIL_USERNAME')
your_password = os.environ.get('MAIL_PASSWORD')

def interpret_frame_with_openai(frame):
    global prompt
    """Sends the frame to OpenAI and gets back what it thinks is happening"""
    base64_image, error = encode_image(frame)
    if error:
        return {"error": error}
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": prompt + "\n\nIMPORTANT: Only mention alerts, danger, or unusual activity if you actually detect something concerning. If everything looks normal and safe, simply describe what you see without using alert-related words."
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/jpeg;base64,{base64_image}"
                        }
                    }
                ]
            }
        ],
        "max_tokens": 300
    }
    
    try:
        response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
        
        if response.status_code == 200:
            result = response.json()
            ai_response = result['choices'][0]['message']['content']
            print(f"🤖 AI Response: {ai_response}")
            
            # Use improved alert detection
            if is_alert_response(ai_response):
                print("AI detected smthg")
                
            
            return result
        else:
            logger.error(f"Failed to interpret image: {response.text}")
            return {"error": response.text, "status_code": response.status_code}
            
    except Exception as e:
        logger.error(f"OpenAI API call failed: {str(e)}")
        return {"error": str(e)}
    

def ai_worker_thread2():
    """Dedicated AI worker thread - adapted from OptimizedRTSPStreamer"""
    global ai_worker_running, ai_processing
    
    logger.info("🤖 AI worker thread started")
    
    while ai_worker_running:
        try:
            # Get next frame to analyze
            frame_data = ai_queue.get(timeout=1.0)
            frame, timestamp = frame_data
            
            # Skip old frames - no point analyzing stale data
            if time.time() - timestamp > 3.0:
                logger.info("⏰ Skipping stale frame")
                ai_queue.task_done()
                continue
            
            ai_processing = True
            logger.info("📤 Processing frame with OpenAI...")
            
            # Call OpenAI API
            result = interpret_frame_with_openai(
                frame
            )
            
            # Save result for processing
            ai_results_queue.put({
                'result': result,
                'timestamp': timestamp,
                'processed_at': time.time(),
                'frame': frame.copy()
            })
            
            ai_processing = False
            ai_queue.task_done()
            
            # Clear out any extra frames that piled up
            while not ai_queue.empty():
                try:
                    ai_queue.get_nowait()
                    ai_queue.task_done()
                    logger.info("🗑️ Cleared extra queued frame")
                except queue.Empty:
                    break
            
        except queue.Empty:
            ai_processing = False
            continue
        except Exception as e:
            logger.error(f"❌ AI worker error: {e}")
            ai_processing = False
            time.sleep(1)


def queue_frame_for_ai2(frame):
    """Queue frame for AI processing with cooldown - adapted from OptimizedRTSPStreamer"""
    global last_ai_call, ai_processing
    
    current_time = time.time()
    
    # Strict cooldown AND ensure AI isn't already processing
    if (current_time - last_ai_call >= ai_cooldown and 
        not ai_processing and 
        ai_queue.empty()):
        
        try:
            ai_queue.put_nowait((frame.copy(), current_time))
            last_ai_call = current_time
            logger.info(f"📋 Frame queued for AI analysis (next in {ai_cooldown}s)")
            return True
        except:
            logger.warning("⚠️ AI queue full, skipping frame")
            return False
    
    return False
@app.route('/generate_summary', methods=['POST'])
@login_required
def generate_summary():
    try:
        # Gather the last 20 messages from the description queue
        descriptions = list(description_queue.queue)[-20:]
        full_text = "\n".join([d['description'] for d in descriptions if 'description' in d])

        if not full_text.strip():
            return jsonify({
                "status": "error",
                "summary": "No messages to summarize."
            }), 400

        # Build the prompt
        prompt_text = (
            "Summarize the following surveillance descriptions in exactly 5 concise sentences. "
            "Focus on important or unusual events and omit repetitive details.\n\n"
            + full_text
        )

        # Call OpenAI
        response = openai.ChatCompletion.create(
            model="gpt-4o",
            messages=[
                {"role": "user", "content": prompt_text}
            ],
            temperature=0.5,
            max_tokens=300
        )

        summary = response['choices'][0]['message']['content'].strip()

        return jsonify({
            "status": "success",
            "summary": summary
        }), 200

    except Exception as e:
        print(f"Error generating summary: {e}")
        return jsonify({
            "status": "error",
            "summary": "Summary generation failed."
        }), 500
    
def process_ai_results2():
    """Process AI results and add to Flask description queue"""
    global last_alert_email_time
    
    try:
        # Only process the most recent result
        latest_result = None
        while not ai_results_queue.empty():
            latest_result = ai_results_queue.get_nowait()
        
        if latest_result:
            result = latest_result['result']
            timestamp = time.strftime("%H:%M:%S", time.localtime(latest_result['timestamp']))
            alert_frame = latest_result.get('frame')
            
            # Only process if we have a valid AI response
            if 'choices' in result and result['choices']:
                ai_response = result['choices'][0]['message']['content']
                
                # Log the AI response (but don't add to transcript yet)
                logger.info(f"✅ AI description ready: {ai_response[:50]}...")
                
                # Check if this is an alert and send email
                if is_alert_response(ai_response):
                    current_time = time.time()
                    
                    # Check if enough time has passed since last alert email
                    if current_time - last_alert_email_time >= email_cooldown_time:
                        
                        # Try multiple ways to get user email
                        user_email = None
                        
                        # Method 1: Try to get from current app context
                        try:
                            with app.app_context():
                                user_email = get_current_user_email()
                        except:
                            pass
                        
                        # Method 2: Try to get from stored sessions
                        if not user_email:
                            for session_id, stored_email in user_email_storage.items():
                                user_email = stored_email
                                break
                        
                        if user_email:
                            logger.info(f"🚨 ALERT DETECTED - Sending email with image to {user_email}")
                            
                            # Send email with image in a separate thread
                            email_thread = threading.Thread(
                                target=send_alert_email_with_image,
                                args=(ai_response, user_email, alert_frame),
                                daemon=True
                            )
                            print(ai_response, user_email, alert_frame)
                            email_thread.start()
                            
                            last_alert_email_time = current_time
                        else:
                            # Log the warning but DON'T add to transcript
                            logger.warning("🚨 ALERT DETECTED but no user email available")
                    else:
                        remaining_time = email_cooldown_time - (current_time - last_alert_email_time)
                        # Log the cooldown but DON'T add to transcript
                        logger.info(f"🚨 ALERT DETECTED but email cooldown active ({remaining_time:.1f}s remaining)")
                
                # ADD TO TRANSCRIPT: Only add the actual AI response
                description_data = {
                    "timestamp": timestamp,
                    "description": ai_response,  # Only the AI response, no extra messages
                    "processed_at": latest_result['processed_at']
                }
                
                try:
                    if description_queue.full():
                        description_queue.get_nowait()  # Remove oldest
                    description_queue.put(description_data, block=False)
                except queue.Full:
                    logger.warning("Description queue full")
            
            # Handle AI errors (but don't add to transcript)
            elif 'error' in result:
                logger.error(f"AI Error: {result['error']}")
                # Don't add error messages to transcript
            else:
                logger.warning("Unexpected AI response format")
                # Don't add format errors to transcript
                
    except queue.Empty:
        pass
    except Exception as e:
        logger.error(f"Error processing AI results: {str(e)}")
        # Don't add processing errors to transcript

def enhanced_process_descriptions2():
    """NEW - Main description processing using AI worker threads"""
    global ai_worker_running, ai_worker_thread
    
    # Start AI worker thread
    ai_worker_running = True
    ai_worker_thread = threading.Thread(target=ai_worker_thread2, daemon=True)
    ai_worker_thread.start()
    logger.info("🚀 Started AI worker thread")
    
    frame_count = 0
    
    while (redis_client.get('camera:is_streaming')=='True'):
        try:
            if not video_queue.empty():
                frame = video_queue.get(timeout=1)
                frame_count += 1
                
                # Try to queue frame for AI processing (non-blocking)
                queued = queue_frame_for_ai2(frame)
                
                # DON'T add status messages to transcript anymore
                if not queued:
                    # Log status but don't add to transcript
                    remaining = ai_cooldown - (time.time() - last_ai_call)
                    if remaining > 0:
                        logger.debug(f"AI cooldown: {remaining:.1f}s remaining")
                    elif ai_processing:
                        logger.debug("AI processing current frame...")
                    else:
                        logger.debug("AI queue busy")
                
                # Process any completed AI results
                process_ai_results2()
                    
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Error in enhanced description processing: {str(e)}")
            
        time.sleep(0.5)
    
    # Cleanup when streaming stops
    ai_worker_running = False
    logger.info("🛑 AI worker thread stopping")