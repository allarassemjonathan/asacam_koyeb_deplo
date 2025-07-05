from flask import Flask, render_template, request, redirect, url_for, flash, session
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

load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
prompt="Act as a security monitor. Describe what you see and alert if anything dangerous is happening."
title='Security Monitoring'
url = 0

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
    global prompt, title
    
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
        
        # Update global variables (modify this part based on your needs)
        current_mission_title = mission_title
        prompt = mission_prompt
        title = mission_title
        
        # Log the received data (optional)
        print(f"Mission Title: {mission_title}")
        print(f"Mission Prompt: {mission_prompt}")
        
        # Return success response
        return jsonify({
            'status': 'success',
            'message': 'Mission created successfully',
            'data': {
                'mission_title': mission_title,
                'mission_prompt': mission_prompt
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
        if not current_user.has_paid:
            return redirect(url_for('payment'))
        else:
            return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/mission')
def mission():
    return render_template('mission.html', username=session.get('username'), prompt=prompt, date=datetime.now().strftime("%Y-%m-%d"), title=title)

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
            
            # All users in database are verified, only check payment
            if not user.has_paid:
                return redirect(url_for('payment'))
            else:
                
                # Store in session manually
                session['username'] = user.first_name  # or user.username if you have that
                session['email'] = user.email
                return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])  # <-- ADD THIS DECORATOR!
def register():
    """User registration with email verification"""
    if request.method == 'POST':
        # Get form data
        email = request.form.get('email').lower().strip()
        password = request.form.get('password')
        first_name = request.form.get('first_name').strip()
        last_name = request.form.get('last_name').strip()

        # Validate data
        if not all([email, password, first_name, last_name]):
            flash('All fields are required.', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html')
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please login instead.', 'error')
            return render_template('register.html')
        
        # Store user data temporarily (don't save to database yet)
        temp_user_data = {
            'email': email,
            'password': password,
            'first_name': first_name,
            'last_name': last_name
        }
        
        # Generate verification code and send email
        verification_code = generate_verification_code()
        
        if send_verification_email_for_registration(email, first_name, verification_code):
            # Store in session for verification
            session['temp_user'] = temp_user_data
            session['verification_code'] = verification_code
            session['code_expires'] = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
            
            flash('Check your email for verification code!', 'success')
            return redirect(url_for('verify_email'))  # <-- USE verify_email, not verify_registration
        else:
            flash('Failed to send verification email. Please try again.', 'error')
            return render_template('register.html')
        
    return render_template('register.html')

@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    """Email verification during registration"""
    # Check if we have pending registration data
    if 'temp_user' not in session or 'verification_code' not in session:
        flash('No pending registration found. Please register again.', 'error')
        return redirect(url_for('register'))
    
    # Check if code has expired
    if 'code_expires' in session:
        code_expires = datetime.fromisoformat(session['code_expires'])
        if datetime.utcnow() > code_expires:
            # Clear expired session data
            session.pop('temp_user', None)
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
                return render_template('verify_email.html', email=session['temp_user']['email'])
            
            if entered_code == session['verification_code']:
                # Code is correct! Create user in database
                temp_data = session['temp_user']
                
                user = User(
                    email=temp_data['email'],
                    first_name=temp_data['first_name'],
                    last_name=temp_data['last_name']
                )
                user.set_password(temp_data['password'])
                # User is verified since they completed email verification
                
                db.session.add(user)
                db.session.commit()
                
                # Clear session data
                session.pop('temp_user', None)
                session.pop('verification_code', None)
                session.pop('code_expires', None)
                
                # Log user in and redirect to payment
                login_user(user)

                # cashing user info
                session['username'] = user.first_name
                session['email'] = user.email
                flash('Registration complete! Welcome!', 'success')
                return redirect(url_for('payment'))
            else:
                flash('Invalid verification code.', 'error')
        
        elif action == 'resend':
            # Generate new code and send
            new_code = generate_verification_code()
            temp_data = session['temp_user']
            
            if send_verification_email_for_registration(temp_data['email'], 
                                                       temp_data['first_name'], 
                                                       new_code):
                session['verification_code'] = new_code
                session['code_expires'] = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
                flash('New verification code sent!', 'success')
            else:
                flash('Failed to send new code. Please try again.', 'error')
    
    return render_template('verify_email.html', email=session['temp_user']['email'])

@app.route('/payment', methods=['GET', 'POST'])
@login_required
def payment():
    """Payment page with Stripe integration"""
    if current_user.has_paid:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        try:
            # Create Stripe checkout session
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'usd',
                        'product_data': {
                            'name': 'App Access Payment',
                            'description': 'One-time payment for app access',
                        },
                        'unit_amount': 100,  # $100 in cents
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url=url_for('payment_success', _external=True),
                cancel_url=url_for('payment_cancel', _external=True),
                client_reference_id=str(current_user.id),  # Track which user paid
            )
            
            return redirect(checkout_session.url, code=303)
            
        except stripe.error.StripeError as e:
            flash(f'Payment error: {str(e)}', 'error')
            return render_template('payment.html')
    
    return render_template('payment.html')

@app.route('/payment-success')
@login_required
def payment_success():
    """Handle successful payment"""
    # Mark user as paid
    current_user.has_paid = True
    current_user.payment_date = datetime.utcnow()
    db.session.commit()
    
    flash('Payment successful! Welcome to the app!', 'success')
    return redirect(url_for('home'))

@app.route('/payment-cancel')
@login_required
def payment_cancel():
    """Handle cancelled payment"""
    flash('Payment was cancelled. You can try again anytime.', 'info')
    return redirect(url_for('payment'))

@app.route('/home')
@login_required
def home():
    """Home page - only for users who have paid"""
    # Remove email verification check - all logged-in users are verified
    if not current_user.has_paid:
        return redirect(url_for('payment'))
    
    return render_template('home.html')

@app.route('/logout')
@login_required
def logout():
    """User logout"""
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
import threading
import cv2
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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Enable CORS for all routes
CORS(app)

# Global variables for video processing
video_queue = queue.Queue(maxsize=10)
description_queue = queue.Queue(maxsize=50)
is_streaming = False
camera = None
def initialize_camera():
    """Robust camera initialization that allows long waits"""
    global camera, url

    MAX_WAIT = 600  # seconds
    LOG_INTERVAL = 5

    try:
        if camera is not None:
            camera.release()

        if url == '0':
            url = 0

        camera = cv2.VideoCapture(url)

        start_time = time.time()
        last_log = 0

        while not camera.isOpened():
            elapsed = time.time() - start_time
            if elapsed > MAX_WAIT:
                logger.error(f"Camera failed to open after {MAX_WAIT} seconds.")
                return False

            if int(elapsed) - last_log >= LOG_INTERVAL:
                logger.warning(f"Waiting for camera to open... ({int(elapsed)}s)")
                last_log = int(elapsed)

            time.sleep(1)

        # Optional: Lower resolution to save memory
        camera.set(cv2.CAP_PROP_FRAME_WIDTH, 320)
        camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 240)

        ret, _ = camera.read()
        if ret:
            logger.info("Camera initialized successfully.")
            return True
        else:
            logger.error("Camera opened but cannot read frame.")
            camera.release()
            camera = None
            return False

    except Exception as e:
        logger.error(f"Exception during camera init: {e}")
        return False

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
    global is_streaming, camera
    
    while is_streaming:
        if camera is None or not camera.isOpened():
            break
            
        success, frame = camera.read()
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
    """Video streaming route - fixed version"""
    global is_streaming
    
    try:
        # Don't initialize camera here, it should be done in start_stream
        if not is_streaming or camera is None:
            return "Stream not started. Click 'Start Stream' first.", 404
            
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
    global is_streaming, url

    data =  request.get_json()
    url = data.get('url')    

    if not is_streaming:
        if initialize_camera():
            is_streaming = True
            # Start the description processing thread
            description_thread = threading.Thread(target=enhanced_process_descriptions2, daemon=True)
            # description_thread = threading.Thread(target=enhanced_process_descriptions, daemon=True)
            description_thread.start()
            return jsonify({"status": "success", "message": "Stream started"})
        else:
            return jsonify({"status": "error", "message": "Failed to initialize camera"}), 500
    else:
        return jsonify({"status": "info", "message": "Stream already running"})

def cleanup_camera():
    """Clean up camera resources"""
    global camera, is_streaming
    is_streaming = False
    if camera is not None:
        camera.release()
        camera = None
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
    """Checks if the AI is actually alerting us about something serious"""
    response_lower = ai_response.lower()
    
    # Stuff we actually care about
    positive_alerts = [
        'alert', 'danger', 'emergency', 'help needed', 'call for help',
        'fighting', 'violence', 'aggressive', 'attacking',
        'fire', 'smoke', 'medical emergency', 'injury', 'accident',
        'suspicious activity', 'intruder', 'break-in', 'theft', 'this', 'the'
    ]
    
    # Stuff that means everything's cool
    negative_indicators = [
        'no danger', 'no alert', 'no emergency', 'no unusual', 'no suspicious',
        'safe environment', 'appears calm', 'normal activity', 'no threat',
        'no alerts necessary', 'no immediate concerns'
    ]
    
    # Check for negative indicators first
    if any(neg in response_lower for neg in negative_indicators):
        return False
    
    # Then check for positive alerts
    return any(alert in response_lower for alert in positive_alerts)


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
                print(f"🚨 ALERT DETECTED: {ai_response}")
                
            
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
    try:
        # Only process the most recent result
        latest_result = None
        while not ai_results_queue.empty():
            latest_result = ai_results_queue.get_nowait()
        
        if latest_result:
            result = latest_result['result']
            timestamp = time.strftime("%H:%M:%S", time.localtime(latest_result['timestamp']))
            
            if 'choices' in result and result['choices']:
                ai_response = result['choices'][0]['message']['content']
                description = f"{ai_response}"
                logger.info(f"✅ AI description ready: {ai_response[:50]}...")
                
            elif 'error' in result:
                description = f"⚠️ AI Error: {result['error'][:100]}"
                logger.error(f"AI Error: {result['error']}")
            else:
                description = "⚠️ Unexpected AI response format"
            
            # Add to Flask description queue
            description_data = {
                "timestamp": timestamp,
                "description": description,
                "processed_at": latest_result['processed_at']
            }
            
            try:
                if description_queue.full():
                    description_queue.get_nowait()  # Remove oldest
                description_queue.put(description_data, block=False)
            except queue.Full:
                logger.warning("Description queue full")
                
    except queue.Empty:
        pass
    except Exception as e:
        logger.error(f"Error processing AI results: {str(e)}")

def enhanced_process_descriptions2():
    """NEW - Main description processing using AI worker threads"""
    global is_streaming, ai_worker_running, ai_worker_thread
    
    # Start AI worker thread
    ai_worker_running = True
    ai_worker_thread = threading.Thread(target=ai_worker_thread2, daemon=True)
    ai_worker_thread.start()
    logger.info("🚀 Started AI worker thread")
    
    frame_count = 0
    
    while is_streaming:
        try:
            if not video_queue.empty():
                frame = video_queue.get(timeout=1)
                frame_count += 1
                
                # Try to queue frame for AI processing (non-blocking)
                queued = queue_frame_for_ai2(frame)
                
                if not queued:
                    # Show status while AI is busy/cooling down
                    remaining = ai_cooldown - (time.time() - last_ai_call)
                    if remaining > 0:
                        status_msg = f"AI cooldown: {remaining:.1f}s remaining"
                    elif ai_processing:
                        status_msg = "AI processing current frame..."
                    else:
                        status_msg = "AI queue busy"

                    # Filter out cooldown-related messages before enqueueing
                    cooldown_keywords = ["cooldown", "processing", "queue busy"]
                    if not any(keyword in status_msg.lower() for keyword in cooldown_keywords):
                        description_data = {
                            "timestamp": time.strftime("%H:%M:%S"),
                            "description": status_msg,
                            "frame_number": frame_count
                        }
                    
                    try:
                        if not description_queue.full():
                            description_queue.put(description_data, block=False)
                    except queue.Full:
                        pass
                
                # Process any completed AI results
                process_ai_results2()
                    
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Error in enhanced description processing: {str(e)}")
            
        time.sleep(0.5)  # Check twice per second for optimal performance
    
    # Cleanup when streaming stops
    ai_worker_running = False
    logger.info("🛑 AI worker thread stopping")
