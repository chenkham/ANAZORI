import os
import json
import logging
import re
import string
import random
import secrets
import time
from flask_mail import Mail, Message
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort
import firebase_admin
from firebase_admin import credentials, auth, firestore
import pyrebase
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "your-secret-key-here")

# Firebase configuration (keep existing)
firebase_config = {
    "apiKey": os.environ.get("FIREBASE_API_KEY"),
    "authDomain": os.environ.get("FIREBASE_AUTH_DOMAIN"),
    "databaseURL": os.environ.get("FIREBASE_DATABASE_URL"),
    "projectId": os.environ.get("FIREBASE_PROJECT_ID"),
    "storageBucket": os.environ.get("FIREBASE_STORAGE_BUCKET"),
    "messagingSenderId": os.environ.get("FIREBASE_MESSAGING_SENDER_ID"),
    "appId": os.environ.get("FIREBASE_APP_ID"),
}

# Mailtrap configuration
app.config['MAIL_SERVER'] = os.environ.get('MAILTRAP_SMTP_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAILTRAP_SMTP_PORT'))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAILTRAP_SMTP_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('MAILTRAP_SMTP_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAILTRAP_SENDER_EMAIL')

# Initialize Flask-Mail
mail = Mail(app)

# Initialize Firebase Admin SDK
try:
    cred_path = os.environ.get("FIREBASE_SERVICE_ACCOUNT_KEY")
    if cred_path and os.path.exists(cred_path):
        cred = credentials.Certificate(cred_path)
    else:
        cred_dict = {
            "type": "service_account",
            "project_id": os.environ.get("FIREBASE_PROJECT_ID"),
            "private_key": os.environ.get("FIREBASE_PRIVATE_KEY", "").replace('\\n', '\n'),
            "client_email": os.environ.get("FIREBASE_CLIENT_EMAIL"),
            "token_uri": "https://oauth2.googleapis.com/token",
        }
        cred = credentials.Certificate(cred_dict)

    firebase_admin.initialize_app(cred)
    db = firestore.client()
except Exception as e:
    print(f"Firebase Admin initialization failed: {e}")
    db = None

# Initialize Pyrebase for client-side auth
try:
    firebase = pyrebase.initialize_app(firebase_config)
    auth_client = firebase.auth()
except Exception as e:
    print(f"Pyrebase initialization failed: {e}")
    auth_client = None

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


# Helper Functions
def generate_captcha():
    """Generate a 6-character captcha code"""
    code = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session["captcha"] = code
    session["captcha_exp"] = time.time() + 300  # 5 minutes expiry
    return code


def validate_captcha(user_input):
    """Validate user-submitted captcha"""
    stored = session.get("captcha", "")
    exp = session.get("captcha_exp", 0)
    if not user_input or time.time() > exp:
        return False
    is_valid = user_input.upper() == stored.upper()
    session.pop("captcha", None)
    session.pop("captcha_exp", None)
    return is_valid


def validate_phone(phone):
    """Validate and format Indian phone number"""
    if not phone:
        return ""
    digits = re.sub(r'\D', '', phone)
    if len(digits) == 10 and digits[0] in "6789":
        return f"+91{digits}"
    elif len(digits) == 12 and digits.startswith("91"):
        return f"+{digits}"
    return None


def clear_user_session():
    """Clear all user-related session data"""
    keys_to_clear = ['user', 'email', 'name', 'phone', 'is_google_account',
                     'id_token', 'verify_link', 'temp_user_data', 'pending_verification',
                     'verified_user_data', 'google_user_data', 'email_verified', 'google_verified',
                     'verified_email']
    for key in keys_to_clear:
        session.pop(key, None)


def login_required(f):
    """Decorator to require login for protected routes"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user')
        if not user_id:
            logger.warning(f"Unauthorized access attempt to {request.endpoint}")
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('signin'))

        id_token = session.get('id_token')
        if id_token:
            try:
                decoded = auth.verify_id_token(id_token)
                if decoded['uid'] != user_id:
                    raise Exception('Token mismatch')
            except Exception as e:
                logger.error(f"Token verification failed: {e}")
                clear_user_session()
                flash('Session expired. Please sign in again.', 'warning')
                return redirect(url_for('signin'))

        return f(*args, **kwargs)

    return decorated_function


def get_user_data(user_id):
    """Fetch user data from Firestore"""
    try:
        if not db:
            logger.error("Firestore not initialized")
            return None
        doc = db.collection('users').document(user_id).get()
        if doc.exists:
            return doc.to_dict()
        else:
            logger.warning(f"User document not found for uid: {user_id}")
            return None
    except Exception as e:
        logger.error(f"Error fetching user data: {e}")
        return None


def send_verification_email(email, verification_token):
    """Send verification email using Flask-Mail with Mailtrap Sandbox"""
    try:
        # Debug info (remove in production)
        print(f"DEBUG - Sending email to: {email}")
        print(f"DEBUG - Using SMTP: {app.config.get('MAIL_SERVER')}:{app.config.get('MAIL_PORT')}")
        print(f"DEBUG - Username: {app.config.get('MAIL_USERNAME')}")

        # Create verification URL
        verification_url = url_for('verify_custom_email', token=verification_token, _external=True)

        # Create Flask-Mail message
        msg = Message(
            subject="Verify your ANAZORI 15.0 account",
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[email]
        )

        # Your existing beautiful HTML template
        msg.html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4; }}
                .container {{ max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }}
                .header {{ text-align: center; margin-bottom: 30px; }}
                .header h1 {{ background: linear-gradient(45deg, #00f5ff, #ff00ff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-size: 2.5rem; margin: 0; }}
                .content {{ color: #333; line-height: 1.6; }}
                .button {{ display: inline-block; padding: 15px 30px; background: linear-gradient(45deg, #00f5ff, #ff00ff); color: white; text-decoration: none; border-radius: 8px; font-weight: 600; margin: 20px 0; }}
                .footer {{ color: #666; font-size: 12px; text-align: center; margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px; }}
                .link-text {{ word-break: break-all; color: #00f5ff; font-size: 14px; background: #f8f9fa; padding: 10px; border-radius: 5px; margin: 10px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>ANAZORI 15.0</h1>
                </div>
                <div class="content">
                    <h2>🚀 Welcome to the Ultimate Tech Festival!</h2>
                    <p>Thank you for signing up for ANAZORI 15.0. Please verify your email address to complete your registration and join the most exciting tech event of the year!</p>

                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{verification_url}" class="button">✉️ Verify Email Address</a>
                    </div>

                    <p><strong>If the button doesn't work, copy and paste this link into your browser:</strong></p>
                    <div class="link-text">{verification_url}</div>

                    <p>🎯 What's waiting for you:</p>
                    <ul>
                        <li>💻 Coding competitions and hackathons</li>
                        <li>🎮 Gaming tournaments</li>
                        <li>🔍 Tech treasure hunts</li>
                        <li>🏆 Amazing prizes and recognition</li>
                    </ul>
                </div>

                <div class="footer">
                    <p>⏰ This link will expire in 24 hours.</p>
                    <p>If you didn't create an account, please ignore this email.</p>
                    <p>© 2025 ANAZORI 15.0. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """

        # Send the email using Flask-Mail
        mail.send(msg)

        logger.info(f"Verification email sent to {email} via Mailtrap Sandbox")
        print("✅ Email sent successfully via Flask-Mail!")
        return True

    except Exception as e:
        logger.error(f"Failed to send verification email: {e}")
        print(f"❌ EMAIL ERROR: {e}")
        return False


# Routes
@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')


@app.route('/signup', methods=['GET'])
def signup():
    """Signup page with Google and Email options"""
    return render_template('signup.html', firebase_config=firebase_config)


@app.route('/email_signup', methods=['POST'])
def email_signup():
    """Send email verification for signup using Mailtrap"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()

        if not email or not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            return jsonify({'success': False, 'error': 'Invalid email address'})

        # Check if user already exists in Firestore
        if db:
            users_ref = db.collection('users')
            existing_users = users_ref.where('email', '==', email).get()

            if existing_users:
                return jsonify({'success': False, 'error': 'Email already registered'})

        # Generate verification token
        verification_token = secrets.token_urlsafe(32)

        # Store pending user data in Firestore
        pending_user_data = {
            'email': email,
            'verification_token': verification_token,
            'created_at': time.time(),
            'expires_at': time.time() + 86400,  # 24 hours
            'verified': False
        }

        if db:
            db.collection('pending_users').document(verification_token).set(pending_user_data)

        # Send verification email using Mailtrap
        if send_verification_email(email, verification_token):
            return jsonify({
                'success': True,
                'message': 'Verification email sent! Please check your inbox (and your Mailtrap inbox for development).'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to send verification email'})

    except Exception as e:
        logger.error(f"Email signup error: {e}")
        return jsonify({'success': False, 'error': 'Failed to send verification email'})


@app.route('/verify_custom_email')
def verify_custom_email():
    """Handle custom email verification"""
    token = request.args.get('token')
    if not token:
        flash('Invalid verification link.', 'error')
        return redirect(url_for('signup'))

    try:
        if not db:
            flash('Service temporarily unavailable.', 'error')
            return redirect(url_for('signup'))

        # Get pending user data
        pending_doc = db.collection('pending_users').document(token).get()

        if not pending_doc.exists:
            flash('Invalid or expired verification link.', 'error')
            return redirect(url_for('signup'))

        pending_data = pending_doc.to_dict()

        # Check expiration
        if time.time() > pending_data.get('expires_at', 0):
            # Clean up expired token
            db.collection('pending_users').document(token).delete()
            flash('Verification link has expired. Please sign up again.', 'error')
            return redirect(url_for('signup'))

        # Mark as verified and store in session
        session['verified_email'] = pending_data['email']
        session['verification_token'] = token

        flash('Email verified successfully! Please complete your profile.', 'success')
        return redirect(url_for('complete_registration'))

    except Exception as e:
        logger.error(f"Email verification error: {e}")
        flash('Verification failed. Please try again.', 'error')
        return redirect(url_for('signup'))


@app.route('/complete_registration', methods=['GET', 'POST'])
def complete_registration():
    """Complete user registration after email verification"""
    if 'verified_email' not in session:
        flash('Please verify your email first.', 'warning')
        return redirect(url_for('signup'))

    if request.method == 'GET':
        captcha_code = generate_captcha()
        return render_template('complete_registration.html',
                               captcha=captcha_code,
                               email=session['verified_email'])

    try:
        # Get form data
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        captcha_input = request.form.get('captcha', '').strip()
        is_du_student = request.form.get('is_du_student') == 'on'

        # Validation
        if not all([name, password, confirm_password, captcha_input]):
            flash('All required fields must be filled.', 'error')
            return render_template('complete_registration.html',
                                   captcha=generate_captcha(), email=session['verified_email'])

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('complete_registration.html',
                                   captcha=generate_captcha(), email=session['verified_email'])

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('complete_registration.html',
                                   captcha=generate_captcha(), email=session['verified_email'])

        if not validate_captcha(captcha_input):
            flash('Invalid or expired security code.', 'error')
            return render_template('complete_registration.html',
                                   captcha=generate_captcha(), email=session['verified_email'])

        # Validate phone
        formatted_phone = ""
        if phone:
            formatted_phone = validate_phone(phone)
            if formatted_phone is None:
                flash('Invalid phone number format.', 'error')
                return render_template('complete_registration.html',
                                       captcha=generate_captcha(), email=session['verified_email'])

        email = session['verified_email']

        # Create user in Firebase Auth
        user_record = auth.create_user(
            email=email,
            password=password,
            display_name=name,
            email_verified=True
        )
        uid = user_record.uid

        # Save to Firestore
        user_doc_data = {
            'name': name,
            'email': email,
            'phone': formatted_phone,
            'is_du_student': is_du_student,
            'email_verified': True,
            'is_google_account': False,
            'created_at': firestore.SERVER_TIMESTAMP,
            'updated_at': firestore.SERVER_TIMESTAMP
        }

        if db:
            db.collection('users').document(uid).set(user_doc_data)

        # Clean up pending user
        token = session.get('verification_token')
        if token and db:
            db.collection('pending_users').document(token).delete()

        # Set user session
        session['user'] = uid
        session['email'] = email
        session['name'] = name
        session['phone'] = formatted_phone
        session['is_google_account'] = False

        # Clear temp data
        session.pop('verified_email', None)
        session.pop('verification_token', None)

        flash('Registration completed successfully! Welcome to ANAZORI 15.0!', 'success')
        return redirect(url_for('new'))

    except Exception as e:
        logger.error(f"Complete registration error: {e}")
        flash('Failed to complete registration. Please try again.', 'error')
        return render_template('complete_registration.html',
                               captcha=generate_captcha(), email=session['verified_email'])


# Keep all your existing routes (Google signup, signin, etc.)
@app.route('/google_signup', methods=['POST'])
def google_signup():
    """Handle Google OAuth signup"""
    try:
        data = request.get_json()
        id_token = data.get('idToken')

        if not id_token:
            return jsonify({'success': False, 'error': 'Missing ID token'})

        # Verify token
        decoded = auth.verify_id_token(id_token)
        uid = decoded['uid']
        email = decoded.get('email', '')
        name = decoded.get('name', '')
        picture = decoded.get('picture', '')

        # Check if user exists
        if db:
            user_doc = db.collection('users').document(uid).get()
            if user_doc.exists:
                # Existing user - login
                user_data = user_doc.to_dict()
                session['user'] = uid
                session['email'] = email
                session['name'] = user_data.get('name', name)
                session['phone'] = user_data.get('phone', '')
                session['is_google_account'] = True
                session['id_token'] = id_token

                # Update last login
                db.collection('users').document(uid).update({
                    'last_login': firestore.SERVER_TIMESTAMP
                })

                return jsonify({
                    'success': True,
                    'redirect': url_for('new'),
                    'existing_user': True
                })

        # New user - store temp data for profile completion
        session['google_user_data'] = {
            'uid': uid,
            'email': email,
            'name': name,
            'picture': picture
        }

        return jsonify({
            'success': True,
            'redirect': url_for('complete_google_profile'),
            'existing_user': False
        })

    except Exception as e:
        logger.error(f"Google signup error: {e}")
        return jsonify({'success': False, 'error': 'Google sign-in failed'})


@app.route('/complete_google_profile', methods=['GET', 'POST'])
def complete_google_profile():
    """Complete Google user profile"""
    google_data = session.get('google_user_data')
    if not google_data:
        flash('Please sign in with Google first.', 'warning')
        return redirect(url_for('signup'))

    if request.method == 'GET':
        captcha_code = generate_captcha()
        return render_template('complete_google_profile.html',
                               captcha=captcha_code,
                               user_data=google_data)

    try:
        # Get form data
        phone = request.form.get('phone', '').strip()
        captcha_input = request.form.get('captcha', '').strip()
        is_du_student = request.form.get('is_du_student') == 'on'

        if not validate_captcha(captcha_input):
            flash('Invalid or expired security code.', 'error')
            return render_template('complete_google_profile.html',
                                   captcha=generate_captcha(), user_data=google_data)

        # Validate phone
        formatted_phone = ""
        if phone:
            formatted_phone = validate_phone(phone)
            if formatted_phone is None:
                flash('Invalid phone number format.', 'error')
                return render_template('complete_google_profile.html',
                                       captcha=generate_captcha(), user_data=google_data)

        uid = google_data['uid']
        email = google_data['email']
        name = google_data['name']
        picture = google_data['picture']

        # Save to Firestore
        user_doc_data = {
            'name': name,
            'email': email,
            'phone': formatted_phone,
            'is_du_student': is_du_student,
            'email_verified': True,
            'is_google_account': True,
            'photo_url': picture,
            'created_at': firestore.SERVER_TIMESTAMP,
            'updated_at': firestore.SERVER_TIMESTAMP
        }

        if db:
            db.collection('users').document(uid).set(user_doc_data)

        # Set user session
        session['user'] = uid
        session['email'] = email
        session['name'] = name
        session['phone'] = formatted_phone
        session['is_google_account'] = True

        # Clear temp data
        session.pop('google_user_data', None)

        flash('Profile completed successfully! Welcome to ANAZORI 15.0!', 'success')
        return redirect(url_for('new'))

    except Exception as e:
        logger.error(f"Complete Google profile error: {e}")
        flash('Failed to complete profile. Please try again.', 'error')
        return render_template('complete_google_profile.html',
                               captcha=generate_captcha(), user_data=google_data)


# Keep all your existing routes (signin, dashboard, settings, etc.)
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    """User sign in page"""
    if request.method == 'GET':
        captcha_code = generate_captcha()
        return render_template('signin.html',
                               captcha=captcha_code,
                               firebase_config=firebase_config)

    try:
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        captcha_input = request.form.get('captcha', '').strip()

        if not all([email, password, captcha_input]):
            flash('All fields are required.', 'error')
            return render_template('signin.html',
                                   captcha=generate_captcha(),
                                   firebase_config=firebase_config)

        if not validate_captcha(captcha_input):
            flash('Invalid or expired security code.', 'error')
            return render_template('signin.html',
                                   captcha=generate_captcha(),
                                   firebase_config=firebase_config)

        # Sign in with Pyrebase
        if not auth_client:
            flash('Authentication service unavailable.', 'error')
            return render_template('signin.html',
                                   captcha=generate_captcha(),
                                   firebase_config=firebase_config)

        user = auth_client.sign_in_with_email_and_password(email, password)
        uid = user['localId']

        # Get user data
        user_data = get_user_data(uid)
        if not user_data:
            flash('User account not found.', 'error')
            return render_template('signin.html',
                                   captcha=generate_captcha(),
                                   firebase_config=firebase_config)

        # Set session
        session['user'] = uid
        session['email'] = email
        session['name'] = user_data.get('name', '')
        session['phone'] = user_data.get('phone', '')
        session['id_token'] = user.get('idToken')
        session['is_google_account'] = user_data.get('is_google_account', False)

        # Update last login
        if db:
            db.collection('users').document(uid).update({
                'last_login': firestore.SERVER_TIMESTAMP
            })

        flash('Welcome back!', 'success')
        return redirect(url_for('new'))

    except Exception as e:
        error_msg = str(e)
        if any(x in error_msg for x in ['EMAIL_NOT_FOUND', 'INVALID_PASSWORD', 'INVALID_LOGIN_CREDENTIALS']):
            flash('Invalid email or password.', 'error')
        else:
            logger.error(f"Signin error: {e}")
            flash('Sign in failed. Please try again.', 'error')

        return render_template('signin.html',
                               captcha=generate_captcha(),
                               firebase_config=firebase_config)


@app.route('/google_signin', methods=['POST'])
def google_signin():
    """Handle Google OAuth signin"""
    try:
        data = request.get_json()
        id_token = data.get('idToken')

        if not id_token:
            return jsonify({'success': False, 'error': 'Missing ID token'})

        # Verify token
        decoded = auth.verify_id_token(id_token)
        uid = decoded['uid']
        email = decoded.get('email', '')
        name = decoded.get('name', '')

        # Get user data
        user_data = get_user_data(uid)
        if not user_data:
            return jsonify({'success': False, 'error': 'User not found. Please sign up first.'})

        # Set session
        session['user'] = uid
        session['email'] = email
        session['name'] = user_data.get('name', name)
        session['phone'] = user_data.get('phone', '')
        session['is_google_account'] = True
        session['id_token'] = id_token

        # Update last login
        if db:
            db.collection('users').document(uid).update({
                'last_login': firestore.SERVER_TIMESTAMP
            })

        return jsonify({'success': True, 'redirect': url_for('new')})

    except Exception as e:
        logger.error(f"Google signin error: {e}")
        return jsonify({'success': False, 'error': 'Google sign-in failed'})


# Keep all your existing protected routes
@app.route('/new')
@login_required
def new():
    """Main dashboard after login"""
    try:
        user_id = session.get('user')
        user_data = get_user_data(user_id)

        if not user_data:
            logger.error(f"User data not found for uid: {user_id}")
            flash('User data not found.', 'error')
            return redirect(url_for('signin'))

        return render_template('new.html', user=user_data)
    except Exception as e:
        logger.error(f"/new error: {e}")
        flash('An error occurred. Please try again.', 'error')
        return redirect(url_for('signin'))


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """User settings page"""
    user_id = session.get('user')
    user_data = get_user_data(user_id)

    if not user_data:
        flash('User data not found.', 'error')
        return redirect(url_for('signin'))

    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            phone = request.form.get('phone', '').strip()
            is_du_student = request.form.get('is_du_student') == 'on'

            # Validate phone
            formatted_phone = ""
            if phone:
                formatted_phone = validate_phone(phone)
                if formatted_phone is None:
                    flash('Invalid phone number format.', 'error')
                    return render_template('settings.html', user=user_data)

            # Update Firestore
            if db:
                db.collection('users').document(user_id).update({
                    'name': name,
                    'phone': formatted_phone,
                    'is_du_student': is_du_student,
                    'updated_at': firestore.SERVER_TIMESTAMP
                })

            # Update session
            session['name'] = name
            session['phone'] = formatted_phone

            flash('Profile updated successfully!', 'success')
            return redirect(url_for('settings'))

        except Exception as e:
            logger.error(f"Settings update error: {e}")
            flash('Failed to update profile. Please try again.', 'error')

    return render_template('settings.html', user=user_data)


@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    user_id = session.get('user')
    user_data = get_user_data(user_id)

    if not user_data:
        flash('User data not found.', 'error')
        return redirect(url_for('signin'))

    return render_template('dashboard.html', user=user_data)


@app.route('/myregistration')
@login_required
def myregistration():
    """User's event registrations"""
    user_id = session.get('user')
    user_data = get_user_data(user_id)

    if not user_data:
        flash('User data not found.', 'error')
        return redirect(url_for('signin'))

    registrations = []

    return render_template('myregistration.html', user=user_data, registrations=registrations)


@app.route('/logout')
def logout():
    """User logout"""
    clear_user_session()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))


# API Routes
@app.route('/generate_captcha')
def generate_captcha_route():
    """Generate new captcha"""
    return jsonify({'captcha': generate_captcha()})


@app.route('/check_login_status')
def check_login_status():
    """Check if user is logged in"""
    user_id = session.get('user')
    if user_id:
        user_data = get_user_data(user_id)
        if user_data:
            return jsonify({
                'logged_in': True,
                'name': user_data.get('name', ''),
                'email': user_data.get('email', ''),
                'profile_image_url': user_data.get('photo_url', '')
            })

    return jsonify({'logged_in': False})


# Keep existing routes
@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    """Update user password"""
    user_id = session.get('user')
    user_data = get_user_data(user_id)

    if not user_data:
        flash('User data not found.', 'error')
        return redirect(url_for('signin'))

    # Check if this is a Google account
    if user_data.get('is_google_account', False):
        flash('Password cannot be changed for Google accounts.', 'error')
        return redirect(url_for('settings'))

    try:
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validation
        if not all([current_password, new_password, confirm_password]):
            flash('All password fields are required.', 'error')
            return redirect(url_for('settings'))

        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('settings'))

        if len(new_password) < 6:
            flash('New password must be at least 6 characters long.', 'error')
            return redirect(url_for('settings'))

        # Verify current password
        email = user_data.get('email')
        if not email:
            flash('Email not found in user data.', 'error')
            return redirect(url_for('settings'))

        try:
            if auth_client:
                auth_client.sign_in_with_email_and_password(email, current_password)
            else:
                flash('Authentication service unavailable.', 'error')
                return redirect(url_for('settings'))
        except Exception as e:
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('settings'))

        # Update password in Firebase Auth
        auth.update_user(user_id, password=new_password)

        flash('Password updated successfully!', 'success')
        return redirect(url_for('settings'))

    except Exception as e:
        logger.error(f"Password update error: {e}")
        flash('Failed to update password. Please try again.', 'error')
        return redirect(url_for('settings'))
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template('forgot_password.html')

    try:
        email = request.form.get('email', '').strip().lower()
        if not email:
            flash('Please enter your email address.', 'error')
            return render_template('forgot_password.html')

        # Send password reset email via Firebase
        if auth_client:
            auth_client.send_password_reset_email(email)
            flash('Password reset email sent! Please check your inbox.', 'success')
            return redirect(url_for('signin'))
        else:
            flash('Authentication service unavailable.', 'error')
            return render_template('forgot_password.html')

    except Exception as e:
        flash('Failed to send reset email. Please try again.', 'error')
        return render_template('forgot_password.html')


@app.route('/home')
def home():
    """Redirect /home to /new"""
    return redirect(url_for('new'))

@app.route('/test_mailtrap')
def test_mailtrap():
    """Test Mailtrap integration - remove in production"""
    try:
        msg = Message(
            subject="🧪 Test Email - ANAZORI 15.0",
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=['test@example.com']
        )
        msg.html = """
        <h2>✅ Mailtrap Integration Test</h2>
        <p>If you're seeing this in your Mailtrap inbox, the integration is working perfectly!</p>
        <p><strong>Configuration:</strong></p>
        <ul>
            <li>Server: sandbox.smtp.mailtrap.io</li>
            <li>Port: 2525</li>
            <li>Flask-Mail: ✅ Working</li>
        </ul>
        """
        mail.send(msg)
        return "<h2>✅ Test email sent!</h2><p>Check your Mailtrap inbox to see if it was received.</p>"
    except Exception as e:
        return f"<h2>❌ Test failed:</h2><p>{e}</p>"


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
