import os
import json
import logging
import re
import string
import random
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mail import Mail, Message
import firebase_admin
from firebase_admin import credentials, auth, firestore
import pyrebase
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "your-secret-key-here")

# Domain Configuration
PRIMARY_DOMAIN = os.environ.get("PRIMARY_DOMAIN", "anazori.online")
WEBSITE_NAME = os.environ.get("WEBSITE_NAME", "ANAZORI 15.0")

# Titan Email Configuration
app.config['MAIL_SERVER'] = os.environ.get('TITAN_SMTP_SERVER', 'smtp.titan.email')
app.config['MAIL_PORT'] = int(os.environ.get('TITAN_SMTP_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('TITAN_USERNAME')  # noreply@anazori.online
app.config['MAIL_PASSWORD'] = os.environ.get('TITAN_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('TITAN_USERNAME')

# Initialize Flask-Mail
mail = Mail(app)

# Firebase configuration
firebase_config = {
    "apiKey": os.environ.get("FIREBASE_API_KEY"),
    "authDomain": os.environ.get("FIREBASE_AUTH_DOMAIN"),
    "databaseURL": os.environ.get("FIREBASE_DATABASE_URL"),
    "projectId": os.environ.get("FIREBASE_PROJECT_ID"),
    "storageBucket": os.environ.get("FIREBASE_STORAGE_BUCKET"),
    "messagingSenderId": os.environ.get("FIREBASE_MESSAGING_SENDER_ID"),
    "appId": os.environ.get("FIREBASE_APP_ID"),
}

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

# Configuration based on environment
class Config:
    def __init__(self):
        if os.environ.get('RENDER'):
            # Running on Render
            self.BASE_URL = 'https://anazori-1.onrender.com'
        elif os.environ.get('PRODUCTION'):
            # Running with custom domain
            self.BASE_URL = 'https://anazori.online'
        else:
            # Local development
            self.BASE_URL = 'http://127.0.0.1:5000'

config = Config()
app.config['BASE_URL'] = config.BASE_URL

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


def get_base_url():
    """Get base URL for email verification links"""
    return os.environ.get('NGROK_URL', 'http://127.0.0.1:5000')


def send_verification_email(email, verification_token):
    """Send anti-spam optimized verification email using Titan"""
    try:
        base_url = get_base_url()
        verification_url = f"{app.config['BASE_URL']}/verify/{verification_token}"

        print(f"📧 Sending verification email to: {email}")
        print(f"📮 From: {app.config['MAIL_DEFAULT_SENDER']}")

        msg = Message(
            subject="Please verify your ANAZORI 15.0 registration",  # Non-spammy subject
            sender=f"ANAZORI 15.0 <{app.config['MAIL_DEFAULT_SENDER']}>",  # Display name
            recipients=[email],
            reply_to=f"support@{PRIMARY_DOMAIN}"
        )

        # Anti-spam optimized HTML template
        msg.html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Verify Your ANAZORI 15.0 Account</title>
        </head>
        <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">

            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
                <h1 style="color: white; margin: 0; font-size: 28px;">{WEBSITE_NAME}</h1>
                <p style="color: #e0e6ff; margin: 10px 0 0 0; font-size: 14px;">Official Registration Verification</p>
            </div>

            <div style="background: white; padding: 30px; border: 1px solid #e1e8ed; border-top: none; border-radius: 0 0 10px 10px;">

                <h2 style="color: #1a202c; margin-bottom: 20px;">Welcome to the Ultimate Tech Festival!</h2>

                <p>Thank you for registering for <strong>{WEBSITE_NAME}</strong>. To complete your registration and secure your spot at India's most exciting tech festival, please verify your email address by clicking the button below:</p>

                <div style="text-align: center; margin: 30px 0;">
                    <a href="{verification_url}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: 600; display: inline-block;">Verify My Email Address</a>
                </div>

                <p style="color: #666; font-size: 14px;"><strong>Can't click the button?</strong> Copy and paste this link into your browser:</p>
                <p style="word-break: break-all; background: #f7f9fc; padding: 10px; border-radius: 5px; font-size: 13px; color: #4a5568;">{verification_url}</p>

                <div style="background: #f0f8ff; padding: 20px; border-radius: 5px; margin: 25px 0; border-left: 4px solid #667eea;">
                    <h3 style="margin: 0 0 10px 0; color: #1a202c; font-size: 16px;">What awaits you at ANAZORI 15.0:</h3>
                    <ul style="margin: 0; padding-left: 20px;">
                        <li>Competitive programming challenges</li>
                        <li>Gaming tournaments and esports</li>
                        <li>Tech treasure hunts</li>
                        <li>Networking with industry professionals</li>
                    </ul>
                </div>

                <div style="border-top: 1px solid #e1e8ed; padding-top: 20px; margin-top: 30px; font-size: 12px; color: #666;">
                    <p><strong>Important:</strong> This verification link will expire in 24 hours for security reasons.</p>
                    <p>If you did not register for this event, please ignore this email or contact our support team.</p>

                    <p style="margin-top: 20px;">
                        <strong>Questions?</strong> Contact us at 
                        <a href="mailto:support@{PRIMARY_DOMAIN}" style="color: #667eea;">support@{PRIMARY_DOMAIN}</a>
                    </p>

                    <hr style="border: none; border-top: 1px solid #e1e8ed; margin: 20px 0;">

                    <p style="text-align: center; color: #999;">
                        © 2025 {WEBSITE_NAME} | Powered by {PRIMARY_DOMAIN}<br>
                        This email was sent to {email} because you registered for our event.
                    </p>
                </div>

            </div>

        </body>
        </html>
        """

        # Add text version for better deliverability
        msg.body = f"""
        ANAZORI 15.0 - Email Verification Required

        Thank you for registering for {WEBSITE_NAME}!

        To complete your registration, please verify your email by visiting:
        {verification_url}

        This link will expire in 24 hours.

        What's waiting for you:
        - Competitive programming challenges
        - Gaming tournaments and esports  
        - Tech treasure hunts
        - Industry networking opportunities

        Questions? Contact: support@{PRIMARY_DOMAIN}

        © 2025 {WEBSITE_NAME} | {PRIMARY_DOMAIN}
        """

        mail.send(msg)
        print(f"✅ Anti-spam verification email sent to {email}")
        return True

    except Exception as e:
        print(f"❌ Email sending failed: {e}")
        logger.error(f"Failed to send verification email to {email}: {e}")
        return False


def send_password_reset_email(email, reset_token):
    """Send password reset email using Titan"""
    try:
        base_url = get_base_url()
        reset_url = f"{base_url}/reset_password?token={reset_token}"

        print(f"📧 Sending password reset to: {email}")
        print(f"🔗 Reset URL: {reset_url}")

        msg = Message(
            subject=f"Reset Your {WEBSITE_NAME} Password",
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[email]
        )

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
                .button {{ display: inline-block; padding: 15px 30px; background: linear-gradient(45deg, #00f5ff, #ff00ff); color: white; text-decoration: none; border-radius: 8px; font-weight: 600; margin: 20px 0; }}
                .link-text {{ word-break: break-all; color: #00f5ff; background: #f8f9fa; padding: 10px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>{WEBSITE_NAME}</h1>
                </div>
                <div class="content">
                    <h2>🔒 Reset Your Password</h2>
                    <p>We received a request to reset your password for your {WEBSITE_NAME} account.</p>

                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{reset_url}" class="button">🔑 Reset Password</a>
                    </div>

                    <p><strong>If the button doesn't work, copy this link:</strong></p>
                    <div class="link-text">{reset_url}</div>

                    <p>⚠️ This link will expire in 1 hour for security reasons.</p>
                    <p>If you didn't request this password reset, you can safely ignore this email.</p>
                </div>

                <div style="color: #666; font-size: 12px; text-align: center; margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px;">
                    <p>© 2025 {WEBSITE_NAME} • Powered by {PRIMARY_DOMAIN}</p>
                </div>
            </div>
        </body>
        </html>
        """

        mail.send(msg)
        print(f"✅ Password reset email sent successfully to {email}")
        return True

    except Exception as e:
        print(f"❌ Password reset email failed: {e}")
        logger.error(f"Failed to send password reset email to {email}: {e}")
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
    """Send email verification for signup using Titan"""
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

        # Send verification email using Titan
        if send_verification_email(email, verification_token):
            return jsonify({
                'success': True,
                'message': f'Verification email sent to {email}! Please check your inbox.'
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

        flash(f'Registration completed successfully! Welcome to {WEBSITE_NAME}!', 'success')
        return redirect(url_for('new'))

    except Exception as e:
        logger.error(f"Complete registration error: {e}")
        flash('Failed to complete registration. Please try again.', 'error')
        return render_template('complete_registration.html',
                               captcha=generate_captcha(), email=session['verified_email'])


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


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot password page"""
    if request.method == 'GET':
        return render_template('forgot_password.html')

    try:
        email = request.form.get('email', '').strip().lower()
        if not email:
            flash('Please enter your email address.', 'error')
            return render_template('forgot_password.html')

        # Generate reset token
        reset_token = secrets.token_urlsafe(32)

        # Store reset token in Firestore with expiration
        reset_data = {
            'email': email,
            'reset_token': reset_token,
            'created_at': time.time(),
            'expires_at': time.time() + 3600,  # 1 hour
        }

        if db:
            db.collection('password_resets').document(reset_token).set(reset_data)

        # Send reset email using Titan
        if send_password_reset_email(email, reset_token):
            flash('Password reset email sent! Please check your inbox.', 'success')
            return redirect(url_for('reset_link_sent'))
        else:
            flash('Failed to send reset email. Please try again.', 'error')
            return render_template('forgot_password.html')

    except Exception as e:
        logger.error(f"Forgot password error: {e}")
        flash('Failed to send reset email. Please try again.', 'error')
        return render_template('forgot_password.html')


@app.route('/reset_link_sent')
def reset_link_sent():
    """Password reset link sent confirmation page"""
    return render_template('reset_link_send.html')


@app.route('/reset_password')
def reset_password():
    """Password reset page"""
    token = request.args.get('token')
    if not token:
        flash('Invalid reset link.', 'error')
        return redirect(url_for('forgot_password'))

    return render_template('reset_password.html', token=token)


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


@app.route('/myregistration')
@login_required
def myregistration():
    """User's event registrations"""
    user_id = session.get('user')
    user_data = get_user_data(user_id)

    if not user_data:
        flash('User data not found.', 'error')
        return redirect(url_for('signin'))

    registrations = []  # Add logic to fetch user registrations

    return render_template('myregistration.html', user=user_data, registrations=registrations)


@app.route('/logout')
def logout():
    """User logout"""
    clear_user_session()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))


# Test Routes
@app.route('/test_titan_email')
def test_titan_email():
    """Test Titan email configuration"""
    test_email = request.args.get('email', 'your-email@gmail.com')

    try:
        token = secrets.token_urlsafe(32)
        success = send_verification_email(test_email, token)

        return f"""
        <h2>📧 Titan Email Test Results</h2>
        <p><strong>Domain:</strong> {PRIMARY_DOMAIN}</p>
        <p><strong>Test email sent to:</strong> {test_email}</p>
        <p><strong>From:</strong> {app.config['MAIL_DEFAULT_SENDER']}</p>
        <p><strong>SMTP Server:</strong> {app.config['MAIL_SERVER']}</p>
        <p><strong>Status:</strong> {'✅ SUCCESS - Check your inbox!' if success else '❌ FAILED - Check console logs'}</p>

        <hr>
        <h3>✅ Expected Results:</h3>
        <ul>
            <li>Email from <strong>{app.config['MAIL_DEFAULT_SENDER']}</strong></li>
            <li>Professional {PRIMARY_DOMAIN} branding</li>
            <li>Working verification link</li>
            <li>Delivered to real inbox</li>
        </ul>

        <p><a href="/test_titan_email?email=different@example.com">Test with different email</a></p>
        <p><a href="/">← Back to Home</a></p>
        """

    except Exception as e:
        return f"<h2>❌ Error:</h2><p>{e}</p>"


@app.route('/debug_email_config')
def debug_email_config():
    """Debug your current email configuration"""
    return f"""
    <h2>📧 Current Titan Email Configuration</h2>
    <p><strong>MAIL_SERVER:</strong> {app.config.get('MAIL_SERVER')}</p>
    <p><strong>MAIL_PORT:</strong> {app.config.get('MAIL_PORT')}</p>
    <p><strong>MAIL_USERNAME:</strong> {app.config.get('MAIL_USERNAME')}</p>
    <p><strong>MAIL_DEFAULT_SENDER:</strong> {app.config.get('MAIL_DEFAULT_SENDER')}</p>
    <p><strong>Password Set:</strong> {'Yes' if app.config.get('MAIL_PASSWORD') else 'No'}</p>
    <p><strong>Domain:</strong> {PRIMARY_DOMAIN}</p>
    <p><strong>Website:</strong> {WEBSITE_NAME}</p>
    """


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


def warm_up_sender_reputation():
    """Gradually increase sending volume to build reputation"""
    import time
    import random

    # Send to different domains to build reputation
    test_emails = [
        'test1@gmail.com', 'test2@yahoo.com', 'test3@outlook.com'
    ]

    for email in test_emails:
        try:
            msg = Message(
                subject="ANAZORI 15.0 - Test Email",
                sender=app.config['MAIL_DEFAULT_SENDER'],
                recipients=[email]
            )
            msg.body = "This is a test email to warm up our sender reputation."
            mail.send(msg)

            # Wait between sends to avoid throttling
            time.sleep(random.randint(30, 60))
            print(f"Reputation warming email sent to {email}")

        except Exception as e:
            print(f"Warm-up email failed for {email}: {e}")


@app.route('/test_spam_score')
def test_spam_score():
    """Test email deliverability and spam score"""
    test_email = request.args.get('email', 'test@mail-tester.com')

    try:
        token = secrets.token_urlsafe(32)
        success = send_verification_email(test_email, token)

        return f"""
        <h2>📊 Email Spam Test Results</h2>
        <p><strong>Test email sent to:</strong> {test_email}</p>
        <p><strong>From:</strong> {app.config['MAIL_DEFAULT_SENDER']}</p>
        <p><strong>Domain:</strong> {PRIMARY_DOMAIN}</p>
        <p><strong>Status:</strong> {'✅ SENT' if success else '❌ FAILED'}</p>

        <hr>
        <h3>📋 Next Steps for Testing:</h3>
        <ol>
            <li><strong>Visit <a href="https://mail-tester.com" target="_blank">Mail-Tester.com</a></strong></li>
            <li><strong>Send test email to:</strong> <code>test-xxxxx@mail-tester.com</code></li>
            <li><strong>Check your spam score</strong> (aim for 10/10)</li>
            <li><strong>Fix any issues</strong> highlighted in the report</li>
        </ol>

        <h3>🛡️ Anti-Spam Checklist:</h3>
        <ul>
            <li>✅ SPF record configured</li>
            <li>✅ DKIM record added</li>
            <li>✅ DMARC policy set</li>
            <li>✅ Professional sender name</li>
            <li>✅ Text + HTML versions</li>
            <li>✅ Reply-to address set</li>
        </ul>

        <p><a href="/">← Back to Home</a></p>
        """

    except Exception as e:
        return f"<h2>❌ Test Error:</h2><p>{e}</p>"


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

