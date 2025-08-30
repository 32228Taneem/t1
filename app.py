from flask import Flask,render_template,url_for,redirect,request,flash,session,jsonify,send_from_directory,g,Blueprint,make_response
from otp import genotp
from cmail import sendmail
from tokens import encode,decode
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import validate_csrf, CSRFError
from werkzeug.exceptions import Forbidden,BadRequest
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired
import mysql.connector
from flask_session import Session
from werkzeug.utils import secure_filename
from mysql.connector import IntegrityError
from mysql.connector.errors import DatabaseError
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask_caching import Cache
import logging
logging.basicConfig(level=logging.DEBUG)
import jwt
import os
import re
import time
import bcrypt
import secrets
# from dotenv import load_dotenv
# load_dotenv()
RESULTS_PER_PAGE = 10

app = Flask(__name__)
cache = Cache(config={'CACHE_TYPE': 'SimpleCache'})
cache.init_app(app)
search_bp = Blueprint('search', __name__)
logger = logging.getLogger(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
app.secret_key = 'tech$tan111'  # Required for session and flash
UPLOAD_FOLDER = 'static/uploads' # path to store images
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['WTF_CSRF_ENABLED'] = True  # Should be True in production
app.config['JWT_SECRET_KEY'] = 'taneem@123jwT'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['SESSION_FILE_THRESHOLD'] = 100
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    SESSION_REFRESH_EACH_REQUEST=True,
    SECRET_KEY='taneem@123jwT'
)
Session(app)
csrf = CSRFProtect(app)

# MySQL Configuration
mytdb = mysql.connector.connect(
    host='localhost',
    user='root',
    password='Taneem_2002',
    database='sharetech'
)
cursor = mytdb.cursor(buffered=True)

# ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'webp'}
# app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Function: allowed_file
# Purpose: Validates if a file has an allowed extension
# Functionality: Checks if filename contains a dot and its extension is in ALLOWED_EXTENSIONS
def allowed_file(filename):
    # Returns True if filename has a valid extension, False otherwise
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Function: is_admin_logged_in
# Purpose: Checks if an admin is logged in
# Functionality: Verifies presence of admin-related session keys
def is_admin_logged_in():
    """Check if admin is logged in with any valid session key"""
    # Returns True if any admin session key exists, False otherwise
    return any(key in session for key in ['Admin_mail', 'admin', 'admin_email'])

# Function: get_admin_id
# Purpose: Retrieves admin ID from session or database
# Functionality: Gets admin ID from session, falls back to database query if needed
def get_admin_id():
    """Get admin ID from session with fallback to database lookup"""
    # Retrieves admin ID from session
    admin_id = session.get('Admin_id') or session.get('admin_id')
    # If not found and admin is logged in, queries database using admin email
    if not admin_id and is_admin_logged_in():
        email = session.get('Admin_mail') or session.get('admin') or session.get('admin_email')
        cursor.execute('SELECT admin_id FROM admins WHERE admin_email=%s', (email,))
        admin_id = cursor.fetchone()[0]
        # Stores admin ID in session for future use
        session['Admin_id'] = admin_id
        session.modified = True
    # Returns admin ID or None if not found
    return admin_id

# Function: create_jwt_token
# Purpose: Generates a JWT token with user data
# Functionality: Creates token with expiration time and user data using secret key
def create_jwt_token(user_data):
    """Create JWT token with user data"""
    # Builds token data with expiration time and user details
    token_data = {
        'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES'],
        **user_data
    }
    # Encodes token using JWT secret key and HS256 algorithm
    return jwt.encode(token_data, app.config['JWT_SECRET_KEY'], algorithm='HS256')

# Function: jwt_required
# Purpose: Decorator to enforce JWT authentication for protected routes
# Functionality: Validates JWT token from cookies or headers, sets user data, and handles errors
def jwt_required(f):
    """Decorator for JWT authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Checks for token in cookies (web) or Authorization header (API)
        if 'access_token' in request.cookies:
            token = request.cookies.get('access_token')
        elif 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        
        # Returns error or redirects if no token is found
        if not token:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Token missing'}), 401
            return redirect(url_for('login'))
        
        try:
            # Decodes and validates JWT token
            payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            # Stores user data in Flask's global object
            g.current_user = payload
        except jwt.ExpiredSignatureError:
            # Handles expired token
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Token expired'}), 401
            return redirect(url_for('login'))
        except jwt.InvalidTokenError:
            # Handles invalid token
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Invalid token'}), 401
            return redirect(url_for('login'))
        
        # Calls original function if token is valid
        return f(*args, **kwargs)
    return decorated_function

# Route: /
# @app.route('/')
# def base():
#     return render_template('index.html')
# Purpose: Displays the homepage with navigation bar items added by admin
# Functionality: Fetches navbar items from database and renders welcome.html template
@app.route('/')
def home():
    # Fetches navigation bar items (id and name) from the database, ordered by position
    cursor.execute('SELECT id, name FROM navbar_items ORDER BY position ASC')
    # Retrieves all navigation items as a list of tuples
    navbar_items = cursor.fetchall()
    # Renders the welcome.html template, passing the navigation items for display
    return render_template('welcome.html', navbar_items=navbar_items)

# Route: /login
# Purpose: Handles user and admin login with form display (GET) and authentication (POST)
# Functionality: Validates credentials, initiates admin OTP or user JWT, and redirects accordingly
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Check if there's a registration success message to display
    registration_success = session.pop('registration_success', None)
    if registration_success:
        flash(registration_success, 'success')
    
    if request.method == 'POST':
        # Retrieves and sanitizes email and password from form submission
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        # Validates that email and password are provided
        if not email or not password:
            flash('Email and password are required', 'error')
            return render_template('login/login.html', email=email, error=True)

        try:
            cursor = mytdb.cursor(buffered=True)
            # ================= ADMIN LOGIN FLOW =================
            # Queries database for admin with matching email
            cursor.execute('SELECT admin_id, admin_name, password FROM admins WHERE admin_email=%s', [email])
            admin_data = cursor.fetchone()
            
            # If admin exists, verifies password
            if admin_data:
                admin_id, admin_name, stored_password = admin_data
                
                # If password matches, generates a 15-minute OTP and stores admin data in session
                if password == stored_password.decode('utf-8'):
                    otp, expires_at = genotp(valid_minutes=15)
                    
                    # Stores temporary admin session data
                    session['admin_temp'] = {
                        'email': email,
                        'admin_id': str(admin_id),
                        'admin_name': admin_name,
                        'expiry': expires_at
                    }
                    
                    # Stores OTP data in session
                    session['admin_otp'] = {
                        'code': otp,
                        'expires_at': expires_at.isoformat()
                    }
                    
                    # Sends OTP email to admin
                    sendmail(
                        to=email,
                        subject='Admin OTP Verification',
                        body=f'Your admin verification code is: {otp}\n\nValid until: {expires_at.strftime("%Y-%m-%d %H:%M")}'
                    )
                    flash('OTP has been sent to your email', 'success')
                    # Redirects to admin OTP verification page
                    return redirect(url_for('admin_otp_verify'))
                
                flash('Invalid credentials', 'error')
                return render_template('login/login.html', email=email, error=True)

            # ================= USER LOGIN FLOW =================
            # Queries database for user with matching email
            cursor.execute('SELECT user_id, username, password FROM usercreate WHERE user_email=%s', [email])
            user_data = cursor.fetchone()
            
            # If user exists, verifies password
            if user_data:
                user_id, username, stored_password = user_data
                
                # If password matches, creates JWT token and stores user data in session
                if password == stored_password.decode('utf-8'):
                    token = create_jwt_token({
                        'user_id': user_id,
                        'email': email,
                        'username': username,
                        'user_type': 'user'
                    })
                    
                    session['user'] = email
                    session['username'] = username
                    
                    # Fetches default navigation item to redirect user
                    cursor.execute('SELECT name FROM navbar_items ORDER BY position ASC LIMIT 1')
                    default_item = cursor.fetchone()
                    
                    # Redirects to default subtopics page if available, sets JWT cookie
                    if default_item:
                        response = make_response(redirect(url_for('view_subtopics', item_name=default_item[0])))
                        response.set_cookie(
                            'access_token', 
                            token, 
                            httponly=True, 
                            secure=True,
                            samesite='Lax',
                            max_age=3600
                        )
                        flash(f'Welcome back, {username}!', 'success')
                        return response
                    else:
                        flash('No content available yet', 'info')
                        # Redirects to home
                        return redirect(url_for('home'))
                else:
                    flash('Invalid password. Please try again.', 'error')
                    return render_template('login/login.html', email=email, error=True)

            # Email not found in usercreate or admins
            flash('Email not registered. Please create an account.', 'error')
            return render_template('login/login.html', email=email, error=True)

        except Exception as e:
            # Logs and flashes error if an exception occurs during login
            print(f"Login error: {str(e)}")
            flash('An error occurred during login', 'error')
            return render_template('login/login.html', email=email, error=True)
    
    # For GET request, renders the login form template
    return render_template('login/login.html')

# Route: /admin_otp_verify
# Purpose: Verifies admin OTP with form display (GET) and OTP validation (POST)
# Functionality: Validates OTP and admin ID, issues JWT, and redirects to admin panel
# Defines a route for admin OTP verification, handling both GET (display form) and POST (process OTP) requests
@app.route('/admin_otp_verify', methods=['GET', 'POST'])
def admin_otp_verify():
    # Initialize session variables for resend limits and attempts
    if 'otp_resends' not in session:
        session['otp_resends'] = 0
    if 'last_resend_time' not in session:
        session['last_resend_time'] = None
    if 'otp_attempts' not in session:
        session['otp_attempts'] = 0
    if 'block_until' not in session:
        session['block_until'] = None

    # Check if admin temporary session data exists
    if 'admin_temp' not in session:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))

    # Check OTP expiration
    expires_at = datetime.fromisoformat(session['admin_otp']['expires_at'])
    if datetime.now() > expires_at:
        flash('OTP has expired. Please login again.', 'error')
        return redirect(url_for('login'))

    # Check if email is blocked
    if session['block_until']:
        block_until = datetime.fromisoformat(session['block_until'])
        if datetime.now() < block_until:
            remaining_block = (block_until - datetime.now()).total_seconds()
            flash(f'Too many incorrect attempts. Please try again in {int(remaining_block // 3600)} hours.', 'error')
            return redirect(url_for('login'))
        else:
            session['block_until'] = None
            session['otp_attempts'] = 0

    # Calculate resend cooldown
    resend_enabled = True
    resend_cooldown = 0
    if session.get('last_resend_time'):
        last_resend_time = datetime.fromisoformat(session['last_resend_time'])
        time_since_resend = (datetime.now() - last_resend_time).total_seconds()
        if time_since_resend < 30:
            resend_enabled = False
            resend_cooldown = max(0, int(30 - time_since_resend))
        if session['otp_resends'] > 0 and time_since_resend > 90:
            session['otp_resends'] = 0
            session['last_resend_time'] = None

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'resend':
            # Check resend limits
            if session['otp_resends'] >= 3:
                flash('Maximum OTP resend attempts reached. Please login again.', 'error')
                return redirect(url_for('login'))

            if not resend_enabled:
                flash(f'Please wait {resend_cooldown} seconds before resending OTP.', 'error')
                return render_template('admin/adminotp.html',
                                     expires_at=expires_at,
                                     admin_id=session['admin_temp']['admin_id'],
                                     resend_enabled=resend_enabled,
                                     resend_cooldown=resend_cooldown,
                                     attempts_left=3 - session['otp_attempts'])

            # Generate and send new OTP
            try:
                otp, new_expires_at = genotp(valid_minutes=15)
                session['admin_otp'] = {
                    'code': otp,
                    'expires_at': new_expires_at.isoformat()
                }
                session['otp_attempts'] = 0
                sendmail(
                    to=session['admin_temp']['email'],
                    subject='New Admin OTP Verification',
                    body=f'Your new admin verification code is: {otp}\n\nValid until: {new_expires_at.strftime("%Y-%m-%d %H:%M")}'
                )
                session['otp_resends'] += 1
                session['last_resend_time'] = datetime.now().isoformat()
                flash('New OTP sent to your email.', 'success')
                return render_template('admin/adminotp.html',
                                     expires_at=new_expires_at,
                                     admin_id=session['admin_temp']['admin_id'],
                                     resend_enabled=False,
                                     resend_cooldown=30,
                                     attempts_left=3)
            except Exception as e:
                print(f"ERROR: Resend OTP failed: {str(e)}")
                flash('Failed to resend OTP. Please try again.', 'error')
                return render_template('admin/adminotp.html',
                                     expires_at=expires_at,
                                     admin_id=session['admin_temp']['admin_id'],
                                     resend_enabled=resend_enabled,
                                     resend_cooldown=resend_cooldown,
                                     attempts_left=3 - session['otp_attempts'])

        # Handle OTP verification
        otp = request.form.get('otp', '').strip()
        admin_id = request.form.get('admin_id', '').strip()
        stored_otp = session['admin_otp']['code']
        expected_admin_id = session['admin_temp']['admin_id']

        # Check if either OTP or Admin ID is incorrect
        if stored_otp == otp and admin_id == expected_admin_id:
            # Successful verification
            token = create_jwt_token({
                'admin_id': session['admin_temp']['admin_id'],
                'email': session['admin_temp']['email'],
                'admin_name': session['admin_temp']['admin_name'],
                'user_type': 'admin'
            })
            session['admin'] = session['admin_temp']['email']
            session['admin_id'] = session['admin_temp']['admin_id']
            session['admin_name'] = session['admin_temp']['admin_name']
            session.pop('admin_temp', None)
            session.pop('admin_otp', None)
            session.pop('otp_resends', None)
            session.pop('last_resend_time', None)
            session.pop('otp_attempts', None)
            session.pop('block_until', None)
            response = redirect(url_for('admin_panel'))
            response.set_cookie('access_token', token, httponly=True, secure=True)
            flash('Authentication successful!', 'success')
            return response
        else:
            # Increment attempts for any incorrect input (OTP or Admin ID)
            session['otp_attempts'] += 1
            if session['otp_attempts'] >= 3:
                session['block_until'] = (datetime.now() + timedelta(hours=24)).isoformat()
                session['otp_attempts'] = 0
                flash('Too many incorrect attempts. Please try again in 24 hours.', 'error')
                return redirect(url_for('login'))
            # Flash specific error messages
            if stored_otp != otp:
                flash('Invalid OTP', 'error')
            if admin_id != expected_admin_id:
                flash('Invalid Admin ID', 'error')
            return render_template('admin/adminotp.html',
                                 expires_at=expires_at,
                                 admin_id=session['admin_temp']['admin_id'],
                                 resend_enabled=resend_enabled,
                                 resend_cooldown=resend_cooldown,
                                 attempts_left=3 - session['otp_attempts'])

    return render_template('admin/adminotp.html',
                         expires_at=expires_at,
                         admin_id=session['admin_temp']['admin_id'],
                         resend_enabled=resend_enabled,
                         resend_cooldown=resend_cooldown,
                         attempts_left=3 - session['otp_attempts'])


# Route: /usercreate
# Purpose: Handles user registration by displaying a signup form (GET) and processing registration data (POST)
# Functionality: Validates email uniqueness, generates and sends OTP, and redirects to OTP verification
@app.route('/usercreate', methods=['GET', 'POST'])
def usercreate():
    if request.method == 'POST':
        try:
            uname = request.form['username']
            uemail = request.form['email']
            upassword = request.form['password']
            
            # Validate password length to match varbinary(20)
            if len(upassword) > 20:
                flash('Password is too long. Maximum length is 20 characters.', 'error')
                return render_template('user/usersignup.html', 
                                     username=uname, 
                                     email=uemail)
            
            cursor = mytdb.cursor(buffered=True)
            # Check usercreate table
            cursor.execute('SELECT count(user_email) FROM usercreate WHERE user_email=%s', [uemail])
            uemail_count = cursor.fetchone()[0]
            # Check admins table
            cursor.execute('SELECT count(admin_email) FROM admins WHERE admin_email=%s', [uemail])
            admin_email_count = cursor.fetchone()[0]
            
            if uemail_count > 0 or admin_email_count > 0:
                flash('Email already registered. Please login.', 'error')
                return render_template('user/usersignup.html', 
                                     username=uname, 
                                     email=uemail)
            
            # Generate OTP (valid for 3 minutes)
            otp, expires_at = genotp(valid_minutes=3)
            
            userdata = {
                'uname': uname,
                'uemail': uemail,
                'upassword': upassword,
                'uotp': otp,
                'otp_expires': expires_at.isoformat(),
                'otp_attempts': 0,  # Initialize attempts
                'block_until': None  # Initialize block status
            }
            
            subject = 'Thank you for registering'
            body = f'Your verification OTP is: {otp}\n\nIt expires in 3 minutes.'
            sendmail(to=uemail, subject=subject, body=body)
            
            flash('OTP has been sent to your email', 'success')
            return redirect(url_for('uotp', pudata=encode(data=userdata)))
            
        except Exception as e:
            print(f"Error in usercreate: {str(e)}")
            flash('An error occurred during registration', 'error')
            return render_template('user/usersignup.html', 
                                 username=uname if 'uname' in locals() else '', 
                                 email=uemail if 'uemail' in locals() else '')
    
    # GET request - show empty form
    return render_template('user/usersignup.html')

# Route: /uotp/<pudata>
# Purpose: Manages OTP verification for user registration, showing OTP form (GET) and validating OTP (POST)
# Functionality: Verifies OTP, checks expiration, inserts user into database, and redirects to login
@app.route('/uotp/<pudata>', methods=['GET', 'POST'])
def uotp(pudata):
    # Initialize session variables for resend limits
    if 'otp_resends' not in session:
        session['otp_resends'] = 0
    if 'last_resend_time' not in session:
        session['last_resend_time'] = None

    try:
        d_udata = decode(data=pudata)
        # Initialize attempts and block_until if not present
        if 'otp_attempts' not in d_udata:
            d_udata['otp_attempts'] = 0
        if 'block_until' not in d_udata:
            d_udata['block_until'] = None

        # Check if email is blocked
        if d_udata['block_until']:
            block_until = datetime.fromisoformat(d_udata['block_until'])
            if datetime.now() < block_until:
                remaining_block = (block_until - datetime.now()).total_seconds()
                flash(f'Too many incorrect attempts for this email. Please try again in {int(remaining_block // 3600)} hours.', 'error')
                return redirect(url_for('usercreate'))
            else:
                # Clear block if time has passed
                d_udata['block_until'] = None
                d_udata['otp_attempts'] = 0
                pudata = encode(d_udata)

        # Calculate resend cooldown
        resend_enabled = True
        resend_cooldown = 0
        if session.get('last_resend_time'):
            last_resend_time = datetime.fromisoformat(session['last_resend_time'])
            time_since_resend = (datetime.now() - last_resend_time).total_seconds()
            if time_since_resend < 30:
                resend_enabled = False
                resend_cooldown = max(0, int(30 - time_since_resend))
            # Check 90-second window for resend limit
            if session['otp_resends'] > 0 and time_since_resend > 90:
                session['otp_resends'] = 0  # Reset resends after 90 seconds
                session['last_resend_time'] = None

        # Calculate OTP expiration
        def get_expires_in(d_udata):
            try:
                expires_at = datetime.fromisoformat(d_udata['otp_expires'])
                remaining_time = int((expires_at - datetime.now()).total_seconds())
                return max(0, remaining_time) if remaining_time > 0 else 'Expired'
            except Exception:
                return 'Expired'

        if request.method == 'POST':
            action = request.form.get('action')
            
            if action == 'resend':
                # Check resend limits
                if session['otp_resends'] >= 3:
                    flash('Maximum OTP resend attempts reached. Please register again.', 'error')
                    return redirect(url_for('usercreate'))
                
                if not resend_enabled:
                    flash(f'Please wait {resend_cooldown} seconds before resending OTP.', 'error')
                    expires_in = get_expires_in(d_udata)
                    return render_template('user/userotp.html', 
                                         email=d_udata['uemail'], 
                                         pudata=pudata,
                                         expires_in=expires_in,
                                         expires_at=d_udata['otp_expires'],
                                         resend_enabled=resend_enabled,
                                         resend_cooldown=resend_cooldown,
                                         attempts_left=3 - d_udata['otp_attempts'])

                # Generate new OTP
                try:
                    new_otp, new_expires_at = genotp(valid_minutes=3)  # 3-minute validity
                    d_udata['uotp'] = new_otp
                    d_udata['otp_expires'] = new_expires_at.isoformat()
                    d_udata['otp_attempts'] = 0  # Reset attempts on resend
                    new_pudata = encode(d_udata)
                    
                    # Send new OTP email
                    sendmail(
                        to=d_udata['uemail'],
                        subject='New OTP for Verification',
                        body=f"Hello {d_udata['uname']},\n\nYour new OTP is: {new_otp}\n\nIt expires in 3 minutes."
                    )
                    
                    session['otp_resends'] += 1
                    session['last_resend_time'] = datetime.now().isoformat()
                    flash('New OTP sent to your email.', 'success')
                    
                    return render_template('user/userotp.html',
                                         email=d_udata['uemail'],
                                         pudata=new_pudata,
                                         expires_in=180,  # 3 minutes in seconds
                                         expires_at=new_expires_at.isoformat(),
                                         resend_enabled=False,
                                         resend_cooldown=30,
                                         attempts_left=3)
                except Exception as e:
                    print(f"ERROR: Resend OTP failed: {str(e)}")
                    flash('Failed to resend OTP. Please try again.', 'error')
                    return redirect(url_for('usercreate'))

            # Handle OTP verification
            fuotp = request.form.get('otp', '').strip()
            
            # Check OTP expiration
            expires_at = datetime.fromisoformat(d_udata['otp_expires'])
            
            if datetime.now() > expires_at:
                flash('Verification code has expired. Please register again.', 'error')
                return redirect(url_for('usercreate'))
            
            if fuotp == d_udata['uotp']:
                # OTP is correct - create user account
                cursor = mytdb.cursor(buffered=True)
                try:
                    cursor.execute(
                        'INSERT INTO usercreate(user_email, username, password) VALUES (%s, %s, %s)',
                        [d_udata['uemail'], d_udata['uname'], d_udata['upassword']]
                    )
                    mytdb.commit()
                    
                    # Clear session resend data
                    session.pop('otp_resends', None)
                    session.pop('last_resend_time', None)
                    
                    # Store success message in session to display on login page
                    session['registration_success'] = 'Your account has been successfully created! Please login.'
                    
                    return redirect(url_for('login'))
                    
                except Exception as e:
                    mytdb.rollback()
                    print(f"ERROR: Database error: {str(e)}")
                    flash('Registration error. Please try again.', 'error')
                    return redirect(url_for('usercreate'))
            else:
                d_udata['otp_attempts'] += 1
                if d_udata['otp_attempts'] >= 3:
                    d_udata['block_until'] = (datetime.now() + timedelta(hours=24)).isoformat()
                    d_udata['otp_attempts'] = 0
                    pudata = encode(d_udata)
                    flash('Too many incorrect attempts for this email. Please try again in 24 hours.', 'error')
                    return redirect(url_for('usercreate'))
                
                flash('Invalid verification code. Please try again.', 'error')
                pudata = encode(d_udata)  # Update pudata with new attempts
                expires_in = get_expires_in(d_udata)
                return render_template('user/userotp.html',
                                      email=d_udata['uemail'],
                                      pudata=pudata,
                                      expires_in=expires_in,
                                      expires_at=d_udata['otp_expires'],
                                      resend_enabled=resend_enabled,
                                      resend_cooldown=resend_cooldown,
                                      attempts_left=3 - d_udata['otp_attempts'])
                
        # GET request - show OTP entry form
        expires_in = get_expires_in(d_udata)
        return render_template('user/userotp.html', 
                              email=d_udata['uemail'],
                              pudata=pudata,
                              expires_in=expires_in,
                              expires_at=d_udata['otp_expires'],
                              resend_enabled=resend_enabled,
                              resend_cooldown=resend_cooldown,
                              attempts_left=3 - d_udata['otp_attempts'])
    
    except Exception as e:
        print(f"ERROR: Failed to decode pudata: {str(e)}")
        flash('Invalid verification data', 'error')
        return redirect(url_for('usercreate'))
        
# Route: /userforgot
# Purpose: Facilitates password reset requests by showing a form (GET) and sending a reset link (POST)
# Functionality: Checks if email exists, sends a password reset link via email, and redirects appropriately
@app.route('/userforgot',methods=['GET','POST'])
def userforgot():
    if request.method=='POST':
        forgot_useremail=request.form['uemail']
        cursor=mytdb.cursor(buffered=True)
        cursor.execute('select count(user_email) from usercreate where user_email=%s',[forgot_useremail])
        stored_email=cursor.fetchone()
        if stored_email[0]==1:
            # Create token with expiration (15 minutes from now)
            expiration = datetime.now(timezone.utc) + timedelta(minutes=15)
            token_data = {
                'email': forgot_useremail,
                'exp': expiration.timestamp(),
                'used': False  # Track if token has been used
            }
            
            # Generate token
            token = encode(data=token_data)
            
            subject='Reset link for user'
            body=f"Click on the link to update your password: {url_for('user_password_update', token=token, _external=True)}\n\nThis link will expire in 15 minutes."
            sendmail(to=forgot_useremail, subject=subject, body=body)
            flash(f'Reset link has been sent to {forgot_useremail}', 'success')
            return render_template('user/userforgot.html')
        elif stored_email[0]==0:
            # Use a single flash message instead of both flash and template variable
            flash('No email registered. Please check.', 'error')
            return render_template('user/userforgot.html')
    
    # For GET requests or if there was an issue with POST
    return render_template('user/userforgot.html')


# Route: /user_password_update/<token>
# Purpose: Manages user password reset by displaying a form (GET) and updating the password (POST)
# Functionality: Decodes token to get email, validates new password, updates database, and redirects
@app.route('/user_password_update/<token>', methods=['GET', 'POST'])
def user_password_update(token):
    try:
        # Decode the token
        token_data = decode(data=token)
        
        # Check if token has expired
        if datetime.now(timezone.utc).timestamp() > token_data['exp']:
            flash('This reset link has expired. Please request a new one.', 'error')
            return redirect(url_for('userforgot'))
            
        # Check if token has already been used
        if token_data.get('used', False):
            flash('This reset link has already been used. Please request a new one.', 'error')
            return redirect(url_for('userforgot'))
            
    except Exception as e:
        print(e)
        flash('Invalid or corrupted reset link. Please request a new one.', 'error')
        return redirect(url_for('userforgot'))
    
    if request.method == 'POST':
        try:
            npassword = request.form['npassword']
            cpassword = request.form['cpassword']
            
            if npassword == cpassword:
                cursor = mytdb.cursor(buffered=True)
                # Update password
                cursor.execute('UPDATE usercreate SET password=%s WHERE user_email=%s', [npassword, token_data['email']])
                
                # Mark token as used (you might want to store this in database)
                # For simplicity, we'll just show a success message
                
                mytdb.commit()
                flash('Password updated successfully! Please login with your new password.', 'success')
                return render_template('user/newuserpassword.html', 
                                      success=True, 
                                      email=token_data['email'])
            else:
                flash('Passwords do not match. Please try again.', 'error')
                return render_template('user/newuserpassword.html', 
                                      token=token)
        except Exception as e:
            print(e)
            flash('Something went wrong. Please try again.', 'error')
            return render_template('user/newuserpassword.html', 
                                  token=token)
    
    # GET request - show the form
    return render_template('user/newuserpassword.html', token=token)

# Route: /logout
# Purpose: Logs out the user by clearing session data
# Functionality: Clears all session variables and redirects to the homepage
@app.route('/logout')
def logout():
    # Removes all session data to end user/admin session
    session.clear()
    # Redirects to the homepage
    return redirect(url_for('home'))

# Route: /admin_panel
# Purpose: Displays the admin panel for authorized admins
# Functionality: Verifies admin JWT, fetches navbar items, and renders admin panel template
@app.route('/admin_panel')
@jwt_required  # Ensures valid JWT token is present
def admin_panel():
    # Redirects to login if user is not an admin
    if g.current_user.get('user_type') != 'admin':
        return redirect(url_for('login'))
    
    # Retrieves admin name from session or JWT
    admin_name = session.get('admin_name') or g.current_user.get('admin_name')
    
    # Fetches navbar item names from database, ordered by position
    cursor.execute('SELECT name FROM navbar_items ORDER BY position')
    nav_items = [item[0] for item in cursor.fetchall()]
    # Renders admin panel template with navbar items and admin name
    return render_template('admin/admin_panel.html', navbar_items=nav_items, admin_name=admin_name)

# Route: /add_navbar_item
# Purpose: Allows admins to add new navigation bar items via a form submission
# Functionality: Validates admin session, checks for duplicate items, assigns position, and inserts item into database
@app.route('/add_navbar_item', methods=['POST'])
def add_navbar_item():
    # Verifies admin is logged in by checking session keys
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        flash('Please login as admin first', 'error')
        return redirect(url_for('login'))

    try:
        # Retrieves and sanitizes navbar item name from form
        item = request.form.get('item', '').strip()
        if not item:
            flash('Navbar item name cannot be empty', 'error')
            return redirect(url_for('admin_panel'))

        # Retrieves admin ID from session or database
        admin_id = session.get('Admin_id')
        if not admin_id:
            admin_email = session.get('Admin_mail') or session.get('admin') or session.get('admin_email')
            cursor.execute('SELECT admin_id FROM admins WHERE admin_email=%s', (admin_email,))
            admin_record = cursor.fetchone()
            if not admin_record:
                flash('Admin account not found', 'error')
                return redirect(url_for('login'))
            admin_id = admin_record[0]
            session['Admin_id'] = admin_id  # Stores admin ID in session
            session.modified = True

        # Debug: Logs admin ID and item name
        app.logger.debug(f"Adding navbar item - Admin ID: {admin_id}")
        app.logger.debug(f"New item: {item}")

        # Determines next position for new item
        cursor.execute('SELECT MAX(position) FROM navbar_items')
        max_position = cursor.fetchone()[0]
        new_position = max_position + 1 if max_position is not None else 1

        # Inserts new navbar item into database with current timestamp
        cursor.execute(
            'INSERT INTO navbar_items (name, position, admin_id, created_at) '
            'VALUES (%s, %s, %s, CURRENT_TIMESTAMP)',
            (item, new_position, admin_id)
        )
        mytdb.commit()

        # Notifies success and redirects to admin panel
        flash(f'Navbar item "{item}" added successfully!', 'success')
        return redirect(url_for('admin_panel'))

    except mysql.connector.IntegrityError:
        # Handles duplicate item error
        mytdb.rollback()
        flash('This navbar item already exists', 'error')
        return redirect(url_for('admin_panel'))

    except mysql.connector.Error as err:
        # Handles general database errors
        mytdb.rollback()
        flash(f'Database error: {err.msg}', 'error')
        return redirect(url_for('admin_panel'))

    except Exception as e:
        # Handles unexpected errors
        mytdb.rollback()
        app.logger.error(f"Error adding navbar item: {str(e)}")
        flash('An unexpected error occurred', 'error')
        return redirect(url_for('admin_panel'))

  # Route: /update_navbar_item
# Purpose: Allows admins to rename existing navigation bar items via form submission
# Functionality: Validates admin session, updates item name in database, and handles duplicates/errors
@app.route('/update_navbar_item', methods=['POST'])
def update_navbar_item():
    # Verifies admin is logged in by checking session keys
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        flash('Please login as admin first', 'error')
        return redirect(url_for('login'))

    try:
        # Retrieves admin ID from session or database
        admin_id = session.get('Admin_id')
        if not admin_id:
            admin_email = session.get('Admin_mail') or session.get('admin') or session.get('admin_email')
            cursor.execute('SELECT admin_id FROM admins WHERE admin_email=%s', (admin_email,))
            admin_record = cursor.fetchone()
            if not admin_record:
                flash('Admin account not found', 'error')
                return redirect(url_for('login'))
            admin_id = admin_record[0]
            session['Admin_id'] = admin_id  # Stores admin ID in session

        # Retrieves and sanitizes old and new item names from form
        old_item = request.form.get('old_item', '').strip()
        new_item = request.form.get('new_item', '').strip()
        
        # Validates that both fields are provided and different
        if not old_item or not new_item:
            flash('Both old and new item names are required', 'error')
            return redirect(url_for('admin_panel'))
        if old_item == new_item:
            flash('New name cannot be same as old name', 'warning')
            return redirect(url_for('admin_panel'))

        # Updates navbar item name and admin ID in database
        cursor.execute(
            '''UPDATE navbar_items 
            SET name = %s, 
                admin_id = %s 
            WHERE name = %s''',
            (new_item, admin_id, old_item)
        )
        
        # Checks if update was successful
        if cursor.rowcount == 0:
            flash('No changes made - item not found', 'warning')
        else:
            mytdb.commit()
            flash(f'Successfully renamed "{old_item}" to "{new_item}"', 'success')

        return redirect(url_for('admin_panel'))

    except mysql.connector.IntegrityError:
        # Handles duplicate item name error
        mytdb.rollback()
        flash('This navbar item name already exists', 'error')
        return redirect(url_for('admin_panel'))

    except Exception as e:
        # Handles unexpected errors
        mytdb.rollback()
        print(f"Error updating navbar item: {str(e)}")
        flash('An error occurred while updating the navbar item', 'error')
        return redirect(url_for('admin_panel'))

# Route: /update_navbar_order
# Purpose: Updates the order of navigation bar items based on admin input
# Functionality: Validates admin session, updates item positions in database, and returns JSON response
@app.route('/update_navbar_order', methods=['POST'])
def update_navbar_order():
    # Verifies admin authentication
    if not is_admin_logged_in():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401

    try:
        # Retrieves admin ID
        admin_id = get_admin_id()
        if not admin_id:
            return jsonify({'status': 'error', 'message': 'Admin information not found'}), 401

        # Retrieves and validates order data from JSON payload
        order = request.json.get('order')
        if not order or not isinstance(order, list):
            return jsonify({'status': 'error', 'message': 'Invalid order data'}), 400

        # Starts transaction if not already in one
        if not mytdb.in_transaction:
            mytdb.start_transaction()
        
        # Updates position for each item based on provided order
        for position, item_name in enumerate(order, start=1):
            cursor.execute(
                'UPDATE navbar_items SET position=%s, admin_id=%s WHERE name=%s',
                (position, admin_id, item_name)
            )
        
        # Commits transaction if started in this scope
        if mytdb.in_transaction:
            mytdb.commit()
            
        # Returns success response
        return jsonify({'status': 'success', 'message': 'Order updated successfully'})

    except mysql.connector.Error as err:
        # Handles database errors
        if mytdb.in_transaction:
            mytdb.rollback()
        logger.error(f"Database error updating navbar order: {str(err)}")
        return jsonify({'status': 'error', 'message': 'Database error'}), 500

    except Exception as e:
        # Handles unexpected errors
        if mytdb.in_transaction:
            mytdb.rollback()
        logger.error(f"Error updating navbar order: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Server error'}), 500  

# Route: /delete_navbar_item
# Purpose: Allows admins to delete navigation bar items and their associated subitems
# Functionality: Validates admin session, logs deletion reason, deletes related content, and removes item
@app.route('/delete_navbar_item', methods=['POST'])
def delete_navbar_item():
    # Verifies admin is logged in by checking session keys
    if not any(key in session for key in ['admin', 'Admin_mail', 'admin_id', 'Admin_id']):
        flash('Administrator authentication required', 'error')
        return redirect(url_for('login'))

    try:
        # Retrieves item name and deletion reason from form
        item = request.form.get('item', '').strip()
        reason = request.form.get('reason', '').strip()
        
        # Ensures both item name and reason are provided
        if not item or not reason:
            flash('Both item name and deletion reason are required', 'error')
            return redirect(url_for('admin_panel'))

        # Retrieves admin ID from session
        admin_id = session.get('admin_id') or session.get('Admin_id')
        
        # Validates admin ID presence
        if not admin_id:
            session.clear()
            flash('Invalid administrator session', 'error')
            return redirect(url_for('login'))

        cursor = mytdb.cursor(buffered=True)
        
        # Logs deletion details with admin ID and timestamp
        cursor.execute('''
            INSERT INTO navbar_deletion_logs 
            (nav_item_name, deletion_reason, admin_id, deleted_at)
            VALUES (%s, %s, %s, NOW())
        ''', (item, reason, admin_id))
        
        # Deletes associated subtopics and sub-subtopics linked to the navbar item
        cursor.execute('''
            DELETE subtopics, sub_subtopics 
            FROM navbar_items
            LEFT JOIN subtopics ON navbar_items.id = subtopics.navbar_id
            LEFT JOIN sub_subtopics ON subtopics.id = sub_subtopics.subtopic_id
            WHERE navbar_items.name = %s
        ''', (item,))
        
        # Deletes the navbar item from database
        cursor.execute('DELETE FROM navbar_items WHERE name=%s', (item,))
        
        # Commits all database changes
        mytdb.commit()
        
        # Notifies success and redirects to admin panel
        flash(f'Successfully deleted "{item}" and all related content', 'success')
        return redirect(url_for('admin_panel'))
        
    except Exception as e:
        # Handles errors by rolling back changes
        mytdb.rollback()
        print(f"Error: {str(e)}")
        flash('An error occurred during deletion', 'error')
        return redirect(url_for('admin_panel'))


# Route: /view_content/<item_name>
# Purpose: Displays subtopics and their sub-subtopics for a specific navbar item for admin view
# Functionality: Fetches navbar item, its subtopics, and sub-subtopics from database, then renders content view
@app.route('/view_content/<item_name>')
def view_content(item_name):
    try:
        # Retrieves navbar item ID based on item name
        cursor.execute('SELECT id FROM navbar_items WHERE name=%s', (item_name,))
        nav_id = cursor.fetchone()
        if not nav_id:
            return 'Navbar item not found', 404

        # Fetches all subtopics for the navbar item, ordered by position
        cursor.execute('''
            SELECT id, title, content, image_filename 
            FROM subtopics 
            WHERE navbar_id=%s 
            ORDER BY position
        ''', (nav_id[0],))
        
        subtopics = []
        for subtopic_row in cursor.fetchall():
            # Fetches all sub-subtopics for the current subtopic, ordered by ID
            cursor.execute('''
                SELECT id, title, content
                FROM sub_subtopics
                WHERE subtopic_id=%s
                ORDER BY id
            ''', (subtopic_row[0],))
            
            subsubtopics = []
            for subsub_row in cursor.fetchall():
                # Builds sub-subtopic data structure
                subsubtopics.append({
                    'id': subsub_row[0],
                    'title': subsub_row[1],
                    'content': subsub_row[2]
                })
            
            # Builds subtopic data structure with sub-subtopics and image URL
            subtopics.append({
                'id': subtopic_row[0],
                'title': subtopic_row[1],
                'content': subtopic_row[2],
                'image': url_for('static', filename=f'uploads/{subtopic_row[3]}') if subtopic_row[3] else None,
                'sub_subtopics': subsubtopics, # This makes the down arrow appea
                'has_subsub': len(subsubtopics) > 0  # Flag for UI rendering
            })
        
        # Renders content view template with item name and subtopics data
        return render_template('admin/view_content.html', item_name=item_name, subtopics=subtopics)
    
    except Exception as e:
        # Handles unexpected errors and returns error message
        return str(e), 500

# Route: /view_subtopics/<item_name>
# Purpose: Displays subtopics and their sub-subtopics for a specific navbar item for user view
# Functionality: Fetches navbar items, subtopics, and sub-subtopics, determines username, and renders user view
@app.route('/view_subtopics/<item_name>')
def view_subtopics(item_name):
    # Initializes username as None for public access
    username = None
    
    # Determines username based on session or JWT token
    if 'user' in session:  # Regular user session
        username = session.get('username')
    elif 'admin' in session or 'Admin_mail' in session:  # Admin session
        username = session.get('admin_name') or session.get('admin_temp', {}).get('admin_name')
    elif 'access_token' in request.cookies:  # JWT token check
        try:
            token = request.cookies.get('access_token')
            # Decodes JWT to extract username
            payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            username = payload.get('username')
        except:
            pass  # Ignores invalid token, treats as public access

    # Fetches all navbar items, ordered by position
    cursor.execute('SELECT id, name FROM navbar_items ORDER BY position ASC')
    navbar_items = cursor.fetchall()
    
    # Retrieves navbar item ID for the given item name
    cursor.execute('SELECT id FROM navbar_items WHERE name=%s', (item_name,))
    nav_id = cursor.fetchone()
    if not nav_id:
        return 'Navbar item not found', 404
    
    # Fetches subtopics for the navbar item, ordered by position
    cursor.execute('''SELECT id, title, content, image_filename 
                   FROM subtopics 
                   WHERE navbar_id=%s 
                   ORDER BY position''', (nav_id[0],))
    subtopics = []
    for row in cursor.fetchall():
        # Fetches sub-subtopics for the current subtopic, ordered by position
        cursor.execute('''
            SELECT id, title, content 
            FROM sub_subtopics 
            WHERE subtopic_id=%s 
            ORDER BY position
        ''', (row[0],))
        
        sub_subtopics = [
            {
                'id': sub_row[0],
                'title': sub_row[1],
                'content': sub_row[2]
            } for sub_row in cursor.fetchall()
        ]
        
        # Builds subtopic data structure with sub-subtopics and image URL
        subtopics.append({
            'id': row[0],
            'title': row[1],
            'content': row[2],
            'image': url_for('static', filename=f'uploads/{row[3]}') if row[3] else None,
            'sub_subtopics': sub_subtopics
        })
    
    # Renders user view template with navbar items, subtopics, and username
    return render_template('user/view_subtopics.html' , item_name = item_name, subtopics=subtopics, navbar_items=navbar_items, username=username,scroll_to=request.args.get('scroll_to'))  # None if not logged in

# Route: /add_subtopic/<item_name>
# Purpose: Allows admins to add subtopics to a specific navbar item via form submission
# Functionality: Validates admin session, checks navbar item, inserts subtopic, and redirects to content view
@app.route('/add_subtopic/<item_name>', methods=['POST'])
def add_subtopic(item_name):
    # Verifies admin is logged in by checking session keys
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        flash('Please login as admin first', 'error')
        return redirect(url_for('login'))

    try:
        # Retrieves and validates subtopic title from form
        title = request.form.get('title', '').strip()
        if not title:
            flash('Title is required', 'error')
            return redirect(url_for('view_content', item_name=item_name))

        # Retrieves subtopic content from form
        content = request.form.get('content', '').strip()
        
        # Retrieves admin ID from session or database
        admin_id = session.get('Admin_id')
        if not admin_id:
            admin_email = session.get('Admin_mail') or session.get('admin') or session.get('admin_email')
            cursor.execute('SELECT admin_id FROM admins WHERE admin_email=%s', (admin_email,))
            admin_record = cursor.fetchone()
            if not admin_record:
                flash('Admin account not found', 'error')
                return redirect(url_for('login'))
            admin_id = admin_record[0]
            session['Admin_id'] = admin_id  # Stores admin ID in session

        # Retrieves navbar item ID for the given item name
        cursor.execute('SELECT id FROM navbar_items WHERE name=%s', (item_name,))
        nav_id_record = cursor.fetchone()
        if not nav_id_record:
            flash('Category not found', 'error')
            return redirect(url_for('admin_panel'))

        # Inserts new subtopic into database
        cursor.execute(
            'INSERT INTO subtopics (title, content, navbar_id, admin_id) '
            'VALUES (%s, %s, %s, %s)',
            (title, content, nav_id_record[0], admin_id)
        )
        mytdb.commit()

        # Notifies success and redirects to content view
        flash(f'Subtopic "{title}" added successfully!', 'success')
        return redirect(url_for('view_content', item_name=item_name))

    except mysql.connector.IntegrityError:
        # Handles duplicate subtopic title error
        mytdb.rollback()
        flash('This subtopic title already exists', 'error')
        return redirect(url_for('view_content', item_name=item_name))

    except Exception as e:
        # Handles unexpected errors
        mytdb.rollback()
        print(f"Error adding subtopic: {str(e)}")
        flash('An error occurred while adding the subtopic', 'error')
        return redirect(url_for('view_content', item_name=item_name))

# Route: /edit_subtopic/<int:sub_id>
# Purpose: Allows admins to edit existing subtopics with form display (GET) and update (POST)
# Functionality: Validates admin session, updates subtopic details, and redirects to content view
@app.route('/edit_subtopic/<int:sub_id>', methods=['GET', 'POST'])
def edit_subtopic(sub_id):
    # Verifies admin is logged in by checking session keys
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        flash('Please login as admin first', 'error')
        return redirect(url_for('login'))

    try:
        if request.method == 'POST':
            # Retrieves and validates subtopic title from form
            title = request.form.get('title', '').strip()
            if not title:
                flash('Title is required', 'error')
                return redirect(url_for('edit_subtopic', sub_id=sub_id))

            # Retrieves subtopic content from form
            content = request.form.get('content', '').strip()
            
            # Retrieves admin ID from session or database
            admin_id = session.get('Admin_id')
            if not admin_id:
                admin_email = session.get('Admin_mail') or session.get('admin') or session.get('admin_email')
                cursor.execute('SELECT admin_id FROM admins WHERE admin_email=%s', (admin_email,))
                admin_record = cursor.fetchone()
                if not admin_record:
                    flash('Admin account not found', 'error')
                    return redirect(url_for('login'))
                admin_id = admin_record[0]
                session['Admin_id'] = admin_id  # Stores admin ID in session

            # Updates subtopic details in database
            cursor.execute(
                'UPDATE subtopics SET title=%s, admin_id=%s, content=%s WHERE id=%s', 
                (title, admin_id, content, sub_id)
            )
            mytdb.commit()

            # Retrieves navbar item name for redirection
            cursor.execute('SELECT navbar_id FROM subtopics WHERE id=%s', (sub_id,))
            nav_id = cursor.fetchone()[0]
            cursor.execute('SELECT name FROM navbar_items WHERE id=%s', (nav_id,))
            item_name = cursor.fetchone()[0]

            # Notifies success and redirects to content view
            flash('Subtopic updated successfully!', 'success')
            return redirect(url_for('view_content', item_name=item_name))

        else:
            # GET: Fetches subtopic data for edit form
            cursor.execute('SELECT title, content, navbar_id FROM subtopics WHERE id=%s', (sub_id,))
            sub = cursor.fetchone()
            if not sub:
                flash('Subtopic not found', 'error')
                return redirect(url_for('admin_panel'))

            # Retrieves navbar item name
            cursor.execute('SELECT name FROM navbar_items WHERE id=%s', (sub[2],))
            item_name = cursor.fetchone()[0]
            
            # Renders edit form with subtopic details
            return render_template(
                'admin/edit_subtopic.html', 
                sub_id=sub_id, 
                title=sub[0], 
                content=sub[1], 
                item_name=item_name
            )

    except Exception as e:
        # Handles unexpected errors
        mytdb.rollback()
        print(f"Error editing subtopic: {str(e)}")
        flash('An error occurred while editing the subtopic', 'error')
        return redirect(url_for('admin_panel'))


# Route: /update_subtopic_order
# Purpose: Updates the order of subtopics based on admin input
# Functionality: Validates admin session, updates subtopic positions, and returns JSON response
@app.route('/update_subtopic_order', methods=['POST'])
def update_subtopic_order():
    # Verifies admin is logged in by checking session keys
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        return {'status': 'error', 'message': 'Please login as admin first'}, 401

    try:
        # Retrieves order data from JSON payload
        order = request.json.get('order')
        if not order:
            return {'status': 'error', 'message': 'No order provided'}, 400

        # Retrieves admin ID from session or database
        admin_id = session.get('Admin_id')
        if not admin_id:
            admin_email = session.get('Admin_mail') or session.get('admin') or session.get('admin_email')
            cursor.execute('SELECT admin_id FROM admins WHERE admin_email=%s', (admin_email,))
            admin_record = cursor.fetchone()
            if not admin_record:
                return {'status': 'error', 'message': 'Admin account not found'}, 401
            admin_id = admin_record[0]
            session['Admin_id'] = admin_id  # Stores admin ID in session

        # Debug: Logs order update request
        print(f"Received order update request from admin {admin_id}: {order}")

        # Updates position for each subtopic
        for position, sub_id in enumerate(order, start=1):
            print(f"Updating subtopic {sub_id} to position {position}")
            cursor.execute(
                'UPDATE subtopics SET position=%s, admin_id=%s WHERE id=%s',
                (position, admin_id, sub_id)
            )

        # Commits changes
        mytdb.commit()
        # Returns success response
        return {'status': 'success', 'message': 'Order updated successfully', 'updated_count': len(order)}

    except mysql.connector.Error as db_error:
        # Handles database errors
        mytdb.rollback()
        print(f"Database error updating subtopic order: {db_error}")
        return {'status': 'error', 'message': 'Database operation failed', 'error': str(db_error)}, 500

    except Exception as e:
        # Handles unexpected errors
        mytdb.rollback()
        print(f"Unexpected error updating subtopic order: {e}")
        return {'status': 'error', 'message': 'An unexpected error occurred', 'error': str(e)}, 500

# Route: /delete_subtopic/<int:sub_id>/<item_name>
# Purpose: Allows admins to delete subtopics via JSON request
# Functionality: Validates admin session, logs deletion reason, deletes subtopic, and returns JSON response
@app.route('/delete_subtopic/<int:sub_id>/<item_name>', methods=['POST'])
def delete_subtopic(sub_id, item_name):
    # Verifies admin is logged in by checking session keys
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        return jsonify({'error': 'Authentication required'}), 401

    try:
        # Retrieves deletion reason from JSON payload
        data = request.get_json()
        reason = data.get('reason', 'No reason provided')

        # Retrieves admin ID from session or database
        admin_id = session.get('Admin_id')
        if not admin_id:
            admin_email = session.get('Admin_mail') or session.get('admin') or session.get('admin_email')
            cursor.execute('SELECT admin_id FROM admins WHERE admin_email=%s', (admin_email,))
            admin_id = cursor.fetchone()[0]

        # Retrieves subtopic title for logging
        cursor.execute('SELECT title FROM subtopics WHERE id=%s', (sub_id,))
        subtopic_title = cursor.fetchone()[0]

        # Logs deletion details
        cursor.execute('''
            INSERT INTO subtopic_deletion_logs 
            (subtopic_id, subtopic_title, admin_id, deletion_reason)
            VALUES (%s, %s, %s, %s)
        ''', (sub_id, subtopic_title, admin_id, reason))

        # Deletes subtopic from database
        cursor.execute('DELETE FROM subtopics WHERE id=%s', (sub_id,))
        mytdb.commit()

        # Returns success response with redirect URL
        return jsonify({
            'success': True, 
            'redirect': url_for('view_content', item_name=item_name)
        })

    except Exception as e:
        # Handles unexpected errors
        mytdb.rollback()
        print(f"Error deleting subtopic: {str(e)}")
        return jsonify({'error': str(e)}), 500

 # sub-sub-topics key routes ya c
@app.route('/get_sub_subtopics/<int:subtopic_id>')
def get_sub_subtopics(subtopic_id):
    try:
        cursor.execute('''
            SELECT id, title, content 
            FROM sub_subtopics 
            WHERE subtopic_id=%s
            ORDER BY id
        ''', (subtopic_id,))
        
        subsubtopics = []
        for row in cursor.fetchall():
            subsubtopics.append({
                'id': row[0],
                'title': row[1],
                'content': row[2]
            })
        
        return jsonify(subsubtopics)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
       
# Route: /add_sub_subtopic
# Purpose: Allows admins to add sub-subtopics to a specific subtopic via form submission
# Functionality: Validates admin session, verifies subtopic, inserts sub-subtopic, and returns JSON response
@app.route('/add_sub_subtopic', methods=['POST'])
def add_sub_subtopic():
    # Verifies admin is logged in by checking session keys
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        return jsonify({
            'success': False,
            'error': 'Please login as admin first',
            'redirect': url_for('login')
        }), 401

    try:
        # Retrieves and validates form data for subtopic ID, title, and content
        subtopic_id = request.form.get('parent_subtopic_id', '').strip()
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()

        # Ensures subtopic ID and title are provided
        if not subtopic_id or not title:
            return jsonify({
                'success': False,
                'error': 'Both parent subtopic ID and title are required'
            }), 400

        # Retrieves admin ID from session or database
        admin_id = session.get('Admin_id')
        if not admin_id:
            admin_email = session.get('Admin_mail') or session.get('admin') or session.get('admin_email')
            cursor.execute('SELECT admin_id FROM admins WHERE admin_email=%s', (admin_email,))
            admin_record = cursor.fetchone()
            if not admin_record:
                return jsonify({
                    'success': False,
                    'error': 'Admin account not found',
                    'redirect': url_for('login')
                }), 401
            admin_id = admin_record[0]
            session['Admin_id'] = admin_id  # Stores admin ID in session

        # Verifies parent subtopic exists in database
        cursor.execute('SELECT id FROM subtopics WHERE id=%s', (subtopic_id,))
        if not cursor.fetchone():
            return jsonify({
                'success': False,
                'error': 'Parent subtopic not found'
            }), 404

        # Inserts new sub-subtopic into database
        cursor.execute('''
            INSERT INTO sub_subtopics (subtopic_id, title, content, admin_id)
            VALUES (%s, %s, %s, %s)
        ''', (subtopic_id, title, content, admin_id))
        mytdb.commit()

        # Retrieves newly created sub-subtopic with parent subtopic title
        cursor.execute('''
            SELECT ss.id, ss.title, ss.content, s.title as parent_title
            FROM sub_subtopics ss
            JOIN subtopics s ON ss.subtopic_id = s.id
            WHERE ss.id = LAST_INSERT_ID()
        ''')
        new_subsub = cursor.fetchone()

        # Returns success response with new sub-subtopic details
        return jsonify({
            'success': True,
            'newSubSubtopic': {
                'id': new_subsub[0],
                'title': new_subsub[1],
                'content': new_subsub[2],
                'parent_title': new_subsub[3]
            },
            'message': 'Sub-subtopic created successfully'
        })

    except mysql.connector.IntegrityError as e:
        # Handles database integrity errors (e.g., duplicate entries)
        mytdb.rollback()
        return jsonify({
            'success': False,
            'error': 'Database integrity error',
            'details': 'This sub-subtopic may already exist' if 'Duplicate entry' in str(e) else str(e)
        }), 400

    except mysql.connector.Error as db_error:
        # Handles general database errors
        mytdb.rollback()
        return jsonify({
            'success': False,
            'error': 'Database operation failed',
            'details': str(db_error)
        }), 500

    except Exception as e:
        # Handles unexpected errors
        mytdb.rollback()
        return jsonify({
            'success': False,
            'error': 'Unexpected error occurred',
            'details': str(e)
        }), 500
    

# Route: /edit_subsubtopic/<int:subsub_id>
# Purpose: Allows admins to edit sub-subtopics with form display (GET) and update (POST)
# Functionality: Validates admin session and ownership, updates sub-subtopic details, and redirects to content view
@app.route('/edit_subsubtopic/<int:subsub_id>', methods=['GET', 'POST'])
def edit_subsubtopic(subsub_id):
    # Verifies admin is logged in by checking session keys
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        return redirect(url_for('login'))

    try:
        # Retrieves admin ID from session or database
        admin_id = session.get('Admin_id')
        if not admin_id:
            admin_email = session.get('Admin_mail') or session.get('admin') or session.get('admin_email')
            cursor.execute('SELECT admin_id FROM admins WHERE admin_email=%s', (admin_email,))
            admin_record = cursor.fetchone()
            if not admin_record:
                flash('Admin account not found', 'error')
                return redirect(url_for('login'))
            admin_id = admin_record[0]
            session['Admin_id'] = admin_id

        if request.method == 'POST':
            # Retrieves and validates title and content from form
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '').strip()

            if not title:
                flash('Title is required', 'error')
                return redirect(url_for('edit_subsubtopic', subsub_id=subsub_id))

            # Verifies sub-subtopic exists and belongs to admin
            cursor.execute('''
                SELECT ss.id FROM sub_subtopics ss
                JOIN subtopics st ON ss.subtopic_id = st.id
                WHERE ss.id = %s AND st.admin_id = %s
            ''', (subsub_id, admin_id))
            if not cursor.fetchone():
                flash('Not authorized to edit this sub-subtopic', 'error')
                return redirect(url_for('admin/admin_panel'))

            # Updates sub-subtopic in database
            cursor.execute('''
                UPDATE sub_subtopics 
                SET title=%s, content=%s, admin_id=%s
                WHERE id=%s
            ''', (title, content, admin_id, subsub_id))
            mytdb.commit()

            # Retrieves navbar item name for redirection
            cursor.execute('''
                SELECT ni.name 
                FROM sub_subtopics ss
                JOIN subtopics st ON ss.subtopic_id = st.id
                JOIN navbar_items ni ON st.navbar_id = ni.id
                WHERE ss.id = %s
            ''', (subsub_id,))
            item_name = cursor.fetchone()[0]

            # Notifies success and redirects to content view
            flash('Sub-subtopic updated successfully!', 'success')
            return redirect(url_for('view_content', item_name=item_name))

        else:
            # GET: Fetches sub-subtopic data for edit form
            cursor.execute('''
                SELECT ss.title, ss.content, st.navbar_id 
                FROM sub_subtopics ss
                JOIN subtopics st ON ss.subtopic_id = st.id
                WHERE ss.id = %s AND st.admin_id = %s
            ''', (subsub_id, admin_id))
            
            subsub = cursor.fetchone()
            if not subsub:
                flash('Sub-subtopic not found or not authorized', 'error')
                return redirect(url_for('admin_panel'))

            # Retrieves navbar item name
            cursor.execute('SELECT name FROM navbar_items WHERE id=%s', (subsub[2],))
            item_name = cursor.fetchone()[0]

            # Renders edit form with sub-subtopic details
            return render_template(
                'admin/edit_subsubtopic.html',
                subsub_id=subsub_id,
                title=subsub[0],
                content=subsub[1],
                item_name=item_name
            )

    except mysql.connector.Error as db_error:
        # Handles database errors
        mytdb.rollback()
        flash('Database error occurred', 'error')
        return redirect(url_for('admin_panel'))

    except Exception as e:
        # Handles unexpected errors
        mytdb.rollback()
        flash('An unexpected error occurred', 'error')
        return redirect(url_for('admin_panel'))

# Route: /update_subsubtopic_order
# Purpose: Updates the order of sub-subtopics under a parent subtopic
# Functionality: Validates admin session and parent subtopic, updates positions, and returns JSON response
@app.route('/update_subsubtopic_order', methods=['POST'])
def update_subsubtopic_order():
    # Verifies admin is logged in by checking session keys
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        return jsonify({
            'status': 'error',
            'message': 'Please login as admin first',
            'redirect': url_for('login')
        }), 401

    try:
        # Retrieves order and parent subtopic ID from JSON payload
        order = request.json.get('order')
        parent_id = request.json.get('parent_id')
        
        # Validates that both order and parent ID are provided
        if not order or not parent_id:
            return jsonify({
                'status': 'error',
                'message': 'Both order and parent_id are required'
            }), 400

        # Retrieves admin ID from session or database
        admin_id = session.get('Admin_id')
        if not admin_id:
            admin_email = session.get('Admin_mail') or session.get('admin') or session.get('admin_email')
            cursor.execute('SELECT admin_id FROM admins WHERE admin_email=%s', (admin_email,))
            admin_record = cursor.fetchone()
            if not admin_record:
                return jsonify({
                    'status': 'error',
                    'message': 'Admin account not found'
                }), 401
            admin_id = admin_record[0]

        # Verifies parent subtopic exists and belongs to admin
        cursor.execute('SELECT id FROM subtopics WHERE id=%s AND admin_id=%s', (parent_id, admin_id))
        if not cursor.fetchone():
            return jsonify({
                'status': 'error',
                'message': 'Parent subtopic not found or not authorized'
            }), 403

        # Updates position for each sub-subtopic
        updates = []
        for position, subsub_id in enumerate(order, start=1):
            cursor.execute('''
                UPDATE sub_subtopics 
                SET position=%s, admin_id=%s
                WHERE id=%s AND subtopic_id=%s
            ''', (position, admin_id, subsub_id, parent_id))
            updates.append(subsub_id)

        # Commits changes
        mytdb.commit()
        # Returns success response with updated IDs
        return jsonify({'status': 'success', 'message': f'Updated {len(updates)} sub-subtopics', 'updated_ids': updates})

    except mysql.connector.Error as db_error:
        # Handles database errors
        mytdb.rollback()
        return jsonify({'status': 'error', 'message': 'Database operation failed', 'error': str(db_error)}), 500

    except Exception as e:
        # Handles unexpected errors
        mytdb.rollback()
        return jsonify({'status': 'error', 'message': 'Unexpected error occurred'}), 500

# Route: /delete_sub_subtopic/<int:subsub_id>
# Purpose: Deletes a specific sub-subtopic and logs the deletion
# Functionality: Validates admin session and ownership, archives sub-subtopic, deletes it, and returns JSON response
@app.route('/delete_sub_subtopic/<int:subsub_id>', methods=['DELETE'])
def delete_sub_subtopic(subsub_id):
    # Verifies admin is logged in by checking session keys
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        return jsonify({
            'success': False,
            'message': 'Please login as admin first',
            'redirect': url_for('login')
        }), 401

    try:
        # Retrieves admin ID from session or database
        admin_id = session.get('Admin_id')
        if not admin_id:
            admin_email = session.get('Admin_mail') or session.get('admin') or session.get('admin_email')
            cursor.execute('SELECT admin_id FROM admins WHERE admin_email=%s', (admin_email,))
            admin_record = cursor.fetchone()
            if not admin_record:
                return jsonify({
                    'success': False,
                    'message': 'Admin account not found'
                }), 401
            admin_id = admin_record[0]

        # Retrieves deletion reason from JSON payload
        deletion_reason = request.json.get('deletion_reason', 'No reason provided')

        # Fetches sub-subtopic details for logging and verification
        cursor.execute('''
            SELECT ss.id, ss.title, ss.content, ss.subtopic_id, ni.name 
            FROM sub_subtopics ss
            JOIN subtopics st ON ss.subtopic_id = st.id
            JOIN navbar_items ni ON st.navbar_id = ni.id
            WHERE ss.id = %s AND st.admin_id = %s
        ''', (subsub_id, admin_id))
        
        result = cursor.fetchone()
        if not result:
            return jsonify({
                'success': False,
                'message': 'Sub-subtopic not found or not authorized'
            }), 404

        # Archives sub-subtopic details in deletion log
        cursor.execute('''
            INSERT INTO sub_subtopic_deletion_logs 
            (sub_subtopic_id, subtopic_id, title, admin_id, deletion_reason)
            VALUES (%s, %s, %s, %s, %s)
        ''', (result[0], result[3], result[1], admin_id, deletion_reason))

        # Deletes sub-subtopic from database
        cursor.execute('DELETE FROM sub_subtopics WHERE id = %s', (subsub_id,))
        mytdb.commit()

        # Returns success response with redirect URL
        return jsonify({
            'success': True,
            'message': 'Sub-subtopic deleted and archived successfully',
            'redirect_url': url_for('view_content', item_name=result[4])
        })

    except mysql.connector.Error as db_error:
        # Handles database errors
        mytdb.rollback()
        return jsonify({
            'success': False,
            'message': 'Database operation failed',
            'error': str(db_error)
        }), 500

    except Exception as e:
        # Handles unexpected errors
        mytdb.rollback()
        return jsonify({'success': False, 'message': 'Unexpected error occurred'}), 500

# Route: /upload_image
# Purpose: Handles image uploads for content
# Functionality: Validates file type, handles duplicates, saves file, and returns file URL
@app.route('/upload_image', methods=['POST'])
def upload_image():
    try:
        # Checks if file is included in request
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        # Validates file selection
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        # Validates file type
        if not (file and allowed_file(file.filename)):
            return jsonify({'error': 'Allowed file types: png, jpg, jpeg, gif'}), 400

        # Secures filename and handles duplicates
        filename = secure_filename(file.filename)
        base, ext = os.path.splitext(filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Appends counter for duplicate filenames
        counter = 1
        while os.path.exists(upload_path):
            filename = f"{base}_{counter}{ext}"
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            counter += 1

        # Saves file to upload directory
        file.save(upload_path)
        # Returns file URL
        return jsonify({
            'location': url_for('uploaded_file', filename=filename, _external=True)
        })

    except Exception as e:
        # Handles unexpected errors
        app.logger.error(f"Upload failed: {str(e)}")
        return jsonify({'error': 'Server error during upload'}), 500

# Route: /uploads/<filename>
# Purpose: Serves uploaded image files
# Functionality: Sends requested file from upload directory
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    # Serves file from configured upload directory
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
  


# Route: /profile
# Update the profile route to include user_id
@app.route('/profile')
@jwt_required
def profile():
    try:
        user_id = g.current_user.get('user_id')
        if not user_id:
            flash("Please log in", "warning")
            return redirect(url_for('login'))

        # Fetch user details
        cursor.execute('''
            SELECT username, user_email, profile_pic, created_at 
            FROM usercreate 
            WHERE user_id = %s
        ''', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            flash("User not found", "error")
            return redirect(url_for('login'))

        username, email, profile_pic, join_date = user

        # Fetch navbar items
        cursor.execute('SELECT id, name FROM navbar_items ORDER BY position ASC')
        navbar_items = cursor.fetchall()

        return render_template('user/profile.html',
            username=username,
            email=email,
            profile_pic=profile_pic if profile_pic else 'default.jpg',
            join_date=join_date.strftime('%d %b %Y'),
            user_id=user_id,
            navbar_items=navbar_items
        )

    except Exception as e:
        print(f"Profile error: {str(e)}")
        flash("Error loading profile", "error")
        return redirect(url_for('home'))

# Route: /edit_profile
@app.route('/edit_profile', methods=['GET', 'POST'])
@jwt_required
def edit_profile():
    user_id = g.current_user.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    # Get navbar items
    cursor.execute('SELECT id, name FROM navbar_items ORDER BY position ASC')
    navbar_items = cursor.fetchall()

    if request.method == 'POST':
        try:
            # Get form data
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            
            # Handle profile picture upload
            profile_pic = None
            if 'profile_pic' in request.files:
                file = request.files['profile_pic']
                if file and allowed_file(file.filename):
                    # Generate unique filename
                    timestamp = int(time.time())
                    ext = file.filename.rsplit('.', 1)[1].lower()
                    filename = f"user_{user_id}_{timestamp}.{ext}"
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    profile_pic = filename

            # Update database
            cursor.execute('''
                UPDATE usercreate 
                SET username = %s,
                    user_email = %s,
                    profile_pic = COALESCE(%s, profile_pic)
                WHERE user_id = %s
            ''', (username, email, profile_pic, user_id))
            mytdb.commit()

            # Update JWT token with new username if changed
            if username != g.current_user.get('username'):
                new_token = create_jwt_token({
                    'user_id': user_id,
                    'email': email,
                    'username': username,
                    'user_type': 'user'
                })
                response = redirect(url_for('profile'))
                response.set_cookie('access_token', new_token, httponly=True, secure=True)
                return response

            flash("Profile updated successfully!", "success")
            return redirect(url_for('profile'))

        except Exception as e:
            mytdb.rollback()
            print(f"Error updating profile: {str(e)}")
            flash("Error updating profile", "error")
            return redirect(url_for('edit_profile'))

    else:
        # GET: Show edit form
        cursor.execute('SELECT username, user_email, profile_pic FROM usercreate WHERE user_id = %s', (user_id,))
        user = cursor.fetchone()
        if request.args.get('deleted'):
            flash("Profile picture deleted successfully", "success")
        return render_template('user/edit_profile.html', 
                             user=user,
                             token=request.cookies.get('access_token'),
                             navbar_items=navbar_items)
    
    
# Add these routes to your app.py

@app.route('/delete_profile_pic', methods=['POST'])
@jwt_required
def delete_profile_pic():
    try:
        user_id = g.current_user.get('user_id')
        if not user_id:
            flash('Please log in first', 'error')
            return redirect(url_for('login'))

        # Get current profile pic filename
        cursor.execute('SELECT profile_pic FROM usercreate WHERE user_id = %s', (user_id,))
        current_pic = cursor.fetchone()[0]

        # Only delete if it's not the default
        if current_pic and current_pic != 'default.jpg':
            # Delete the file
            pic_path = os.path.join(app.config['UPLOAD_FOLDER'], current_pic)
            if os.path.exists(pic_path):
                os.remove(pic_path)

            # Update database to set to default
            cursor.execute('''
                UPDATE usercreate 
                SET profile_pic = 'default.jpg'
                WHERE user_id = %s
            ''', (user_id,))
            mytdb.commit()
            flash('Profile picture deleted successfully', 'success')
        else:
            flash('No custom profile picture to delete', 'info')

        return redirect(url_for('edit_profile', deleted=True))

    except Exception as e:
        mytdb.rollback()
        print(f"Error deleting profile pic: {str(e)}")
        flash('Error deleting profile picture', 'error')
        return redirect(url_for('edit_profile'))

@app.route('/search')
def search():
    query = request.args.get('query', '').strip().lower()
    
    if not query:
        return render_template('_search_results.html', results={'query': query})

    try:
        results = {
            'query': query,
            'navbar_items': [],
            'subtopics': [],
            'sub_subtopics': []
        }

        # Search navbar items
        cursor.execute('SELECT id, name FROM navbar_items WHERE name LIKE %s LIMIT 3', 
                      [f'%{query}%'])
        results['navbar_items'] = [{'id': row[0], 'name': row[1]} for row in cursor.fetchall()]

        # Search subtopics
        cursor.execute('''SELECT s.id, s.title, n.name as category 
                       FROM subtopics s
                       JOIN navbar_items n ON s.navbar_id = n.id
                       WHERE s.title LIKE %s LIMIT 3''', 
                     [f'%{query}%'])
        results['subtopics'] = [{'id': row[0], 'title': row[1], 'category': row[2]} 
                              for row in cursor.fetchall()]

        # Search sub-subtopics
        cursor.execute('''SELECT ss.id, ss.title, s.title as parent, n.name as category
                       FROM sub_subtopics ss
                       JOIN subtopics s ON ss.subtopic_id = s.id
                       JOIN navbar_items n ON s.navbar_id = n.id
                       WHERE ss.title LIKE %s LIMIT 3''',
                     [f'%{query}%'])
        results['sub_subtopics'] = [{'id': row[0], 'title': row[1], 'parent': row[2], 'category': row[3]} 
                                  for row in cursor.fetchall()]

        return render_template('_search_results.html', results=results)

    except Exception as e:
        print(f"Search error: {str(e)}")
        return render_template('_search_results.html', results={'error': 'Search failed'})

app.run(use_reloader=True, debug=True, host='0.0.0.0', port=5000)