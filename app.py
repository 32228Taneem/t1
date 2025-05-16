from flask import Flask,render_template,url_for,redirect,request,flash,session,jsonify,send_from_directory,json
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
from flask import g 
from datetime import datetime, timedelta
from functools import wraps
import logging
logging.basicConfig(level=logging.DEBUG)
import jwt
import os
import re
# from dotenv import load_dotenv
# load_dotenv()
RESULTS_PER_PAGE = 10

app = Flask(__name__)
logger = logging.getLogger(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
app.secret_key = 'tech$tan111'  # Required for session and flash
UPLOAD_FOLDER = 'static/uploads'
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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def is_admin_logged_in():
    """Check if admin is logged in with any valid session key"""
    return any(key in session for key in ['Admin_mail', 'admin', 'admin_email'])

def get_admin_id():
    """Get admin ID from session with fallback to database lookup"""
    admin_id = session.get('Admin_id') or session.get('admin_id')
    if not admin_id and is_admin_logged_in():
        email = session.get('Admin_mail') or session.get('admin') or session.get('admin_email')
        cursor.execute('SELECT admin_id FROM admins WHERE admin_email=%s', (email,))
        admin_id = cursor.fetchone()[0]
        session['Admin_id'] = admin_id
        session.modified = True
    return admin_id

def create_jwt_token(user_data):
    """Create JWT token with user data"""
    token_data = {
        'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES'],
        **user_data
    }
    return jwt.encode(token_data, app.config['JWT_SECRET_KEY'], algorithm='HS256')

def jwt_required(f):
    """Decorator for JWT authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Check for token in cookies (web) or headers (API)
        if 'access_token' in request.cookies:
            token = request.cookies.get('access_token')
        elif 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        
        if not token:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Token missing'}), 401
            return redirect(url_for('login'))
        
        try:
            payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            g.current_user = payload
        except jwt.ExpiredSignatureError:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Token expired'}), 401
            return redirect(url_for('login'))
        except jwt.InvalidTokenError:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Invalid token'}), 401
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    # cursor = db.cursor()
    cursor.execute('SELECT id, name FROM navbar_items ORDER BY position ASC')  # Fetch navbar items
    navbar_items = cursor.fetchall()  # Retrieve all navbar items
    return render_template('welcome.html', navbar_items=navbar_items)

@app.route('/upload_image', methods=['POST'])
def upload_image():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        if not (file and allowed_file(file.filename)):
            return jsonify({'error': 'Allowed file types: png, jpg, jpeg, gif'}), 400

        # Secure filename and handle duplicates
        filename = secure_filename(file.filename)
        base, ext = os.path.splitext(filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Handle duplicate files
        counter = 1
        while os.path.exists(upload_path):
            filename = f"{base}_{counter}{ext}"
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            counter += 1

        file.save(upload_path)
        return jsonify({
            'location': url_for('uploaded_file', filename=filename, _external=True)
        })

    except Exception as e:
        app.logger.error(f"Upload failed: {str(e)}")
        return jsonify({'error': 'Server error during upload'}), 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/usercreate', methods=['GET','POST'])
def usercreate():
    if request.method == 'POST':
        try:
            uname = request.form['username']
            uemail = request.form['email']
            upassword = request.form['password']
            
            cursor = mytdb.cursor(buffered=True)
            cursor.execute('SELECT count(user_email) FROM usercreate WHERE user_email=%s', [uemail])
            uemail_count = cursor.fetchone()
            
            if uemail_count[0] == 0:
                # Generate OTP (valid for 15 minutes)
                otp, expires_at = genotp(valid_minutes=15)
                
                userdata = {
                    'uname': uname,
                    'uemail': uemail,
                    'upassword': upassword,
                    'uotp': otp,
                    'otp_expires': expires_at.isoformat()
                }
                
                subject = 'Thank you for registering'
                body = f'Your verification OTP is: {otp} (valid until {expires_at.strftime("%Y-%m-%d %H:%M")})'
                sendmail(to=uemail, subject=subject, body=body)
                
                flash('OTP has been sent to your email', 'success')
                return redirect(url_for('uotp', pudata=encode(data=userdata)))
            
            flash('Email already exists. Please login.', 'warning')
            return redirect(url_for('login'))
            
        except Exception as e:
            print(f"Error in usercreate: {str(e)}")
            flash('An error occurred during registration', 'error')
            return redirect(url_for('usercreate'))
    
    return render_template('usersignup.html')

@app.route('/uotp/<pudata>', methods=['GET', 'POST'])
def uotp(pudata):
    if request.method == 'POST':
        fuotp = request.form.get('otp', '').strip()
        print(f"DEBUG: Received OTP attempt: {fuotp}")  # Debug log
        
        try:
            d_udata = decode(data=pudata)
            print(f"DEBUG: Decoded user data: {d_udata}")  # Debug log
            
            # Check OTP expiration
            expires_at = datetime.fromisoformat(d_udata['otp_expires'])
            print(f"DEBUG: OTP expires at: {expires_at}")  # Debug log
            
            if datetime.now() > expires_at:
                flash('Verification code has expired. Please register again.', 'error')
                return redirect(url_for('usercreate'))
            
            print(f"DEBUG: Comparing entered OTP {fuotp} with stored OTP {d_udata['uotp']}")  # Debug log
            if fuotp == d_udata['uotp']:
                cursor = mytdb.cursor(buffered=True)
                try:
                    print("DEBUG: Attempting to create user in database")  # Debug log
                    cursor.execute(
                        'INSERT INTO usercreate(user_email, username, password) VALUES (%s, %s, %s)',
                        [d_udata['uemail'], d_udata['uname'], d_udata['upassword']]
                    )
                    mytdb.commit()
                    print("DEBUG: User created successfully")  # Debug log
                    
                    # Send welcome email
                    sendmail(
                        to=d_udata['uemail'],
                        subject='Welcome to Our Service',
                        body=f"Hello {d_udata['uname']},\n\nYour account has been successfully created!"
                    )
                    
                    flash('Registration successful! Please login.', 'success')
                    return redirect(url_for('login'))  # IMPORTANT: Redirect to login, not usercreate
                    
                except Exception as e:
                    mytdb.rollback()
                    print(f"ERROR: Database error: {str(e)}")  # Debug log
                    flash('Registration error. Please try again.', 'error')
                    return redirect(url_for('usercreate'))
            else:
                print("DEBUG: OTP mismatch")  # Debug log
                flash('Invalid verification code. Please try again.', 'error')
                return redirect(url_for('usercreate'))
                
        except Exception as e:
            print(f"ERROR: in uotp: {str(e)}")  # Debug log
            flash('Invalid verification data', 'error')
            return redirect(url_for('usercreate'))
    
    # GET request - show OTP entry form
    try:
        d_udata = decode(data=pudata)
        expires_at = datetime.fromisoformat(d_udata['otp_expires'])
        remaining_time = expires_at - datetime.now()
        
        return render_template('userotp.html', 
                           email=d_udata['uemail'],
                           expires_in=f"{int(remaining_time.total_seconds() / 60)} minutes")
    
    except Exception as e:
        print(f"ERROR: Failed to decode pudata: {str(e)}")  # Debug log
        flash('Invalid verification data', 'error')
        return redirect(url_for('usercreate'))
    
@app.route('/userforgot',methods=['GET','POST'])
def userforgot():
    if request.method=='POST':
        forgot_useremail=request.form['uemail']
        cursor=mytdb.cursor(buffered=True)
        cursor.execute('select count(user_email) from usercreate where user_email=%s',[forgot_useremail])
        stored_email=cursor.fetchone()
        if stored_email[0]==1:
            subject='reset link for user'
            body=f"click on the link to update ur password:{url_for('user_password_update',token=encode(data=forgot_useremail),_external=True)}" # _external=true likhay nai tho o data pura text kay naad jata
            sendmail(to=forgot_useremail,subject=subject,body=body)
            flash(f'reset link has sent to given mail {forgot_useremail}')
            return redirect(url_for('userforgot'))
        elif stored_email[0]==0:
            flash('no email regestered please check')
            return redirect(url_for('login'))
    return render_template('userforgot.html')

@app.route('/user_password_update/<token>',methods=['GET','POST'])
def user_password_update(token):
    if request.method=='POST':
        try:
            npassword=request.form['npassword']
            cpassword=request.form['cpassword']
            dtoken=decode(data=token) #detoken the encrpt email
        except Exception as e:
            print(e)
            flash('something went wrong')
            return redirect(url_for('login'))
        else:
            if npassword==cpassword:
                cursor=mytdb.cursor(buffered=True)
                cursor.execute('update usercreate set password=%s where user_email=%s',[npassword,dtoken])
                mytdb.commit()
                flash('password updated succesfully')
                return redirect(url_for('login'))
            else:
                flash('password mismaitches')
                return redirect(url_for('user_password_update',token=token))
    return render_template('newuserpassword.html')

# @app.route('/userlogout')
# def userlogout():
#     if session.get('user'):
#         session.pop('user')
#         return redirect(url_for('index'))
#     return redirect(url_for('userlogin'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        if not email or not password:
            flash('Email and password are required', 'error')
            return redirect(url_for('login'))

        try:
            # ================= ADMIN LOGIN FLOW =================
            cursor.execute('SELECT admin_id, admin_name, password FROM admins WHERE admin_email=%s', [email])
            admin_data = cursor.fetchone()
            
            if admin_data:
                admin_id, admin_name, stored_password = admin_data
                
                if password == stored_password.decode('utf-8'):
                    # Generate time-limited OTP (15 minutes for admin)
                    otp, expires_at = genotp(valid_minutes=15)
                    
                    session['admin_temp'] = {
                        'email': email,
                        'admin_id': str(admin_id),
                        'admin_name': admin_name,
                        'expiry': expires_at
                    }
                    
                    session['admin_otp'] = {
                        'code': otp,
                        'expires_at': expires_at.isoformat()
                    }
                    
                    sendmail(
                        to=email,
                        subject='Admin OTP Verification',
                        body=f'Your admin verification code is: {otp}\n\nValid until: {expires_at.strftime("%Y-%m-%d %H:%M")}'
                    )
                    flash('OTP has been sent to your email', 'success')
                    return redirect(url_for('admin_otp_verify'))
                
                flash('Invalid credentials', 'error')
                return redirect(url_for('login'))

            # ================= USER LOGIN FLOW =================
            cursor.execute('SELECT user_id, username, password FROM usercreate WHERE user_email=%s', [email])
            user_data = cursor.fetchone()
            
            if user_data:
                user_id, username, stored_password = user_data
                
                if password == stored_password.decode('utf-8'):
                    token = create_jwt_token({
                        'user_id': user_id,
                        'email': email,
                        'username': username,
                        'user_type': 'user'
                    })
                    
                    session['user'] = email
                    session['username'] = username
                    
                    cursor.execute('SELECT name FROM navbar_items ORDER BY position ASC LIMIT 1')
                    default_item = cursor.fetchone()
                    
                    if default_item:
                        response = redirect(url_for('view_subtopics', item_name=default_item[0]))
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
                        return redirect(url_for('home'))  # Replace 'home' with your default route
                else:
                    flash('Invalid credentials', 'error')
                    return redirect(url_for('login'))

            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))

        except Exception as e:
            print(f"Login error: {str(e)}")
            flash('An error occurred during login', 'error')
            return redirect(url_for('login'))
    
    # GET request - show login form
    return render_template('login.html')  # Make sure you have this template

@app.route('/admin_otp_verify', methods=['GET', 'POST'])
def admin_otp_verify():
    # Debug: Print session data for verification
    print(f"Session data at start: {session}")
    
    if 'admin_temp' not in session:
        flash('Session expired. Please login again.')
        return redirect(url_for('login'))
    
    # Check if OTP already expired
    expires_at = datetime.fromisoformat(session['admin_otp']['expires_at'])
    if datetime.now() > expires_at:
        flash('OTP has expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        admin_id = request.form.get('admin_id', '').strip()
        
        # Get stored values
        stored_otp = session['admin_otp']['code']
        expected_admin_id = session['admin_temp']['admin_id']
        
        if stored_otp == otp and admin_id == expected_admin_id:
            # Create JWT token
            token = create_jwt_token({
                'admin_id': session['admin_temp']['admin_id'],
                'email': session['admin_temp']['email'],
                'admin_name': session['admin_temp']['admin_name'],
                'user_type': 'admin'
            })
            
            # Set session variables
            session['admin'] = session['admin_temp']['email']
            session['admin_id'] = session['admin_temp']['admin_id']
            session['admin_name'] = session['admin_temp']['admin_name']
            
            # Cleanup
            session.pop('admin_temp', None)
            session.pop('admin_otp', None)
            
            response = redirect(url_for('admin_panel'))
            response.set_cookie('access_token', token, httponly=True, secure=True)
            flash('Authentication successful!')
            return response
        else:
            if stored_otp != otp:
                flash('Invalid OTP', 'error')
            if admin_id != expected_admin_id:
                flash('Invalid Admin ID', 'error')
            return redirect(url_for('admin_otp_verify'))
    
    return render_template('adminotp.html', 
                         expires_at=expires_at,  # Fixed typo (was expires_at)
                         admin_id=session['admin_temp']['admin_id'])

# Update your view_subtopics route to show username
@app.route('/view_subtopics/<item_name>')
def view_subtopics(item_name):
    # Initialize username as None (for public access)
    username = None
    
    # Check if user is logged in (either via session or JWT)
    if 'user' in session:  # Regular user session
        username = session.get('username')
    elif 'admin' in session or 'Admin_mail' in session:  # Admin session
        username = session.get('admin_name') or session.get('admin_temp', {}).get('admin_name')
    elif 'access_token' in request.cookies:  # JWT token check
        try:
            token = request.cookies.get('access_token')
            payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            username = payload.get('username')
        except:
            pass  # Invalid token, treat as public access

    # Get navbar items
    cursor.execute('SELECT id, name FROM navbar_items ORDER BY position ASC')
    navbar_items = cursor.fetchall()
    
    # Get the navbar item ID
    cursor.execute('SELECT id FROM navbar_items WHERE name=%s', (item_name,))
    nav_id = cursor.fetchone()
    if not nav_id:
        return 'Navbar item not found', 404
    
    # Get subtopics
    cursor.execute('''SELECT id, title, content, image_filename 
                   FROM subtopics 
                   WHERE navbar_id=%s 
                   ORDER BY position''', (nav_id[0],))
    subtopics = []
    for row in cursor.fetchall():
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
        
        subtopics.append({
            'id': row[0],
            'title': row[1],
            'content': row[2],
            'image': url_for('static', filename=f'uploads/{row[3]}') if row[3] else None,
            'sub_subtopics': sub_subtopics
        })
    
    return render_template(
        'view_subtopics.html',
        item_name=item_name,
        subtopics=subtopics,
        navbar_items=navbar_items,
        username=username  # Will be None if not logged in
    )

# Update your admin_panel route to show admin name
@app.route('/admin_panel')
@jwt_required
def admin_panel():
    if g.current_user.get('user_type') != 'admin':
        return redirect(url_for('login'))
    
    # Get admin name from either session or JWT
    admin_name = session.get('admin_name') or g.current_user.get('admin_name')
    
    cursor.execute('SELECT name FROM navbar_items ORDER BY position')
    nav_items = [item[0] for item in cursor.fetchall()]
    return render_template('admin_panel.html', navbar_items=nav_items, admin_name=admin_name)

@app.route('/logout')
def logout():
    session.clear()  # Clears all session data
    return redirect(url_for('home'))




@app.route('/add_navbar_item', methods=['POST'])
def add_navbar_item():
    # Check admin login using multiple possible session keys
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        flash('Please login as admin first', 'error')
        return redirect(url_for('login'))

    try:
        # Get form data
        item = request.form.get('item', '').strip()
        if not item:
            flash('Navbar item name cannot be empty', 'error')
            return redirect(url_for('admin_panel'))

        # Get admin ID - first from session, then from database
        admin_id = session.get('Admin_id')
        if not admin_id:
            admin_email = session.get('Admin_mail') or session.get('admin') or session.get('admin_email')
            cursor.execute('SELECT admin_id FROM admins WHERE admin_email=%s', (admin_email,))
            admin_record = cursor.fetchone()
            if not admin_record:
                flash('Admin account not found', 'error')
                return redirect(url_for('login'))
            admin_id = admin_record[0]
            session['Admin_id'] = admin_id  # Store for future use
            session.modified = True

        # Debug prints (can be removed in production)
        app.logger.debug(f"Adding navbar item - Admin ID: {admin_id}")
        app.logger.debug(f"New item: {item}")

        # Get current max position (handle empty table case)
        cursor.execute('SELECT MAX(position) FROM navbar_items')
        max_position = cursor.fetchone()[0]
        new_position = max_position + 1 if max_position is not None else 1

        # Insert new navbar item
        cursor.execute(
            'INSERT INTO navbar_items (name, position, admin_id, created_at) '
            'VALUES (%s, %s, %s, CURRENT_TIMESTAMP)',
            (item, new_position, admin_id)
        )
        mytdb.commit()

        flash(f'Navbar item "{item}" added successfully!', 'success')
        return redirect(url_for('admin_panel'))

    except mysql.connector.IntegrityError:
        mytdb.rollback()
        flash('This navbar item already exists', 'error')
        return redirect(url_for('admin_panel'))

    except mysql.connector.Error as err:
        mytdb.rollback()
        flash(f'Database error: {err.msg}', 'error')
        return redirect(url_for('admin_panel'))

    except Exception as e:
        mytdb.rollback()
        app.logger.error(f"Error adding navbar item: {str(e)}")
        flash('An unexpected error occurred', 'error')
        return redirect(url_for('admin_panel'))


@app.route('/view_content/<item_name>')
def view_content(item_name):
    try:
        # 1. Get the navbar item ID
        cursor.execute('SELECT id FROM navbar_items WHERE name=%s', (item_name,))
        nav_id = cursor.fetchone()
        if not nav_id:
            return 'Navbar item not found', 404

        # 2. Get all subtopics for this navbar item
        cursor.execute('''
            SELECT id, title, content, image_filename 
            FROM subtopics 
            WHERE navbar_id=%s 
            ORDER BY position
        ''', (nav_id[0],))
        
        subtopics = []
        for subtopic_row in cursor.fetchall():
            # 3. Get ALL sub-subtopics for this subtopic
            cursor.execute('''
                SELECT id, title, content
                FROM sub_subtopics
                WHERE subtopic_id=%s
                ORDER BY id
            ''', (subtopic_row[0],))
            
            subsubtopics = []
            for subsub_row in cursor.fetchall():
                subsubtopics.append({
                    'id': subsub_row[0],
                    'title': subsub_row[1],
                    'content': subsub_row[2]
                })
            
            # 4. Add to subtopics list WITH subsubtopics
            subtopics.append({
                'id': subtopic_row[0],
                'title': subtopic_row[1],
                'content': subtopic_row[2],
                'image': url_for('static', filename=f'uploads/{subtopic_row[3]}') if subtopic_row[3] else None,
                'sub_subtopics': subsubtopics,  # This makes the down arrow appear
                'has_subsub': len(subsubtopics) > 0  # Alternative approach
            })
        
        return render_template('view_content.html', 
                            item_name=item_name, 
                            subtopics=subtopics)
    
    except Exception as e:
        return str(e), 500


@app.route('/add_subtopic/<item_name>', methods=['POST'])
def add_subtopic(item_name):
    # Check admin login using multiple possible session keys
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        flash('Please login as admin first', 'error')
        return redirect(url_for('login'))

    try:
        # Get form data
        title = request.form.get('title', '').strip()
        if not title:
            flash('Title is required', 'error')
            return redirect(url_for('view_content', item_name=item_name))

        content = request.form.get('content', '').strip()
        
        # Get admin ID - first from session, then from database
        admin_id = session.get('Admin_id')
        if not admin_id:
            admin_email = session.get('Admin_mail') or session.get('admin') or session.get('admin_email')
            cursor.execute('SELECT admin_id FROM admins WHERE admin_email=%s', (admin_email,))
            admin_record = cursor.fetchone()
            if not admin_record:
                flash('Admin account not found', 'error')
                return redirect(url_for('login'))
            admin_id = admin_record[0]
            session['Admin_id'] = admin_id  # Store for future use

        # Get navbar item ID
        cursor.execute('SELECT id FROM navbar_items WHERE name=%s', (item_name,))
        nav_id_record = cursor.fetchone()
        if not nav_id_record:
            flash('Category not found', 'error')
            return redirect(url_for('admin_panel'))

        # Insert new subtopic
        cursor.execute(
            'INSERT INTO subtopics (title, content, navbar_id, admin_id) '
            'VALUES (%s, %s, %s, %s)',
            (title, content, nav_id_record[0], admin_id)
        )
        mytdb.commit()

        flash(f'Subtopic "{title}" added successfully!', 'success')
        return redirect(url_for('view_content', item_name=item_name))

    except mysql.connector.IntegrityError:
        mytdb.rollback()
        flash('This subtopic title already exists', 'error')
        return redirect(url_for('view_content', item_name=item_name))

    except Exception as e:
        mytdb.rollback()
        print(f"Error adding subtopic: {str(e)}")
        flash('An error occurred while adding the subtopic', 'error')
        return redirect(url_for('view_content', item_name=item_name))

@app.route('/edit_subtopic/<int:sub_id>', methods=['GET', 'POST'])
def edit_subtopic(sub_id):
    # Check admin login using multiple possible session keys
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        flash('Please login as admin first', 'error')
        return redirect(url_for('login'))

    try:
        if request.method == 'POST':
            # Get form data
            title = request.form.get('title', '').strip()
            if not title:
                flash('Title is required', 'error')
                return redirect(url_for('edit_subtopic', sub_id=sub_id))

            content = request.form.get('content', '').strip()
            
            # Get admin ID - first from session, then from database
            admin_id = session.get('Admin_id')
            if not admin_id:
                admin_email = session.get('Admin_mail') or session.get('admin') or session.get('admin_email')
                cursor.execute('SELECT admin_id FROM admins WHERE admin_email=%s', (admin_email,))
                admin_record = cursor.fetchone()
                if not admin_record:
                    flash('Admin account not found', 'error')
                    return redirect(url_for('login'))
                admin_id = admin_record[0]
                session['Admin_id'] = admin_id  # Store for future use

            # Update subtopic
            cursor.execute(
                'UPDATE subtopics SET title=%s, admin_id=%s, content=%s WHERE id=%s', 
                (title, admin_id, content, sub_id)
            )
            mytdb.commit()

            # Get the item_name for redirecting
            cursor.execute('SELECT navbar_id FROM subtopics WHERE id=%s', (sub_id,))
            nav_id = cursor.fetchone()[0]
            cursor.execute('SELECT name FROM navbar_items WHERE id=%s', (nav_id,))
            item_name = cursor.fetchone()[0]

            flash('Subtopic updated successfully!', 'success')
            return redirect(url_for('view_content', item_name=item_name))

        else:
            # GET request - show edit form
            cursor.execute('SELECT title, content, navbar_id FROM subtopics WHERE id=%s', (sub_id,))
            sub = cursor.fetchone()
            if not sub:
                flash('Subtopic not found', 'error')
                return redirect(url_for('admin_panel'))

            cursor.execute('SELECT name FROM navbar_items WHERE id=%s', (sub[2],))
            item_name = cursor.fetchone()[0]
            
            return render_template(
                'edit_subtopic.html', 
                sub_id=sub_id, 
                title=sub[0], 
                content=sub[1], 
                item_name=item_name
            )

    except Exception as e:
        mytdb.rollback()
        print(f"Error editing subtopic: {str(e)}")
        flash('An error occurred while editing the subtopic', 'error')
        return redirect(url_for('admin_panel'))

@app.route('/delete_navbar_item', methods=['POST'])
def delete_navbar_item():
    if not any(key in session for key in ['admin', 'Admin_mail', 'admin_id', 'Admin_id']):
        flash('Administrator authentication required', 'error')
        return redirect(url_for('login'))

    try:
        item = request.form.get('item', '').strip()
        reason = request.form.get('reason', '').strip()
        
        if not item or not reason:
            flash('Both item name and deletion reason are required', 'error')
            return redirect(url_for('admin_panel'))

        # Get admin info - handles all session formats
        admin_id = session.get('admin_id') or session.get('Admin_id')
        
        if not admin_id:
            session.clear()
            flash('Invalid administrator session', 'error')
            return redirect(url_for('login'))

        cursor = mytdb.cursor(buffered=True)
        
        # 1. Log the deletion with admin info (updated to match your table structure)
        cursor.execute('''
            INSERT INTO navbar_deletion_logs 
            (nav_item_name, deletion_reason, admin_id, deleted_at)
            VALUES (%s, %s, %s, NOW())
        ''', (item, reason, admin_id))
        
        # 2. Delete associated subitems first
        cursor.execute('''
            DELETE subtopics, sub_subtopics 
            FROM navbar_items
            LEFT JOIN subtopics ON navbar_items.id = subtopics.navbar_id
            LEFT JOIN sub_subtopics ON subtopics.id = sub_subtopics.subtopic_id
            WHERE navbar_items.name = %s
        ''', (item,))
        
        # 3. Finally delete the navbar item
        cursor.execute('DELETE FROM navbar_items WHERE name=%s', (item,))
        
        mytdb.commit()
        
        flash(f'Successfully deleted "{item}" and all related content', 'success')
        return redirect(url_for('admin_panel'))
        
    except Exception as e:
        mytdb.rollback()
        print(f"Error: {str(e)}")
        flash('An error occurred during deletion', 'error')
        return redirect(url_for('admin_panel'))

@app.route('/delete_subtopic/<int:sub_id>/<item_name>', methods=['POST'])
def delete_subtopic(sub_id, item_name):
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        return jsonify({'error': 'Authentication required'}), 401

    try:
        data = request.get_json()
        reason = data.get('reason', 'No reason provided')

        # Get admin ID
        admin_id = session.get('Admin_id')
        if not admin_id:
            admin_email = session.get('Admin_mail') or session.get('admin') or session.get('admin_email')
            cursor.execute('SELECT admin_id FROM admins WHERE admin_email=%s', (admin_email,))
            admin_id = cursor.fetchone()[0]

        # Get subtopic title before deletion
        cursor.execute('SELECT title FROM subtopics WHERE id=%s', (sub_id,))
        subtopic_title = cursor.fetchone()[0]

        # Log the deletion
        cursor.execute('''
            INSERT INTO subtopic_deletion_logs 
            (subtopic_id, subtopic_title, admin_id, deletion_reason)
            VALUES (%s, %s, %s, %s)
        ''', (sub_id, subtopic_title, admin_id, reason))

        # Perform deletion
        cursor.execute('DELETE FROM subtopics WHERE id=%s', (sub_id,))
        mytdb.commit()

        return jsonify({
            'success': True, 
            'redirect': url_for('view_content', item_name=item_name)
        })

    except Exception as e:
        mytdb.rollback()
        print(f"Error deleting subtopic: {str(e)}")
        return jsonify({'error': str(e)}), 500
    

@app.route('/update_navbar_item', methods=['POST'])
def update_navbar_item():
    # Check admin login using multiple possible session keys
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        flash('Please login as admin first', 'error')
        return redirect(url_for('login'))

    try:
        # Get admin ID - first from session, then from database
        admin_id = session.get('Admin_id')
        if not admin_id:
            admin_email = session.get('Admin_mail') or session.get('admin') or session.get('admin_email')
            cursor.execute('SELECT admin_id FROM admins WHERE admin_email=%s', (admin_email,))
            admin_record = cursor.fetchone()
            if not admin_record:
                flash('Admin account not found', 'error')
                return redirect(url_for('login'))
            admin_id = admin_record[0]
            session['Admin_id'] = admin_id  # Store for future use

        # Get form data safely
        old_item = request.form.get('old_item', '').strip()
        new_item = request.form.get('new_item', '').strip()
        
        # Validate input
        if not old_item or not new_item:
            flash('Both old and new item names are required', 'error')
            return redirect(url_for('admin_panel'))
        if old_item == new_item:
            flash('New name cannot be same as old name', 'warning')
            return redirect(url_for('admin_panel'))

        # Update query using your existing table structure
        cursor.execute(
            '''UPDATE navbar_items 
            SET name = %s, 
                admin_id = %s 
            WHERE name = %s''',
            (new_item, admin_id, old_item)
        )
        
        # Check if any rows were affected
        if cursor.rowcount == 0:
            flash('No changes made - item not found', 'warning')
        else:
            mytdb.commit()
            flash(f'Successfully renamed "{old_item}" to "{new_item}"', 'success')

        return redirect(url_for('admin_panel'))

    except mysql.connector.IntegrityError:
        mytdb.rollback()
        flash('This navbar item name already exists', 'error')
        return redirect(url_for('admin_panel'))

    except Exception as e:
        mytdb.rollback()
        print(f"Error updating navbar item: {str(e)}")
        flash('An error occurred while updating the navbar item', 'error')
        return redirect(url_for('admin_panel'))

@app.route('/update_navbar_order', methods=['POST'])
def update_navbar_order():
    # Check admin authentication
    if not is_admin_logged_in():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401

    try:
        # Get admin ID
        admin_id = get_admin_id()
        if not admin_id:
            return jsonify({'status': 'error', 'message': 'Admin information not found'}), 401

        # Get and validate order data
        order = request.json.get('order')
        if not order or not isinstance(order, list):
            return jsonify({'status': 'error', 'message': 'Invalid order data'}), 400

        # Check if we're already in a transaction
        if not mytdb.in_transaction:
            mytdb.start_transaction()
        
        for position, item_name in enumerate(order, start=1):
            cursor.execute(
                'UPDATE navbar_items SET position=%s, admin_id=%s WHERE name=%s',
                (position, admin_id, item_name)
            )
        
        if mytdb.in_transaction:
            mytdb.commit()
            
        return jsonify({'status': 'success', 'message': 'Order updated successfully'})

    except mysql.connector.Error as err:
        if mytdb.in_transaction:
            mytdb.rollback()
        logger.error(f"Database error updating navbar order: {str(err)}")
        return jsonify({'status': 'error', 'message': 'Database error'}), 500

    except Exception as e:
        if mytdb.in_transaction:
            mytdb.rollback()
        logger.error(f"Error updating navbar order: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Server error'}), 500

@app.route('/update_subtopic_order', methods=['POST'])
def update_subtopic_order():
    # Check admin login using multiple possible session keys
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        return {'status': 'error', 'message': 'Please login as admin first'}, 401

    try:
        order = request.json.get('order')
        if not order:
            return {'status': 'error', 'message': 'No order provided'}, 400

        # Get admin ID - first from session, then from database
        admin_id = session.get('Admin_id')
        if not admin_id:
            admin_email = session.get('Admin_mail') or session.get('admin') or session.get('admin_email')
            cursor.execute('SELECT admin_id FROM admins WHERE admin_email=%s', (admin_email,))
            admin_record = cursor.fetchone()
            if not admin_record:
                return {'status': 'error', 'message': 'Admin account not found'}, 401
            admin_id = admin_record[0]
            session['Admin_id'] = admin_id  # Store for future use

        # Log the received order for debugging
        print(f"Received order update request from admin {admin_id}: {order}")

        # Update each subtopic position
        for position, sub_id in enumerate(order, start=1):
            print(f"Updating subtopic {sub_id} to position {position}")
            cursor.execute(
                'UPDATE subtopics SET position=%s, admin_id=%s WHERE id=%s',
                (position, admin_id, sub_id)
            )

        mytdb.commit()
        return {'status': 'success','message': 'Order updated successfully','updated_count': len(order)}

    except mysql.connector.Error as db_error:
        mytdb.rollback()
        print(f"Database error updating subtopic order: {db_error}")
        return {'status': 'error','message': 'Database operation failed','error': str(db_error)}, 500

    except Exception as e:
        mytdb.rollback()
        print(f"Unexpected error updating subtopic order: {e}")
        return {'status': 'error','message': 'An unexpected error occurred','error': str(e)}, 500


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

@app.route('/add_sub_subtopic', methods=['POST'])
def add_sub_subtopic():
    # Check admin login using multiple possible session keys
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        return jsonify({
            'success': False,
            'error': 'Please login as admin first',
            'redirect': url_for('login')
        }), 401

    try:
        # Get and validate form data
        subtopic_id = request.form.get('parent_subtopic_id', '').strip()
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()

        if not subtopic_id or not title:
            return jsonify({
                'success': False,
                'error': 'Both parent subtopic ID and title are required'
            }), 400

        # Get admin ID - first from session, then from database
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
            session['Admin_id'] = admin_id  # Store for future use

        # Verify parent subtopic exists
        cursor.execute('SELECT id FROM subtopics WHERE id=%s', (subtopic_id,))
        if not cursor.fetchone():
            return jsonify({
                'success': False,
                'error': 'Parent subtopic not found'
            }), 404

        # Insert new sub-subtopic
        cursor.execute('''
            INSERT INTO sub_subtopics (subtopic_id, title, content, admin_id)
            VALUES (%s, %s, %s, %s)
        ''', (subtopic_id, title, content, admin_id))
        mytdb.commit()

        # Get the newly created sub-subtopic with additional details
        cursor.execute('''
            SELECT ss.id, ss.title, ss.content, s.title as parent_title
            FROM sub_subtopics ss
            JOIN subtopics s ON ss.subtopic_id = s.id
            WHERE ss.id = LAST_INSERT_ID()
        ''')
        new_subsub = cursor.fetchone()

        return jsonify({'success': True,'newSubSubtopic': {'id': new_subsub[0],'title': new_subsub[1],'content': new_subsub[2],
                'parent_title': new_subsub[3]  # Added parent title for reference
            },'message': 'Sub-subtopic created successfully'})

    except mysql.connector.IntegrityError as e:
        mytdb.rollback()
        return jsonify({'success': False,'error': 'Database integrity error','details': 'This sub-subtopic may already exist' if 'Duplicate entry' in str(e) else str(e)}), 400

    except mysql.connector.Error as db_error:
        mytdb.rollback()
        return jsonify({'success': False,'error': 'Database operation failed','details': str(db_error)}), 500

    except Exception as e:
        mytdb.rollback()
        return jsonify({'success': False,'error': 'Unexpected error occurred','details': str(e)}), 500
    
@app.route('/update_subsubtopic_order', methods=['POST'])
def update_subsubtopic_order():
    # Check admin login using multiple possible session keys
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        return jsonify({
            'status': 'error',
            'message': 'Please login as admin first',
            'redirect': url_for('login')
        }), 401

    try:
        order = request.json.get('order')
        parent_id = request.json.get('parent_id')
        
        if not order or not parent_id:
            return jsonify({
                'status': 'error',
                'message': 'Both order and parent_id are required'
            }), 400

        # Get admin ID
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

        # Verify parent subtopic exists and belongs to admin
        cursor.execute('SELECT id FROM subtopics WHERE id=%s AND admin_id=%s', (parent_id, admin_id))
        if not cursor.fetchone():
            return jsonify({
                'status': 'error',
                'message': 'Parent subtopic not found or not authorized'
            }), 403

        # Update positions
        updates = []
        for position, subsub_id in enumerate(order, start=1):
            cursor.execute('''
                UPDATE sub_subtopics 
                SET position=%s, admin_id=%s
                WHERE id=%s AND subtopic_id=%s
            ''', (position, admin_id, subsub_id, parent_id))
            updates.append(subsub_id)

        mytdb.commit()
        return jsonify({
            'status': 'success',
            'message': f'Updated {len(updates)} sub-subtopics',
            'updated_ids': updates
        })

    except mysql.connector.Error as db_error:
        mytdb.rollback()
        return jsonify({
            'status': 'error',
            'message': 'Database operation failed',
            'error': str(db_error)
        }), 500

    except Exception as e:
        mytdb.rollback()
        return jsonify({
            'status': 'error',
            'message': 'Unexpected error occurred'
        }), 500

@app.route('/edit_subsubtopic/<int:subsub_id>', methods=['GET', 'POST'])
def edit_subsubtopic(subsub_id):
    # Check admin login
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        return redirect(url_for('login'))

    try:
        # Get admin ID
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
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '').strip()

            if not title:
                flash('Title is required', 'error')
                return redirect(url_for('edit_subsubtopic', subsub_id=subsub_id))

            # Verify subsubtopic belongs to admin
            cursor.execute('''
                SELECT ss.id FROM sub_subtopics ss
                JOIN subtopics st ON ss.subtopic_id = st.id
                WHERE ss.id = %s AND st.admin_id = %s
            ''', (subsub_id, admin_id))
            if not cursor.fetchone():
                flash('Not authorized to edit this sub-subtopic', 'error')
                return redirect(url_for('admin_panel'))

            # Update the sub-subtopic
            cursor.execute('''
                UPDATE sub_subtopics 
                SET title=%s, content=%s, admin_id=%s
                WHERE id=%s
            ''', (title, content, admin_id, subsub_id))
            mytdb.commit()

            # Get redirect info
            cursor.execute('''
                SELECT ni.name 
                FROM sub_subtopics ss
                JOIN subtopics st ON ss.subtopic_id = st.id
                JOIN navbar_items ni ON st.navbar_id = ni.id
                WHERE ss.id = %s
            ''', (subsub_id,))
            item_name = cursor.fetchone()[0]

            flash('Sub-subtopic updated successfully!', 'success')
            return redirect(url_for('view_content', item_name=item_name))

        else:
            # GET request - verify ownership and show form
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

            cursor.execute('SELECT name FROM navbar_items WHERE id=%s', (subsub[2],))
            item_name = cursor.fetchone()[0]

            return render_template(
                'edit_subsubtopic.html',
                subsub_id=subsub_id,
                title=subsub[0],
                content=subsub[1],
                item_name=item_name
            )

    except mysql.connector.Error as db_error:
        mytdb.rollback()
        flash('Database error occurred', 'error')
        return redirect(url_for('admin_panel'))

    except Exception as e:
        mytdb.rollback()
        flash('An unexpected error occurred', 'error')
        return redirect(url_for('admin_panel'))

@app.route('/delete_sub_subtopic/<int:subsub_id>', methods=['DELETE'])
def delete_sub_subtopic(subsub_id):
    # Check admin login
    if not any(key in session for key in ['Admin_mail', 'admin', 'admin_email']):
        return jsonify({
            'success': False,
            'message': 'Please login as admin first',
            'redirect': url_for('login')
        }), 401

    try:
        # Get admin ID
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

        # Get deletion reason from request
        deletion_reason = request.json.get('deletion_reason', 'No reason provided')

        # Get sub-subtopic details before deletion
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

        # Archive the sub-subtopic before deletion
        cursor.execute('''
    INSERT INTO sub_subtopic_deletion_logs 
    (sub_subtopic_id, subtopic_id, title, admin_id, deletion_reason)
    VALUES (%s, %s, %s, %s, %s)
''', (
    result[0],  # sub_subtopic_id
    result[3],  # subtopic_id
    result[1],  # title
    result[2],  # content
    admin_id,
    deletion_reason
))

        # Perform deletion
        cursor.execute('DELETE FROM sub_subtopics WHERE id = %s', (subsub_id,))
        mytdb.commit()

        return jsonify({
            'success': True,
            'message': 'Sub-subtopic deleted and archived successfully',
            'redirect_url': url_for('view_content', item_name=result[4])
        })

    except mysql.connector.Error as db_error:
        mytdb.rollback()
        return jsonify({
            'success': False,
            'message': 'Database operation failed',
            'error': str(db_error)
        }), 500

    except Exception as e:
        mytdb.rollback()
        return jsonify({'success': False,'message': 'Unexpected error occurred'}), 500
    

@app.route('/admin/search', methods=['GET', 'POST'])
def admin_search():
    # Admin-only search with additional capabilities
    if not is_admin_logged_in():  # Your admin check function
        flash('Admin access required', 'error')
        return redirect(url_for('login'))
    return handle_search(is_admin=True)

def handle_search(is_admin=False):
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
            search_term = request.form.get('search_term', '').strip()
            
            if not search_term:
                flash('Please enter a search term', 'warning')
                return redirect(request.referrer or url_for('home'))
            
            session['search_term'] = search_term
            return redirect(url_for('admin_search' if is_admin else 'user_search', page=1))
            
        except (CSRFError, BadRequest):
            flash('Security validation failed', 'error')
            return redirect(url_for('home'))
    
    # Handle GET requests (pagination)
    search_term = session.get('search_term', request.args.get('search_term', ''))
    page = int(request.args.get('page', 1))
    
    try:
        cursor = mytdb.cursor(dictionary=True)
        
        # Base query differs for admin vs user
        if is_admin:
            query = """
                (SELECT id, name AS title, content, 'navbar' AS type, 
                        CONCAT('/admin/view/', name) AS url
                 FROM navbar_items 
                 WHERE name LIKE %s OR content LIKE %s)
                
                UNION ALL
                
                (SELECT s.id, s.title, s.content, 'subtopic' AS type,
                        CONCAT('/admin/view/', n.name, '#', s.id) AS url
                 FROM subtopics s
                 JOIN navbar_items n ON s.navbar_id = n.id
                 WHERE s.title LIKE %s OR s.content LIKE %s)
            """
            params = [f'%{search_term}%'] * 4
        else:
            query = """
                (SELECT id, name AS title, NULL AS content, 'navbar' AS type, 
                        CONCAT('/view/', name) AS url
                 FROM navbar_items 
                 WHERE name LIKE %s AND is_public = 1)
                
                UNION ALL
                
                (SELECT s.id, s.title, s.content, 'subtopic' AS type,
                        CONCAT('/view/', n.name, '#', s.id) AS url
                 FROM subtopics s
                 JOIN navbar_items n ON s.navbar_id = n.id
                 WHERE (s.title LIKE %s OR s.content LIKE %s) AND s.is_public = 1)
            """
            params = [f'%{search_term}%'] * 3
        
        # Get total count
        count_query = f"SELECT COUNT(*) AS total FROM ({query}) AS results"
        cursor.execute(count_query, params)
        total = cursor.fetchone()['total']
        
        # Get paginated results
        results_query = f"""
            {query}
            ORDER BY title
            LIMIT %s OFFSET %s
        """
        offset = (page - 1) * RESULTS_PER_PAGE
        cursor.execute(results_query, params + [RESULTS_PER_PAGE, offset])
        results = cursor.fetchall()
        
        total_pages = max(1, (total + RESULTS_PER_PAGE - 1) // RESULTS_PER_PAGE)
        
        return render_template('search_results.html',
                            results=results,
                            search_term=search_term,
                            page=page,
                            total=total,
                            total_pages=total_pages,
                            start=offset + 1,
                            end=min(offset + RESULTS_PER_PAGE, total),
                            search_route='admin_search' if is_admin else 'user_search')
        
    except Exception as e:
        app.logger.error(f"Search error: {str(e)}")
        flash('Search temporarily unavailable', 'error')
        return redirect(url_for('home'))
    finally:
        cursor.close()

@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        try:
            # Get form data
            form_data = request.form
            search_term = form_data.get('search_term', '').strip()
            
            if not search_term:
                flash('Please enter a search term', 'warning')
                return redirect(url_for('home'))
            
            # Search logic
            cursor = mytdb.cursor(dictionary=True)
            
            try:
                # Search navbar items
                cursor.execute("""
                    SELECT id, name AS title, 'navbar_item' AS type 
                    FROM navbar_items 
                    WHERE name LIKE %s
                    ORDER BY name
                    LIMIT 10
                """, [f'%{search_term}%'])
                navbar_results = cursor.fetchall()
                
                # Search subtopics
                cursor.execute("""
                    SELECT s.id, s.title, 'subtopic' AS type, n.name AS parent_name
                    FROM subtopics s
                    JOIN navbar_items n ON s.navbar_id = n.id
                    WHERE s.title LIKE %s OR s.content LIKE %s
                    ORDER BY s.title
                    LIMIT 10
                """, [f'%{search_term}%', f'%{search_term}%'])
                subtopic_results = cursor.fetchall()
                
                # Search sub-subtopics
                cursor.execute("""
                    SELECT ss.id, ss.title, 'sub_subtopic' AS type, 
                           s.title AS parent_name, n.name AS grandparent_name
                    FROM sub_subtopics ss
                    JOIN subtopics s ON ss.subtopic_id = s.id
                    JOIN navbar_items n ON s.navbar_id = n.id
                    WHERE ss.title LIKE %s OR ss.content LIKE %s
                    ORDER BY ss.title
                    LIMIT 10
                """, [f'%{search_term}%', f'%{search_term}%'])
                subsubtopic_results = cursor.fetchall()
                
                # Combine results
                results = navbar_results + subtopic_results + subsubtopic_results
                
                return render_template('search_results.html',
                                    search_term=search_term,
                                    results=results)
                
            except mysql.connector.Error as e:
                app.logger.error(f"Database error: {str(e)}")
                flash('Database error during search', 'error')
                return redirect(url_for('home'))
                
            finally:
                cursor.close()
                
        except (CSRFError, BadRequest) as e:
            app.logger.warning(f"CSRF validation failed: {str(e)}")
            flash('Security validation failed. Please try again.', 'error')
            return redirect(url_for('home'))
            
        except Exception as e:
            app.logger.error(f"Search error: {str(e)}")
            flash('An error occurred during search', 'error')
            return redirect(url_for('home'))
    
    # GET request - redirect to home
    return redirect(url_for('home'))

@app.route('/profile')
@jwt_required  # If using JWT
def profile():
    # Your profile page implementation
    pass
    return render_template('profile.html')

app.run(use_reloader=True, debug=True)
