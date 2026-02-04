import sqlite3
import secrets
import random
import os
import json
import markdown
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, render_template, redirect, session, flash, url_for
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import Markup


def get_db_connection():
    """
    Open a connection to the SQLite database and enable foreign key support.
    Returns a connection object where rows can be accessed like dictionaries.
    """
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    # Make sure foreign key constraints are enforced in SQLite
    conn.execute('PRAGMA foreign_keys = ON;')
    return conn


def login_required(f):
    """
    Decorator to protect routes that require the user to be logged in.
    If there is no user_id in the session, redirect to the login page.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def role_required(*roles):
    """
    Decorator to protect routes that require specific user roles.
    Example: @role_required('admin') or @role_required('admin', 'seller')
    Checks the role stored in the session and redirects if not allowed.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # User must be logged in first
            if 'user_id' not in session:
                flash('Please login to access this page')
                return redirect(url_for('login'))
            
            user_role = session.get('user_role')
            # If the user role is not in the list of allowed roles, block access
            if user_role not in roles:
                flash(f'Access denied. This page requires {" or ".join(roles)} role.')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def validate_input_length(field_name, value, max_length):
    """ 
    Simple input validation.
    - Prevents very long input (helps against DoS and abuse).
    - Prevents empty strings.
    Returns (True, "") if valid, or (False, "error message") if not.
    """
    if len(value) > max_length:
        return False, f"{field_name} must be {max_length} characters or less"
    if len(value.strip()) == 0:
        return False, f"{field_name} cannot be empty"
    return True, ""


def is_password_strong(password):
    """
    Check if the password meets basic strength rules:
    - At least 8 characters
    - Not longer than 128 characters
    - Has uppercase, lowercase, and a digit
    Returns (False, errors_html) or (True, "Password is strong").
    """
    errors = []
    
    if len(password) < 8:
        errors.append("• Password must be at least 8 characters")
    if len(password) > 128:
        errors.append("• Password must be 128 characters or less")
    if not any(c.isupper() for c in password):
        errors.append("• Password must contain uppercase letter")
    if not any(c.islower() for c in password):
        errors.append("• Password must contain lowercase letter")
    if not any(c.isdigit() for c in password):
        errors.append("• Password must contain a number")
    
    if errors:
        # Join multiple messages with <br> so they show line by line in HTML
        return False, "<br>".join(errors)
    return True, "Password is strong"


def hash_password(password):
    """
    Hash the password using PBKDF2 with SHA-256.
    This helps protect passwords if the database is leaked.
    """
    return generate_password_hash(password, method='pbkdf2:sha256')


def log_activity(event_type, details=None, user_id=None):
    """
    Log important user actions into the activity_logs table.
    Used later for analytics and auditing.
    If user_id is not passed, try to read it from the session.
    """
    if user_id is None:
        user_id = session.get('user_id')
    
    conn = get_db_connection()
    current_time = datetime.now().isoformat()
    
    conn.execute('''INSERT INTO activity_logs 
                   (user_id, event_type, details, created_at) 
                   VALUES (?, ?, ?, ?)''',
                (user_id, event_type, details, current_time))
    conn.commit()
    conn.close()

# Create the Flask application
app = Flask(__name__)

# Secret key used to sign session cookies and CSRF tokens
app.secret_key = secrets.token_hex(32)

# Enable CSRF protection for all forms
csrf = CSRFProtect(app)


@app.template_filter('markdown')
def markdown_filter(text):
    """
    Custom Jinja2 filter to render Markdown safely in templates.
    Allows basic formatting like bold, italic, and lists.
    """
    if not text:
        return ""
    # Convert markdown text to HTML
    html = markdown.markdown(text, extensions=['nl2br', 'sane_lists'])
    # Mark the result as safe so Jinja does not escape it
    result = Markup(html)
    return result

# Folder where uploaded images will be stored inside /static
UPLOAD_FOLDER = 'static/uploads'
# Only allow safe image types
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
# Max file size: 5 MB
MAX_FILE_SIZE = 5 * 1024 * 1024

# Flask upload configuration
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Make sure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    """
    Check if the uploaded file has a valid extension.
    Returns True if extension is allowed image type.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Secure session cookie configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True   # Prevent JavaScript from reading session cookie
app.config['SESSION_COOKIE_SECURE'] = False    # Should be True in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # Stop most CSRF attacks from other sites
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout


@app.before_request
def check_session_timeout():
    """
    This runs before every request.
    - Makes the session "permanent" so timeout is applied.
    - If user is logged in, check last_activity timestamp.
    - If inactive for more than 30 minutes, log them out.
    """
    session.permanent = True
    if 'user_id' in session:
        last_activity = session.get('last_activity')
        if last_activity:
            last_time = datetime.fromisoformat(last_activity)
            # If user has been inactive for more than 30 minutes, clear session
            if datetime.now() - last_time > timedelta(minutes=30):
                session.clear()
                flash('Session expired due to inactivity. Please login again.')
                return redirect('/login')
        # Update last activity time on every request
        session['last_activity'] = datetime.now().isoformat()


@app.after_request
def set_security_headers(resp):
    """
    This runs after every request.
    Sets common security headers to protect the app:
    - X-Content-Type-Options: nosniff (stop MIME sniffing)
    - X-Frame-Options: DENY (prevent clickjacking in iframes)
    - Referrer-Policy: no-referrer (do not send referrer header)
    - Content-Security-Policy: restrict where scripts, images, styles can load from
    """
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self';"
    return resp

@app.route('/')
def home():
    """
    Redirect visitors from the root URL to the products page.
    """
    return redirect('/products')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handle user login.
    - GET: show login form.
    - POST: check email and password, create session if correct.
    Also logs successful and failed login attempts.
    """
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        
        # If user exists and password is correct
        if user and check_password_hash(user['password_hash'], password):
            # Clear any old session data to avoid session fixation
            session.clear()
            
            # Store basic user info in session
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['user_role'] = user['role']
            session['last_activity'] = datetime.now().isoformat()
            
            # Log successful login
            log_activity('login_success', f'email={email}', user_id=user['id'])
            
            flash(f'Welcome back, {user["name"]}!', 'success')
            return redirect('/dashboard')
        else:
            # Log failed login attempt
            log_activity('login_failed', f'email={email}', user_id=None)
            flash('Wrong email or password', 'error')
    
    # Initial GET request or failed login
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handle new user registration.
    - Validates name, email, password, and confirmation.
    - Checks if email is already registered.
    - Creates a verification code and stores pending data in verification_codes.
    - Shows a page where the user must enter the verification code.
    """
    if request.method == 'POST':
        # Get form inputs
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']
        
        # Default role for new users is "customer"
        role = 'customer'
        
        # Validate name length
        is_valid, error = validate_input_length('Name', name, 255)
        if not is_valid:
            return render_template('register.html', 
                                 name=name, email=email, role=role,
                                 general_error=error)
        
        # Validate email length
        is_valid, error = validate_input_length('Email', email, 255)
        if not is_valid:
            return render_template('register.html', 
                                 name=name, email=email, role=role,
                                 general_error=error)
        
        # Check if passwords match
        if password != confirm_password:
            return render_template('register.html', 
                                 name=name, email=email, role=role,
                                 general_error='Passwords do not match')
        
        # Check password strength rules
        is_strong, message = is_password_strong(password)
        if not is_strong:
            return render_template('register.html', 
                                 name=name, email=email, role=role,
                                 password_error=message)
        
        conn = get_db_connection()
        # Check if email is already used
        existing_user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if existing_user:
            conn.close()
            return render_template('register.html', 
                                 name=name, email=email, role=role,
                                 general_error='Email already exists')
        
        # Generate a 6-digit verification code using cryptographically secure random
        verification_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        
        # Hash the password before storing anything
        password_hash = hash_password(password)
        
        current_time = datetime.now()
        # Verification code expires after 15 minutes
        expires_at = (current_time + timedelta(minutes=15)).isoformat()
        
        # Remove any old unused registration codes for this email
        conn.execute('DELETE FROM verification_codes WHERE email = ? AND code_type = ? AND is_used = 0', 
                    (email, 'registration'))
        
        # Store pending user data as JSON, to use after code is verified
        user_data = json.dumps({
            'name': name,
            'password_hash': password_hash,
            'role': role
        })
        
        # Insert new verification code record
        conn.execute('''
            INSERT INTO verification_codes (email, code, code_type, created_at, expires_at, is_used, user_data)
            VALUES (?, ?, ?, ?, ?, 0, ?)
        ''', (email, verification_code, 'registration', current_time.isoformat(), expires_at, user_data))
        conn.commit()
        conn.close()
        
        # Log that registration has started for this email
        log_activity('registration_started', f'email={email}', user_id=None)
        
        # Show verification page (for demo, we display the code)
        return render_template('verify_code.html', 
                             email=email, 
                             name=name,
                             password=password_hash,
                             verification_code=verification_code,
                             verification_type='registration',
                             verify_action='/verify_registration',
                             cancel_url='/register')
    
    # Initial GET: show the registration form
    return render_template('register.html')

@app.route('/verify_registration', methods=['POST'])
def verify_registration():
    """ 
    Verify the registration code and create the user account.
    This reads the latest unused registration code for the email,
    checks it, and if valid creates the user in the users table.
    """
    
    email = request.form.get('email', '').strip()
    code = request.form.get('code', '').strip()
    
    conn = get_db_connection()
    
    # Get the latest unused registration code for this email
    verification_record = conn.execute('''
        SELECT * FROM verification_codes 
        WHERE email = ? AND code_type = ? AND is_used = 0 
        ORDER BY created_at DESC LIMIT 1
    ''', (email, 'registration')).fetchone()
    
    # If no record found, show error and ask to register again
    if not verification_record:
        conn.close()
        flash('Invalid or expired verification code. Please register again.', 'error')
        return redirect('/register')
    
    # Check if the code is already expired
    expires_at = datetime.fromisoformat(verification_record['expires_at'])
    if datetime.now() > expires_at:
        conn.close()
        flash('Verification code has expired. Please register again.', 'error')
        return redirect('/register')
    
    # If the code does not match what user entered
    if verification_record['code'] != code:
        conn.close()
        verification_code = verification_record['code']
        user_data = json.loads(verification_record['user_data'])
        flash('Incorrect code. Please try again.', 'error')
        # Re-show the verification page with the same stored code
        return render_template('verify_code.html', 
                             email=email,
                             name=user_data['name'],
                             password=user_data['password_hash'],
                             verification_code=verification_code,
                             verification_type='registration',
                             verify_action='/verify_registration',
                             cancel_url='/register')
    
    try:
        # Parse stored user data (name, password hash, role)
        user_data = json.loads(verification_record['user_data'])
        current_time = datetime.now().isoformat()
        
        # Create new user in the users table
        conn.execute('INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)',
                    (user_data['name'], email, user_data['password_hash'], user_data['role'], current_time))
        
        # Mark the verification code as used
        conn.execute('UPDATE verification_codes SET is_used = 1 WHERE id = ?', (verification_record['id'],))
        conn.commit()
        
        # Get the new user id (for logging)
        new_user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        
        # Log successful registration
        log_activity('register_success', f'email={email}, role={user_data["role"]}', user_id=new_user['id'] if new_user else None)
        
        flash('Account created successfully! Please login to continue.', 'success')
        return redirect('/login')
    except Exception as e:
        # If something goes wrong, show generic error
        conn.close()
        flash('An error occurred during registration. Please try again.', 'error')
        return redirect('/register')
@app.route('/dashboard')
@login_required
def dashboard():
    """
    Simple user dashboard.
    Shows the logged-in user's name and role.
    Access is protected by login_required.
    """
    user_name = session.get('user_name', 'User')
    user_role = session.get('user_role', 'customer')
    
    return render_template('dashboard.html', 
                         user_name=user_name, 
                         user_role=user_role)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    """
    Log the user out:
    - Record the logout in the activity log.
    - Clear the session.
    - Redirect to the login page.
    """
    log_activity('logout', f'user_id={session.get("user_id")}', user_id=session.get('user_id'))
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect('/login')

@app.route('/forgot_password', methods=['GET'])
def forgot_password():
    """Display forgot password form"""
    # Just show the page where the user enters their email
    return render_template('forgot_password.html')

@app.route('/send_reset_code', methods=['POST'])
def send_reset_code():
    """Generate and display verification code"""
    
    # Get the email from the form and strip any extra spaces
    email = request.form.get('email', '').strip()
    
    conn = get_db_connection()
    # Check if there is a user with this email
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    
    # To avoid leaking which emails exist, always show a generic message
    if not user:
        conn.close()
        flash('If this email exists in our system, a verification code will be shown.', 'info')
        return render_template('forgot_password.html', email=email)
    
    # Generate a 6-digit reset code using cryptographically secure random
    reset_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    
    current_time = datetime.now()
    # Code expires in 15 minutes
    expires_at = (current_time + timedelta(minutes=15)).isoformat()
    
    # Remove any previous unused password reset codes for this email
    conn.execute('DELETE FROM verification_codes WHERE email = ? AND code_type = ? AND is_used = 0', 
                (email, 'password_reset'))
    
    # Insert the new reset code (no extra user_data needed here)
    conn.execute('''
        INSERT INTO verification_codes (email, code, code_type, created_at, expires_at, is_used, user_data)
        VALUES (?, ?, ?, ?, ?, 0, NULL)
    ''', (email, reset_code, 'password_reset', current_time.isoformat(), expires_at))
    conn.commit()
    conn.close()
    
    # Log that a password reset was requested
    log_activity('password_reset_requested', f'email={email}', user_id=None)
    
    # Show the page where the user can enter the code (for demo, we show the code directly)
    return render_template('verify_code.html', 
                         email=email, 
                         verification_code=reset_code,
                         verification_type='password_reset',
                         verify_action='/verify_reset_code',
                         cancel_url='/login')

@app.route('/verify_reset_code', methods=['POST'])
def verify_reset_code():
    """Verify the code entered by user"""
    
    # Get email and code from the form
    email = request.form.get('email', '').strip()
    code = request.form.get('code', '').strip()
    
    conn = get_db_connection()
    
    # Get the latest unused reset code for this email
    reset_record = conn.execute('''
        SELECT * FROM verification_codes 
        WHERE email = ? AND code_type = ? AND is_used = 0 
        ORDER BY created_at DESC LIMIT 1
    ''', (email, 'password_reset')).fetchone()
    
    # If there is no valid record
    if not reset_record:
        conn.close()
        flash('Invalid or expired verification code. Please try again.', 'error')
        return redirect('/forgot_password')
    
    # Check if the code is expired
    expires_at = datetime.fromisoformat(reset_record['expires_at'])
    if datetime.now() > expires_at:
        conn.close()
        flash('Verification code has expired. Please request a new one.', 'error')
        return redirect('/forgot_password')
    
    # Check if the code entered by the user matches the one in the database
    if reset_record['code'] != code:
        conn.close()
        reset_code = reset_record['code']
        flash('Incorrect code. Please try again.', 'error')
        # Re-show the code entry page (code is re-rendered on the page)
        return render_template('verify_code.html', 
                             email=email, 
                             verification_code=reset_code,
                             verification_type='password_reset',
                             verify_action='/verify_reset_code',
                             cancel_url='/login')
    
    # Mark the code as used so it cannot be reused
    conn.execute('UPDATE verification_codes SET is_used = 1 WHERE id = ?', (reset_record['id'],))
    conn.commit()
    conn.close()
    
    # Log that the reset code was successfully verified
    log_activity('password_reset_verified', f'email={email}', user_id=None)
    
    # Show the form where user can enter a new password
    return render_template('reset_password.html', email=email)

@app.route('/reset_password', methods=['POST'])
def reset_password():
    """Update user's password"""
    # Get form fields and strip spaces
    email = request.form.get('email', '').strip()
    new_password = request.form.get('new_password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()
    
    # Check that both passwords match
    if new_password != confirm_password:
        flash('Passwords do not match', 'error')
        return render_template('reset_password.html', email=email)
    
    # Check password strength again for security
    is_strong, message = is_password_strong(new_password)
    if not is_strong:
        flash(message, 'error')
        return render_template('reset_password.html', email=email)
    
    conn = get_db_connection()
    # Hash the new password
    password_hash = hash_password(new_password)
    
    try:
        # Update password in the users table
        conn.execute('UPDATE users SET password_hash = ? WHERE email = ?', (password_hash, email))
        conn.commit()
        
        # Get user id for logging
        user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        if user:
            log_activity('password_reset_completed', f'email={email}', user_id=user['id'])
        
        conn.close()
        
        flash('Your password has been successfully reset. You can now log in with your new password.', 'success')
        return redirect('/login')
    except Exception as e:
        conn.close()
        flash('An error occurred. Please try again.', 'error')
        return render_template('reset_password.html', email=email)
@app.route('/request_seller_upgrade', methods=['POST'])
@role_required('customer')
def request_seller_upgrade():
    """
    Allow a customer to request an upgrade to 'seller'.
    Security:
    - Only users with role 'customer' can access this route (via role_required).
    - Prevent duplicate pending requests.
    """
    user_id = session['user_id']
    conn = get_db_connection()
    
    # Check if there is already a pending request from this user
    existing = conn.execute('SELECT * FROM seller_requests WHERE user_id = ? AND status = ?', 
                           (user_id, 'pending')).fetchone()
    
    if existing:
        conn.close()
        flash('You already have a pending upgrade request', 'info')
        return redirect('/dashboard')
    
    # Create a new pending request
    current_time = datetime.now().isoformat()
    conn.execute('INSERT INTO seller_requests (user_id, status, requested_at) VALUES (?, ?, ?)',
                (user_id, 'pending', current_time))
    conn.commit()
    conn.close()
    
    # Log the upgrade request
    log_activity('seller_upgrade_request', f'user_id={user_id}', user_id=user_id)
    
    flash('Your request was sent to the admin. Please wait for approval.', 'success')
    return redirect('/dashboard')

@app.route('/admin/upgrade_requests')
@role_required('admin')
def admin_upgrade_requests():
    """
    Admin view to see all pending seller upgrade requests.
    Security: Only admin can access this page.
    """
    conn = get_db_connection()
    # Join with users table so admin can see who made the request
    requests = conn.execute('''SELECT sr.*, u.name, u.email 
                              FROM seller_requests sr 
                              JOIN users u ON sr.user_id = u.id 
                              WHERE sr.status = 'pending'
                              ORDER BY sr.requested_at DESC''').fetchall()
    conn.close()
    
    return render_template('upgrade_requests.html', requests=requests)

@app.route('/admin/approve_upgrade/<int:request_id>', methods=['POST'])
@role_required('admin')
def approve_upgrade(request_id):
    """
    Admin action to approve a seller upgrade request.
    Steps:
    - Change the user's role to 'seller'.
    - Mark the request as 'approved' with admin id and reviewed time.
    """
    conn = get_db_connection()
    
    # Get the request from database
    req = conn.execute('SELECT * FROM seller_requests WHERE id = ?', (request_id,)).fetchone()
    
    if req:
        current_time = datetime.now().isoformat()
        
        # Update the target user's role to seller
        conn.execute('UPDATE users SET role = ? WHERE id = ?', ('seller', req['user_id']))
        
        # Update the seller_requests record to show it has been approved
        conn.execute('UPDATE seller_requests SET status = ?, reviewed_at = ?, admin_id = ? WHERE id = ?',
                    ('approved', current_time, session['user_id'], request_id))
        
        conn.commit()
        
        # Log that admin approved this upgrade
        log_activity('seller_upgrade_approved', f'target_user={req["user_id"]}', user_id=session['user_id'])
        
        flash('Seller upgrade approved! User can now list products.', 'success')
    
    conn.close()
    return redirect('/admin/upgrade_requests')

@app.route('/admin/reject_upgrade/<int:request_id>', methods=['POST'])
@role_required('admin')
def reject_upgrade(request_id):
    """
    Admin action to reject a seller upgrade request.
    Marks the request as 'rejected' and logs the action.
    """
    conn = get_db_connection()
    
    # Get the request (for logging purposes)
    req = conn.execute('SELECT * FROM seller_requests WHERE id = ?', (request_id,)).fetchone()
    
    current_time = datetime.now().isoformat()
    
    # Update status to rejected
    conn.execute('UPDATE seller_requests SET status = ?, reviewed_at = ?, admin_id = ? WHERE id = ?',
                ('rejected', current_time, session['user_id'], request_id))
    conn.commit()
    conn.close()
    
    # If the request existed, log rejection
    if req:
        log_activity('seller_upgrade_rejected', f'target_user={req["user_id"]}', user_id=session['user_id'])
    
    flash('Upgrade request has been rejected', 'info')
    return redirect('/admin/upgrade_requests')

@app.route('/admin/activity_logs')
@role_required('admin')
def activity_logs():
    """
    Admin view for recent user activity logs.
    Shows events like logins, upgrades, purchases, etc.
    """
    conn = get_db_connection()
    
    logs = conn.execute('''SELECT al.*, u.name, u.email, u.role
                          FROM activity_logs al
                          LEFT JOIN users u ON al.user_id = u.id
                          ORDER BY al.created_at DESC
                          LIMIT 200''').fetchall()
    conn.close()
    
    return render_template('activity_logs.html', logs=logs)

@app.route('/admin/analytics')
@role_required('admin')
def analytics():
    """
    Admin dashboard for basic site analytics.
    Shows:
    - Total users
    - Total products
    - Total orders
    - Count of events in the last 7 days (grouped by event_type)
    """
    conn = get_db_connection()
    
    stats = {}
    # Count total users
    stats['total_users'] = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    # Count total products
    stats['total_products'] = conn.execute('SELECT COUNT(*) as count FROM products').fetchone()['count']
    # Count total orders
    stats['total_orders'] = conn.execute('SELECT COUNT(*) as count FROM orders').fetchone()['count']
    
    # Look at user activity from the last 7 days
    seven_days_ago = (datetime.now() - timedelta(days=7)).isoformat()
    recent_activity = conn.execute('''SELECT event_type, COUNT(*) as count
                                     FROM activity_logs
                                     WHERE created_at > ?
                                     GROUP BY event_type
                                     ORDER BY count DESC''', (seven_days_ago,)).fetchall()
    
    conn.close()
    
    return render_template('analytics.html', stats=stats, recent_activity=recent_activity)

@app.route('/admin/manage_users')
@role_required('admin')
def manage_users():
    """
    Admin view to see and manage all user accounts.
    Basic info: id, name, email, role, created_at.
    """
    conn = get_db_connection()
    
    users = conn.execute('''SELECT id, name, email, role, created_at 
                           FROM users 
                           ORDER BY created_at DESC''').fetchall()
    conn.close()
    
    return render_template('manage_users.html', users=users)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@role_required('admin')
def edit_user(user_id):
    """
    Admin can change another user's role (customer/seller/admin).
    Security:
    - Admin cannot change their own role (to avoid locking themselves out).
    - Only valid roles are accepted.
    """
    conn = get_db_connection()
    
    # Prevent admin from editing their own role for safety
    if user_id == session['user_id']:
        flash('You cannot change your own role for security reasons', 'error')
        conn.close()
        return redirect('/admin/manage_users')
    
    if request.method == 'POST':
        role = request.form['role']
        
        # Only allow roles from the known list
        if role not in ['customer', 'seller', 'admin']:
            flash('Invalid role selected', 'error')
            conn.close()
            return redirect(url_for('edit_user', user_id=user_id))
        
        try:
            # Update the user's role in the database
            conn.execute('UPDATE users SET role = ? WHERE id = ?',
                        (role, user_id))
            conn.commit()
            
            # Log the change
            log_activity('user_updated', f'Updated user_id={user_id}, new_role={role}', user_id=session['user_id'])
            
            flash('User role updated successfully!', 'success')
        except Exception as e:
            flash('Error updating user', 'error')
        
        conn.close()
        return redirect('/admin/manage_users')
    
    # GET request: fetch user info to show in the form
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if not user:
        flash('User not found', 'error')
        return redirect('/admin/manage_users')
    
    return render_template('edit_user.html', user=user)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@role_required('admin')
def delete_user(user_id):
    """
    Admin action to delete a user account.
    Security:
    - Admin cannot delete their own account.
    - If user exists, remove them and log the action.
    """
    if user_id == session['user_id']:
        flash('You cannot delete your own account', 'error')
        return redirect('/admin/manage_users')
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if user:
        # Delete user record. (Any dependent rows should be handled by foreign keys if set)
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        
        # Log the deletion with the user's email
        log_activity('user_deleted', f'Deleted user_id={user_id}, email={user["email"]}', user_id=session['user_id'])
        
        flash(f'User {user["email"]} deleted successfully', 'success')
    
    conn.close()
    return redirect('/admin/manage_users')
@app.route('/products')
def products():
    """
    Public products page.
    - Shows all products with their seller names.
    - If a user is logged in, we log that they viewed the products page.
    """
    conn = get_db_connection()
    
    products = conn.execute('''
        SELECT p.*, u.name as seller_name 
        FROM products p 
        JOIN users u ON p.seller_id = u.id 
        ORDER BY p.created_at DESC
    ''').fetchall()
    
    # Log activity only if user is logged in
    if 'user_id' in session:
        log_activity('viewed_products_page', 'Browsed product catalog')
    
    conn.close()
    return render_template('products.html', products=products)


@app.route('/products/<int:product_id>')
def product_detail(product_id):
    """
    Show the details of a single product.
    Also:
    - Shows all reviews for this product.
    - Shows average rating and review count.
    """
    conn = get_db_connection()
    
    # Get product and its seller details
    product = conn.execute('''
        SELECT p.*, u.name as seller_name, u.email as seller_email
        FROM products p 
        JOIN users u ON p.seller_id = u.id 
        WHERE p.id = ?
    ''', (product_id,)).fetchone()
    
    if not product:
        flash('Product not found', 'error')
        conn.close()
        return redirect(url_for('products'))
    
    # Get all reviews for this product
    reviews = conn.execute('''
        SELECT r.*, u.name as user_name
        FROM reviews r
        JOIN users u ON r.user_id = u.id
        WHERE r.product_id = ?
        ORDER BY r.created_at DESC
    ''', (product_id,)).fetchall()
    
    # Get average rating and number of reviews
    avg_rating = conn.execute('''
        SELECT AVG(rating) as avg_rating, COUNT(*) as review_count
        FROM reviews
        WHERE product_id = ?
    ''', (product_id,)).fetchone()
    
    if 'user_id' in session:
        # Log that the user viewed a specific product
        log_activity('viewed_product_detail', f'Product: {product["title"]} (ID: {product_id})')
    
    conn.close()
    return render_template('product_detail.html', 
                         product=product, 
                         reviews=reviews,
                         avg_rating=avg_rating)


@app.route('/admin/manage_products')
@role_required('admin')
def manage_products():
    """
    Admin page to manage all products on the site.
    Shows:
    - Product info
    - Seller name
    """
    conn = get_db_connection()
    
    products = conn.execute('''
        SELECT p.*, u.name as seller_name
        FROM products p 
        JOIN users u ON p.seller_id = u.id 
        ORDER BY p.created_at DESC
    ''').fetchall()
    
    # Log how many products the admin is viewing
    log_activity('viewed_product_management', f'Total products: {len(products)}')
    
    conn.close()
    return render_template('manage_products.html', products=products)


@app.route('/admin/edit_product/<int:product_id>', methods=['GET', 'POST'])
@role_required('admin')
def edit_product(product_id):
    """
    Admin can edit any product.
    Security:
    - Only admin (role_required) can access.
    - Validates title, description, price, and stock.
    """
    conn = get_db_connection()
    
    if request.method == 'POST':
        # Read and strip form fields
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        price = request.form.get('price', '').strip()
        stock = request.form.get('stock', '').strip()
        
        # Validate title length
        valid, msg = validate_input_length('Title', title, 200)
        if not valid:
            flash(msg, 'error')
            return redirect(request.url)
        
        # Validate description length
        valid, msg = validate_input_length('Description', description, 2000)
        if not valid:
            flash(msg, 'error')
            return redirect(request.url)
        
        # Validate price and stock as numbers
        try:
            price = float(price)
            stock = int(stock)
            if price < 0 or stock < 0:
                flash('Price and stock must be positive numbers', 'error')
                return redirect(request.url)
        except ValueError:
            flash('Invalid price or stock value', 'error')
            return redirect(request.url)
        
        # Update product in database
        conn.execute('''
            UPDATE products 
            SET title = ?, description = ?, price = ?, stock = ?
            WHERE id = ?
        ''', (title, description, price, stock, product_id))
        conn.commit()
        
        # Log edit action
        log_activity('edited_product', f'Product ID: {product_id} - {title}')
        flash('Product updated successfully', 'success')
        conn.close()
        return redirect(url_for('manage_products'))
    
    # GET request: fetch product data
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    
    if not product:
        flash('Product not found', 'error')
        conn.close()
        return redirect(url_for('manage_products'))
    
    conn.close()
    return render_template('edit_product.html', product=product)


@app.route('/admin/delete_product/<int:product_id>', methods=['POST'])
@role_required('admin')
def delete_product(product_id):
    """
    Admin can delete any product.
    Also deletes:
    - All reviews for this product
    (Other related cleanup depends on DB constraints).
    """
    conn = get_db_connection()
    
    # Get title for nicer flash/log messages
    product = conn.execute('SELECT title FROM products WHERE id = ?', (product_id,)).fetchone()
    
    if product:
        # First delete related reviews to avoid orphaned data
        conn.execute('DELETE FROM reviews WHERE product_id = ?', (product_id,))
        # Then delete the actual product
        conn.execute('DELETE FROM products WHERE id = ?', (product_id,))
        conn.commit()
        
        log_activity('deleted_product', f'Product ID: {product_id} - {product["title"]}')
        flash('Product deleted successfully', 'success')
    else:
        flash('Product not found', 'error')
    
    conn.close()
    return redirect(url_for('manage_products'))


@app.route('/seller/add_product', methods=['GET', 'POST'])
@role_required('seller')
def add_product():
    """
    Seller route to add a new product.
    Security:
    - Only sellers (role_required) can use this.
    - Validates title, description, price, and stock.
    - Restricts image type and size.
    """
    if request.method == 'POST':
        # Read inputs safely and strip spaces
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        price = request.form.get('price', '').strip()
        stock = request.form.get('stock', '').strip()
        
        # Basic length checks
        valid, msg = validate_input_length('Product Title', title, 200)
        if not valid:
            flash(msg, 'error')
            return render_template('add_product.html', title=title, description=description, price=price, stock=stock)
        
        valid, msg = validate_input_length('Product Description', description, 2000)
        if not valid:
            flash(msg, 'error')
            return render_template('add_product.html', title=title, description=description, price=price, stock=stock)
        
        # Validate price range and format
        try:
            price_value = float(price)
            if price_value < 0 or price_value > 999999.99:
                flash('Price must be between $0 and $999,999.99', 'error')
                return render_template('add_product.html', title=title, description=description, price=price, stock=stock)
        except ValueError:
            flash('Invalid price value', 'error')
            return render_template('add_product.html', title=title, description=description, price=price, stock=stock)
        
        # Validate stock range and format
        try:
            stock_value = int(stock)
            if stock_value < 0 or stock_value > 999999:
                flash('Stock must be between 0 and 999,999 units', 'error')
                return render_template('add_product.html', title=title, description=description, price=price, stock=stock)
        except ValueError:
            flash('Invalid stock value', 'error')
            return render_template('add_product.html', title=title, description=description, price=price, stock=stock)
        
        image_path = None
        # Handle optional image upload
        if 'image' in request.files:
            file = request.files['image']
            # Check file is present and has allowed extension
            if file and file.filename != '' and allowed_file(file.filename):
                # Use secure_filename to avoid dangerous file names
                filename = secure_filename(file.filename)
                # Add timestamp to filename to avoid collisions
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{timestamp}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                # Store relative path to use in templates
                image_path = f"uploads/{filename}"
            elif file and file.filename != '' and not allowed_file(file.filename):
                flash('Invalid image format. Use PNG, JPG, JPEG, or GIF', 'error')
                return render_template('add_product.html', title=title, description=description, price=price, stock=stock)
        
        conn = get_db_connection()
        current_time = datetime.now().isoformat()
        seller_id = session['user_id']
        
        try:
            # Insert new product into the database
            cursor = conn.execute('''
                INSERT INTO products (seller_id, title, description, price, stock, image_path, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (seller_id, title, description, price_value, stock_value, image_path, current_time))
            conn.commit()
            product_id = cursor.lastrowid
            # Log product creation
            log_activity('product_created', f'Product: {title} (ID: {product_id})', user_id=seller_id)
            flash('Product listed successfully!', 'success')
            conn.close()
            return redirect(url_for('my_products'))
        except Exception as e:
            conn.close()
            flash('Error creating product. Please try again.', 'error')
            return render_template('add_product.html', title=title, description=description, price=price, stock=stock)
    
    # GET: show the add product form
    return render_template('add_product.html')


@app.route('/seller/my_products')
@role_required('seller')
def my_products():
    """
    Seller view that shows only the products owned by the logged-in seller.
    """
    conn = get_db_connection()
    seller_id = session['user_id']
    
    products = conn.execute('''
        SELECT p.*, u.name as seller_name
        FROM products p
        JOIN users u ON p.seller_id = u.id
        WHERE p.seller_id = ?
        ORDER BY p.created_at DESC
    ''', (seller_id,)).fetchall()
    
    # Log how many products this seller viewed
    log_activity('viewed_my_products', f'Total products: {len(products)}')
    conn.close()
    return render_template('my_products.html', products=products)
@app.route('/seller/edit_product/<int:product_id>', methods=['GET', 'POST'])
@role_required('seller')
def seller_edit_product(product_id):
    """
    Seller can edit one of their own products.
    Security:
    - Only users with role 'seller' can access this route.
    - Seller can only edit products where they are the owner.
    """
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    
    # If the product does not exist
    if not product:
        flash('Product not found', 'error')
        conn.close()
        return redirect(url_for('my_products'))
    
    # Prevent editing of products that belong to another seller
    if product['seller_id'] != session['user_id']:
        flash('You can only edit your own products', 'error')
        conn.close()
        return redirect(url_for('my_products'))
    
    if request.method == 'POST':
        # Get updated values from form
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        price = request.form.get('price', '').strip()
        stock = request.form.get('stock', '').strip()
        
        # Validate title length
        valid, msg = validate_input_length('Product Title', title, 200)
        if not valid:
            flash(msg, 'error')
            return redirect(request.url)
        
        # Validate description length
        valid, msg = validate_input_length('Product Description', description, 2000)
        if not valid:
            flash(msg, 'error')
            return redirect(request.url)
        
        try:
            # Convert price and stock to correct types
            price_value = float(price)
            stock_value = int(stock)
            # Check that values are in valid range
            if price_value < 0 or stock_value < 0 or price_value > 999999.99 or stock_value > 999999:
                flash('Invalid price or stock range', 'error')
                return redirect(request.url)
        except ValueError:
            flash('Invalid price or stock value', 'error')
            return redirect(request.url)
        
        # Keep the old image path by default
        image_path = product['image_path']
        if 'image' in request.files:
            file = request.files['image']
            # If a new file is uploaded and type is allowed
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{timestamp}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                # Update to new image path
                image_path = f"uploads/{filename}"
                # Remove old image file from disk if it exists
                if product['image_path']:
                    old_path = os.path.join('static', product['image_path'])
                    if os.path.exists(old_path):
                        os.remove(old_path)
            # If file uploaded but extension is not allowed
            elif file and file.filename != '' and not allowed_file(file.filename):
                flash('Invalid image format. Use PNG, JPG, JPEG, or GIF', 'error')
                return redirect(request.url)
        
        # Update product details in database
        conn.execute('''
            UPDATE products 
            SET title = ?, description = ?, price = ?, stock = ?, image_path = ?
            WHERE id = ?
        ''', (title, description, price_value, stock_value, image_path, product_id))
        conn.commit()
        # Log edit event
        log_activity('edited_product', f'Product ID: {product_id} - {title}')
        flash('Product updated successfully', 'success')
        conn.close()
        return redirect(url_for('my_products'))
    
    conn.close()
    # GET: show edit form with current product info
    return render_template('seller_edit_product.html', product=product)


@app.route('/seller/delete_product/<int:product_id>', methods=['POST'])
@role_required('seller')
def seller_delete_product(product_id):
    """
    Seller can delete one of their own products.
    Also cleans up:
    - Product image file (if exists)
    - Cart items
    - Reviews
    - Order items
    """
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    
    # If product does not exist
    if not product:
        flash('Product not found', 'error')
        conn.close()
        return redirect(url_for('my_products'))
    
    # Only the owner seller can delete their product
    if product['seller_id'] != session['user_id']:
        flash('You can only delete your own products', 'error')
        conn.close()
        return redirect(url_for('my_products'))
    
    # If product has an image, remove the file from disk
    if product['image_path']:
        image_file = os.path.join('static', product['image_path'])
        if os.path.exists(image_file):
            os.remove(image_file)
    
    # Remove related data from other tables
    conn.execute('DELETE FROM cart WHERE product_id = ?', (product_id,))
    conn.execute('DELETE FROM reviews WHERE product_id = ?', (product_id,))
    conn.execute('DELETE FROM order_items WHERE product_id = ?', (product_id,))
    conn.execute('DELETE FROM products WHERE id = ?', (product_id,))
    conn.commit()
    # Log deletion
    log_activity('deleted_product', f'Product ID: {product_id} - {product["title"]}')
    flash('Product deleted successfully', 'success')
    conn.close()
    return redirect(url_for('my_products'))


@app.route('/cart/add/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    """
    Add a product to the cart.
    Security:
    - Only logged-in users can use this.
    - Only users with role 'customer' are allowed to buy.
    - Respects stock levels.
    """
    # Prevent sellers/admins from buying items
    if session.get('user_role') != 'customer':
        flash('Only customers can purchase products. Please create a customer account to buy items.', 'error')
        return redirect(url_for('product_detail', product_id=product_id))
    
    conn = get_db_connection()
    # Get the selected product
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    
    # Product must exist
    if not product:
        flash('Product not found', 'error')
        conn.close()
        return redirect(url_for('products'))
    
    # Check stock > 0 before adding
    if product['stock'] <= 0:
        flash('Product is out of stock', 'error')
        conn.close()
        return redirect(url_for('product_detail', product_id=product_id))
    
    # See if this product is already in the user's cart
    cart_item = conn.execute('SELECT * FROM cart WHERE user_id = ? AND product_id = ?', 
                             (session['user_id'], product_id)).fetchone()
    
    if cart_item:
        # If already in cart, increase quantity by 1 (if stock allows)
        new_quantity = cart_item['quantity'] + 1
        if new_quantity > product['stock']:
            flash('Cannot add more - stock limit reached', 'error')
        else:
            conn.execute('UPDATE cart SET quantity = ? WHERE id = ?', (new_quantity, cart_item['id']))
            conn.commit()
            flash(f'Cart updated! You now have {new_quantity} of this item', 'success')
    else:
        # If not in cart, insert a new row with quantity 1
        conn.execute('INSERT INTO cart (user_id, product_id, quantity, added_at) VALUES (?, ?, 1, ?)',
                    (session['user_id'], product_id, datetime.now().isoformat()))
        conn.commit()
        flash('Added to cart successfully!', 'success')
    
    # Log cart action
    log_activity('added_to_cart', f'Product ID: {product_id}')
    conn.close()
    return redirect(url_for('product_detail', product_id=product_id))


@app.route('/cart')
@login_required
def view_cart():
    """
    Show the current user's cart.
    Security:
    - Only customers can buy, so non-customers are blocked.
    Shows:
    - Items in the cart, with seller name and total price.
    """
    if session.get('user_role') != 'customer':
        flash('Only customers can purchase products. Please create a customer account to buy items.', 'error')
        return redirect(url_for('products'))
    
    conn = get_db_connection()
    # Join with products and sellers for display info
    cart_items = conn.execute('''
        SELECT c.id as cart_id, c.quantity, c.added_at,
               p.id as product_id, p.title, p.price, p.stock, p.image_path,
               u.name as seller_name
        FROM cart c
        JOIN products p ON c.product_id = p.id
        JOIN users u ON p.seller_id = u.id
        WHERE c.user_id = ?
        ORDER BY c.added_at DESC
    ''', (session['user_id'],)).fetchall()
    
    # Calculate cart total
    total = sum(item['price'] * item['quantity'] for item in cart_items)
    conn.close()
    return render_template('cart.html', cart_items=cart_items, total=total)


@app.route('/cart/update/<int:cart_id>', methods=['POST'])
@login_required
def update_cart(cart_id):
    """
    Update the quantity of a cart item.
    Security:
    - Checks that the cart item belongs to the logged-in user.
    - Validates that the new quantity does not exceed stock.
    """
    # Get requested quantity as integer
    quantity = request.form.get('quantity', type=int)
    
    # Quantity must be at least 1
    if not quantity or quantity < 1:
        flash('Invalid quantity', 'error')
        return redirect(url_for('view_cart'))
    
    conn = get_db_connection()
    # Load cart item and related product stock
    cart_item = conn.execute('''
        SELECT c.*, p.stock 
        FROM cart c 
        JOIN products p ON c.product_id = p.id 
        WHERE c.id = ? AND c.user_id = ?
    ''', (cart_id, session['user_id'])).fetchone()
    
    if not cart_item:
        flash('Cart item not found', 'error')
        conn.close()
        return redirect(url_for('view_cart'))
    
    # New quantity must not be more than available stock
    if quantity > cart_item['stock']:
        flash(f'Only {cart_item["stock"]} items available', 'error')
        conn.close()
        return redirect(url_for('view_cart'))
    
    # Update quantity
    conn.execute('UPDATE cart SET quantity = ? WHERE id = ?', (quantity, cart_id))
    conn.commit()
    conn.close()
    flash(f'Quantity updated to {quantity}', 'success')
    return redirect(url_for('view_cart'))


@app.route('/cart/remove/<int:cart_id>', methods=['POST'])
@login_required
def remove_from_cart(cart_id):
    """
    Remove a single item from the user's cart.
    Security:
    - Checks that the item belongs to the logged-in user.
    """
    conn = get_db_connection()
    cart_item = conn.execute('SELECT * FROM cart WHERE id = ? AND user_id = ?', 
                            (cart_id, session['user_id'])).fetchone()
    
    # Only delete if the item actually exists for this user
    if not cart_item:
        flash('Cart item not found', 'error')
        conn.close()
        return redirect(url_for('view_cart'))
    
    conn.execute('DELETE FROM cart WHERE id = ?', (cart_id,))
    conn.commit()
    conn.close()
    flash('Item removed from your cart', 'success')
    return redirect(url_for('view_cart'))


@app.route('/cart/checkout', methods=['POST'])
@login_required
def checkout():
    """
    Complete the purchase for all items in the cart.
    Steps:
    - Only customers can purchase.
    - Check that the cart is not empty.
    - Check stock for each item.
    - Create an order and order_items.
    - Decrease stock.
    - Clear the cart.
    """
    if session.get('user_role') != 'customer':
        flash('Only customers can purchase products. Please create a customer account to buy items.', 'error')
        return redirect(url_for('products'))
    
    conn = get_db_connection()
    
    # Get all cart items for this user with product details
    cart_items = conn.execute('''
        SELECT c.*, p.title, p.price, p.stock, p.seller_id
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = ?
    ''', (session['user_id'],)).fetchall()
    
    # Cart must not be empty
    if not cart_items:
        flash('Your cart is empty', 'error')
        conn.close()
        return redirect(url_for('view_cart'))
    
    # Ensure there is enough stock for every item
    for item in cart_items:
        if item['quantity'] > item['stock']:
            flash(f'Insufficient stock for {item["title"]}', 'error')
            conn.close()
            return redirect(url_for('view_cart'))
    
    # Calculate total cost of the order
    total = sum(item['price'] * item['quantity'] for item in cart_items)
    # Create a new order record with status 'completed'
    conn.execute('INSERT INTO orders (user_id, status, total, created_at) VALUES (?, ?, ?, ?)',
                (session['user_id'], 'completed', total, datetime.now().isoformat()))
    # Get ID of the new order
    order_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
    
    # Insert each cart item into order_items and update product stock
    for item in cart_items:
        conn.execute('''
            INSERT INTO order_items (order_id, product_id, quantity, unit_price)
            VALUES (?, ?, ?, ?)
        ''', (order_id, item['product_id'], item['quantity'], item['price']))
        
        conn.execute('UPDATE products SET stock = stock - ? WHERE id = ?',
                    (item['quantity'], item['product_id']))
    
    # Clear the cart now that order is created
    conn.execute('DELETE FROM cart WHERE user_id = ?', (session['user_id'],))
    conn.commit()
    
    # Log completed purchase
    log_activity('completed_purchase', f'Order ID: {order_id}, Total: ${total:.2f}')
    flash(f'Order placed successfully! Your Order ID is #{order_id}. Total: ${total:.2f}', 'success')
    conn.close()
    return redirect(url_for('dashboard'))


@app.route('/orders')
@login_required
def my_orders():
    """
    Show all orders for the logged-in user.
    Includes:
    - Order id, status, total, date, and number of items.
    """
    conn = get_db_connection()
    
    orders = conn.execute('''
        SELECT o.id, o.status, o.total, o.created_at,
               COUNT(oi.id) as item_count
        FROM orders o
        LEFT JOIN order_items oi ON o.id = oi.order_id
        WHERE o.user_id = ?
        GROUP BY o.id
        ORDER BY o.created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    return render_template('my_orders.html', orders=orders)


@app.route('/orders/<int:order_id>')
@login_required
def order_detail(order_id):
    """
    Show details of a single order for the logged-in user.
    Security:
    - User can only see their own orders.
    """
    conn = get_db_connection()
    
    # Load the order and confirm owner
    order = conn.execute('''
        SELECT * FROM orders WHERE id = ? AND user_id = ?
    ''', (order_id, session['user_id'])).fetchone()
    
    if not order:
        flash('Order not found', 'error')
        conn.close()
        return redirect(url_for('my_orders'))
    
    # Get all items that belong to this order
    order_items = conn.execute('''
        SELECT oi.*, p.title, p.image_path, u.name as seller_name
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
        JOIN users u ON p.seller_id = u.id
        WHERE oi.order_id = ?
    ''', (order_id,)).fetchall()
    
    conn.close()
    return render_template('order_detail.html', order=order, order_items=order_items)


@app.route('/seller/transactions')
@role_required('seller')
def seller_transactions():
    """
    Show all transactions related to the logged-in seller's products.
    Includes:
    - Each order that contains their products
    - Customer name
    - Quantity and item total
    Also calculates total sales and total items sold.
    """
    conn = get_db_connection()
    
    transactions = conn.execute('''
        SELECT o.id as order_id, o.status, o.created_at,
               oi.product_id, oi.quantity, oi.unit_price,
               p.title as product_title,
               u.name as customer_name,
               (oi.quantity * oi.unit_price) as item_total
        FROM order_items oi
        JOIN orders o ON oi.order_id = o.id
        JOIN products p ON oi.product_id = p.id
        JOIN users u ON o.user_id = u.id
        WHERE p.seller_id = ?
        ORDER BY o.created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    # Sum of all revenue for this seller
    total_sales = sum(t['item_total'] for t in transactions)
    # Total number of units sold
    total_items = sum(t['quantity'] for t in transactions)
    
    conn.close()
    return render_template('seller_transactions.html', 
                         transactions=transactions,
                         total_sales=total_sales,
                         total_items=total_items)


@app.route('/seller/sales_report')
@role_required('seller')
def sales_report():
    """
    Summary report for each product of the logged-in seller.
    Shows:
    - How many orders include the product
    - How many units sold
    - Total revenue per product
    """
    conn = get_db_connection()
    
    product_sales = conn.execute('''
        SELECT p.id, p.title, p.price, p.stock,
               COUNT(oi.id) as orders_count,
               SUM(oi.quantity) as units_sold,
               SUM(oi.quantity * oi.unit_price) as revenue
        FROM products p
        LEFT JOIN order_items oi ON p.id = oi.product_id
        WHERE p.seller_id = ?
        GROUP BY p.id
        ORDER BY revenue DESC
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    return render_template('sales_report.html', product_sales=product_sales)
@app.route('/write_review')
@login_required
def write_review():
    """
    Show products that the user has purchased and can review.
    Security:
    - User can only review products they actually bought.
    - Uses DISTINCT so each product is shown once.
    - Also shows if the user already reviewed a product.
    """
    conn = get_db_connection()
    
    purchased_products = conn.execute('''
        SELECT DISTINCT p.id, p.title, p.price, p.image_path,
               (SELECT COUNT(*) FROM reviews WHERE user_id = ? AND product_id = p.id) as has_reviewed
        FROM products p
        JOIN order_items oi ON p.id = oi.product_id
        JOIN orders o ON oi.order_id = o.id
        WHERE o.user_id = ? AND o.status = 'completed'
        ORDER BY o.created_at DESC
    ''', (session['user_id'], session['user_id'])).fetchall()
    
    # Log that user visited the write-review page
    log_activity('viewed_write_review', f'Purchased products: {len(purchased_products)}')
    
    conn.close()
    return render_template('write_review.html', products=purchased_products)


@app.route('/product/<int:product_id>/add_review', methods=['GET', 'POST'])
@login_required
def add_review(product_id):
    """
    Add review for a specific product.
    Security:
    - User must have purchased the product before.
    - Prevents duplicate reviews by same user on same product.
    - Validates rating and content length.
    - Optional image upload with allowed file types only.
    """
    conn = get_db_connection()
    
    # Get product being reviewed
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    
    if not product:
        flash('Product not found', 'error')
        conn.close()
        return redirect(url_for('write_review'))
    
    # Verify user has purchased this product in a completed order
    has_purchased = conn.execute('''
        SELECT COUNT(*) as count
        FROM orders o
        JOIN order_items oi ON o.id = oi.order_id
        WHERE o.user_id = ? AND oi.product_id = ? AND o.status = 'completed'
    ''', (session['user_id'], product_id)).fetchone()
    
    if has_purchased['count'] == 0:
        flash('You can only review products you have purchased', 'error')
        conn.close()
        return redirect(url_for('write_review'))
    
    # Check if user already submitted a review for this product
    existing_review = conn.execute('''
        SELECT * FROM reviews WHERE user_id = ? AND product_id = ?
    ''', (session['user_id'], product_id)).fetchone()
    
    if existing_review:
        flash('You have already reviewed this product', 'error')
        conn.close()
        return redirect(url_for('my_reviews'))
    
    if request.method == 'POST':
        # Read rating and review text
        rating = request.form.get('rating')
        content = request.form.get('content', '').strip()
        
        # Rating must be an integer between 1 and 5
        if not rating or not rating.isdigit() or int(rating) < 1 or int(rating) > 5:
            flash('Please select a rating between 1 and 5 stars', 'error')
            return render_template('add_review.html', product=product, rating=rating, content=content)
        
        rating = int(rating)
        
        # Review content must not be empty
        if not content:
            flash('Please write your review', 'error')
            return render_template('add_review.html', product=product, rating=rating, content=content)
        
        # Limit review length to avoid abuse
        if len(content) > 1000:
            flash('Review must be less than 1000 characters', 'error')
            return render_template('add_review.html', product=product, rating=rating, content=content)
        
        image_path = None
        # Optional review image upload
        if 'image' in request.files:
            file = request.files['image']
            # Check file name and extension
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"review_{timestamp}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                image_path = f"uploads/{filename}"
        
        # Insert new review into database
        conn.execute('''
            INSERT INTO reviews (product_id, user_id, rating, content, image_path, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (product_id, session['user_id'], rating, content, image_path, datetime.now().isoformat()))
        conn.commit()
        
        # Log review submission
        log_activity('added_review', f'Product: {product["title"]} (ID: {product_id}), Rating: {rating}')
        
        flash('Review submitted successfully!', 'success')
        conn.close()
        return redirect(url_for('my_reviews'))
    
    conn.close()
    # GET: show the add review form
    return render_template('add_review.html', product=product)


@app.route('/my_reviews')
@login_required
def my_reviews():
    """
    Display all reviews written by the logged-in user.
    Security:
    - Only the current user's reviews are shown.
    """
    conn = get_db_connection()
    
    reviews = conn.execute('''
        SELECT r.*, p.title as product_title, p.image_path as product_image, p.price
        FROM reviews r
        JOIN products p ON r.product_id = p.id
        WHERE r.user_id = ?
        ORDER BY r.created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    # Log that user viewed their reviews
    log_activity('viewed_my_reviews', f'Total reviews: {len(reviews)}')
    
    conn.close()
    return render_template('my_reviews.html', reviews=reviews)


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """
    Allow users to edit their own profile:
    - Update name and email.
    - Optionally change password if current password is correct.
    Security:
    - User can only edit their own profile (based on session user_id).
    - Checks for unique email.
    - Verifies current password before changing to a new one.
    """
    conn = get_db_connection()
    
    if request.method == 'POST':
        # Read form values
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Get old values for logging what changed
        old_user = conn.execute('SELECT name, email FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        
        # Name must not be empty
        if not name:
            flash('Name is required', 'error')
            user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            conn.close()
            return render_template('edit_profile.html', user=user)
        
        # Very simple email validation (must contain @)
        if not email or '@' not in email:
            flash('Valid email is required', 'error')
            user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            conn.close()
            return render_template('edit_profile.html', user=user)
        
        # Check if the email is already used by someone else
        existing_user = conn.execute('SELECT id FROM users WHERE email = ? AND id != ?', 
                                     (email, session['user_id'])).fetchone()
        if existing_user:
            flash('Email is already in use by another account', 'error')
            user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            conn.close()
            return render_template('edit_profile.html', user=user)
        
        # Update name and email first
        conn.execute('UPDATE users SET name = ?, email = ? WHERE id = ?',
                    (name, email, session['user_id']))
        
        # Flag to track if password was changed
        if current_password or new_password or confirm_password:
            # If any password field is filled, require current password and all checks
            user_data = conn.execute('SELECT password_hash FROM users WHERE id = ?', 
                               (session['user_id'],)).fetchone()
            
            # Must provide current password
            if not current_password:
                flash('Current password is required to change password', 'error')
                user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
                conn.close()
                return render_template('edit_profile.html', user=user)
            
            # Check current password matches stored hash
            if not check_password_hash(user_data['password_hash'], current_password):
                flash('Current password is incorrect', 'error')
                user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
                conn.close()
                return render_template('edit_profile.html', user=user)
            
            # New password and confirm must match
            if new_password != confirm_password:
                flash('New passwords do not match', 'error')
                user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
                conn.close()
                return render_template('edit_profile.html', user=user)
            
            # Check new password strength
            is_strong, message = is_password_strong(new_password)
            if not is_strong:
                flash(message, 'error')
                user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
                conn.close()
                return render_template('edit_profile.html', user=user)
            
            # Hash and update new password
            hashed_password = generate_password_hash(new_password)
            conn.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                        (hashed_password, session['user_id']))
            password_changed = True
        else:
            # No password change requested
            password_changed = False
        
        conn.commit()
        
        # Update session username so the change shows immediately in UI
        session['user_name'] = name
        
        # Work out what fields actually changed
        changes = []
        if password_changed:
            changes.append('password')
        if old_user['name'] != name:
            changes.append('name')
        if old_user['email'] != email:
            changes.append('email')
        
        if changes:
            # Build a simple text like "name, email, password"
            change_list = ', '.join(changes)
            flash(f'Your {change_list} has been updated successfully!', 'success')
            # Log what was updated (no sensitive values, only field names)
            log_activity('updated_profile', f'Updated: {change_list}')
            user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            conn.close()
            return render_template('edit_profile.html', user=user)
        else:
            # No actual change detected
            flash('No changes were made to your profile.', 'success')
            log_activity('updated_profile', 'Profile viewed, no changes')
        
        conn.close()
        return redirect(url_for('dashboard'))
    
    # GET: load current profile information
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    # Log that user opened edit profile page
    log_activity('viewed_edit_profile', 'Accessed profile edit page')
    
    conn.close()
    return render_template('edit_profile.html', user=user)


if __name__ == '__main__':
    
    app.run()
