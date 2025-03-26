import os
import logging
import base64
import io
import uuid
import qrcode
import json
import hashlib
import csv
import re
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.security import generate_password_hash, check_password_hash
from face_utils import compare_faces, face_encodings_from_image
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
# create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev_secret_key")

# Use SQLite with absolute path
import pathlib
base_dir = pathlib.Path(__file__).resolve().parent
instance_path = base_dir / "instance"
instance_path.mkdir(exist_ok=True)
db_path = instance_path / "voters.db"
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Get security settings from environment
# Face recognition settings - Higher values are more lenient (0.7-0.8 is a good balance)
FACE_SIMILARITY_THRESHOLD = float(os.environ.get("FACE_SIMILARITY_THRESHOLD", 0.7))

# Rate limiting settings
RATE_LIMIT_VERIFICATION = int(os.environ.get("RATE_LIMIT_VERIFICATION", 10))
RATE_LIMIT_REGISTRATION = int(os.environ.get("RATE_LIMIT_REGISTRATION", 5))
RATE_LIMIT_LOGIN = int(os.environ.get("RATE_LIMIT_LOGIN", 10))

# QR Code settings
QR_CODE_EXPIRY_HOURS = int(os.environ.get("QR_CODE_EXPIRY_HOURS", 24))

# Set session lifetime from environment or default to 30 days
app.permanent_session_lifetime = timedelta(seconds=int(os.environ.get("SESSION_LIFETIME", 2592000)))

# Set logging level
log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
app.logger.setLevel(getattr(logging, log_level))

# Set secure cookie flags
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# initialize the app with the extension
db.init_app(app)

# Define models here to avoid circular imports
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<Admin {self.username}>'

class VerificationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.String(64), db.ForeignKey('voter.voter_id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 can be up to 45 chars
    user_agent = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<VerificationLog {self.voter_id} {self.timestamp}>'

class Voter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False, index=True)
    email = db.Column(db.String(120), nullable=False, index=True)
    dob = db.Column(db.Date, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    face_encoding = db.Column(db.Text, nullable=False)  # JSON string of face encoding
    registration_date = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_verified = db.Column(db.DateTime, nullable=True, index=True)
    verification_count = db.Column(db.Integer, default=0)
    verification_logs = db.relationship('VerificationLog', backref='voter', lazy='dynamic',
                                      primaryjoin="Voter.voter_id == foreign(VerificationLog.voter_id)")
    
    def __repr__(self):
        return f'<Voter {self.name}>'
        
# Rate limiting decorator to prevent brute force attacks
def rate_limit(max_requests=5, per_seconds=60):
    def decorator(f):
        requests = {}
        
        @wraps(f)
        def wrapped(*args, **kwargs):
            now = datetime.now()
            ip = request.remote_addr
            
            # Clean up old requests
            for req_ip in list(requests.keys()):
                for timestamp in list(requests[req_ip]):
                    if (now - timestamp).total_seconds() > per_seconds:
                        requests[req_ip].remove(timestamp)
                if not requests[req_ip]:
                    del requests[req_ip]
            
            # Check if IP has made too many requests
            if ip in requests and len(requests[ip]) >= max_requests:
                abort(429)  # Too Many Requests
            
            # Add this request
            if ip not in requests:
                requests[ip] = []
            requests[ip].append(now)
            
            return f(*args, **kwargs)
        return wrapped
    return decorator

with app.app_context():
    db.create_all()
    
    # Create default admin if none exists
    if not Admin.query.filter_by(username='admin').first():
        admin = Admin(username='admin', email='admin@example.com')
        admin.set_password('Admin@123')  # Should be changed after first login
        db.session.add(admin)
        db.session.commit()
        app.logger.info('Created default admin account')

# Admin login required decorator
def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('admin_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Input validation functions
def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    # At least 8 chars, at least one uppercase, one lowercase, one digit
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    return True

def sanitize_input(text):
    """Basic input sanitization"""
    if text is None:
        return None
    # Remove potentially dangerous patterns
    sanitized = re.sub(r'<[^>]*>', '', text)
    return sanitized

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@rate_limit(max_requests=RATE_LIMIT_REGISTRATION, per_seconds=60)  # Rate limit registration attempts
def register():
    if request.method == 'POST':
        # Sanitize inputs
        voter_id = sanitize_input(request.form.get('voter_id'))
        name = sanitize_input(request.form.get('name'))
        email = sanitize_input(request.form.get('email'))
        dob = sanitize_input(request.form.get('dob'))
        phone = sanitize_input(request.form.get('phone'))
        face_data = request.form.get('face_data')
        
        # Validate the inputs
        if not all([voter_id, name, email, dob, phone, face_data]):
            flash('All fields are required', 'danger')
            return render_template('register.html')
        
        # Validate email format
        if not validate_email(email):
            flash('Please enter a valid email address', 'danger')
            return render_template('register.html')
            
        # Validate date of birth
        try:
            dob_date = datetime.strptime(dob, '%Y-%m-%d')
            # Check if date is in the past
            if dob_date >= datetime.now():
                flash('Date of birth must be in the past', 'danger')
                return render_template('register.html')
                
            # Check if voter is at least 18 years old
            age = (datetime.now() - dob_date).days // 365
            if age < 18:
                flash('You must be at least 18 years old to register', 'danger')
                return render_template('register.html')
                
        except ValueError:
            flash('Invalid date format', 'danger')
            return render_template('register.html')
            
        # Validate phone number (basic check)
        if not re.match(r'^\+?[0-9() -]{8,20}$', phone):
            flash('Please enter a valid phone number', 'danger')
            return render_template('register.html')
        
        # Check if voter ID already exists
        existing_voter = Voter.query.filter_by(voter_id=voter_id).first()
        if existing_voter:
            flash('Voter ID already registered', 'danger')
            return render_template('register.html')
            
        # Check if email already registered
        existing_email = Voter.query.filter_by(email=email).first()
        if existing_email:
            flash('Email address already registered', 'danger')
            return render_template('register.html')
        
        try:
            # Process the base64 encoded image
            face_data = face_data.split(',')[1]
            face_image = base64.b64decode(face_data)
            
            # Get face encodings
            face_encoding = face_encodings_from_image(face_image)
            
            if not face_encoding:
                flash('No face detected in the photo. Please try again.', 'danger')
                return render_template('register.html')
            
            # Create a new voter
            new_voter = Voter(
                voter_id=voter_id,
                name=name,
                email=email,
                dob=dob_date,
                phone=phone,
                face_encoding=face_encoding  # Already a JSON string from face_utils
            )
            
            # Create verification log for registration
            log = VerificationLog(
                voter_id=voter_id,
                success=True,
                details="New voter registration",
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            
            db.session.add(new_voter)
            db.session.add(log)
            db.session.commit()
            
            app.logger.info(f"New voter registered: {voter_id}, {name}")
            flash('Registration successful! You can now verify your identity.', 'success')
            return redirect(url_for('verify'))
            
        except Exception as e:
            app.logger.error(f"Registration error: {str(e)}")
            flash('An error occurred during registration. Please try again.', 'danger')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/verify', methods=['GET', 'POST'])
@rate_limit(max_requests=RATE_LIMIT_VERIFICATION, per_seconds=60)  # Rate limit verification attempts
def verify():
    if request.method == 'POST':
        # Sanitize inputs
        voter_id = sanitize_input(request.form.get('voter_id'))
        face_data = request.form.get('face_data')
        
        if not all([voter_id, face_data]):
            flash('Both voter ID and face photo are required', 'danger')
            return render_template('verify.html')
        
        # Initialize verification log
        verification_log = None
        success = False
        details = "Verification attempt initiated"
        
        try:
            voter = Voter.query.filter_by(voter_id=voter_id).first()
            
            if not voter:
                details = "Voter ID not found"
                flash('Voter ID not found', 'danger')
                app.logger.warning(f"Verification attempt with invalid voter ID: {voter_id}")
                
                # Log failed attempt
                verification_log = VerificationLog(
                    voter_id=voter_id,
                    success=False,
                    details=details,
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string
                )
                db.session.add(verification_log)
                db.session.commit()
                
                return render_template('verify.html')
            
            # Process the base64 encoded image
            face_data = face_data.split(',')[1]
            face_image = base64.b64decode(face_data)
            
            # Get face encodings from the uploaded image
            captured_face_encoding = face_encodings_from_image(face_image)
            
            if not captured_face_encoding:
                details = "No face detected in the photo"
                flash('No face detected in the photo. Please try again.', 'danger')
                
                # Log failed attempt
                verification_log = VerificationLog(
                    voter_id=voter.voter_id,
                    success=False,
                    details=details,
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string
                )
                db.session.add(verification_log)
                db.session.commit()
                
                return render_template('verify.html')
            
            # Compare with stored face encoding
            stored_face_encoding = json.loads(voter.face_encoding)
            match = compare_faces(stored_face_encoding, captured_face_encoding, FACE_SIMILARITY_THRESHOLD)
            
            if match:
                # Generate QR code with voter metadata and secure expiration
                expiration_time = (datetime.now() + timedelta(hours=QR_CODE_EXPIRY_HOURS)).strftime('%Y-%m-%d %H:%M:%S')
                
                # Create a secure hash to validate the QR code later
                data_to_hash = f"{voter.voter_id}:{expiration_time}:{app.secret_key}"
                secure_hash = hashlib.sha256(data_to_hash.encode()).hexdigest()
                
                voter_data = {
                    "voter_id": voter.voter_id,
                    "name": voter.name,
                    "email": voter.email,
                    "dob": voter.dob.strftime('%Y-%m-%d'),
                    "phone": voter.phone,
                    "verification_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "expires_at": expiration_time,
                    "verification_hash": secure_hash
                }
                
                # Create QR code with higher error correction
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_M,  # Medium error correction
                    box_size=10,
                    border=4,
                )
                qr.add_data(json.dumps(voter_data))
                qr.make(fit=True)
                
                # Convert QR code to in-memory bytes
                img = qr.make_image(fill_color="black", back_color="white")
                img_byte_arr = io.BytesIO()
                img.save(img_byte_arr, format='PNG')
                img_byte_arr = img_byte_arr.getvalue()
                
                # Convert bytes to base64 for embedding in HTML
                qr_code_b64 = base64.b64encode(img_byte_arr).decode('utf-8')
                
                # Update verification count and last verified time
                voter.verification_count += 1
                voter.last_verified = datetime.now()
                
                # Log successful verification
                details = "Face verification successful"
                success = True
                verification_log = VerificationLog(
                    voter_id=voter.voter_id,
                    success=True,
                    details=details,
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string
                )
                
                db.session.add(verification_log)
                db.session.commit()
                
                app.logger.info(f"Successful verification for voter {voter.voter_id}")
                return render_template('success.html', voter=voter, qr_code=qr_code_b64)
            else:
                details = "Face verification failed - faces did not match"
                flash('Face verification failed. Please ensure you have good lighting, face the camera directly, and try again.', 'danger')
                app.logger.warning(f"Face verification failed for voter {voter.voter_id}")
                
                # Log failed verification
                verification_log = VerificationLog(
                    voter_id=voter.voter_id,
                    success=False,
                    details=details,
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string
                )
                db.session.add(verification_log)
                db.session.commit()
                
                return render_template('verify.html')
                
        except Exception as e:
            details = f"Verification error: {str(e)}"
            app.logger.error(details)
            flash('An error occurred during verification. Please try again.', 'danger')
            
            # Log error
            if voter_id:
                verification_log = VerificationLog(
                    voter_id=voter_id,
                    success=False,
                    details=details,
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string
                )
                db.session.add(verification_log)
                db.session.commit()
            
            return render_template('verify.html')
    
    return render_template('verify.html')

@app.route('/admin/login', methods=['GET', 'POST'])
@rate_limit(max_requests=RATE_LIMIT_LOGIN, per_seconds=60)  # Rate limit login attempts
def admin_login():
    if 'admin_id' in session:
        return redirect(url_for('admin_dashboard'))
        
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        next_url = request.form.get('next', url_for('admin_dashboard'))
        
        if not all([username, password]):
            flash('Please provide both username and password', 'danger')
            return render_template('admin_login.html')
            
        admin = Admin.query.filter_by(username=username, is_active=True).first()
        
        if admin and admin.check_password(password):
            # Set session variables
            session['admin_id'] = admin.id
            session['admin_username'] = admin.username
            
            if remember:
                # If remember me is checked, set session to last longer
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=30)
            
            # Update last login time
            admin.last_login = datetime.utcnow()
            db.session.commit()
            
            app.logger.info(f"Admin login: {admin.username}")
            flash(f'Welcome, {admin.username}!', 'success')
            return redirect(next_url)
        else:
            app.logger.warning(f"Failed admin login attempt for username: {username}")
            flash('Invalid username or password', 'danger')
            
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    # Clear admin session data
    session.pop('admin_id', None)
    session.pop('admin_username', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('admin_login'))

@app.route('/admin/change-password', methods=['GET', 'POST'])
@admin_login_required
def admin_change_password():
    admin_id = session.get('admin_id')
    admin = Admin.query.get_or_404(admin_id)
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([current_password, new_password, confirm_password]):
            flash('All fields are required', 'danger')
            return render_template('admin_change_password.html')
            
        if not admin.check_password(current_password):
            flash('Current password is incorrect', 'danger')
            return render_template('admin_change_password.html')
            
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return render_template('admin_change_password.html')
            
        if not validate_password(new_password):
            flash('Password must be at least 8 characters and include uppercase, lowercase, and a number', 'danger')
            return render_template('admin_change_password.html')
            
        # Update password
        admin.set_password(new_password)
        db.session.commit()
        
        flash('Password updated successfully', 'success')
        return redirect(url_for('admin_dashboard'))
        
    return render_template('admin_change_password.html')

@app.route('/admin/dashboard')
@admin_login_required
def admin_dashboard():
    # Get query parameters
    search_term = request.args.get('search', '')
    filter_type = request.args.get('filter', '')
    
    # Base query
    query = Voter.query
    
    # Apply search if provided
    if search_term:
        query = query.filter(
            (Voter.voter_id.contains(search_term)) |
            (Voter.name.contains(search_term)) |
            (Voter.email.contains(search_term))
        )
    
    # Apply filters if provided
    if filter_type == 'verified_today':
        today = datetime.today().date()
        query = query.filter(db.func.date(Voter.last_verified) == today)
    elif filter_type == 'never_verified':
        query = query.filter(Voter.last_verified == None)
    
    # Execute query and get voters
    voters = query.order_by(Voter.registration_date.desc()).all()
    
    # Get statistics
    stats = {
        'total_voters': Voter.query.count(),
        'today_verifications': Voter.query.filter(
            db.func.date(Voter.last_verified) == datetime.today().date()
        ).count(),
        'total_verifications': db.session.query(db.func.sum(Voter.verification_count)).scalar() or 0
    }
    
    return render_template('admin.html', 
                          voters=voters, 
                          stats=stats, 
                          request=request, 
                          admin_username=session.get('admin_username'))

# For backward compatibility, redirect old admin URL to new dashboard
@app.route('/admin')
def admin():
    return redirect(url_for('admin_login'))

@app.route('/admin/voter/<voter_id>')
@admin_login_required
def voter_details(voter_id):
    voter = Voter.query.filter_by(voter_id=voter_id).first_or_404()
    now = datetime.now()
    
    # Get verification logs for this voter
    verification_logs = VerificationLog.query.filter_by(voter_id=voter_id)\
                                          .order_by(VerificationLog.timestamp.desc())\
                                          .limit(20).all()
    
    return render_template('voter_details.html', 
                          voter=voter, 
                          now=now, 
                          verification_logs=verification_logs,
                          admin_username=session.get('admin_username'))

@app.route('/admin/reset_verification/<voter_id>', methods=['POST'])
@admin_login_required
def reset_verification(voter_id):
    voter = Voter.query.filter_by(voter_id=voter_id).first_or_404()
    
    # Log this action
    log = VerificationLog(
        voter_id=voter.voter_id,
        success=True,
        details=f"Verification reset by admin: {session.get('admin_username')}",
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    
    voter.verification_count = 0
    voter.last_verified = None
    db.session.add(log)
    db.session.commit()
    
    flash(f'Verification status for {voter.name} has been reset', 'success')
    return redirect(url_for('voter_details', voter_id=voter.voter_id))

@app.route('/admin/generate_qr/<voter_id>')
@admin_login_required
def generate_qr(voter_id):
    try:
        voter = Voter.query.filter_by(voter_id=voter_id).first()
        
        if not voter:
            return jsonify({'success': False, 'message': 'Voter not found'})
        
        # Generate QR code with voter metadata including expiration
        expiration_time = (datetime.now() + timedelta(hours=QR_CODE_EXPIRY_HOURS)).strftime('%Y-%m-%d %H:%M:%S')
        
        # Create a secure hash to validate the QR code later
        data_to_hash = f"{voter.voter_id}:{expiration_time}:{app.secret_key}"
        secure_hash = hashlib.sha256(data_to_hash.encode()).hexdigest()
        
        voter_data = {
            "voter_id": voter.voter_id,
            "name": voter.name,
            "email": voter.email,
            "dob": voter.dob.strftime('%Y-%m-%d'),
            "phone": voter.phone,
            "generated_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "expires_at": expiration_time,
            "verification_hash": secure_hash
        }
        
        # Create QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,  # Medium error correction
            box_size=10,
            border=4,
        )
        qr.add_data(json.dumps(voter_data))
        qr.make(fit=True)
        
        # Convert QR code to in-memory bytes
        img = qr.make_image(fill_color="black", back_color="white")
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='PNG')
        img_byte_arr = img_byte_arr.getvalue()
        
        # Convert bytes to base64 for embedding in HTML
        qr_code_b64 = base64.b64encode(img_byte_arr).decode('utf-8')
        
        return jsonify({
            'success': True, 
            'qr_code': qr_code_b64,
            'voter_id': voter.voter_id,
            'voter_name': voter.name
        })
        
    except Exception as e:
        app.logger.error(f"QR generation error: {str(e)}")
        return jsonify({'success': False, 'message': f'Error generating QR code: {str(e)}'})

@app.route('/admin/export_csv')
@admin_login_required
def export_csv():
    try:
        # Create a string buffer to write CSV data
        si = io.StringIO()
        csv_writer = csv.writer(si)
        
        # Add timestamp to filename for security
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"voters_export_{timestamp}.csv"
        
        # Write header
        csv_writer.writerow(['Voter ID', 'Name', 'Email', 'Phone', 'DOB', 'Registration Date', 
                            'Last Verified', 'Verification Count'])
        
        # Write voter data
        for voter in Voter.query.all():
            csv_writer.writerow([
                voter.voter_id,
                voter.name,
                voter.email,
                voter.phone,
                voter.dob.strftime('%Y-%m-%d'),
                voter.registration_date.strftime('%Y-%m-%d %H:%M'),
                voter.last_verified.strftime('%Y-%m-%d %H:%M') if voter.last_verified else 'Never',
                voter.verification_count
            ])
        
        # Log this action
        app.logger.info(f"Admin {session.get('admin_username')} exported voter data")
        
        # Create response
        output = si.getvalue()
        response = Response(output, mimetype='text/csv')
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
        
    except Exception as e:
        app.logger.error(f"CSV export error: {str(e)}")
        flash('Error exporting data', 'danger')
        return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
