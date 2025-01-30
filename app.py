import os
from datetime import datetime, timedelta
from urllib.parse import quote
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.text import MIMEText
import logging

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)

# Email configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Add current_user to template context
@app.context_processor
def inject_context():
    return dict(
        current_user=current_user,
        project_name="Sea Horse"
    )

# Configure logging to both console and file
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Create file handler which logs even debug messages
fh = logging.FileHandler('app.log')
fh.setLevel(logging.DEBUG)

# Create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# Create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(ch)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///material_inspections.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}
db = SQLAlchemy(app)

class FailedLoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    first_login = db.Column(db.Boolean, default=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    last_login = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(45))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class MaterialInspection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_number = db.Column(db.String(50), nullable=False, index=True)
    material_type = db.Column(db.String(100), nullable=False)
    material_grade = db.Column(db.String(50), nullable=False)
    thickness = db.Column(db.Float, nullable=False)
    size = db.Column(db.String(50), nullable=False)
    inspection_date = db.Column(db.Date, nullable=False, index=True)
    inspection_status = db.Column(db.String(20), nullable=False)
    heat_number = db.Column(db.String(50), nullable=False)
    material_count = db.Column(db.Integer, nullable=False)
    mill_cert_attachment = db.Column(db.String(200))

    __table_args__ = (
        db.Index('idx_material_type_grade', 'material_type', 'material_grade'),
    )

class FitUpUpdate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    joint_number = db.Column(db.String(50), nullable=False)
    drawing_no = db.Column(db.String(50), nullable=False)
    part1_material = db.Column(db.String(50), nullable=False)
    part1_grade = db.Column(db.String(50), nullable=False)
    part1_thickness = db.Column(db.Float, nullable=False)
    part2_material = db.Column(db.String(50), nullable=False)
    part2_grade = db.Column(db.String(50), nullable=False)
    part2_thickness = db.Column(db.Float, nullable=False)
    fit_up_date = db.Column(db.Date, nullable=False)
    fit_up_status = db.Column(db.String(20), nullable=False)
    fit_up_type = db.Column(db.String(20), nullable=False)
    remarks = db.Column(db.Text)
    photos = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            ip = request.remote_addr
            user_agent = request.headers.get('User-Agent', '')
        except Exception as e:
            logger.error(f"Error getting request details: {str(e)}")
            return jsonify({
                'error': 'Login error',
                'message': 'An error occurred while processing your request',
                'details': str(e),
                'ip': 'unknown',
                'timestamp': datetime.now().isoformat()
            }), 500
            
        try:
            ip = request.remote_addr
            user_agent = request.headers.get('User-Agent', '')
        except Exception as e:
            logger.error(f"Error getting request details: {str(e)}")
            return jsonify({
                'error': 'Login error',
                'message': 'An error occurred while processing your request',
                'details': str(e),
                'ip': 'unknown',
                'timestamp': datetime.now().isoformat()
            }), 500
            
        try:
            ip = request.remote_addr
            user_agent = request.headers.get('User-Agent', '')
        except Exception as e:
            logger.error(f"Error getting request details: {str(e)}")
            return jsonify({
                'error': 'Login error',
                'message': 'An error occurred while processing your request',
                'details': str(e),
                'ip': 'unknown',
                'timestamp': datetime.now().isoformat()
            }), 500
            
        try:
            ip = request.remote_addr
            user_agent = request.headers.get('User-Agent', '')
        except Exception as e:
            logger.error(f"Error getting request details: {str(e)}")
            return jsonify({
                'error': 'Login error',
                'message': 'An error occurred while processing your request',
                'details': str(e),
                'ip': 'unknown',
                'timestamp': datetime.now().isoformat()
            }), 500
            
        try:
            ip = request.remote_addr
            user_agent = request.headers.get('User-Agent', '')
        except Exception as e:
            logger.error(f"Error getting request details: {str(e)}")
            return jsonify({
                'error': 'Login error',
                'message': 'An error occurred while processing your request',
                'details': str(e),
                'ip': 'unknown',
                'timestamp': datetime.now().isoformat()
            }), 500
            
        try:
            ip = request.remote_addr
            user_agent = request.headers.get('User-Agent', '')
        except Exception as e:
            logger.error(f"Error getting request details: {str(e)}")
            return jsonify({
                'error': 'Login error',
                'message': 'An error occurred while processing your request',
                'details': str(e),
                'ip': 'unknown',
                'timestamp': datetime.now().isoformat()
            }), 500
            
        try:
            ip = request.remote_addr
            user_agent = request.headers.get('User-Agent', '')
        except Exception as e:
            logger.error(f"Error getting request details: {str(e)}")
            return jsonify({
                'error': 'Login error',
                'message': 'An error occurred while processing your request',
                'details': str(e),
                'ip': 'unknown',
                'timestamp': datetime.now().isoformat()
            }), 500
            
        try:
            ip = request.remote_addr
            user_agent = request.headers.get('User-Agent', '')
        except Exception as e:
            logger.error(f"Error getting request details: {str(e)}")
            return jsonify({
                'error': 'Login error',
                'message': 'An error occurred while processing your request',
                'details': str(e),
                'ip': 'unknown',
                'timestamp': datetime.now().isoformat()
            }), 500
            
        try:
            ip = request.remote_addr
            user_agent = request.headers.get('User-Agent', '')
            
            if not request.form.get('username') or not request.form.get('password'):
                flash('Username and password are required', 'error')
                logger.warning(f'Login attempt with missing credentials from IP: {ip}')
                return jsonify({
                    'error': 'Missing credentials',
                    'message': 'Username and password are required',
                    'ip': ip,
                    'timestamp': datetime.now().isoformat()
                }), 400
            
            if not user_agent or len(user_agent) > 512:
                logger.warning(f'Suspicious user agent from IP: {ip}')
                return jsonify({
                    'error': 'Invalid request',
                    'message': 'Suspicious user agent detected',
                    'ip': ip,
                    'timestamp': datetime.now().isoformat()
                }), 400
            
            username = request.form['username'].strip()
            password = request.form['password']
            
            if len(username) > 50 or len(password) > 128:
                logger.warning(f'Invalid input length from IP: {ip}')
                return jsonify({
                    'error': 'Invalid input',
                    'message': 'Username or password exceeds maximum length',
                    'ip': ip,
                    'timestamp': datetime.now().isoformat()
                }), 400
                
            if not username or not password:
                logger.warning(f'Empty credentials from IP: {ip}')
                return jsonify({
                    'error': 'Invalid input',
                    'message': 'Username and password cannot be empty',
                    'ip': ip,
                    'timestamp': datetime.now().isoformat()
                }), 400
            
            if any(char in username for char in [';', '--', '/*', '*/', "'", '"']):
                logger.warning(f'Potential SQL injection attempt from {ip}')
                return jsonify({
                    'error': 'Invalid input',
                    'message': 'Username contains invalid characters',
                    'ip': ip,
                    'timestamp': datetime.now().isoformat()
                }), 400
            
            failed_attempts = FailedLoginAttempt.query.filter_by(
                username=username,
                timestamp__gte=datetime.now() - timedelta(minutes=5)
            ).count()
            
            if failed_attempts >= 5:
                wait_time = min(2 ** (failed_attempts - 5), 300)
                logger.warning(f'Rate limit exceeded for username: {username} from IP: {ip}')
                return jsonify({
                    'error': 'Too many attempts',
                    'message': f'Please wait {wait_time} seconds before trying again',
                    'retry_after': wait_time,
                    'ip': ip,
                    'timestamp': datetime.now().isoformat()
                }), 429
            
            user = User.query.filter_by(username=username).first()
            
            if user and user.check_password(password):
                FailedLoginAttempt.query.filter_by(username=username).delete()
                user.last_login = datetime.now()
                user.last_login_ip = ip
                db.session.commit()
                
                session_token = generate_session_token(user.id)
                
                logger.info(f"Login successful for user: {user.username} from IP: {ip}")
                login_user(user)
                
                try:
                    with open('audit.log', 'a') as audit_log:
                        audit_log.write(f"{datetime.now().isoformat()} - LOGIN - {user.username} from {ip}\n")
                except Exception as e:
                    logger.error(f"Error writing to audit log: {str(e)}")
                
                if user.is_admin:
                    logger.info(f"Admin user {user.username} logged in")
                    return jsonify({
                        'message': 'Login successful',
                        'user': user.username,
                        'role': 'admin',
                        'session_token': session_token,
                        'redirect': url_for('admin_dashboard')
                    }), 200
                
                if user.first_login:
                    user.first_login = False
                    db.session.commit()
                    logger.info(f"First login for user: {user.username}")
                    return jsonify({
                        'message': 'First login detected',
                        'user': user.username,
                        'role': 'user',
                        'session_token': session_token,
                        'redirect': url_for('change_password')
                    }), 200
                
                logger.info(f"Regular user {user.username} logged in")
                return jsonify({
                    'message': 'Login successful',
                    'user': user.username,
                    'role': 'user',
                    'session_token': session_token,
                    'redirect': url_for('dashboard')
                }), 200
            
            logger.warning(f"Failed login attempt for username: {username} from IP: {ip}")
            failed_attempt = FailedLoginAttempt(
                username=username,
                timestamp=datetime.now(),
                ip_address=ip
            )
            db.session.add(failed_attempt)
            db.session.commit()
            
            return jsonify({
                'error': 'Invalid credentials',
                'message': 'Invalid username or password',
                'ip': ip,
                'timestamp': datetime.now().isoformat()
            }), 401
            
        except Exception as e:
            logger.error(f"Login error: {str(e)} from IP: {ip}")
            return jsonify({
                'error': 'Login error',
                'message': 'An error occurred during login',
                'details': str(e),
                'ip': ip,
                'timestamp': datetime.now().isoformat()
            }), 500
            
    return render_template('login.html')

def generate_session_token(user_id):
    try:
        token = os.urandom(32).hex()
        session_token = SessionToken(
            user_id=user_id,
            token=token,
            expires_at=datetime.now() + timedelta(hours=1)
        )
        db.session.add(session_token)
        db.session.commit()
        return token
    except Exception as e:
        logger.error(f"Error generating session token: {str(e)}")
        raise

class SessionToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
@login_required
def dashboard():
    try:
        logger.debug("Attempting to render dashboard")
        return render_template('dashboard.html', current_user=current_user)
    except Exception as e:
        logger.error(f"Error serving dashboard page: {str(e)}")
        flash('Error loading dashboard')
        return redirect(url_for('login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Unauthorized access')
        return redirect(url_for('dashboard'))
        
    try:
        total_users = User.query.count()
        total_inspections = MaterialInspection.query.count()
        total_fitups = FitUpUpdate.query.count()
        
        recent_inspections = MaterialInspection.query.order_by(
            MaterialInspection.inspection_date.desc()
        ).limit(5).all()
        
        recent_fitups = FitUpUpdate.query.order_by(
            FitUpUpdate.fit_up_date.desc()
        ).limit(5).all()
        
        recent_logins = User.query.filter(
            User.last_login.isnot(None)
        ).order_by(
            User.last_login.desc()
        ).limit(5).all()
        
        recent_failed_attempts = FailedLoginAttempt.query.order_by(
            FailedLoginAttempt.timestamp.desc()
        ).limit(5).all()
        
        return render_template('admin_dashboard.html',
                            total_users=total_users,
                            total_inspections=total_inspections,
                            total_fitups=total_fitups,
                            recent_inspections=recent_inspections,
                            recent_fitups=recent_fitups,
                            recent_logins=recent_logins,
                            recent_failed_attempts=recent_failed_attempts,
                            current_user=current_user)
    except Exception as e:
        logger.error(f"Error loading admin dashboard: {str(e)}")
        flash('Error loading admin dashboard')
        return redirect(url_for('dashboard'))

@app.route('/material-inspection')
@app.route('/material_inspection')
@login_required
def material_inspection():
    try:
        return render_template('material_inspection.html', current_user=current_user)
    except Exception as e:
        logger.error(f"Error loading material inspection: {str(e)}")
        flash('Error loading material inspection')
        return redirect(url_for('dashboard'))

@app.route('/fit-up-update')
@login_required
def fit_up_update():
    try:
        return render_template('fit_up_update.html', current_user=current_user)
    except Exception as e:
        logger.error(f"Error loading fit up update: {str(e)}")
        flash('Error loading fit up update')
        return redirect(url_for('dashboard'))

@app.route('/fit-up-update/submit', methods=['POST'])
@login_required
def submit_fit_up_update():
    try:
        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        if not user_agent or len(user_agent) > 512:
            logger.warning(f'Suspicious user agent from IP: {ip}')
            return jsonify({
                'error': 'Invalid request',
                'message': 'Suspicious user agent detected',
                'ip': ip,
                'timestamp': datetime.now().isoformat()
            }), 400

        required_fields = [
            'jointNumber', 'drawingNo', 'part1Material', 'part1Grade',
            'part1Thickness', 'part2Material', 'part2Grade', 'part2Thickness',
            'fitUpDate', 'fitUpStatus', 'fitUpType'
        ]
        
        missing_fields = []
        for field in required_fields:
            if field not in request.form or not request.form[field].strip():
                missing_fields.append(field)
        
        if missing_fields:
            logger.warning(f"Missing required fields: {missing_fields} from IP: {ip}")
            return jsonify({
                'error': 'Missing fields',
                'message': 'All required fields must be provided',
                'missing_fields': missing_fields,
                'ip': ip,
                'timestamp': datetime.now().isoformat()
            }), 400

        joint_number = request.form['jointNumber'].strip()
        if len(joint_number) > 50 or not joint_number:
            logger.warning(f"Invalid joint number format: {joint_number} from IP: {ip}")
            return jsonify({
                'error': 'Invalid input',
                'message': 'Joint number must be between 1-50 characters',
                'ip': ip,
                'timestamp': datetime.now().isoformat()
            }), 400

        try:
            part1_thickness = float(request.form['part1Thickness'])
            part2_thickness = float(request.form['part2Thickness'])
            
            if part1_thickness <= 0 or part2_thickness <= 0:
                logger.warning(f"Invalid thickness values from IP: {ip}")
                return jsonify({
                    'error': 'Invalid input',
                    'message': 'Thickness values must be greater than 0',
                    'ip': ip,
                    'timestamp': datetime.now().isoformat()
                }), 400
        except ValueError:
            logger.warning(f"Invalid numeric input from IP: {ip}")
            return jsonify({
                'error': 'Invalid input',
                'message': 'Thickness values must be valid numbers',
                'ip': ip,
                'timestamp': datetime.now().isoformat()
            }), 400
        photo_filenames = []
        if 'fitUpPhotos' in request.files:
            files = request.files.getlist('fitUpPhotos')
            for file in files:
                if file:
                    if file.content_length > app.config['MAX_CONTENT_LENGTH']:
                        logger.warning(f"File size exceeds maximum allowed from IP: {ip}")
                        return jsonify({
                            'error': 'File too large',
                            'message': f'File size exceeds {app.config["MAX_CONTENT_LENGTH"]} bytes',
                            'ip': ip,
                            'timestamp': datetime.now().isoformat()
                        }), 413  # This line was causing the syntax error previously

                    # Add proper file handling here
                    if file and allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        photo_filenames.append(filename)
        # photo_filenames = []
        # if 'fitUpPhotos' in request.files:
        #     files = request.files.getlist('fitUpPhotos')
        #     for file in files:
        #         if file:
        #             if file.content_length > app.config['MAX_CONTENT_LENGTH']:
        #                 logger.warning(f"File size exceeds maximum allowed from IP: {ip}")
        #                 return jsonify({
        #                     'error': 'File too large',
        #                     'message': f'File size exceeds {app.config["MAX_CONTENT_LENGTH"]} bytes',
        #                     'ip': ip,
        #                     'timestamp': datetime.now().isoformat()
        #                 }), 413
    except Exception as e:
        logger.error(f"Error submitting fit-up update: {str(e)}")
        return jsonify({
            'error': 'Processing error',
            'message': 'Failed to process fit-up update',
            'details': str(e)
        }), 500