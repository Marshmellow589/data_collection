import sys
import flask
import sqlalchemy
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import logging
from sqlalchemy.sql import text

app = Flask(__name__)

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

class MaterialInspection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_number = db.Column(db.String(50), nullable=False)
    material_type = db.Column(db.String(100), nullable=False)
    material_grade = db.Column(db.String(50), nullable=False)
    thickness = db.Column(db.Float, nullable=False)
    size = db.Column(db.String(50), nullable=False)
    inspection_date = db.Column(db.Date, nullable=False)
    inspection_status = db.Column(db.String(20), nullable=False)
    heat_number = db.Column(db.String(50), nullable=False)
    material_count = db.Column(db.Integer, nullable=False)
    mill_cert_attachment = db.Column(db.String(200))

@app.route('/')
def index():
    try:
        logger.debug("Attempting to render index.html")
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error serving index page: {str(e)}")
        return f"Error loading page: {str(e)}", 500

@app.route('/records')
def view_records():
    try:
        records = MaterialInspection.query.order_by(MaterialInspection.inspection_date.desc()).all()
        logger.debug(f"Found {len(records)} records")
        return render_template('records.html', records=records)
    except Exception as e:
        logger.error(f"Error loading records: {str(e)}")
        return f"Error loading records: {str(e)}", 500

@app.route('/health')
def health_check():
    logger.info("Health check endpoint accessed")
    return "OK", 200

@app.route('/test')
def test_endpoint():
    logger.info("Test endpoint accessed")
    return "Test endpoint working", 200

from datetime import datetime

from urllib.parse import quote

@app.route('/print/<report_number>')
def print_record(report_number):
    try:
        record = MaterialInspection.query.filter_by(report_number=report_number).first()
        if not record:
            return "Record not found", 404
            
        # Generate QR code data
        qr_data = f"""Material Report
Report No: {record.report_number}
Type: {record.material_type}
Grade: {record.material_grade}
Thickness: {record.thickness}mm
Heat No: {record.heat_number}
Count: {record.material_count}
"""
        
        qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=150x150&data={quote(qr_data)}"
        logger.debug(f"Generated QR URL: {qr_url}")
        
        # Test if QR service is reachable
        try:
            import requests
            test_response = requests.get(qr_url, timeout=5)
            if test_response.status_code != 200:
                logger.error(f"QR service returned status {test_response.status_code}")
                qr_url = None
        except Exception as e:
            logger.error(f"QR service connection failed: {str(e)}")
            qr_url = None
            
        return render_template('print_view.html', 
                             record=record,
                             current_date=datetime.now(),
                             qr_url=qr_url)
    except Exception as e:
        logger.error(f"Error loading print view: {str(e)}")
        return f"Error loading print view: {str(e)}", 500

import os
from werkzeug.utils import secure_filename

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/submit', methods=['POST'])
def submit_inspection():
    try:
        # Create uploads directory if it doesn't exist
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])

        mill_cert_filename = None
        if 'millCert' in request.files:
            file = request.files['millCert']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                try:
                    file.save(file_path)
                    mill_cert_filename = filename
                except Exception as e:
                    logger.error(f"Error saving file: {str(e)}")
                    return f"Error saving file: {str(e)}", 500

        try:
            inspection = MaterialInspection(
                report_number=request.form['reportNumber'],
                material_type=request.form['materialType'],
                material_grade=request.form['materialGrade'],
                thickness=float(request.form['thickness']),
                size=request.form['size'],
                inspection_date=datetime.strptime(request.form['inspectionDate'], '%Y-%m-%d').date(),
                inspection_status=request.form['inspectionStatus'],
                heat_number=request.form['heatNumber'],
                material_count=int(request.form['materialCount']),
                mill_cert_attachment=mill_cert_filename
            )
            
            db.session.add(inspection)
            db.session.commit()
            logger.info(f"Successfully created inspection record: {inspection.report_number}")
            return redirect(url_for('index'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Database error: {str(e)}")
            return f"Database error: {str(e)}", 500
            
    except Exception as e:
        logger.error(f"Submission error: {str(e)}")
        return f"Submission error: {str(e)}", 500

# Initialize database
with app.app_context():
    try:
        # Create database file if it doesn't exist
        db_file = 'material_inspections.db'
        logger.info(f"Checking for database file at: {os.path.abspath(db_file)}")
        
        # Drop all tables if they exist
        if os.path.exists(db_file):
            logger.info("Dropping existing tables")
            db.drop_all()
            
        # Create new database file
        if not os.path.exists(db_file):
            logger.info("Database file not found, creating new one")
            try:
                open(db_file, 'w').close()
                logger.info(f"Successfully created database file: {db_file}")
            except Exception as create_error:
                logger.error(f"Failed to create database file: {str(create_error)}")
                raise
            
        # Create tables with current schema
        logger.info("Initializing database tables with current schema")
        try:
            db.create_all()
            logger.info("Database tables initialized successfully")
        except Exception as table_error:
            logger.error(f"Failed to create tables: {str(table_error)}")
            raise
            
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise

if __name__ == '__main__':
    try:
        logger.info("Starting Flask application on port 5002")
        
        # Windows-specific configuration
        if os.name == 'nt':
            logger.info("Running on Windows system")
            # Increase socket timeout for Windows
            import socket
            socket.setdefaulttimeout(300)
            # Enable Windows-specific debug logging
            app.debug = True
            # Disable reloader to avoid port conflicts
            use_reloader = False
            
            # Add detailed startup logging
            logger.info("Checking system environment...")
            logger.info(f"Python version: {sys.version}")
            logger.info(f"Working directory: {os.getcwd()}")
            logger.info(f"Flask version: {flask.__version__}")
            logger.info(f"SQLAlchemy version: {sqlalchemy.__version__}")
            
        else:
            use_reloader = True

        # Verify database connection
        with app.app_context():
            try:
                db.session.execute(text('SELECT 1'))
                logger.info("Database connection verified")
            except Exception as e:
                logger.error(f"Database connection failed: {str(e)}")
                raise
        
        # Check if port is available
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(('0.0.0.0', 5002))
            sock.close()
        except socket.error as e:
            logger.error(f"Port 5002 is already in use: {str(e)}")
            print("\n===========================================")
            print("ERROR: Port 5002 is already in use")
            print("Please stop any other services using this port")
            print("or change the port number in app.py")
            print("===========================================\n")
            raise
        
        print("\n===========================================")
        print("Flask application running on port 5002")
        print("Access it at: http://localhost:5002")
        print("If you can't access it, try:")
        print("1. Check your firewall settings")
        print("2. Try http://127.0.0.1:5002")
        print("3. Try http://0.0.0.0:5002")
        print("4. Run Command Prompt as Administrator")
        print("5. Check Windows Defender Firewall settings")
        print("===========================================\n")
        
        # Start Flask application with Windows-specific settings
        try:
            app.run(
                host='0.0.0.0',
                port=5002,
                debug=True,
                use_reloader=use_reloader
            )
        except Exception as e:
            logger.error(f"Failed to start Flask server: {str(e)}")
            print("\n===========================================")
            print("ERROR: Failed to start Flask server")
            print("Possible solutions:")
            print("1. Run Command Prompt as Administrator")
            print("2. Check Windows Defender Firewall settings")
            print("3. Try a different port (e.g., 5003)")
            print("4. Run 'netstat -ano | findstr :5002' to check port usage")
            print("5. Run 'netsh advfirewall firewall add rule name='Flask' dir=in action=allow protocol=TCP localport=5002' to allow port")
            print("===========================================\n")
            raise
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
