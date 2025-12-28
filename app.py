from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import db, User, PythonFile
import os
import signal
import subprocess
import json
import time
from datetime import datetime
import psutil

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RUNNING_PROCESSES'] = 'running_processes'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RUNNING_PROCESSES'], exist_ok=True)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Process management functions
def save_process_info(pid, filename, user_id):
    process_info = {
        'pid': pid,
        'filename': filename,
        'user_id': user_id,
        'start_time': datetime.now().isoformat()
    }
    with open(f"{app.config['RUNNING_PROCESSES']}/{pid}.json", 'w') as f:
        json.dump(process_info, f)

def get_process_info(pid):
    try:
        with open(f"{app.config['RUNNING_PROCESSES']}/{pid}.json", 'r') as f:
            return json.load(f)
    except:
        return None

def delete_process_info(pid):
    try:
        os.remove(f"{app.config['RUNNING_PROCESSES']}/{pid}.json")
    except:
        pass

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            flash('Email already registered!', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password, password):
            flash('Invalid email or password!', 'danger')
            return redirect(url_for('login'))
        
        login_user(user, remember=remember)
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_files = PythonFile.query.filter_by(user_id=current_user.id).all()
    
    # Get running processes
    running_processes = []
    for file in os.listdir(app.config['RUNNING_PROCESSES']):
        if file.endswith('.json'):
            with open(os.path.join(app.config['RUNNING_PROCESSES'], file), 'r') as f:
                proc_info = json.load(f)
                if proc_info['user_id'] == current_user.id:
                    try:
                        process = psutil.Process(proc_info['pid'])
                        proc_info['status'] = 'Running' if process.is_running() else 'Stopped'
                    except:
                        proc_info['status'] = 'Stopped'
                    running_processes.append(proc_info)
    
    return render_template('dashboard.html', files=user_files, processes=running_processes)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file selected!', 'danger')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected!', 'danger')
        return redirect(url_for('dashboard'))
    
    if not file.filename.endswith('.py'):
        flash('Only Python files (.py) are allowed!', 'danger')
        return redirect(url_for('dashboard'))
    
    filename = secure_filename(file.filename)
    unique_filename = f"{current_user.id}_{int(time.time())}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(filepath)
    
    new_file = PythonFile(
        filename=filename,
        stored_filename=unique_filename,
        filepath=filepath,
        user_id=current_user.id
    )
    
    db.session.add(new_file)
    db.session.commit()
    
    flash(f'File {filename} uploaded successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/start/<int:file_id>', methods=['POST'])
@login_required
def start_file(file_id):
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id:
        abort(403)
    
    # Check if already running
    for proc_file in os.listdir(app.config['RUNNING_PROCESSES']):
        if proc_file.endswith('.json'):
            with open(os.path.join(app.config['RUNNING_PROCESSES'], proc_file), 'r') as f:
                proc_info = json.load(f)
                if proc_info['filename'] == python_file.filename and proc_info['user_id'] == current_user.id:
                    flash('File is already running!', 'warning')
                    return redirect(url_for('dashboard'))
    
    # Start the Python file
    try:
        process = subprocess.Popen(
            ['python', python_file.filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        save_process_info(process.pid, python_file.filename, current_user.id)
        
        python_file.is_running = True
        db.session.commit()
        
        flash(f'Started {python_file.filename} successfully!', 'success')
    except Exception as e:
        flash(f'Error starting file: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/stop/<int:pid>', methods=['POST'])
@login_required
def stop_file(pid):
    proc_info = get_process_info(pid)
    
    if not proc_info or proc_info['user_id'] != current_user.id:
        flash('Process not found or unauthorized!', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Try graceful termination
        os.kill(pid, signal.SIGTERM)
        time.sleep(1)
        
        # Force kill if still running
        try:
            os.kill(pid, signal.SIGKILL)
        except:
            pass
        
        # Update file status
        python_file = PythonFile.query.filter_by(
            filename=proc_info['filename'],
            user_id=current_user.id
        ).first()
        
        if python_file:
            python_file.is_running = False
            db.session.commit()
        
        delete_process_info(pid)
        flash('Process stopped successfully!', 'success')
    except Exception as e:
        flash(f'Error stopping process: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id:
        abort(403)
    
    # Stop if running
    if python_file.is_running:
        for proc_file in os.listdir(app.config['RUNNING_PROCESSES']):
            if proc_file.endswith('.json'):
                with open(os.path.join(app.config['RUNNING_PROCESSES'], proc_file), 'r') as f:
                    proc_info = json.load(f)
                    if proc_info['filename'] == python_file.filename and proc_info['user_id'] == current_user.id:
                        try:
                            os.kill(proc_info['pid'], signal.SIGKILL)
                        except:
                            pass
                        delete_process_info(proc_info['pid'])
    
    # Delete file from filesystem
    try:
        os.remove(python_file.filepath)
    except:
        pass
    
    # Delete from database
    db.session.delete(python_file)
    db.session.commit()
    
    flash('File deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id:
        abort(403)
    
    return send_file(python_file.filepath, as_attachment=True, download_name=python_file.filename)

@app.route('/view/<int:file_id>')
@login_required
def view_file(file_id):
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id:
        abort(403)
    
    try:
        with open(python_file.filepath, 'r') as f:
            content = f.read()
        return jsonify({'content': content})
    except:
        return jsonify({'content': 'Unable to read file'})

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)