from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import subprocess
import psutil
import signal
import threading
import time
from datetime import datetime
import sqlite3

from models import db, User, PythonFile

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('running_processes', exist_ok=True)
os.makedirs('static/css', exist_ok=True)
os.makedirs('static/js', exist_ok=True)

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

running_processes = {}

class PythonProcess:
    def __init__(self, file_id, file_path, port):
        self.file_id = file_id
        self.file_path = file_path
        self.port = port
        self.process = None
        self.log_file = f"running_processes/{file_id}.log"
        
    def start(self):
        try:
            file_obj = PythonFile.query.get(self.file_id)
            if not file_obj:
                return False

            venv_path = f"running_processes/venv_{self.file_id}"
            if not os.path.exists(venv_path):
                result = os.system(f"python -m venv {venv_path}")
                if result != 0:
                    return False

            requirements_file = os.path.join(os.path.dirname(self.file_path), 'requirements.txt')
            if os.path.exists(requirements_file):
                os.system(f"{venv_path}/bin/pip install -r {requirements_file}")

            self.process = subprocess.Popen(
                ["python", self.file_path],
                stdout=open(self.log_file, 'w'),
                stderr=subprocess.STDOUT,
                shell=False
            )
            
            file_obj.status = 'running'
            file_obj.pid = self.process.pid
            file_obj.last_started = datetime.utcnow()
            db.session.commit()
            
            running_processes[self.file_id] = self
            return True
        except Exception as e:
            print(f"Error starting process: {e}")
            return False
    
    def stop(self):
        try:
            if self.process:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=10)
                except:
                    try:
                        os.kill(self.process.pid, signal.SIGKILL)
                    except:
                        pass
            
            file_obj = PythonFile.query.get(self.file_id)
            if file_obj:
                file_obj.status = 'stopped'
                file_obj.pid = None
                db.session.commit()
            
            if self.file_id in running_processes:
                del running_processes[self.file_id]
            return True
        except Exception as e:
            print(f"Error stopping process: {e}")
            return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            is_admin=(username == 'admin')
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_files = PythonFile.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', files=user_files)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'python_file' not in request.files:
        flash('No file selected')
        return redirect(url_for('dashboard'))
    
    file = request.files['python_file']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('dashboard'))
    
    if file and file.filename.endswith('.py'):
        filename = secure_filename(file.filename)
        unique_filename = f"{current_user.id}_{int(time.time())}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        python_file = PythonFile(
            filename=unique_filename,
            file_path=file_path,
            original_name=filename,
            user_id=current_user.id,
            port=8000 + current_user.id
        )
        
        db.session.add(python_file)
        db.session.commit()
        
        flash('File uploaded successfully!')
    else:
        flash('Please upload a valid Python file (.py)')
    
    return redirect(url_for('dashboard'))

@app.route('/start_file/<int:file_id>')
@login_required
def start_file(file_id):
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    if python_file.status == 'running':
        flash('File is already running')
        return redirect(url_for('dashboard'))
    
    process = PythonProcess(file_id, python_file.file_path, python_file.port)
    if process.start():
        flash('File started successfully!')
    else:
        flash('Error starting file')
    
    return redirect(url_for('dashboard'))

@app.route('/stop_file/<int:file_id>')
@login_required
def stop_file(file_id):
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    if file_id in running_processes:
        if running_processes[file_id].stop():
            flash('File stopped successfully!')
        else:
            flash('Error stopping file')
    else:
        flash('File is not running')
    
    return redirect(url_for('dashboard'))

@app.route('/delete_file/<int:file_id>')
@login_required
def delete_file(file_id):
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    if file_id in running_processes:
        running_processes[file_id].stop()
    
    try:
        if os.path.exists(python_file.file_path):
            os.remove(python_file.file_path)
    except:
        pass
    
    db.session.delete(python_file)
    db.session.commit()
    
    flash('File deleted successfully!')
    return redirect(url_for('dashboard'))

@app.route('/file_manager')
@login_required
def file_manager():
    user_files = PythonFile.query.filter_by(user_id=current_user.id).all()
    return render_template('file_manager.html', files=user_files)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    all_files = PythonFile.query.all()
    all_users = User.query.all()
    return render_template('admin.html', files=all_files, users=all_users)

@app.route('/api/files')
@login_required
def api_files():
    files = PythonFile.query.filter_by(user_id=current_user.id).all()
    result = []
    for file in files:
        result.append({
            'id': file.id,
            'filename': file.original_name,
            'status': file.status,
            'created_at': file.created_at.isoformat(),
            'last_started': file.last_started.isoformat() if file.last_started else None
        })
    return jsonify(result)

@app.route('/api/start/<int:file_id>', methods=['POST'])
@login_required
def api_start_file(file_id):
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    process = PythonProcess(file_id, python_file.file_path, python_file.port)
    if process.start():
        return jsonify({'message': 'File started successfully'})
    else:
        return jsonify({'error': 'Error starting file'}), 500

@app.route('/api/stop/<int:file_id>', methods=['POST'])
@login_required
def api_stop_file(file_id):
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    if file_id in running_processes:
        if running_processes[file_id].stop():
            return jsonify({'message': 'File stopped successfully'})
        else:
            return jsonify({'error': 'Error stopping file'}), 500
    else:
        return jsonify({'error': 'File is not running'}), 400

@app.route('/api/delete/<int:file_id>', methods=['DELETE'])
@login_required
def api_delete_file(file_id):
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    if file_id in running_processes:
        running_processes[file_id].stop()
    
    try:
        if os.path.exists(python_file.file_path):
            os.remove(python_file.file_path)
    except:
        pass
    
    db.session.delete(python_file)
    db.session.commit()
    
    return jsonify({'message': 'File deleted successfully'})

@app.route('/view_logs/<int:file_id>')
@login_required
def view_logs(file_id):
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    log_file = f"running_processes/{file_id}.log"
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            logs = f.read()
    else:
        logs = "No logs available"
    
    return render_template('logs.html', logs=logs, filename=python_file.original_name)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

def init_db():
    with app.app_context():
        db.create_all()
        
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                email='admin@example.com',
                password=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()
        print("Database initialized successfully!")

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)