#!/usr/bin/env python3
import os, json, time, uuid, random, string, subprocess, signal, shlex, threading, select
from pathlib import Path
from datetime import datetime, date
from functools import wraps
import zipfile
import io
import queue
import psutil
import logging

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, send_file, jsonify, Response
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker, scoped_session

from models import Base, User, Bot, KeyValue, TerminalSession

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ------------------ Config ------------------

DATA_DIR = Path(os.environ.get("DATA_DIR", "./data")).resolve()
UPLOAD_DIR = DATA_DIR / "uploads"
LOG_DIR = DATA_DIR / "logs"
RUN_DIR = DATA_DIR / "run"
HOME_DIR = DATA_DIR / "home"
TERMINAL_SESSIONS_DIR = DATA_DIR / "terminal_sessions"
TCP_BOTS_DIR = DATA_DIR / "tcp_bots"

for d in (DATA_DIR, UPLOAD_DIR, LOG_DIR, RUN_DIR, HOME_DIR, TERMINAL_SESSIONS_DIR, TCP_BOTS_DIR):
    d.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "app.db"
ENGINE = create_engine(f"sqlite:///{DB_PATH}", echo=False, future=True)
SessionLocal = scoped_session(sessionmaker(bind=ENGINE, expire_on_commit=False))

# Create tables safely
try:
    Base.metadata.create_all(ENGINE)
except Exception as e:
    logger.error(f"Error creating database tables: {e}")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_change_me")

# Owner fixed credentials
OWNER_USERNAME = "DANGERxHOST"
OWNER_PASSWORD = "DANGER73"

# Store active terminal processes
active_processes = {}
active_sessions = {}
process_queues = {}
process_threads = {}

# TCP Bot Management
tcp_bots = {}
tcp_bot_threads = {}

# ------------------ Helpers ------------------

def get_db():
    return SessionLocal()

def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    db = get_db()
    try:
        return db.get(User, uid)
    except Exception as e:
        logger.error(f"Error getting current user: {e}")
        return None
    finally:
        db.close()

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not current_user():
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapper

def owner_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if not u or u.role != "owner":
            flash("Permission denied. Owner only.", "error")
            return redirect(url_for("dashboard"))
        return fn(*a, **kw)
    return wrapper

def approved_required(fn):
    """Only allow approved users (or owner) to perform actions."""
    @wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if not u:
            return redirect(url_for("login"))
        if u.role == "owner":
            return fn(*a, **kw)
        if not u.approved:
            flash("⚠️ Account pending approval. Please wait for admin approval.", "warning")
            return redirect(url_for("dashboard"))
        return fn(*a, **kw)
    return wrapper

def get_user_home(user_id):
    try:
        user_home = HOME_DIR / f"user_{user_id}"
        user_home.mkdir(exist_ok=True)
        
        # Create default directories
        default_dirs = ["storage", "storage/shared", "storage/shared/TCP-BOT", "projects", "downloads", "tcp_bots"]
        for dir_name in default_dirs:
            (user_home / dir_name).mkdir(exist_ok=True)
        
        return user_home
    except Exception as e:
        logger.error(f"Error creating user home: {e}")
        return HOME_DIR / f"user_{user_id}"

def resolve_user_path(user_id, path):
    """Resolve any path to user's storage/shared directory"""
    user_home = get_user_home(user_id)
    shared_path = user_home / "storage" / "shared"
    
    # If path is absolute and within user home, use it
    if path.startswith('/'):
        abs_path = Path(path)
        if str(abs_path).startswith(str(HOME_DIR)):
            return str(abs_path)
    
    # Handle relative paths
    if path.startswith('storage/shared/'):
        path = path.replace('storage/shared/', '', 1)
    
    # Resolve to shared directory
    resolved_path = shared_path / path
    return str(resolved_path)

def create_terminal_session(user_id):
    """Create a new terminal session"""
    try:
        session_id = str(uuid.uuid4())
        session_dir = TERMINAL_SESSIONS_DIR / f"user_{user_id}" / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        
        # Create log file
        log_file = session_dir / "terminal.log"
        log_file.touch()
        
        user_home_path = get_user_home(user_id)
        shared_path = user_home_path / "storage" / "shared"
        
        # Store session info
        active_sessions[session_id] = {
            'user_id': user_id,
            'created_at': datetime.utcnow(),
            'log_file': str(log_file),
            'cwd': str(shared_path),
            'process': None,
            'is_running': False,
            'current_command': None,
            'is_tcp_bot': False
        }
        
        # Create output queue for this session
        process_queues[session_id] = queue.Queue()
        
        return session_id
    except Exception as e:
        logger.error(f"Error creating terminal session: {e}")
        return str(uuid.uuid4())

def read_process_output(process, session_id, command):
    """Read output from process in real-time"""
    try:
        if session_id not in active_sessions:
            return
            
        session_info = active_sessions[session_id]
        
        # Write command to log
        try:
            with open(session_info['log_file'], 'a', encoding='utf-8') as f:
                f.write(f"\n$ {command}\n")
        except:
            pass
        
        while True:
            # Check if process is still running
            if process.poll() is not None:
                break
                
            # Read from stdout
            try:
                stdout_line = process.stdout.readline()
                if stdout_line:
                    process_queues[session_id].put(('output', stdout_line))
                    
                    # Also write to log file
                    try:
                        with open(session_info['log_file'], 'a', encoding='utf-8') as f:
                            f.write(stdout_line)
                    except:
                        pass
            except:
                pass
            
            # Read from stderr
            try:
                stderr_line = process.stderr.readline()
                if stderr_line:
                    process_queues[session_id].put(('error', stderr_line))
                    
                    # Also write to log file
                    try:
                        with open(session_info['log_file'], 'a', encoding='utf-8') as f:
                            f.write(stderr_line)
                    except:
                        pass
            except:
                pass
            
            # Small delay to prevent busy waiting
            time.sleep(0.01)
            
        # Process finished
        return_code = process.poll()
        if return_code is not None:
            finish_msg = f"\n[Process finished with return code: {return_code}]\n"
            process_queues[session_id].put(('output', finish_msg))
            
    except Exception as e:
        logger.error(f"Error reading process output: {e}")
        error_msg = f"\nError reading process output: {str(e)}\n"
        if session_id in process_queues:
            process_queues[session_id].put(('error', error_msg))

def execute_command_in_session(session_id, command):
    """Execute command in a specific terminal session with real-time output"""
    try:
        if session_id not in active_sessions:
            return {'success': False, 'output': 'Session not found'}
        
        session_info = active_sessions[session_id]
        user_id = session_info['user_id']
        user_home = get_user_home(user_id)
        
        # Handle special commands
        if command.startswith('cd '):
            path = command[3:].strip()
            if path == "storage/shared":
                path = str(user_home / "storage" / "shared")
            elif path == "TCP-BOT":
                path = str(user_home / "storage" / "shared" / "TCP-BOT")
            try:
                if path.startswith('/'):
                    new_path = Path(path).resolve()
                else:
                    current_cwd = session_info['cwd']
                    new_path = (Path(current_cwd) / path).resolve()
                
                # Security check - ensure path is within user's home
                if str(new_path).startswith(str(HOME_DIR)):
                    if new_path.exists() and new_path.is_dir():
                        session_info['cwd'] = str(new_path)
                        return {'success': True, 'output': '', 'cwd': str(new_path)}
                    else:
                        return {'success': False, 'output': f'cd: {path}: No such directory\n'}
                else:
                    return {'success': False, 'output': 'cd: Permission denied\n'}
            except Exception as e:
                return {'success': False, 'output': f'cd: {str(e)}\n'}
        
        # Stop any existing process
        if session_id in active_processes:
            stop_terminal_process(session_id)
        
        # Get current working directory
        cwd = session_info['cwd']
        
        # Execute command with proper environment
        env = os.environ.copy()
        env['HOME'] = str(user_home)
        env['USER'] = f'user_{user_id}'
        env['PYTHONPATH'] = str(user_home)
        env['PYTHONUNBUFFERED'] = '1'
        
        # For TCP bot commands, use optimized settings
        if any(cmd in command.lower() for cmd in ['lag', 'tcp', 'bot', 'python', 'node']):
            # Use larger buffers for high output
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                env=env,
                bufsize=8192,
                universal_newlines=True
            )
        else:
            # Normal commands with standard buffer
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                env=env,
                bufsize=1,
                universal_newlines=True
            )
        
        # Store process info
        session_info['process'] = process
        session_info['is_running'] = True
        session_info['current_command'] = command
        active_processes[session_id] = process
        
        # Start thread to read output in real-time
        output_thread = threading.Thread(
            target=read_process_output, 
            args=(process, session_id, command),
            daemon=True
        )
        output_thread.start()
        process_threads[session_id] = output_thread
        
        # Store session data in database
        db = get_db()
        try:
            terminal_session = TerminalSession(
                user_id=user_id,
                session_data=json.dumps({
                    'command': command,
                    'timestamp': datetime.utcnow().isoformat(),
                    'session_id': session_id
                })
            )
            db.add(terminal_session)
            db.commit()
        except Exception as e:
            logger.error(f"Error storing session: {e}")
        finally:
            db.close()
        
        return {
            'success': True,
            'output': 'Command started successfully. Real-time output will be available.',
            'session_id': session_id,
            'pid': process.pid
        }
        
    except Exception as e:
        logger.error(f"Error executing command: {e}")
        return {'success': False, 'output': f'Error starting command: {str(e)}'}

def stop_terminal_process(session_id):
    """Stop a running process in terminal session - OPTIMIZED FOR TCP BOT"""
    try:
        if session_id in active_processes:
            process = active_processes[session_id]
            try:
                # For TCP bots, we need to be more aggressive in termination
                if process and process.poll() is None:
                    # First try graceful termination
                    process.terminate()
                    
                    # Wait a bit for graceful shutdown
                    for _ in range(10):  # 1 second total
                        if process.poll() is not None:
                            break
                        time.sleep(0.1)
                    
                    # If still running, force kill
                    if process.poll() is None:
                        # Try to kill process group if possible
                        try:
                            if os.name == 'posix':  # Unix/Linux
                                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                            else:  # Windows
                                process.kill()
                        except:
                            process.kill()
                        
                        # Final wait
                        try:
                            process.wait(timeout=2)
                        except:
                            pass
                
            except Exception as e:
                logger.error(f"Error stopping process: {e}")
                try:
                    process.kill()
                except:
                    pass
            
            # Clean up
            if session_id in active_processes:
                del active_processes[session_id]
            if session_id in active_sessions:
                active_sessions[session_id]['process'] = None
                active_sessions[session_id]['is_running'] = False
                active_sessions[session_id]['current_command'] = None
            
            # Add termination message to output
            if session_id in process_queues:
                process_queues[session_id].put(('output', '\n[Process stopped by user]\n'))
            
            return True
        
        return False
    except Exception as e:
        logger.error(f"Error in stop_terminal_process: {e}")
        return False

def get_session_logs(session_id, lines=100):
    """Get recent logs from session"""
    try:
        if session_id not in active_sessions:
            return ""
        
        log_file = active_sessions[session_id]['log_file']
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
            # Return last N lines
            lines_list = content.split('\n')
            return '\n'.join(lines_list[-lines:])
    except:
        return ""

def get_realtime_output(session_id):
    """Get real-time output from process queue - OPTIMIZED FOR HIGH OUTPUT"""
    try:
        if session_id not in process_queues:
            return ""
        
        output_lines = []
        max_lines = 50  # Limit output to prevent overload
        
        line_count = 0
        while line_count < max_lines:
            try:
                msg_type, line = process_queues[session_id].get_nowait()
                output_lines.append(line)
                line_count += 1
                
                # If we have a lot of output, break early to prevent overload
                if line_count >= max_lines:
                    output_lines.append("\n[Output truncated...]\n")
                    break
                    
            except queue.Empty:
                break
        
        # Check if process is still running
        if session_id in active_sessions:
            session_info = active_sessions[session_id]
            if session_info['is_running'] and session_info['process']:
                process = session_info['process']
                if process.poll() is not None:
                    session_info['is_running'] = False
                    return_code = process.poll()
                    output_lines.append(f'\n[Process finished with return code: {return_code}]\n')
        
        return ''.join(output_lines)
    except Exception as e:
        logger.error(f"Error getting realtime output: {e}")
        return ""

# ------------------ TCP Bot Management ------------------

def start_tcp_bot(user_id, bot_id, main_file_path, session_id=None):
    """Start a TCP bot with automatic cleanup and restart - FIXED VERSION"""
    try:
        # Resolve the path properly
        main_file = Path(resolve_user_path(user_id, main_file_path))
        
        # Debug logging
        logger.info(f"Starting TCP Bot - User: {user_id}, File: {main_file_path}, Resolved: {main_file}, Exists: {main_file.exists()}")
        
        if not main_file.exists():
            logger.error(f"TCP Bot main file not found: {main_file}")
            return {'success': False, 'message': f'Main file not found: {main_file}'}
        
        # Stop existing bot if running
        if bot_id in tcp_bots:
            stop_tcp_bot(bot_id)
        
        # Create bot directory
        bot_dir = TCP_BOTS_DIR / f"user_{user_id}" / bot_id
        bot_dir.mkdir(parents=True, exist_ok=True)
        
        # Create log file
        log_file = bot_dir / "bot.log"
        
        # Store bot info
        tcp_bots[bot_id] = {
            'user_id': user_id,
            'main_file': str(main_file),
            'bot_dir': str(bot_dir),
            'log_file': str(log_file),
            'process': None,
            'is_running': False,
            'started_at': datetime.utcnow(),
            'session_id': session_id,
            'restart_count': 0
        }
        
        # Start the bot process with proper environment
        env = os.environ.copy()
        env['HOME'] = str(get_user_home(user_id))
        env['USER'] = f'user_{user_id}'
        env['PYTHONUNBUFFERED'] = '1'
        env['PYTHONIOENCODING'] = 'utf-8'
        
        # Determine command based on file extension
        if main_file.suffix == '.py':
            command = f"python3 {main_file}"
        elif main_file.suffix == '.js':
            command = f"node {main_file}"
        else:
            # For other files, try to make executable and run directly
            try:
                os.chmod(main_file, 0o755)
            except:
                pass
            command = f"./{main_file}"
        
        logger.info(f"TCP Bot command: {command}")
        logger.info(f"TCP Bot working directory: {main_file.parent}")
        
        # Start process
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(main_file.parent),  # Use string path to avoid issues
            env=env,
            bufsize=8192,
            universal_newlines=True,
            preexec_fn=os.setsid if os.name == 'posix' else None
        )
        
        tcp_bots[bot_id]['process'] = process
        tcp_bots[bot_id]['is_running'] = True
        
        # Start monitoring thread
        monitor_thread = threading.Thread(
            target=monitor_tcp_bot,
            args=(bot_id,),
            daemon=True
        )
        monitor_thread.start()
        tcp_bot_threads[bot_id] = monitor_thread
        
        # Log startup
        with open(log_file, 'a') as f:
            f.write(f"[{datetime.utcnow()}] TCP Bot started - {main_file}\n")
            f.write(f"[{datetime.utcnow()}] Command: {command}\n")
            f.write(f"[{datetime.utcnow()}] Working Directory: {main_file.parent}\n")
            f.write(f"[{datetime.utcnow()}] Process PID: {process.pid}\n")
        
        logger.info(f"TCP Bot started successfully - ID: {bot_id}, PID: {process.pid}")
        
        return {'success': True, 'message': 'TCP Bot started successfully', 'bot_id': bot_id, 'pid': process.pid}
        
    except Exception as e:
        logger.error(f"Error starting TCP bot: {e}")
        return {'success': False, 'message': f'Error starting TCP bot: {str(e)}'}

def stop_tcp_bot(bot_id):
    """Stop a TCP bot - FIXED VERSION"""
    try:
        if bot_id in tcp_bots:
            bot_info = tcp_bots[bot_id]
            process = bot_info['process']
            
            logger.info(f"Stopping TCP Bot: {bot_id}")
            
            if process and process.poll() is None:
                try:
                    # Try graceful termination first
                    if os.name == 'posix':
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    else:
                        process.terminate()
                    
                    # Wait for process to terminate
                    for _ in range(10):
                        if process.poll() is not None:
                            break
                        time.sleep(0.5)
                    
                    # Force kill if still running
                    if process.poll() is None:
                        if os.name == 'posix':
                            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                        else:
                            process.kill()
                        process.wait()
                        
                except Exception as e:
                    logger.error(f"Error stopping TCP bot process: {e}")
                    try:
                        process.kill()
                    except:
                        pass
            
            # Log shutdown
            try:
                with open(bot_info['log_file'], 'a') as f:
                    f.write(f"[{datetime.utcnow()}] TCP Bot stopped\n")
            except:
                pass
            
            bot_info['is_running'] = False
            bot_info['process'] = None
            
            if bot_id in tcp_bot_threads:
                del tcp_bot_threads[bot_id]
            
            logger.info(f"TCP Bot stopped: {bot_id}")
            return True
        return False
    except Exception as e:
        logger.error(f"Error stopping TCP bot: {e}")
        return False

def monitor_tcp_bot(bot_id):
    """Monitor TCP bot and handle automatic restart - FIXED VERSION"""
    max_restarts = 5
    
    while bot_id in tcp_bots and tcp_bots[bot_id]['is_running'] and tcp_bots[bot_id]['restart_count'] < max_restarts:
        try:
            bot_info = tcp_bots[bot_id]
            process = bot_info['process']
            
            if process and process.poll() is not None:
                # Bot crashed, restart it
                bot_info['restart_count'] += 1
                
                with open(bot_info['log_file'], 'a') as f:
                    f.write(f"[{datetime.utcnow()}] TCP Bot crashed, restarting... (Attempt {bot_info['restart_count']}/{max_restarts})\n")
                
                logger.info(f"TCP Bot {bot_id} crashed, restarting (Attempt {bot_info['restart_count']}/{max_restarts})")
                
                # Clean up old process
                if process:
                    try:
                        if os.name == 'posix':
                            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                        else:
                            process.kill()
                    except:
                        pass
                
                # Restart bot
                user_id = bot_info['user_id']
                main_file = bot_info['main_file']
                
                env = os.environ.copy()
                env['HOME'] = str(get_user_home(user_id))
                env['USER'] = f'user_{user_id}'
                env['PYTHONUNBUFFERED'] = '1'
                env['PYTHONIOENCODING'] = 'utf-8'
                
                main_path = Path(main_file)
                if main_path.suffix == '.py':
                    command = f"python3 {main_path}"
                elif main_path.suffix == '.js':
                    command = f"node {main_path}"
                else:
                    command = f"./{main_path}"
                
                new_process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=str(main_path.parent),
                    env=env,
                    bufsize=8192,
                    universal_newlines=True,
                    preexec_fn=os.setsid if os.name == 'posix' else None
                )
                
                bot_info['process'] = new_process
                
                with open(bot_info['log_file'], 'a') as f:
                    f.write(f"[{datetime.utcnow()}] TCP Bot restarted successfully\n")
                
                logger.info(f"TCP Bot {bot_id} restarted successfully")
                
                # Wait a bit before checking again
                time.sleep(10)
            
            time.sleep(5)  # Check every 5 seconds
            
        except Exception as e:
            logger.error(f"Error monitoring TCP bot {bot_id}: {e}")
            time.sleep(10)
    
    if bot_id in tcp_bots and tcp_bots[bot_id]['restart_count'] >= max_restarts:
        logger.error(f"TCP Bot {bot_id} reached maximum restart attempts, stopping")
        stop_tcp_bot(bot_id)

def cleanup_tcp_bots():
    """Clean up TCP bots every 3 hours"""
    while True:
        time.sleep(10800)  # 3 hours
        try:
            current_time = datetime.utcnow()
            bots_to_remove = []
            
            for bot_id, bot_info in tcp_bots.items():
                # Remove bots older than 6 hours or not running
                if (current_time - bot_info['started_at']).total_seconds() > 21600 or not bot_info['is_running']:
                    stop_tcp_bot(bot_id)
                    bots_to_remove.append(bot_id)
            
            for bot_id in bots_to_remove:
                if bot_id in tcp_bots:
                    del tcp_bots[bot_id]
                
        except Exception as e:
            logger.error(f"Error in TCP bot cleanup: {e}")

def get_user_tcp_bots(user_id):
    """Get all TCP bots for a user"""
    user_bots = {}
    for bot_id, bot_info in tcp_bots.items():
        if bot_info['user_id'] == user_id:
            user_bots[bot_id] = bot_info
    return user_bots

def ensure_owner_exists():
    db = get_db()
    try:
        user = db.execute(select(User).where(User.username == OWNER_USERNAME)).scalar_one_or_none()
        if not user:
            user = User(
                username=OWNER_USERNAME,
                password_hash=generate_password_hash(OWNER_PASSWORD),
                role="owner",
                approved=True,
                expiry=None
            )
            db.add(user)
            db.commit()
            
            # Create owner home directory
            get_user_home(user.id)
            logger.info("✅ Owner user created successfully!")
        else:
            logger.info("✅ Owner user already exists!")
    except Exception as e:
        logger.error(f"❌ Error creating owner: {e}")
    finally:
        db.close()

# Initialize owner
ensure_owner_exists()

# Start TCP bot cleanup thread
tcp_cleanup_thread = threading.Thread(target=cleanup_tcp_bots, daemon=True)
tcp_cleanup_thread.start()

# --------------- Auth Routes ----------------

@app.get("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.get("/login")
def login():
    return render_template("login.html")

@app.post("/login")
def login_post():
    db = get_db()
    try:
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        u = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if not u:
            flash("Invalid username or password", "error")
            return redirect(url_for("login"))

        if u.is_expired():
            flash("Account expired. Please contact owner.", "error")
            return redirect(url_for("login"))

        if not check_password_hash(u.password_hash, password):
            flash("Invalid username or password", "error")
            return redirect(url_for("login"))

        session["uid"] = u.id
        session["role"] = u.role
        session["username"] = u.username
        flash("Welcome back!", "success")
        return redirect(url_for("dashboard"))
    except Exception as e:
        logger.error(f"Login error: {e}")
        flash("Login error occurred", "error")
        return redirect(url_for("login"))
    finally:
        db.close()

@app.get("/logout")
def logout():
    # Clean up user's terminal sessions
    uid = session.get("uid")
    if uid:
        user_sessions = [sid for sid, info in active_sessions.items() if info['user_id'] == uid]
        for session_id in user_sessions:
            stop_terminal_process(session_id)
            if session_id in active_sessions:
                del active_sessions[session_id]
            if session_id in process_queues:
                del process_queues[session_id]
            if session_id in process_threads:
                del process_threads[session_id]
        
        # Clean up user's TCP bots
        user_bots = [bid for bid, info in tcp_bots.items() if info['user_id'] == uid]
        for bot_id in user_bots:
            stop_tcp_bot(bot_id)
            if bot_id in tcp_bots:
                del tcp_bots[bot_id]
    
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect(url_for("login"))

@app.get("/register")
def register():
    return render_template("register.html")

@app.post("/register")
def register_post():
    db = get_db()
    try:
        username = request.form.get("username","").strip()
        password = request.form.get("password","")

        if not username or not password:
            flash("Username & password required.", "error")
            return redirect(url_for("register"))

        exists = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if exists:
            flash("Username already taken.", "error")
            return redirect(url_for("register"))

        u = User(
            username=username,
            password_hash=generate_password_hash(password),
            role="user",
            approved=False,
            expiry=None
        )
        db.add(u)
        db.commit()
        
        # Create user home directory
        get_user_home(u.id)
        
        flash("Registered! Waiting for owner approval.", "success")
        return redirect(url_for("login"))
    except Exception as e:
        logger.error(f"Registration error: {e}")
        flash("Registration error occurred", "error")
        return redirect(url_for("register"))
    finally:
        db.close()

# ------------ Dashboard & Terminal ------------

@app.get("/dashboard")
@login_required
def dashboard():
    try:
        u = current_user()
        user_tcp_bots = get_user_tcp_bots(u.id)
        return render_template("dashboard.html", user=u, user_tcp_bots=user_tcp_bots)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash("Error loading dashboard", "error")
        return redirect(url_for("login"))

@app.get("/terminal")
@login_required
def terminal():
    try:
        u = current_user()
        
        # Get or create terminal session
        terminal_session_id = request.args.get('session_id')
        if not terminal_session_id or terminal_session_id not in active_sessions:
            terminal_session_id = create_terminal_session(u.id)
        
        # Get user's active sessions
        user_sessions = {}
        for sid, info in active_sessions.items():
            if info['user_id'] == u.id:
                user_sessions[sid] = {
                    'created_at': info['created_at'],
                    'is_running': info['is_running'],
                    'current_command': info['current_command']
                }
        
        # Get user's TCP bots
        user_tcp_bots = get_user_tcp_bots(u.id)
        
        return render_template("terminal.html", 
                             user=u, 
                             session_id=terminal_session_id,
                             user_sessions=user_sessions,
                             user_tcp_bots=user_tcp_bots)
    except Exception as e:
        logger.error(f"Terminal error: {e}")
        flash("Error loading terminal", "error")
        return redirect(url_for("dashboard"))

# ------------------ Real-time Terminal API Routes ------------------

@app.post("/api/terminal/create_session")
@login_required
def api_create_terminal_session():
    try:
        u = current_user()
        session_id = create_terminal_session(u.id)
        return jsonify({'success': True, 'session_id': session_id})
    except Exception as e:
        logger.error(f"Create session error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.post("/api/terminal/command")
@login_required
def api_terminal_command():
    try:
        if not request.is_json:
            return jsonify({'success': False, 'output': 'Request must be JSON'}), 400
            
        data = request.get_json()
        command = data.get('command', '').strip()
        session_id = data.get('session_id', '')
        
        if not command:
            return jsonify({'output': ''})
        
        if not session_id:
            return jsonify({'success': False, 'output': 'No active session'})
        
        result = execute_command_in_session(session_id, command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Terminal command error: {e}")
        return jsonify({'success': False, 'output': f'Server error: {str(e)}'}), 500

@app.post("/api/terminal/stop")
@login_required
def api_terminal_stop():
    try:
        if not request.is_json:
            return jsonify({'success': False, 'message': 'Request must be JSON'}), 400
            
        data = request.get_json()
        session_id = data.get('session_id', '')
        
        if not session_id:
            return jsonify({'success': False, 'message': 'No session specified'})
        
        stopped = stop_terminal_process(session_id)
        if stopped:
            return jsonify({'success': True, 'message': 'Process stopped successfully'})
        else:
            return jsonify({'success': False, 'message': 'No process running'})
    except Exception as e:
        logger.error(f"Terminal stop error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.get("/api/terminal/logs")
@login_required
def api_terminal_logs():
    try:
        session_id = request.args.get('session_id', '')
        lines = int(request.args.get('lines', 100))
        
        if not session_id:
            return jsonify({'success': False, 'logs': ''})
        
        logs = get_session_logs(session_id, lines)
        return jsonify({'success': True, 'logs': logs})
    except Exception as e:
        logger.error(f"Terminal logs error: {e}")
        return jsonify({'success': False, 'logs': str(e)}), 500

@app.get("/api/terminal/output")
@login_required
def api_terminal_output():
    """Get real-time output from running process - OPTIMIZED FOR TCP BOT"""
    try:
        session_id = request.args.get('session_id', '')
        
        if not session_id:
            return jsonify({'success': False, 'output': '', 'is_running': False})
        
        # Get real-time output
        output = get_realtime_output(session_id)
        
        # Check if process is running
        is_running = False
        current_command = None
        if session_id in active_sessions:
            is_running = active_sessions[session_id]['is_running']
            current_command = active_sessions[session_id]['current_command']
        
        return jsonify({
            'success': True, 
            'output': output,
            'is_running': is_running,
            'current_command': current_command
        })
    except Exception as e:
        logger.error(f"Terminal output error: {e}")
        return jsonify({'success': False, 'output': str(e), 'is_running': False}), 500

@app.get("/api/terminal/sessions")
@login_required
def api_terminal_sessions():
    try:
        u = current_user()
        user_sessions = {}
        for sid, info in active_sessions.items():
            if info['user_id'] == u.id:
                user_sessions[sid] = {
                    'created_at': info['created_at'].strftime('%Y-%m-%d %H:%M'),
                    'is_running': info['is_running'],
                    'current_command': info['current_command']
                }
        
        return jsonify({'success': True, 'sessions': user_sessions})
    except Exception as e:
        logger.error(f"Terminal sessions error: {e}")
        return jsonify({'success': False, 'sessions': {}, 'message': str(e)}), 500

@app.post("/api/terminal/delete_session")
@login_required
def api_terminal_delete_session():
    try:
        if not request.is_json:
            return jsonify({'success': False, 'message': 'Request must be JSON'}), 400
            
        data = request.get_json()
        session_id = data.get('session_id', '')
        
        if not session_id:
            return jsonify({'success': False, 'message': 'No session specified'})
        
        u = current_user()
        
        # Security check - user can only delete their own sessions
        if session_id in active_sessions and active_sessions[session_id]['user_id'] == u.id:
            # Stop any running process
            stop_terminal_process(session_id)
            
            # Delete session files
            try:
                session_dir = TERMINAL_SESSIONS_DIR / f"user_{u.id}" / session_id
                import shutil
                shutil.rmtree(session_dir, ignore_errors=True)
            except:
                pass
            
            # Remove from all dictionaries
            if session_id in active_sessions:
                del active_sessions[session_id]
            if session_id in process_queues:
                del process_queues[session_id]
            if session_id in process_threads:
                del process_threads[session_id]
            if session_id in active_processes:
                del active_processes[session_id]
            
            return jsonify({'success': True, 'message': 'Session deleted'})
        
        return jsonify({'success': False, 'message': 'Session not found or permission denied'})
    except Exception as e:
        logger.error(f"Delete session error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.get("/api/terminal/status")
@login_required
def api_terminal_status():
    """Check if a process is running in session"""
    try:
        session_id = request.args.get('session_id', '')
        
        if not session_id:
            return jsonify({'success': False, 'is_running': False})
        
        is_running = False
        current_command = None
        if session_id in active_sessions:
            is_running = active_sessions[session_id]['is_running']
            current_command = active_sessions[session_id]['current_command']
        
        return jsonify({
            'success': True, 
            'is_running': is_running,
            'current_command': current_command
        })
    except Exception as e:
        logger.error(f"Terminal status error: {e}")
        return jsonify({'success': False, 'is_running': False, 'message': str(e)})

# ------------------ TCP Bot API Routes ------------------

@app.post("/api/tcp_bot/start")
@login_required
@approved_required
def api_tcp_bot_start():
    try:
        if not request.is_json:
            return jsonify({'success': False, 'message': 'Request must be JSON'}), 400
            
        data = request.get_json()
        main_file_path = data.get('main_file_path', '').strip()
        session_id = data.get('session_id', '')
        
        if not main_file_path:
            return jsonify({'success': False, 'message': 'Main file path required'})
        
        u = current_user()
        
        # Use the resolve_user_path function to handle all path formats
        resolved_path = resolve_user_path(u.id, main_file_path)
        
        # Check if file exists
        main_file = Path(resolved_path)
        if not main_file.exists():
            return jsonify({'success': False, 'message': f'File not found: {resolved_path}'})
        
        bot_id = str(uuid.uuid4())
        result = start_tcp_bot(u.id, bot_id, main_file_path, session_id)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"TCP bot start error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.post("/api/tcp_bot/stop")
@login_required
@approved_required
def api_tcp_bot_stop():
    try:
        if not request.is_json:
            return jsonify({'success': False, 'message': 'Request must be JSON'}), 400
            
        data = request.get_json()
        bot_id = data.get('bot_id', '')
        
        if not bot_id:
            return jsonify({'success': False, 'message': 'Bot ID required'})
        
        u = current_user()
        
        # Security check - user can only stop their own bots
        if bot_id in tcp_bots and tcp_bots[bot_id]['user_id'] == u.id:
            stopped = stop_tcp_bot(bot_id)
            if stopped:
                if bot_id in tcp_bots:
                    del tcp_bots[bot_id]
                return jsonify({'success': True, 'message': 'TCP Bot stopped successfully'})
            else:
                return jsonify({'success': False, 'message': 'Failed to stop TCP Bot'})
        
        return jsonify({'success': False, 'message': 'Bot not found or permission denied'})
        
    except Exception as e:
        logger.error(f"TCP bot stop error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.get("/api/tcp_bot/status")
@login_required
def api_tcp_bot_status():
    try:
        u = current_user()
        user_bots = get_user_tcp_bots(u.id)
        
        bot_status = {}
        for bot_id, bot_info in user_bots.items():
            process = bot_info['process']
            is_running = False
            pid = None
            
            if process:
                is_running = process.poll() is None
                pid = process.pid
            
            # Get just the filename for display
            main_file = Path(bot_info['main_file'])
            display_name = main_file.name
            
            bot_status[bot_id] = {
                'main_file': display_name,
                'full_path': bot_info['main_file'],
                'is_running': is_running,
                'started_at': bot_info['started_at'].strftime('%Y-%m-%d %H:%M:%S'),
                'session_id': bot_info.get('session_id'),
                'pid': pid,
                'restart_count': bot_info.get('restart_count', 0)
            }
        
        return jsonify({'success': True, 'bots': bot_status})
        
    except Exception as e:
        logger.error(f"TCP bot status error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.get("/api/tcp_bot/logs")
@login_required
def api_tcp_bot_logs():
    try:
        bot_id = request.args.get('bot_id', '')
        lines = int(request.args.get('lines', 50))
        
        if not bot_id:
            return jsonify({'success': False, 'logs': ''})
        
        u = current_user()
        
        # Security check
        if bot_id in tcp_bots and tcp_bots[bot_id]['user_id'] == u.id:
            log_file = tcp_bots[bot_id]['log_file']
            try:
                with open(log_file, 'r') as f:
                    content = f.read()
                    lines_list = content.split('\n')
                    logs = '\n'.join(lines_list[-lines:])
                return jsonify({'success': True, 'logs': logs})
            except:
                return jsonify({'success': True, 'logs': ''})
        
        return jsonify({'success': False, 'logs': 'Bot not found'})
        
    except Exception as e:
        logger.error(f"TCP bot logs error: {e}")
        return jsonify({'success': False, 'logs': str(e)}), 500

# ------------------ File Manager Routes ------------------

@app.get("/filemanager")
@login_required
def file_manager():
    try:
        u = current_user()
        user_home = get_user_home(u.id)
        
        path = request.args.get('path', '')
        if path:
            try:
                current_path = Path(path)
                # Security check
                if not str(current_path).startswith(str(HOME_DIR)):
                    current_path = user_home / "storage" / "shared"
            except:
                current_path = user_home / "storage" / "shared"
        else:
            current_path = user_home / "storage" / "shared"
        
        try:
            items = []
            if current_path.exists() and current_path.is_dir():
                for item in current_path.iterdir():
                    try:
                        items.append({
                            'name': item.name,
                            'path': str(item),
                            'is_dir': item.is_dir(),
                            'size': item.stat().st_size if item.is_file() else 0,
                            'modified': datetime.fromtimestamp(item.stat().st_mtime)
                        })
                    except (OSError, PermissionError):
                        continue
            
            # Sort: directories first, then files
            items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
            
            parent_path = str(current_path.parent) if current_path != user_home and current_path != user_home / "storage" / "shared" else None
            
            return render_template("file_manager.html", 
                                 user=u,
                                 items=items,
                                 current_path=str(current_path),
                                 parent_path=parent_path,
                                 user_home=str(user_home))
        except Exception as e:
            logger.error(f"File manager directory error: {e}")
            flash(f"Error accessing directory: {str(e)}", "error")
            return redirect(url_for("file_manager", path=str(user_home / "storage" / "shared")))
    except Exception as e:
        logger.error(f"File manager error: {e}")
        flash("Error loading file manager", "error")
        return redirect(url_for("dashboard"))

# ------------------ File Manager API Routes ------------------

@app.post("/api/create_folder")
@login_required
@approved_required
def api_create_folder():
    try:
        if not request.is_json:
            return jsonify({'success': False, 'message': 'Request must be JSON'}), 400
            
        data = request.get_json()
        folder_name = data.get('name', '').strip()
        current_path = data.get('current_path', '')
        
        if not folder_name:
            return jsonify({'success': False, 'message': 'Folder name required'})
        
        u = current_user()
        user_home = get_user_home(u.id)
        
        # Security check - ensure path is within user's home
        target_path = Path(current_path) / folder_name
        if not str(target_path).startswith(str(HOME_DIR)):
            return jsonify({'success': False, 'message': 'Permission denied'})
        
        target_path.mkdir(exist_ok=True)
        return jsonify({'success': True, 'message': 'Folder created'})
        
    except Exception as e:
        logger.error(f"Create folder error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.post("/api/upload_files")
@login_required
@approved_required
def api_upload_files():
    try:
        if 'files' not in request.files:
            return jsonify({'success': False, 'message': 'No files provided'}), 400
        
        files = request.files.getlist('files')
        current_path = request.form.get('current_path', '')
        
        if not files or all(file.filename == '' for file in files):
            return jsonify({'success': False, 'message': 'No files selected'})
        
        u = current_user()
        user_home = get_user_home(u.id)
        
        uploaded_files = []
        error_files = []
        
        for file in files:
            if file.filename == '':
                continue
                
            try:
                # Security check - ensure path is within user's home
                target_path = Path(current_path) / file.filename
                if not str(target_path).startswith(str(HOME_DIR)):
                    error_files.append({'name': file.filename, 'error': 'Permission denied'})
                    continue
                
                # Check if file already exists
                if target_path.exists():
                    # Add timestamp to avoid overwriting
                    name_parts = target_path.stem, target_path.suffix
                    timestamp = int(time.time())
                    new_filename = f"{name_parts[0]}_{timestamp}{name_parts[1]}"
                    target_path = Path(current_path) / new_filename
                
                file.save(str(target_path))
                uploaded_files.append(file.filename)
                
            except Exception as e:
                error_files.append({'name': file.filename, 'error': str(e)})
        
        message = f"Uploaded {len(uploaded_files)} file(s) successfully"
        if error_files:
            message += f", {len(error_files)} file(s) failed"
        
        return jsonify({
            'success': True, 
            'message': message,
            'uploaded_files': uploaded_files,
            'error_files': error_files
        })
        
    except Exception as e:
        logger.error(f"Upload files error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.get("/api/download_file")
@login_required
@approved_required
def api_download_file():
    try:
        file_path = request.args.get('path', '')
        
        if not file_path:
            return jsonify({'success': False, 'message': 'No file specified'}), 400
        
        u = current_user()
        
        # Security check - ensure path is within user's home
        if not file_path.startswith(str(HOME_DIR)):
            return jsonify({'success': False, 'message': 'Permission denied'}), 403
        
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return jsonify({'success': False, 'message': 'File not found'}), 404
        
        return send_file(str(path), as_attachment=True)
        
    except Exception as e:
        logger.error(f"Download file error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.post("/api/delete_items")
@login_required
@approved_required
def api_delete_items():
    try:
        if not request.is_json:
            return jsonify({'success': False, 'message': 'Request must be JSON'}), 400
            
        data = request.get_json()
        items = data.get('items', [])
        
        if not items:
            return jsonify({'success': False, 'message': 'No items specified'})
        
        u = current_user()
        deleted_count = 0
        
        for item_path in items:
            try:
                # Security check - ensure path is within user's home
                if not item_path.startswith(str(HOME_DIR)):
                    continue
                
                path = Path(item_path)
                if path.exists():
                    if path.is_file():
                        path.unlink()
                    else:
                        import shutil
                        shutil.rmtree(path)
                    deleted_count += 1
            except:
                continue
        
        return jsonify({
            'success': True, 
            'message': f'Deleted {deleted_count} item(s)'
        })
        
    except Exception as e:
        logger.error(f"Delete items error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.post("/api/download_items")
@login_required
@approved_required
def api_download_items():
    try:
        if not request.is_json:
            return jsonify({'success': False, 'message': 'Request must be JSON'}), 400
            
        data = request.get_json()
        items = data.get('items', [])
        
        if not items:
            return jsonify({'success': False, 'message': 'No items specified'}), 400
        
        u = current_user()
        
        # Create in-memory zip file
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for item_path in items:
                try:
                    # Security check - ensure path is within user's home
                    if not item_path.startswith(str(HOME_DIR)):
                        continue
                    
                    path = Path(item_path)
                    if path.exists():
                        if path.is_file():
                            zip_file.write(str(path), path.name)
                        else:
                            for file_path in path.rglob('*'):
                                if file_path.is_file():
                                    arcname = file_path.relative_to(path.parent)
                                    zip_file.write(str(file_path), str(arcname))
                except:
                    continue
        
        zip_buffer.seek(0)
        return send_file(
            zip_buffer,
            as_attachment=True,
            download_name=f'files_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.zip',
            mimetype='application/zip'
        )
        
    except Exception as e:
        logger.error(f"Download items error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ---------------- Admin Panel ----------------

@app.get("/admin")
@login_required
@owner_required
def admin_panel():
    db = get_db()
    try:
        users = db.query(User).order_by(User.created_at.desc()).all()
        sessions = db.query(TerminalSession).order_by(TerminalSession.created_at.desc()).limit(50).all()
        
        # Get pending users count
        pending_users = [u for u in users if not u.approved and u.role != 'owner']
        
        # Get active terminal sessions count
        active_terminal_sessions = len([s for s in active_sessions.values()])
        
        # Get active TCP bots count
        active_tcp_bots = len([b for b in tcp_bots.values() if b['is_running']])
        
        return render_template("admin.html", 
                             users=users, 
                             sessions=sessions,
                             pending_users_count=len(pending_users),
                             active_terminal_sessions=active_terminal_sessions,
                             active_tcp_bots=active_tcp_bots)
    except Exception as e:
        logger.error(f"Admin panel error: {e}")
        flash("Error loading admin panel", "error")
        return redirect(url_for("dashboard"))
    finally:
        db.close()

@app.post("/admin/create_user")
@login_required
@owner_required
def admin_create_user():
    db = get_db()
    try:
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        approved = request.form.get("approved") == "on"
        expiry_str = request.form.get("expiry", "").strip()

        if not username or not password:
            flash("Username and password required", "error")
            return redirect(url_for("admin_panel"))

        exists = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if exists:
            flash("Username already exists", "error")
            return redirect(url_for("admin_panel"))

        expiry = None
        if expiry_str:
            try:
                expiry = datetime.strptime(expiry_str, "%Y-%m-%d").date()
            except ValueError:
                flash("Invalid expiry date format. Use YYYY-MM-DD", "error")
                return redirect(url_for("admin_panel"))

        u = User(
            username=username,
            password_hash=generate_password_hash(password),
            role="user",
            approved=approved,
            expiry=expiry
        )
        db.add(u)
        db.commit()
        
        # Create user home directory
        get_user_home(u.id)
        
        flash(f"User {username} created successfully!", "success")
        return redirect(url_for("admin_panel"))
    except Exception as e:
        logger.error(f"Admin create user error: {e}")
        flash("Error creating user", "error")
        return redirect(url_for("admin_panel"))
    finally:
        db.close()

@app.post("/admin/set_user_status/<int:user_id>")
@login_required
@owner_required
def admin_set_user_status(user_id):
    db = get_db()
    try:
        user = db.get(User, user_id)
        if not user:
            flash("User not found", "error")
            return redirect(url_for("admin_panel"))

        action = request.form.get("action")
        expiry_str = request.form.get("expiry", "").strip()

        if action == "approve":
            user.approved = True
            flash(f"User {user.username} approved", "success")
        elif action == "deny":
            user.approved = False
            flash(f"User {user.username} denied", "success")
        elif action == "delete":
            # Clean up user's data
            user_home = get_user_home(user_id)
            try:
                import shutil
                shutil.rmtree(user_home, ignore_errors=True)
            except:
                pass
            db.delete(user)
            flash(f"User {user.username} deleted", "success")
        
        if expiry_str:
            try:
                user.expiry = datetime.strptime(expiry_str, "%Y-%m-%d").date()
            except ValueError:
                flash("Invalid expiry date format", "error")

        db.commit()
        return redirect(url_for("admin_panel"))
    except Exception as e:
        logger.error(f"Admin set user status error: {e}")
        flash("Error updating user status", "error")
        return redirect(url_for("admin_panel"))
    finally:
        db.close()

@app.post("/admin/approve_all_pending")
@login_required
@owner_required
def admin_approve_all_pending():
    db = get_db()
    try:
        pending_users = db.execute(select(User).where(User.approved == False, User.role != "owner")).scalars().all()
        for user in pending_users:
            user.approved = True
        
        db.commit()
        flash(f"Approved {len(pending_users)} pending users", "success")
        return redirect(url_for("admin_panel"))
    except Exception as e:
        logger.error(f"Admin approve all error: {e}")
        flash("Error approving users", "error")
        return redirect(url_for("admin_panel"))
    finally:
        db.close()

@app.post("/admin/clear_all_sessions")
@login_required
@owner_required
def admin_clear_all_sessions():
    db = get_db()
    try:
        # Clear terminal sessions from memory
        for session_id in list(active_sessions.keys()):
            stop_terminal_process(session_id)
        active_sessions.clear()
        active_processes.clear()
        process_queues.clear()
        process_threads.clear()
        
        # Clear TCP bots
        for bot_id in list(tcp_bots.keys()):
            stop_tcp_bot(bot_id)
        tcp_bots.clear()
        tcp_bot_threads.clear()
        
        # Clear database sessions
        db.query(TerminalSession).delete()
        db.commit()
        
        flash("All sessions and TCP bots cleared", "success")
        return redirect(url_for("admin_panel"))
    except Exception as e:
        logger.error(f"Admin clear sessions error: {e}")
        flash("Error clearing sessions", "error")
        return redirect(url_for("admin_panel"))
    finally:
        db.close()

@app.post("/admin/delete_session/<int:session_id>")
@login_required
@owner_required
def admin_delete_session(session_id):
    db = get_db()
    try:
        session_obj = db.get(TerminalSession, session_id)
        if session_obj:
            db.delete(session_obj)
            db.commit()
            flash("Session deleted", "success")
        else:
            flash("Session not found", "error")
        return redirect(url_for("admin_panel"))
    except Exception as e:
        logger.error(f"Admin delete session error: {e}")
        flash("Error deleting session", "error")
        return redirect(url_for("admin_panel"))
    finally:
        db.close()

# ------------------- Main --------------------

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'message': 'Endpoint not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"500 Error: {e}")
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'message': 'Internal server error'}), 500
    return render_template('500.html'), 500

@app.errorhandler(502)
def bad_gateway(e):
    logger.error(f"502 Error: {e}")
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'message': 'Process timeout or server error'}), 502
    return render_template('500.html'), 502

# Cleanup function for expired sessions
def cleanup_old_sessions():
    """Clean up old terminal sessions"""
    while True:
        time.sleep(3600)  # Run every hour
        try:
            current_time = datetime.utcnow()
            sessions_to_remove = []
            
            for session_id, session_info in active_sessions.items():
                # Remove sessions older than 24 hours
                if (current_time - session_info['created_at']).total_seconds() > 86400:
                    sessions_to_remove.append(session_id)
            
            for session_id in sessions_to_remove:
                stop_terminal_process(session_id)
                # Delete session files
                try:
                    user_id = active_sessions[session_id]['user_id']
                    session_dir = TERMINAL_SESSIONS_DIR / f"user_{user_id}" / session_id
                    import shutil
                    shutil.rmtree(session_dir, ignore_errors=True)
                except:
                    pass
                
                # Remove from all dictionaries
                if session_id in active_sessions:
                    del active_sessions[session_id]
                if session_id in process_queues:
                    del process_queues[session_id]
                if session_id in process_threads:
                    del process_threads[session_id]
                if session_id in active_processes:
                    del active_processes[session_id]
                
        except Exception as e:
            logger.error(f"Error in session cleanup: {e}")

# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_old_sessions, daemon=True)
cleanup_thread.start()

if __name__ == "__main__":
    print("🚀 Starting DANGER HOSTING Platform...")
    print(f"📁 Data Directory: {DATA_DIR}")
    print(f"🔗 Database: {DB_PATH}")
    print("🤖 TCP Bot Management: FIXED & ENABLED")
    print("🔄 Auto Cleanup: Enabled (3 hours for TCP bots, 24 hours for sessions)")
    print("🔧 Path Resolution: Fixed for storage/shared/TCP-BOT/")
    print("✅ Server is running on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False, threaded=True)