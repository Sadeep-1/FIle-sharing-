import os
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from .models import User, SharedDocument, ActivityLog
from .database import db
from datetime import datetime

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'uploads')
SIGNED_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'signed_docs')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)

def create_app():
    template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))
    app = Flask(__name__, template_folder=template_dir)

    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_secret")

    instance_path = os.path.join(os.path.dirname(__file__), '..', 'instance')
    os.makedirs(instance_path, exist_ok=True)
    db_path = os.path.join(instance_path, 'users.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    with app.app_context():
        db.create_all()

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/register_page')
    def register_page():
        return render_template('register.html')

    @app.route('/login_page')
    def login_page():
        return render_template('login.html')

    @app.route('/sign_page')
    def sign_page():
        if 'username' not in session:
            return redirect(url_for('login_page'))

        users = User.query.all()
        logs = ActivityLog.query.filter_by(username=session['username']).order_by(ActivityLog.timestamp.desc()).limit(10).all()
        current_user = session['username']
        received_docs = SharedDocument.query.filter_by(recipient=current_user).order_by(SharedDocument.shared_at.desc()).all()
        return render_template('sign.html', users=users, logs=logs, current_user=current_user, received_docs=received_docs)

    @app.route('/register', methods=['POST'])
    def register():
        username = request.form.get('username', '').strip()
        pin = request.form.get('pin', '').strip()

        if not username or not pin:
            return jsonify(error="Username and 4-digit PIN are required."), 400

        if len(pin) != 4 or not pin.isdigit():
            return jsonify(error="PIN must be exactly 4 digits."), 400

        if User.query.filter_by(username=username).first():
            return jsonify(error="Username already registered. Please login."), 400

        new_user = User(username=username)
        new_user.set_pin(pin)
        db.session.add(new_user)
        db.session.commit()
        return jsonify(message="Registered successfully!"), 200

    @app.route('/login', methods=['POST'])
    def login():
        username = request.form.get('username', '').strip()
        pin = request.form.get('pin', '').strip()

        if not username or not pin:
            return jsonify(error="Username and PIN are required."), 400

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_pin(pin):
            return jsonify(error="Invalid username or PIN."), 401

        session['username'] = username
        return jsonify(message=f"Welcome, {username}!"), 200

    @app.route('/sign', methods=['POST'])
    def sign():
        if 'username' not in session:
            return jsonify(error="Unauthorized. Please login."), 401

        file = request.files.get('file')
        recipient = request.form.get('recipient')
        sender = session['username']

        if not file or file.filename == '':
            return jsonify(error="No file selected."), 400

        if not recipient:
            return jsonify(error="Recipient is required."), 400

        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        signed_path = os.path.join(SIGNED_FOLDER, filename)
        with open(file_path, 'rb') as f_src, open(signed_path, 'wb') as f_dst:
            f_dst.write(f_src.read())

        # Log action
        log = ActivityLog(
            username=sender,
            action="Signed and shared document",
            details=f"Shared '{filename}' with {recipient}"
        )
        db.session.add(log)

        # Save shared document
        shared_doc = SharedDocument(
            sender=sender,
            recipient=recipient,
            file_path=signed_path,
            iv_path='',
            key_path=''
        )
        db.session.add(shared_doc)
        db.session.commit()

        return jsonify(message=f"Document '{filename}' signed and shared with {recipient}.")

    @app.route('/download/<int:file_id>')
    def download(file_id):
        if 'username' not in session:
            return redirect(url_for('login_page'))

        doc = SharedDocument.query.get_or_404(file_id)
        if doc.recipient != session['username']:
            return "Unauthorized", 403

        return send_file(doc.file_path, as_attachment=True)

    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login_page'))

    return app
