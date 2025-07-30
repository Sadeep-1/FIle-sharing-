import os
import base64
import io
from flask import request, jsonify, session, send_file
from werkzeug.utils import secure_filename
from .models import User, SignedDocument, ActivityLog, SharedDocument
from .database import db
from .utils import symmetric_sign_file, symmetric_decrypt_file
import json

UPLOAD_DIR = 'uploads'
SIGNED_DIR = 'signed_docs'

def init_routes(app):
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(SIGNED_DIR, exist_ok=True)

    @app.route('/register', methods=['POST'])
    def register():
        username = request.form.get('username', '').strip()
        pin = request.form.get('pin', '').strip()

        if not username or not pin or len(pin) != 4 or not pin.isdigit():
            return jsonify({'error': 'Username and 4-digit PIN required'}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400

        user = User(username=username)
        user.set_pin(pin)

        db.session.add(user)
        db.session.add(ActivityLog(username=username, action="register", details="User registered"))
        db.session.commit()

        return jsonify({'message': 'Registered successfully'})

    @app.route('/login', methods=['POST'])
    def login():
        username = request.form.get('username', '').strip()
        pin = request.form.get('pin', '').strip()

        if not username or not pin:
            return jsonify({'error': 'Username and PIN required'}), 400

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_pin(pin):
            return jsonify({'error': 'Invalid username or PIN'}), 401

        session['username'] = username
        session['pin'] = pin  # Store PIN in session for signing/encryption

        db.session.add(ActivityLog(username=username, action="login", details="User logged in"))
        db.session.commit()

        return jsonify({'message': 'Login successful'})

    @app.route('/users', methods=['GET'])
    def get_users():
        if 'username' not in session:
            return jsonify({'error': 'Unauthorized'}), 403
        users = User.query.with_entities(User.username).all()
        usernames = [u.username for u in users if u.username != session['username']]
        return jsonify({'users': usernames})

    @app.route('/sign', methods=['POST'])
    def sign_file():
        if 'username' not in session or 'pin' not in session:
            return jsonify({'error': 'Unauthorized'}), 403

        file = request.files.get('file')
        if not file:
            return jsonify({'error': 'File is required'}), 400

        filename = secure_filename(file.filename)
        username = session['username']
        temp_path = os.path.join(UPLOAD_DIR, filename)
        file.save(temp_path)

        # Symmetric sign using username + pin
        signature = symmetric_sign_file(temp_path, username, session['pin'])
        sig_path = os.path.join(SIGNED_DIR, f"{filename}.sig")
        with open(sig_path, 'wb') as sf:
            sf.write(signature)

        record = SignedDocument(
            filename=filename,
            signature_path=sig_path,
            signed_by=username
        )
        db.session.add(record)
        db.session.add(ActivityLog(username=username, action="sign", details=f"Signed file: {filename}"))
        db.session.commit()

        os.remove(temp_path)

        return jsonify({
            'message': 'File signed successfully',
            'signature': base64.b64encode(signature).decode(),
            'signature_path': sig_path
        })

    @app.route('/share', methods=['POST'])
    def share_file():
        if 'username' not in session:
            return jsonify({'error': 'Unauthorized'}), 403

        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400

        recipient = data.get('recipient')
        file_path = data.get('file_path')

        if not recipient or not file_path:
            return jsonify({'error': 'Missing recipient or file_path'}), 400

        recipient_user = User.query.filter_by(username=recipient).first()
        if not recipient_user:
            return jsonify({'error': 'Recipient user not found'}), 404

        file_basename = secure_filename(os.path.basename(file_path))

        signed_doc = SignedDocument.query.filter_by(filename=file_basename, signed_by=session['username']).first()
        if not signed_doc:
            return jsonify({'error': 'You do not own this file or file not signed'}), 403

        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404

        shared_record = SharedDocument(sender=session['username'], recipient=recipient, file_path=file_path)
        db.session.add(shared_record)
        db.session.add(ActivityLog(username=session['username'], action="share", details=f"Shared {file_path} with {recipient}"))
        db.session.commit()

        return jsonify({'message': f'File shared with {recipient}'})

    @app.route('/shared_files', methods=['GET'])
    def list_shared_files():
        if 'username' not in session:
            return jsonify({'error': 'Unauthorized'}), 403

        username = session['username']
        shared_files = SharedDocument.query.filter_by(recipient=username).all()
        result = []
        for sf in shared_files:
            result.append({
                'id': sf.id,
                'sender': sf.sender,
                'file_path': sf.file_path,
                'shared_at': sf.shared_at.isoformat()
            })
        return jsonify({'shared_files': result})

    @app.route('/download_shared/<int:shared_id>', methods=['POST'])
    def download_shared_file(shared_id):
        if 'username' not in session or 'pin' not in session:
            return jsonify({'error': 'Unauthorized'}), 403

        user = User.query.filter_by(username=session['username']).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        shared_record = SharedDocument.query.filter_by(id=shared_id, recipient=user.username).first()
        if not shared_record:
            return jsonify({'error': 'Shared file not found or access denied'}), 404

        if not os.path.exists(shared_record.file_path):
            return jsonify({'error': 'File missing on server'}), 404

        decrypted_content = symmetric_decrypt_file(shared_record.file_path, user.username, session['pin'])

        decrypted_bytes_io = io.BytesIO(decrypted_content)
        decrypted_bytes_io.seek(0)

        db.session.add(ActivityLog(username=user.username, action="download_shared", details=f"Downloaded shared file {shared_record.file_path}"))
        db.session.commit()

        return send_file(
            decrypted_bytes_io,
            as_attachment=True,
            download_name=f"decrypted_{secure_filename(os.path.basename(shared_record.file_path))}",
            mimetype='application/octet-stream'
        )

    @app.route('/logout', methods=['POST'])
    def logout():
        session.clear()
        return jsonify({'message': 'Logged out'})
