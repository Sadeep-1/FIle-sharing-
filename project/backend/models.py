# backend/models.py
from .database import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    pin_hash = db.Column(db.String(255), nullable=True)
    public_key = db.Column(db.LargeBinary, nullable=True)
    certificate = db.Column(db.LargeBinary, nullable=True)
    revoked = db.Column(db.Boolean, default=False)

    def set_pin(self, pin: str):
        self.pin_hash = generate_password_hash(pin)

    def check_pin(self, pin: str) -> bool:
        return check_password_hash(self.pin_hash, pin) if self.pin_hash else False

class SignedDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    signature_path = db.Column(db.String(255), nullable=False)
    signed_by = db.Column(db.String(150), db.ForeignKey('user.username'), nullable=False)
    signed_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='signed_documents')

class SharedDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(150), db.ForeignKey('user.username'), nullable=False)
    recipient = db.Column(db.String(150), db.ForeignKey('user.username'), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    iv_path = db.Column(db.String(255), nullable=False)
    key_path = db.Column(db.String(255), nullable=False)
    shared_at = db.Column(db.DateTime, default=datetime.utcnow)
    sender_user = db.relationship('User', foreign_keys=[sender], backref='sent_documents')
    recipient_user = db.relationship('User', foreign_keys=[recipient], backref='received_documents')

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), db.ForeignKey('user.username'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    details = db.Column(db.String(512), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='activity_logs')