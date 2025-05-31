from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Initialize SQLAlchemy
# configure the database URI and call db.init_app(app)
db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    history = db.relationship('UserHistory', backref='user', lazy=True)

class UserHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class PacketLog(db.Model):
    __tablename__ = 'packet_logs'
    id = db.Column(db.Integer, primary_key=True)
    protocol = db.Column(db.String(50))
    src = db.Column(db.String(100))
    dst = db.Column(db.String(100))
    dns = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class VulnerabilityScan(db.Model):
    __tablename__ = 'vulnerability_scans'
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255), nullable=False)
    result = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class PhishingCheck(db.Model):
    __tablename__ = 'phishing_checks'
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2083), nullable=False)
    is_phishing = db.Column(db.Boolean)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class HashLog(db.Model):
    __tablename__ = 'hash_logs'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text)
    algorithm = db.Column(db.String(50))
    hash = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
