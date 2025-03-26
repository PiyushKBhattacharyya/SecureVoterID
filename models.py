from app import db
from datetime import datetime

class Voter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    face_encoding = db.Column(db.Text, nullable=False)  # JSON string of face encoding
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_verified = db.Column(db.DateTime, nullable=True)
    verification_count = db.Column(db.Integer, default=0)
    
    def __repr__(self):
        return f'<Voter {self.name}>'
