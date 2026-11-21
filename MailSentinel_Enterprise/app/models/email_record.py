from datetime import datetime
from app import db

class EmailRecord(db.Model):
    __tablename__ = 'email_records'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=True)
    sender = db.Column(db.String(255), nullable=True)
    recipient = db.Column(db.String(255), nullable=True)
    subject = db.Column(db.String(512), nullable=True)
    threat_score = db.Column(db.Float, default=0.0)
    risk_level = db.Column(db.String(50), default='Low')
    analysis_summary = db.Column(db.Text, nullable=True)
    raw_headers = db.Column(db.Text, nullable=True)
    analysis_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'filename': self.filename, 'sender': self.sender,
            'recipient': self.recipient, 'subject': self.subject,
            'threat_score': self.threat_score, 'risk_level': self.risk_level,
            'analysis_summary': self.analysis_summary,
            'created_at': self.created_at.isoformat()
        }
