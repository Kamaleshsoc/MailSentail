from flask import Blueprint, render_template, request
from app.models.email_record import EmailRecord

history_bp = Blueprint('history', __name__)

@history_bp.route('/')
def index():
    query = EmailRecord.query
    risk = request.args.get('risk', '').strip()
    search = request.args.get('q', '').strip()
    if risk in ('Critical', 'High', 'Medium', 'Low'):
        query = query.filter_by(risk_level=risk)
    if search:
        like = f"%{search}%"
        query = query.filter(
            db_or(EmailRecord.subject.ilike(like), EmailRecord.sender.ilike(like),
                  EmailRecord.filename.ilike(like))
        )
    records = query.order_by(EmailRecord.created_at.desc()).limit(250).all()
    return render_template('history.html', records=records, risk=risk, search=search)

def db_or(*conditions):
    from sqlalchemy import or_
    return or_(*conditions)
