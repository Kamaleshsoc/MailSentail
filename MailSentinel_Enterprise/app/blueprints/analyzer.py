import json
from flask import Blueprint, render_template, request, redirect, flash, current_app, url_for
from werkzeug.utils import secure_filename
from app import db
from app.models.email_record import EmailRecord
from app.services.analyzer import EmailAnalyzerService

analyzer_bp = Blueprint('analyzer', __name__)
ALLOWED_EXTENSIONS = {'.eml', '.txt'}

@analyzer_bp.route('/', methods=['GET', 'POST'])
def analyze():
    if request.method == 'POST':
        raw_text, filename = "", None
        uploaded = request.files.get('email_file')
        if uploaded and uploaded.filename:
            safe_name = secure_filename(uploaded.filename)
            ext = '.' + safe_name.rsplit('.', 1)[-1].lower() if '.' in safe_name else ''
            if ext not in ALLOWED_EXTENSIONS:
                flash('Unsupported file type. Upload an .eml or .txt email source.', 'danger')
                return redirect(url_for('analyzer.analyze'))
            data = uploaded.stream.read(current_app.config['MAX_CONTENT_LENGTH'] + 1)
            if len(data) > current_app.config['MAX_CONTENT_LENGTH']:
                flash('File exceeds the 10 MB upload limit.', 'danger')
                return redirect(url_for('analyzer.analyze'))
            raw_text = data.decode('utf-8-sig', errors='replace')
            filename = safe_name
        else:
            raw_text = request.form.get('raw_content', '').strip()

        if not raw_text:
            flash('Upload an email file or paste the raw email source.', 'warning')
            return redirect(url_for('analyzer.analyze'))
        try:
            analysis = EmailAnalyzerService.analyze_raw_content(raw_text, filename)
            record = EmailRecord(
                filename=analysis['filename'], sender=analysis['sender'],
                recipient=analysis['recipient'], subject=analysis['subject'],
                threat_score=analysis['threat_score'], risk_level=analysis['risk_level'],
                analysis_summary=analysis['analysis_summary'],
                raw_headers=json.dumps(analysis['headers'], ensure_ascii=False),
                analysis_json=json.dumps(analysis, ensure_ascii=False)
            )
            db.session.add(record)
            db.session.commit()
            return render_template('result.html', analysis=analysis, record_id=record.id)
        except ValueError as exc:
            flash(str(exc), 'warning')
            return redirect(url_for('analyzer.analyze'))
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Email analysis failed")
            flash('Analysis could not be completed. Check the server log for details.', 'danger')
            return redirect(url_for('analyzer.analyze'))
    return render_template('analyze.html')

@analyzer_bp.route('/report/<int:record_id>')
def report(record_id):
    record = db.session.get(EmailRecord, record_id)
    if not record:
        return render_template('error.html', code=404, message="Report not found."), 404
    try:
        analysis = json.loads(record.analysis_json) if record.analysis_json else None
    except (TypeError, ValueError):
        analysis = None
    return render_template('report.html', record=record, analysis=analysis)
