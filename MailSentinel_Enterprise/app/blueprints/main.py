import json
from collections import Counter
from datetime import date, timedelta

from flask import Blueprint, jsonify, render_template, request

from app.models.email_record import EmailRecord

main_bp = Blueprint('main', __name__)

THREAT_CATEGORY_MAP = {
    'sender identity': 'Sender Spoofing',
    'email authentication': 'Authentication Signal',
    'authentication signal': 'Authentication Signal',
    'authentication failure': 'Authentication Signal',
    'credential theft': 'Credential Theft',
    'social engineering': 'Social Engineering',
    'url reputation': 'Malicious URLs',
    'attachment risk': 'Suspicious Attachments',
    'financial fraud': 'Financial Fraud',
    'phishing': 'Phishing',
}


def _snapshot(record):
    try:
        value = json.loads(record.analysis_json or '{}')
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def _threat_counts(records):
    counts = Counter()
    for record in records:
        for indicator in (_snapshot(record).get('indicators') or []):
            if not isinstance(indicator, dict):
                continue
            category = str(indicator.get('category') or 'Other').strip().lower()
            # Authentication results are evidence about mail delivery/authentication,
            # not an attack type; keep them out of the threat-category doughnut.
            if category in ('email authentication', 'authentication signal', 'authentication failure'):
                continue
            label = THREAT_CATEGORY_MAP.get(category, category.title())
            counts[label] += 1
    order = ['Phishing', 'Sender Spoofing', 'Credential Theft', 'Malicious URLs',
             'Financial Fraud', 'Suspicious Attachments', 'Social Engineering']
    return [{'label': label, 'value': counts.pop(label)} for label in order if counts.get(label)] + [
        {'label': label, 'value': value} for label, value in counts.most_common()
    ]


def _activity(records, period):
    today = date.today()
    if period == 'weekly':
        start = today - timedelta(days=7 * 11 + today.weekday())
        buckets = []
        cursor = start
        while cursor <= today:
            week_start = cursor - timedelta(days=cursor.weekday())
            if not buckets or buckets[-1]['key'] != week_start.isoformat():
                buckets.append({'key': week_start.isoformat(), 'label': week_start.strftime('%d %b'),
                                'emails': 0, 'threats': 0, 'suspicious': 0})
            cursor += timedelta(days=7)
    elif period == 'monthly':
        first = date(today.year, today.month, 1)
        buckets = []
        year, month = first.year, first.month
        for _ in range(11, -1, -1):
            y, m = year, month - _
            while m <= 0:
                y -= 1
                m += 12
            buckets.append({'key': f'{y:04d}-{m:02d}', 'label': date(y, m, 1).strftime('%b %y'),
                            'emails': 0, 'threats': 0, 'suspicious': 0})
    else:
        start = today - timedelta(days=13)
        buckets = [{'key': (start + timedelta(days=i)).isoformat(),
                    'label': (start + timedelta(days=i)).strftime('%d %b'),
                    'emails': 0, 'threats': 0, 'suspicious': 0} for i in range(14)]

    by_key = {item['key']: item for item in buckets}
    for record in records:
        if not record.created_at:
            continue
        created = record.created_at.date()
        if period == 'weekly':
            key = (created - timedelta(days=created.weekday())).isoformat()
        elif period == 'monthly':
            key = created.strftime('%Y-%m')
        else:
            key = created.isoformat()
        item = by_key.get(key)
        if item is None:
            continue
        item['emails'] += 1
        snapshot = _snapshot(record)
        threat_indicators = [i for i in (snapshot.get('indicators') or [])
                             if isinstance(i, dict) and str(i.get('category', '')).lower() not in ('email authentication', 'authentication signal', 'authentication failure')]
        if threat_indicators:
            item['threats'] += 1
        if record.risk_level == 'Medium':
            item['suspicious'] += 1
    return buckets


@main_bp.route('/')
def index():
    records = EmailRecord.query.order_by(EmailRecord.created_at.desc()).all()
    risk_counts = Counter(record.risk_level for record in records)
    threat_types = _threat_counts(records)
    return render_template(
        'index.html', total=len(records), critical=risk_counts.get('Critical', 0),
        high=risk_counts.get('High', 0), medium=risk_counts.get('Medium', 0),
        low=risk_counts.get('Low', 0), recent=records[:8], threat_types=threat_types,
        threat_total=sum(item['value'] for item in threat_types),
        remediation=[
            {'label': 'Containment recommended', 'value': risk_counts.get('Critical', 0) + risk_counts.get('High', 0), 'color': '#df5876'},
            {'label': 'Analyst review', 'value': risk_counts.get('Medium', 0), 'color': '#dcb65d'},
            {'label': 'Routine review', 'value': risk_counts.get('Low', 0), 'color': '#50b99a'},
        ],
        risk_counts=risk_counts,
    )


@main_bp.route('/api/dashboard/activity')
def dashboard_activity():
    period = request.args.get('period', 'daily').lower()
    if period not in ('daily', 'weekly', 'monthly'):
        return jsonify({'error': 'period must be daily, weekly or monthly'}), 400
    records = EmailRecord.query.all()
    rows = _activity(records, period)
    return jsonify({
        'period': period,
        'labels': [row['label'] for row in rows],
        'emails': [row['emails'] for row in rows],
        'threats': [row['threats'] for row in rows],
        'suspicious': [row['suspicious'] for row in rows],
        'source': 'local_database',
    })


@main_bp.route('/about')
def about():
    return render_template('about.html')
