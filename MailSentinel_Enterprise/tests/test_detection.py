import json
from datetime import datetime, timedelta

import pytest
from app import create_app, db
from app.services.analyzer import EmailAnalyzerService
from app.models.email_record import EmailRecord

@pytest.fixture
def app():
    app = create_app('testing')
    with app.app_context():
        db.drop_all()
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

def test_high_risk_email_has_explainable_findings():
    raw = ("From: attacker@evil.example\nTo: analyst@company.example\n"
           "Reply-To: harvest@other.example\nSubject: Urgent verify your banking account now!\n"
           "Authentication-Results: mx; spf=fail; dkim=fail\n\n"
           "Click https://192.0.2.10/login to verify your password.")
    result = EmailAnalyzerService.analyze_raw_content(raw)
    assert result['risk_level'] in ('High', 'Critical')
    assert result['threat_score'] >= 65
    assert any('Reply-To' in item['title'] for item in result['indicators'])
    assert result['remediation']

def test_clean_email_has_no_rule_hits():
    result = EmailAnalyzerService.analyze_raw_content(
        "From: colleague@example.com\nTo: me@example.com\nSubject: Meeting notes\n\nPlease see the notes."
    )
    assert result['risk_level'] == 'Low'
    assert result['threat_score'] == 0

def test_empty_email_rejected():
    with pytest.raises(ValueError):
        EmailAnalyzerService.analyze_raw_content(" ")

def test_dashboard_and_analyze_pages(client):
    assert client.get('/').status_code == 200
    assert client.get('/analyze/').status_code == 200
    assert client.get('/history/').status_code == 200

def test_api_analyze(client):
    response = client.post('/api/analyze', json={'raw_content': 'Subject: Test\n\nHello world'})
    assert response.status_code == 200
    assert 'threat_score' in response.get_json()
    assert 'remediation' in response.get_json()

def test_api_rejects_invalid_payload(client):
    response = client.post('/api/analyze', json={'wrong': 'field'})
    assert response.status_code == 400

def test_dashboard_renders_enterprise_chart_sections(client):
    response = client.get('/')
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert 'Threat Type Breakdown' in page
    assert 'Remediation Breakdown' in page
    assert 'Threat Activity Over Time' in page
    assert 'data-period="daily"' in page
    assert 'data-period="weekly"' in page
    assert 'data-period="monthly"' in page
    assert 'dashboard.js' in page


def test_activity_api_supports_all_periods(client):
    for period in ('daily', 'weekly', 'monthly'):
        response = client.get(f'/api/dashboard/activity?period={period}')
        assert response.status_code == 200
        data = response.get_json()
        assert data['period'] == period
        assert len(data['labels']) == len(data['emails'])
        assert len(data['emails']) == len(data['threats'])
        assert len(data['threats']) == len(data['suspicious'])
        assert data['source'] == 'local_database'


def test_activity_api_rejects_unknown_period(client):
    response = client.get('/api/dashboard/activity?period=yearly')
    assert response.status_code == 400
    assert 'error' in response.get_json()


def test_dashboard_charts_use_saved_database_records(client, app):
    with app.app_context():
        record = EmailRecord(
            filename='sample.eml', sender='attacker@example.test',
            recipient='analyst@example.test', subject='Urgent account verification',
            threat_score=88, risk_level='Critical',
            analysis_summary='Reply-To mismatch; credential request',
            analysis_json=json.dumps({'indicators': [
                {'category': 'Sender identity', 'title': 'Reply-To mismatch'},
                {'category': 'Credential theft', 'title': 'Credential harvesting'},
                {'category': 'URL reputation', 'title': 'Raw IP URL'},
            ]}),
            created_at=datetime.utcnow() - timedelta(days=1),
        )
        db.session.add(record)
        db.session.commit()

    page = client.get('/').get_data(as_text=True)
    assert 'Email Investigations' in page
    assert 'Threat Type Breakdown' in page
    assert 'Sender Spoofing' in page
    assert 'Credential Theft' in page
    assert 'Malicious URLs' in page

    activity = client.get('/api/dashboard/activity?period=daily').get_json()
    assert sum(activity['emails']) == 1
    assert sum(activity['threats']) == 1
    assert sum(activity['suspicious']) == 0


def test_authentication_failures_are_not_threat_type_categories(client, app):
    from app.blueprints.main import _threat_counts
    with app.app_context():
        record = EmailRecord(
            filename='auth-signal.eml', sender='sender@example.test',
            recipient='analyst@example.test', subject='Authentication test',
            threat_score=24, risk_level='Medium',
            analysis_json=json.dumps({'indicators': [
                {'category': 'Authentication Signal', 'title': 'SPF reported fail'},
                {'category': 'Authentication Signal', 'title': 'DKIM reported fail'},
                {'category': 'Credential Theft', 'title': 'Credential request'},
            ]}),
        )
        db.session.add(record)
        db.session.commit()
        categories = _threat_counts([record])
        assert categories == [{'label': 'Credential Theft', 'value': 1}]


def test_attachment_is_not_mixed_into_body_and_html_is_flagged():
    from email.message import EmailMessage
    from email.policy import SMTP
    message = EmailMessage()
    message['From'] = 'security@example.test'
    message['To'] = 'analyst@example.test'
    message['Subject'] = 'Please review this notice'
    message.set_content('This is the visible email body.')
    message.add_attachment(
        b'This string belongs to the attached file, not the message body.',
        maintype='text', subtype='html', filename='Security_Update.html'
    )
    result = EmailAnalyzerService.analyze_raw_content(message.as_string(policy=SMTP), 'sample.eml')
    assert 'attached file' not in result['raw_body']
    assert len(result['attachments']) == 1
    assert result['attachments'][0]['risk'] == 'medium'
    assert result['attachments'][0]['sha256']
    assert any(item['category'] == 'Suspicious Attachments' for item in result['indicators'])


def test_authentication_results_are_explicitly_unverified_and_capped():
    raw = (
        'From: "Microsoft 365 Security Team" <security-alerts@account-protection.example>\n'
        'To: analyst@your-company.example\n'
        'Reply-To: credential-review@external-mail.example\n'
        'Return-Path: <bounce@bulk-notifications.example>\n'
        'Subject: URGENT: Your Microsoft 365 account will be suspended - verify immediately\n'
        'Authentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail\n\n'
        'Your mailbox will be suspended. Verify your password and one-time verification code now.\n'
        'http://192.0.2.10/microsoft365/verify-account\n'
    )
    result = EmailAnalyzerService.analyze_raw_content(raw)
    assert result['risk_level'] == 'High'
    assert 65 <= result['threat_score'] < 100
    assert all(check['verified'] is False for check in result['authentication_checks'])
    assert all('not independently verified' in check['detail'] for check in result['authentication_checks'])


def test_no_authentication_headers_are_unknown_not_failed():
    result = EmailAnalyzerService.analyze_raw_content(
        'From: colleague@example.test\nTo: analyst@example.test\nSubject: Meeting notes\n\nSee you at 10.'
    )
    assert [item['status'] for item in result['authentication_checks']] == ['Unknown', 'Unknown', 'Unknown']
    assert result['threat_score'] == 0
