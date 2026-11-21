# MailSentinel — Enterprise-style Email Threat Investigation Platform

MailSentinel is a local Flask application for explainable, rule-based phishing-email triage. The interface is inspired by enterprise email-security and SOC dashboards; it is an independent educational project, not a Proofpoint product or a deployed enterprise mail gateway.

## Features

- Dark enterprise-style dashboard with database-backed Critical, High, Medium and Low counts. The Critical / High KPI describes heuristic risk classifications, not independently confirmed malware.
- Threat Type Breakdown doughnut chart generated from actual saved detection indicators.
- Remediation Breakdown doughnut chart showing recommended analyst handling by risk level. It does not claim to quarantine or remediate messages.
- Threat Activity Over Time chart with working Daily, Weekly and Monthly filters. Series show emails analyzed, emails with at least one detection indicator, and Medium-risk emails.
- Recent Security Events with links to detailed investigation reports.
- Upload `.eml` / `.txt` email source or paste raw email source.
- Email header, sender, recipient, Reply-To, Return-Path, SPF/DKIM/DMARC submitted-header signal review, URL extraction, attachment metadata and SHA-256 fingerprints, explainable findings, capped 0–100 heuristic score and response recommendations.
- Authentication failures are displayed as authentication signals and are not counted as threat attack categories. HTML/HTM/SVG and macro-enabled Office attachments are flagged for analyst review; executable/script extensions receive a higher-risk label. The analyzer never executes or extracts an attachment.
- SQLite persistence, investigation history, search/filter, JSON analysis API, CSRF protection for browser forms, file extension allowlist, secure filenames and 10 MB request limit.
- Dashboard charts are rendered with local JavaScript and SVG; chart rendering does not require Chart.js or a chart CDN.

## Windows PowerShell setup

1. Extract the ZIP into a normal folder, for example `C:\Users\YourName\Downloads\MailSentinel_Enterprise`.
2. Open PowerShell in that folder.
3. Run the installer:

```powershell
.\install_windows.bat
```

4. Start the local website:

```powershell
.\start_mailsentinel.bat
```

5. Open this address in your browser:

```text
http://127.0.0.1:5000
```

Keep the terminal open while using the website. The app is local; it does not need an external hosting provider. The first install needs an internet connection to download Python dependencies. After installation, dashboard chart rendering itself is local.

### Manual setup (if needed)

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
$env:FLASK_CONFIG = "development"
$env:SECRET_KEY = "replace-this-with-a-long-random-local-secret"
python -m flask --app "app:create_app('development')" run --debug
```

If PowerShell blocks script activation, use Command Prompt and run `venv\Scripts\activate.bat`, then continue with `pip install -r requirements.txt`.

## Tests

After dependencies are installed:

```powershell
python -m pytest -q
```

The test suite covers suspicious and clean email scoring, invalid input, dashboard rendering, all three activity periods, invalid period handling, and aggregation from a saved database record.

## Dashboard data definitions

- **Emails analyzed:** number of saved records in the local SQLite database.
- **Threat Type Breakdown:** counts of saved attack-related indicators grouped by detection category. Authentication signals are excluded from attack categories. One email may contribute multiple indicators.
- **Remediation Breakdown:** counts of saved records by risk level, labelled as recommended handling only.
- **Emails analyzed:** all saved records grouped by date/week/month.
- **Threats detected:** saved emails with at least one configured detection indicator.
- **Suspicious:** Medium-risk saved emails.
- **Spam:** no separate spam classifier is currently implemented, so the dashboard does not invent a spam count.

## Important limitations

This version uses static, explainable heuristics. It is not a trained machine-learning model and is not connected to Microsoft 365, Google Workspace, Proofpoint, a mail gateway, a SIEM, EDR, live URL/domain reputation services or a detonation sandbox. SPF/DKIM/DMARC values are read from the submitted `Authentication-Results` header and are not independently verified; that header can be forged. Attachments are classified by filename and MIME metadata; SHA-256 is calculated from the encoded attachment payload without executing it. Extension classification is a triage signal, not proof of malware. A low score does not prove an email is safe. Recommended quarantine/block actions are instructions for an authorized analyst; the application does not perform them.

Before organizational deployment, implement authentication and role-based access, HTTPS, hardened production configuration, database migrations/backups, audit logging, retention controls, secure file isolation, trusted gateway integration, independent authentication verification, threat-intelligence connectors and a reviewed detection test corpus. Do not expose the Flask development server directly to the internet.
