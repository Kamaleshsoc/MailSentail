# MailSentinel quality-fix release

## Fixed
- Excluded attachment parts from the email body so attached text cannot create false body-language findings.
- Added attachment filename risk tiers: executable/script extensions are high-risk; HTML/HTM/SVG and macro-enabled Office files require active-content review; other files are not automatically declared safe.
- Added attachment byte size and SHA-256 fingerprint metadata without executing or extracting attachments.
- Separated SPF/DKIM/DMARC results into unverified authentication signals, not attack categories.
- Added explicit source and verification caveats to authentication checks; supplied headers are not independently validated.
- Rebalanced and capped score contributions by signal family. Critical scores no longer reach 100 merely because several related authentication checks failed.
- Improved sender/recipient address extraction for the investigation report.
- Expanded saved case reports with email overview, authentication, URLs, attachment metadata/hash, original headers and remediation recommendations.
- Excluded legacy authentication-failure indicators from threat-type chart and threat activity counts.
- Changed the dashboard KPI wording from “Malicious Emails” to “Critical / High Risk” to distinguish heuristic classification from confirmed malware.
- Improved dashboard KPI spacing and recent-event table wrapping; added a clear HTTP 413 message for oversized uploads.

## Verification performed in this build environment
- Python bytecode compilation: passed for application modules and tests.
- Dashboard JavaScript syntax check (`node --check`): passed.
- Direct analyzer test with a synthetic multipart phishing email: passed; produced Critical 86/100, parsed sender/subject, kept attachment content out of body, generated attachment SHA-256 and marked SPF/DKIM/DMARC as unverified.
- Full Flask/pytest integration suite: not run here because Flask dependencies are not installed in the build environment and package download access is unavailable. Run `python -m pytest -q` on the Windows machine after setup.
