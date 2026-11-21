"""Local, explainable email triage. Never opens URLs or executes attachments."""
import hashlib
import ipaddress
import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from urllib.parse import urlparse

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'()]+")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "cutt.ly", "ow.ly", "buff.ly"}
URGENT = {"urgent", "immediately", "within 24 hours", "suspended", "suspend", "final warning", "action required", "verify now", "unusual activity", "account locked"}
CREDENTIALS = {"password", "login", "sign in", "verify", "credential", "account details", "mfa", "verification code", "one-time code"}
PAYMENT = {"wire transfer", "payment overdue", "invoice attached", "gift card", "banking details"}
# These extensions are flagged for analyst review; filename alone never proves malware.
HIGH_RISK_EXT = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".iso", ".img", ".lnk", ".msi", ".dll", ".jar", ".reg")
ACTIVE_CONTENT_EXT = (".html", ".htm", ".svg", ".docm", ".xlsm", ".pptm", ".xlam")


def _mailbox(value):
    display, address = parseaddr(str(value or ""))
    return display.strip(), address.strip()


def _domain(value):
    _, address = _mailbox(value)
    return address.rsplit("@", 1)[-1].lower().strip().rstrip(".") if "@" in address else ""


class EmailAnalyzerService:
    """Static heuristics for SOC learning; no network reputation or live auth checks."""

    @staticmethod
    def _body(msg):
        chunks = []
        parts = msg.walk() if msg.is_multipart() else [msg]
        for part in parts:
            if part.get_content_maintype() == "multipart":
                continue
            # Do not mix attached text/HTML files into the message body evidence.
            if part.get_filename() or part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() not in ("text/plain", "text/html"):
                continue
            try:
                value = part.get_content()
            except Exception:
                value = part.get_payload(decode=True) or b""
                if isinstance(value, bytes):
                    value = value.decode("utf-8", errors="replace")
            chunks.append(str(value))
        return "\n".join(chunks)

    @staticmethod
    def analyze_raw_content(raw_text: str, filename: str = None) -> dict:
        if not isinstance(raw_text, str) or not raw_text.strip():
            raise ValueError("Email source is empty.")
        if len(raw_text.encode("utf-8", errors="replace")) > 10 * 1024 * 1024:
            raise ValueError("Email source exceeds the 10 MB analysis limit.")

        msg = Parser(policy=policy.default).parsestr(raw_text)
        subject_value = msg.get("subject")
        subject = str(subject_value).strip() if subject_value else "No Subject"
        from_display, from_address = _mailbox(msg.get("from", ""))
        to_display, to_address = _mailbox(msg.get("to", ""))
        sender = str(msg.get("from", "Unknown Sender")) if from_address else "Unknown Sender"
        recipient = str(msg.get("to", "Unknown Recipient")) if to_address else "Unknown Recipient"
        reply_to = str(msg.get("reply-to", ""))
        return_path = str(msg.get("return-path", ""))
        body = EmailAnalyzerService._body(msg)
        auth_headers = [str(value).lower() for value in msg.get_all("Authentication-Results", [])]
        auth = "; ".join(auth_headers)
        combined = subject + "\n" + body
        lower = combined.lower()

        indicators = []
        score_groups = {}

        def add(points, title, detail, severity, category, evidence="", group=None):
            indicators.append({
                "title": title, "detail": detail, "severity": severity,
                "category": category, "points": points, "evidence": evidence,
            })
            group_key = group or category
            score_groups[group_key] = score_groups.get(group_key, 0) + points

        sender_domain = _domain(msg.get("from", ""))
        reply_domain = _domain(reply_to)
        return_domain = _domain(return_path)
        if sender_domain and reply_domain and sender_domain != reply_domain:
            add(18, "From / Reply-To domain mismatch",
                f"Visible sender domain ({sender_domain}) differs from Reply-To ({reply_domain}). Verify the reply destination independently.",
                "High", "Sender Spoofing", reply_to, "sender_identity")
        if sender_domain and return_domain and sender_domain != return_domain:
            add(6, "Return-Path domain differs",
                f"From domain ({sender_domain}) differs from Return-Path ({return_domain}); forwarding services can cause legitimate differences.",
                "Medium", "Sender Spoofing", return_path, "sender_identity")

        urgent_hits = sorted(term for term in URGENT if term in lower)
        credential_hits = sorted(term for term in CREDENTIALS if term in lower)
        payment_hits = sorted(term for term in PAYMENT if term in lower)
        if urgent_hits:
            add(8, "Urgency / pressure language",
                "Detected phrases: " + ", ".join(urgent_hits[:8]), "Medium", "Social Engineering", group="social_engineering")
        if credential_hits:
            add(18, "Credential-harvesting language",
                "Detected phrases: " + ", ".join(credential_hits[:8]), "High", "Credential Theft", group="credential_theft")
        if payment_hits:
            add(15, "Payment manipulation language",
                "Detected financial-request wording: " + ", ".join(payment_hits[:6]),
                "High", "Financial Fraud", group="financial_fraud")

        urls = list(dict.fromkeys(u.rstrip(".,;:!?]}") for u in URL_RE.findall(combined)))
        url_details = []
        for raw_url in urls:
            candidate = raw_url if raw_url.lower().startswith(("http://", "https://")) else "http://" + raw_url
            parsed = urlparse(candidate)
            host = (parsed.hostname or "").lower().rstrip(".")
            reasons = []
            if host:
                try:
                    ipaddress.ip_address(host)
                    reasons.append("Raw IP address")
                    add(18, "URL uses a raw IP address",
                        f"The link destination is an IP address ({host}), which is unusual for branded sign-in links.",
                        "High", "Malicious URLs", raw_url, "url_risk")
                except ValueError:
                    pass
                if host in SHORTENERS:
                    reasons.append("URL shortener")
                    add(8, "URL shortener detected",
                        f"The destination is obscured by {host}; inspect it using an approved safe-analysis process.",
                        "Medium", "Malicious URLs", raw_url, "url_risk")
                if host.startswith("xn--") or ".xn--" in host:
                    reasons.append("Punycode domain")
                    add(15, "Internationalized / punycode domain",
                        f"The hostname contains a punycode label ({host}); check for lookalike characters.",
                        "High", "Malicious URLs", raw_url, "url_risk")
                url_details.append({"url": raw_url, "domain": host, "flags": reasons or ["No local URL rule triggered"]})

        if re.search(r"(?i)https?://[^\s/]+@", combined):
            add(15, "URL contains user-info syntax",
                "The URL contains user-info syntax that can make the actual destination misleading.",
                "High", "Malicious URLs", group="url_risk")

        # Authentication-Results is supplied message content and can be forged.
        # We report it as an authentication signal, not as an attack category.
        checks = []
        received_spf = str(msg.get("Received-SPF", "")).lower()
        for method in ("spf", "dkim", "dmarc"):
            match = re.search(rf"\b{method}\s*=\s*(pass|fail|softfail|none|neutral|temperror|permerror)", auth)
            if not match and method == "spf":
                spf_match = re.match(r"\s*(pass|fail|softfail|none|neutral|temperror|permerror)\b", received_spf)
                match = spf_match
            status = match.group(1).upper() if match else "Unknown"
            source = "Supplied Authentication-Results header" if auth else ("Supplied Received-SPF header" if method == "spf" and received_spf else "Not supplied")
            checks.append({
                "name": method.upper(), "status": status, "source": source,
                "detail": "Reported by the submitted email headers; MailSentinel has not independently verified this result.",
                "verified": False,
            })
            if status in ("FAIL", "SOFTFAIL"):
                add(6, f"{method.upper()} reported {status.lower()}",
                    f"The submitted headers report {method.upper()}={status.lower()}. Treat this as an unverified signal until confirmed by the receiving mail gateway.",
                    "High", "Authentication Signal", status, "authentication")

        attachments = []
        for part in msg.walk():
            name = part.get_filename()
            if not name:
                continue
            clean_name = str(name).replace("\\", "/").rsplit("/", 1)[-1]
            lower_name = clean_name.lower()
            risk = "high" if lower_name.endswith(HIGH_RISK_EXT) else "medium" if lower_name.endswith(ACTIVE_CONTENT_EXT) else "low"
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": clean_name,
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest() if payload else None,
                "risk": risk,
                "risky": risk != "low",
                "note": "Filename/content-type triage only; this does not establish that the file is malicious.",
            })
        for item in attachments:
            if item["risk"] == "high":
                add(18, "High-risk attachment extension",
                    f"Attachment {item['filename']} uses an executable or script-capable extension and requires isolated inspection.",
                    "High", "Suspicious Attachments", item["filename"], "attachments")
            elif item["risk"] == "medium":
                add(8, "Active-content attachment requires review",
                    f"Attachment {item['filename']} can contain active content or macros; inspect it in an isolated environment.",
                    "Medium", "Suspicious Attachments", item["filename"], "attachments")

        # Cap contributions by signal family so repeated related indicators do not
        # automatically force every complex message to 100/100.
        group_caps = {
            "sender_identity": 22, "social_engineering": 8,
            "credential_theft": 18, "financial_fraud": 15,
            "url_risk": 25, "authentication": 12, "attachments": 12,
        }
        score = min(100, sum(min(value, group_caps.get(key, value)) for key, value in score_groups.items()))
        level = "Critical" if score >= 85 else "High" if score >= 65 else "Medium" if score >= 30 else "Low"
        priority = "P1 - Immediate review" if level in ("Critical", "High") else "P2 - Investigate" if level == "Medium" else "P3 - Routine review"
        if level in ("Critical", "High"):
            actions = [
                "Treat the message as untrusted and preserve the original email and full headers as evidence.",
                "If you administer the mail environment, locate and quarantine matching messages using the approved mail-gateway workflow; MailSentinel does not quarantine mail.",
                "Inspect URLs and attachments only in an isolated, approved analysis environment; do not click links or execute files.",
                "Search mail logs and user mailboxes for matching sender, subject, URLs and attachment hashes.",
                "If a user submitted credentials, reset affected credentials, revoke sessions and review MFA/sign-in events.",
                "Escalate confirmed compromise or malware to the incident-response team."
            ]
        elif level == "Medium":
            actions = [
                "Hold for analyst review and verify the sender through a separate trusted channel.",
                "Review authentication results at the receiving gateway; do not trust the submitted header alone.",
                "Inspect extracted URLs and attachments in an isolated environment before interacting with them.",
                "Search for similar messages before deciding whether to release or delete the email."
            ]
        else:
            actions = [
                "No configured high-risk rule was triggered; this does not prove the message is safe.",
                "Verify unexpected requests through a trusted communication channel.",
                "Apply your organization's normal URL and attachment inspection process."
            ]

        headers = [{"name": str(k), "value": str(v)} for k, v in msg.items()]
        return {
            "filename": filename or "Pasted email source",
            "sender": sender, "sender_address": from_address or "Not provided", "sender_display": from_display or "Not provided",
            "recipient": recipient, "recipient_address": to_address or "Not provided", "recipient_display": to_display or "Not provided",
            "subject": subject, "date": str(msg.get("date", "Not provided")),
            "reply_to": reply_to or "Not provided", "return_path": return_path or "Not provided",
            "message_id": str(msg.get("message-id", "Not provided")),
            "threat_score": score, "risk_level": level, "priority": priority,
            "indicators": indicators, "extracted_urls": urls, "url_details": url_details,
            "headers": headers, "raw_body": body, "authentication_checks": checks,
            "attachments": attachments,
            "analysis_summary": "; ".join(item["title"] for item in indicators) or "No configured rule triggered",
            "remediation": actions,
            "disclaimer": "Static, rule-based triage only. Authentication values are read from submitted headers and are not independently verified. Header values can be forged. Attachments are not executed or detonated; extension and hash checks do not prove maliciousness. No live reputation lookup, sandbox or ML model is used. A low score does not establish that an email is safe.",
        }
