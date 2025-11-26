import json
import os
import smtplib
from email.mime.text import MIMEText
import requests
from twilio.rest import Client

ALERT_LOG = os.path.join(os.path.dirname(__file__), "..", "alerts.log")

class AlertSystem:

    def __init__(self, logfile=ALERT_LOG):
        self.logfile = logfile

        self.email_enabled = False
        self.sms_enabled = False
        self.slack_enabled = False

        # Email settings
        self.smtp_server = None
        self.smtp_user = None
        self.smtp_password = None
        self.email_to = None

        # Twilio settings
        self.twilio_sid = None
        self.twilio_token = None
        self.twilio_from = None
        self.twilio_to = None

        # Slack settings
        self.slack_webhook = None

    # ---------------- Log to file ----------------
    def log(self, alert, features):
        entry = {"type": alert, "features": features}
        with open(self.logfile, "a") as f:
            f.write(json.dumps(entry) + "\n")

    # ---------------- Email ----------------
    def setup_email(self, server, user, password, to):
        self.email_enabled = True
        self.smtp_server = server
        self.smtp_user = user
        self.smtp_password = password
        self.email_to = to

    def send_email(self, alert, features):
        msg = MIMEText(str(features))
        msg["Subject"] = f"IDS Alert: {alert}"
        msg["From"] = self.smtp_user
        msg["To"] = self.email_to

        with smtplib.SMTP_SSL(self.smtp_server, 465) as server:
            server.login(self.smtp_user, self.smtp_password)
            server.send_message(msg)

    # ---------------- Slack ----------------
    def setup_slack(self, webhook):
        self.slack_enabled = True
        self.slack_webhook = webhook

    def send_slack(self, alert, features):
        payload = {"text": f"⚠️ IDS Alert: {alert}\n{features}"}
        requests.post(self.slack_webhook, json=payload)

    # ---------------- SMS (Twilio) ----------------
    def setup_sms(self, sid, token, from_num, to_num):
        self.sms_enabled = True
        self.twilio_sid = sid
        self.twilio_token = token
        self.twilio_from = from_num
        self.twilio_to = to_num

    def send_sms(self, alert, features):
        client = Client(self.twilio_sid, self.twilio_token)
        body = f"IDS Alert: {alert}\n{features}"
        client.messages.create(body=body, from_=self.twilio_from, to=self.twilio_to)

    # ---------------- Main send_alert ----------------
    def send_alert(self, alert, features):
        self.log(alert, features)

        if self.email_enabled:
            self.send_email(alert, features)

        if self.sms_enabled:
            self.send_sms(alert, features)

        if self.slack_enabled:
            self.send_slack(alert, features)