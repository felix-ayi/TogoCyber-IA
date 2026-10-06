"""Real notification delivery.

The outbox accumulates messages produced by genuine SOC events. This dispatcher attempts
an actual delivery only when an operator has configured a channel through the environment.
If no channel is configured, nothing is sent and rows stay 'not_configured' — a delivery is
never simulated or marked 'sent' without a real, successful transport.
"""

import os
import smtplib
from email.message import EmailMessage

import requests

from backend.app.repositories import notification_repository

_TIMEOUT_SECONDS = 10
_HTTP_SCHEMES = ("http://", "https://")


def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def _valid_url(value: str) -> bool:
    return value.startswith(_HTTP_SCHEMES)


def configured_channel() -> tuple[str | None, dict]:
    """Return the first configured delivery channel and its settings, or (None, {})."""
    webhook = _env("NOTIFICATION_WEBHOOK_URL")
    if _valid_url(webhook):
        return "webhook", {"url": webhook}

    slack = _env("NOTIFICATION_SLACK_WEBHOOK")
    if _valid_url(slack):
        return "slack", {"url": slack}

    host = _env("NOTIFICATION_SMTP_HOST")
    sender = _env("NOTIFICATION_SMTP_FROM")
    recipient = _env("NOTIFICATION_SMTP_TO")
    if host and sender and recipient:
        return "email", {
            "host": host,
            "port": int(_env("NOTIFICATION_SMTP_PORT") or "587"),
            "username": _env("NOTIFICATION_SMTP_USERNAME"),
            "password": _env("NOTIFICATION_SMTP_PASSWORD"),
            "sender": sender,
            "recipient": recipient,
        }
    return None, {}


def _deliver_webhook(url: str, notification: dict) -> None:
    payload = {
        "event_type": notification["event_type"],
        "severity": notification["severity"],
        "subject": notification["subject"],
        "body": notification["body"],
        "created_at": notification["created_at"],
    }
    response = requests.post(url, json=payload, timeout=_TIMEOUT_SECONDS)
    response.raise_for_status()


def _deliver_slack(url: str, notification: dict) -> None:
    text = f"[{notification['severity']}] {notification['subject']}\n{notification['body']}"
    response = requests.post(url, json={"text": text}, timeout=_TIMEOUT_SECONDS)
    response.raise_for_status()


def _deliver_email(config: dict, notification: dict) -> None:
    message = EmailMessage()
    message["Subject"] = f"[{notification['severity']}] {notification['subject']}"
    message["From"] = config["sender"]
    message["To"] = config["recipient"]
    message.set_content(notification["body"])
    with smtplib.SMTP(config["host"], config["port"], timeout=_TIMEOUT_SECONDS) as server:
        server.starttls()
        if config["username"] and config["password"]:
            server.login(config["username"], config["password"])
        server.send_message(message)


def _deliver(channel: str, config: dict, notification: dict) -> None:
    if channel == "webhook":
        _deliver_webhook(config["url"], notification)
    elif channel == "slack":
        _deliver_slack(config["url"], notification)
    elif channel == "email":
        _deliver_email(config, notification)
    else:  # pragma: no cover - guarded by configured_channel()
        raise ValueError("unknown delivery channel")


def dispatch_outbox(limit: int = 50) -> dict:
    """Attempt real delivery of pending notifications via the configured channel."""
    channel, config = configured_channel()
    pending = notification_repository.list_pending(limit=limit)
    if channel is None:
        return {
            "configured_channel": None,
            "considered": len(pending),
            "sent": 0,
            "failed": 0,
            "remaining_not_configured": len(pending),
            "detail": (
                "Aucun canal de diffusion configuré : aucun message n’a été envoyé et "
                "la file reste en attente. Renseignez NOTIFICATION_WEBHOOK_URL, "
                "NOTIFICATION_SLACK_WEBHOOK ou NOTIFICATION_SMTP_HOST/FROM/TO."
            ),
        }

    sent = failed = 0
    for notification in pending:
        try:
            _deliver(channel, config, notification)
        except (requests.RequestException, smtplib.SMTPException, OSError, ValueError):
            failed += 1
            notification_repository.mark_delivered(notification["id"], channel, "failed")
        else:
            sent += 1
            notification_repository.mark_delivered(notification["id"], channel, "sent")

    return {
        "configured_channel": channel,
        "considered": len(pending),
        "sent": sent,
        "failed": failed,
        "remaining_not_configured": notification_repository.counts().get("not_configured", 0),
        "detail": f"Canal utilisé : {channel}.",
    }
