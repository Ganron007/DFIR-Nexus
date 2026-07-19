"""E.0.3 — Notification channels for case events."""

from __future__ import annotations

import json
import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Any

import httpx

from nexus.utils.constants import (
    ENV_DISCORD_WEBHOOK,
    ENV_SLACK_WEBHOOK,
    ENV_SMTP_FROM,
    ENV_SMTP_HOST,
    ENV_SMTP_PASSWORD,
    ENV_SMTP_PORT,
    ENV_SMTP_TO,
    ENV_SMTP_USER,
    ENV_TEAMS_WEBHOOK,
    ENV_TELEGRAM_BOT_TOKEN,
    ENV_TELEGRAM_CHAT_ID,
)

log = logging.getLogger(__name__)


async def send_slack(webhook_url: str, text: str, *, blocks: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"text": text}
    if blocks:
        payload["blocks"] = blocks
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(webhook_url, json=payload)
        return {"status": resp.status_code, "ok": resp.is_success}


async def send_teams(webhook_url: str, text: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(webhook_url, json={"text": text})
        return {"status": resp.status_code, "ok": resp.is_success}


async def send_discord(webhook_url: str, text: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(webhook_url, json={"content": text[:2000]})
        return {"status": resp.status_code, "ok": resp.is_success}


async def send_telegram(bot_token: str, chat_id: str, text: str) -> dict[str, Any]:
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(url, json={"chat_id": chat_id, "text": text[:4000]})
        return {"status": resp.status_code, "ok": resp.is_success, "body": resp.text[:200]}


def send_smtp(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    mail_from: str,
    mail_to: list[str],
    subject: str,
    body: str,
) -> dict[str, Any]:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = mail_from
    msg["To"] = ", ".join(mail_to)
    msg.set_content(body)
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.starttls()
        if username:
            smtp.login(username, password)
        smtp.send_message(msg)
    return {"ok": True, "recipients": mail_to}


async def notify_channel(channel: str, message: str, **kwargs: Any) -> dict[str, Any]:
    """Dispatch to configured channel using environment variables only (no caller SSRF)."""
    ch = channel.lower()
    if ch == "slack":
        url = os.environ.get(ENV_SLACK_WEBHOOK, "")
        if not url:
            return {"ok": False, "error": "Slack webhook not configured"}
        return await send_slack(url, message)
    if ch == "teams":
        url = os.environ.get(ENV_TEAMS_WEBHOOK, "")
        if not url:
            return {"ok": False, "error": "Teams webhook not configured"}
        return await send_teams(url, message)
    if ch == "discord":
        url = os.environ.get(ENV_DISCORD_WEBHOOK, "")
        if not url:
            return {"ok": False, "error": "Discord webhook not configured"}
        return await send_discord(url, message)
    if ch == "telegram":
        token = os.environ.get(ENV_TELEGRAM_BOT_TOKEN, "")
        chat_id = os.environ.get(ENV_TELEGRAM_CHAT_ID, "")
        if not token or not chat_id:
            return {"ok": False, "error": "Telegram bot_token/chat_id not configured"}
        return await send_telegram(token, chat_id, message)
    if ch == "smtp":
        host = os.environ.get(ENV_SMTP_HOST, "")
        if not host:
            return {"ok": False, "error": "SMTP host not configured"}
        return send_smtp(
            host=host,
            port=int(os.environ.get(ENV_SMTP_PORT, "587")),
            username=os.environ.get(ENV_SMTP_USER, ""),
            password=os.environ.get(ENV_SMTP_PASSWORD, ""),
            mail_from=os.environ.get(ENV_SMTP_FROM, "dfir-nexus@localhost"),
            mail_to=json.loads(os.environ.get(ENV_SMTP_TO, "[]")),
            subject="DFIR-Nexus notification",
            body=message,
        )
    return {"ok": False, "error": f"Unknown channel: {channel}"}
