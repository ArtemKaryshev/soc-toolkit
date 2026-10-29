"""Чтение входных данных для извлечения IOC: текст, логи, CSV, JSON, HTML, письма .eml.

Для .eml дополнительно разбираются заголовки (From, Reply-To, Return-Path, Received,
Authentication-Results) и считаются хэши вложений, не сохраняя сами вложения на диск.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import html
import json
import re
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path

MAX_FILE_SIZE = 50 * 1024 * 1024


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    md5: str
    sha1: str
    sha256: str
    strings: str = field(default="", repr=False)  # печатаемые строки из вложения (как утилита strings)


@dataclass
class EmailInfo:
    subject: str = ""
    sender: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    date: str = ""
    message_id: str = ""
    received: list[str] = field(default_factory=list)
    auth_results: str = ""
    spf: str = ""
    dkim: str = ""
    dmarc: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    body: str = ""

    @property
    def warnings(self) -> list[str]:
        """Типовые признаки фишинга в заголовках."""
        w = []

        def addr(v: str) -> str:
            m = re.search(r"[\w.+-]+@[\w.-]+", v)
            return m.group(0).lower() if m else ""

        def dom(v: str) -> str:
            return addr(v).rsplit("@", 1)[-1]

        if self.reply_to and dom(self.reply_to) and dom(self.reply_to) != dom(self.sender):
            w.append(f"Reply-To ({addr(self.reply_to)}) отличается от домена отправителя ({dom(self.sender)})")
        if self.return_path and dom(self.return_path) and dom(self.return_path) != dom(self.sender):
            w.append(f"Return-Path ({addr(self.return_path)}) не совпадает с доменом From")
        for name, value in (("SPF", self.spf), ("DKIM", self.dkim), ("DMARC", self.dmarc)):
            if value and value not in ("pass", "none", ""):
                w.append(f"{name}: {value}")
        for a in self.attachments:
            ext = a.filename.rsplit(".", 1)[-1].lower() if "." in a.filename else ""
            if ext in {"exe", "scr", "js", "vbs", "hta", "lnk", "iso", "img", "one", "docm", "xlsm", "html", "htm",
                       "zip", "rar", "7z"}:
                w.append(f"Вложение с рискованным расширением: {a.filename}")
        return w


def strip_html(text: str) -> str:
    # ссылки из href сохраняем, иначе они пропадут вместе с тегами
    text = re.sub(r"""<a\s[^>]*href=["']([^"']+)["'][^>]*>""", r" \1 ", text, flags=re.I)
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    return html.unescape(text)


def _auth_value(results: str, mech: str) -> str:
    m = re.search(rf"\b{mech}=(\w+)", results, re.I)
    return m.group(1).lower() if m else ""


def parse_eml(data: bytes) -> EmailInfo:
    msg = email.message_from_bytes(data, policy=email.policy.default)
    assert isinstance(msg, EmailMessage)
    auth = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))
    info = EmailInfo(
        subject=str(msg.get("Subject", "")), sender=str(msg.get("From", "")), reply_to=str(msg.get("Reply-To", "")),
        return_path=str(msg.get("Return-Path", "")), to=str(msg.get("To", "")), date=str(msg.get("Date", "")),
        message_id=str(msg.get("Message-ID", "")), received=[str(r) for r in msg.get_all("Received", [])],
        auth_results=auth, spf=_auth_value(auth, "spf"), dkim=_auth_value(auth, "dkim"),
        dmarc=_auth_value(auth, "dmarc"),
    )
    bodies = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        raw = part.get_payload(decode=True)
        payload: bytes = raw if isinstance(raw, bytes) else b""
        if filename or part.get_content_disposition() == "attachment":
            # Печатаемые строки помогают найти URL/команды в скриптах и макросах.
            # Сжатые форматы (docx/docm/zip) так не раскрыть: их нужно распаковывать отдельно.
            strings = b"\n".join(re.findall(rb"[\x20-\x7e]{6,}", payload[:5_000_000])[:5000])
            info.attachments.append(Attachment(
                filename or "(без имени)", part.get_content_type(), len(payload),
                hashlib.md5(payload).hexdigest(), hashlib.sha1(payload).hexdigest(),
                hashlib.sha256(payload).hexdigest(), strings.decode("ascii"),
            ))
            continue
        if part.get_content_maintype() == "text":
            charset = part.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")
            bodies.append(strip_html(text) if part.get_content_subtype() == "html" else text)
    info.body = "\n".join(bodies)
    return info


def email_to_text(info: EmailInfo) -> str:
    """Собрать из письма текст для извлечения IOC: заголовки, тело, имена и хэши вложений."""
    lines = [f"From: {info.sender}", f"Reply-To: {info.reply_to}", f"Return-Path: {info.return_path}",
             f"Subject: {info.subject}", *[f"Received: {r}" for r in info.received], "", info.body, ""]
    for a in info.attachments:
        lines.append(f"Attachment: {a.filename} md5={a.md5} sha1={a.sha1} sha256={a.sha256}")
        if a.strings:
            lines.append(a.strings)
    return "\n".join(lines)


def read_text(name: str, data: bytes) -> tuple[str, EmailInfo | None]:
    """Превратить содержимое файла в текст для поиска IOC. Для писем возвращает и разбор заголовков."""
    if len(data) > MAX_FILE_SIZE:
        raise ValueError(f"Файл больше {MAX_FILE_SIZE // 1024 // 1024} МБ")
    ext = Path(name).suffix.lower()
    if ext == ".eml":
        info = parse_eml(data)
        return email_to_text(info), info
    text = data.decode("utf-8-sig", errors="replace")
    if ext in (".html", ".htm"):
        return strip_html(text), None
    if ext == ".json":
        try:
            # json.dumps с ensure_ascii=False раскрывает \u-последовательности
            return json.dumps(json.loads(text), ensure_ascii=False, indent=1), None
        except json.JSONDecodeError:
            return text, None
    return text, None
