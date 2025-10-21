import os
import re
import hmac
import ssl
import smtplib
import hashlib
from email.message import EmailMessage
from pathlib import Path
import pymysql
from urllib.parse import urlencode
from urllib.request import Request, urlopen

def _load_secrets_env(path: str = "secrets.env") -> None:
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if sep:  
            os.environ.setdefault(key.strip(), value.strip())

_load_secrets_env()

db_config = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
}
_MAX_NAME_LEN = 16
_NAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z\s'-]{0,15}$")  

def get_user_input():
    while True:
        user_input = input(f"Enter your name (max {_MAX_NAME_LEN} chars; letters, spaces, - and ' only): ").strip()
        if len(user_input) > _MAX_NAME_LEN:
            print(f"Too long. Please use at most {_MAX_NAME_LEN} characters.")
            continue
        if not _NAME_PATTERN.match(user_input):
            print("Invalid characters. Use letters, spaces, hyphen (-), or apostrophe (').")
            continue
        return user_input

_EMAIL_RE = re.compile(r"^[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9-.]+$")  
_MAX_SUBJECT_LEN = 120
_MAX_BODY_LEN = 4000

def _sanitize_header(value: str, max_len: int) -> str:
    clean = value.replace("\r", "").replace("\n", "").strip()
    return clean[:max_len]

def _truncate_body(value: str, max_len: int) -> str:
    return value.replace("\r\n", "\n")[:max_len]

def send_email(to: str, subject: str, body: str):
    if not _EMAIL_RE.match(to):
        raise ValueError("Invalid recipient email address.")
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASSWORD")
    mail_from = os.getenv("SMTP_FROM", user)

    if not all([host, port, user, password, mail_from]):
        raise RuntimeError("Missing SMTP configuration (SMTP_HOST/PORT/USER/PASSWORD/FROM).")

    msg = EmailMessage()
    msg["From"] = _sanitize_header(mail_from, 254)
    msg["To"] = _sanitize_header(to, 254)
    msg["Subject"] = _sanitize_header(subject, _MAX_SUBJECT_LEN)
    msg.set_content(_truncate_body(body, _MAX_BODY_LEN))

    context = ssl.create_default_context()
    with smtplib.SMTP(host, port) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(user, password)
        server.send_message(msg)

def _verify_integrity(body: bytes, signature_hex: str, key: str) -> None:
    if not signature_hex:
        raise RuntimeError("Missing X-Signature header from API; cannot verify integrity.")
    if not key:
        raise RuntimeError("Missing API signing key; set API_SIGNING_KEY in environment or secrets.env.")
    expected = hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature_hex.strip()):
        raise RuntimeError("API response failed integrity check (signature mismatch).")

def get_data():
    api_url = os.getenv('API_URL', 'https://insecure-api.com/get-data')  
    token = os.getenv('API_TOKEN')
    signing_key = os.getenv('API_SIGNING_KEY')
    if not token:
        raise RuntimeError("Missing API token. Set API_TOKEN.")
    full_url = f"{api_url}?{urlencode({'token': token})}"
    req = Request(full_url)
    with urlopen(req) as resp:
        body = resp.read()
        signature = resp.headers.get('X-Signature')
    _verify_integrity(body, signature, signing_key)
    return body.decode()

def save_to_db(data):
    query = f"INSERT INTO mytable (column1, column2) VALUES ('{data}', 'Another Value')"
    connection = pymysql.connect(**db_config)
    cursor = connection.cursor()
    cursor.execute(query)
    connection.commit()
    cursor.close()
    connection.close()

if __name__ == '__main__':
    user_input = get_user_input()
    data = get_data()
    save_to_db(data)
    send_email('admin@example.com', 'User Input', user_input)
