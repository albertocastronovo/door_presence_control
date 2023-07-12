from flask_mail import Mail, Message
from textwrap import dedent
import secrets
from datetime import datetime, timedelta
from .database import Database
from .password_functions import password_hash, password_verify


def send_reset_email(mail: Mail, recipient: str, recovery_link: str, recovery_code: str):
    msg = Message("Password reset", recipients=[recipient])
    msg.body = dedent(f"""\
        Please click on the link below to reset your password:
        {recovery_link}
        
        Or insert this code in the text field:
        {recovery_code}
        
        If you did not request password recovery for your DCS account, please ignore this message.
        
        - DCS
    """)
    mail.send(msg)
    return "OK"


def generate_recovery_code() -> str:
    return str(secrets.token_urlsafe(16))


def verify_recovery_code(db: Database, requested_user: str, received_code: str) -> bool:
    saved_query = db.select_where("password_recovery", "user_id", requested_user)
    try:
        saved_code = saved_query[0]["recovery_code"]
        expiration_date = saved_query[0]["expires_at"]
    except (IndexError, KeyError):
        return False

    is_correct = password_verify(received_code, saved_code) and datetime.now() < expiration_date
    return is_correct


def request_password_recovery(db: Database, user: str, mail: Mail, recipient: str | None, route_link: str):
    if recipient is None:
        return
    code = generate_recovery_code()
    recovery_link = route_link + "/" + user + "/" + code
    hashed_code = password_hash(code)
    db.delete("password_recovery", "user_id", user)
    expiration = datetime.now() + timedelta(minutes=15)
    db.insert("password_recovery", ("user_id", "recovery_code", "expires_at"), (user, hashed_code, expiration))
    send_reset_email(mail=mail, recipient=recipient, recovery_link=recovery_link, recovery_code=f"{user}...{code}")
