from argon2 import hash_password, verify_password
from argon2.exceptions import VerifyMismatchError
from database import Database


def password_hash(password: str) -> str:
    hash_bytes = hash_password(
        bytes(password, "utf-8"),
        hash_len=55
    )
    return hash_bytes.decode("utf-8")


def password_verify(password: str, test_hash: str) -> bool:
    try:
        return verify_password(
            password=bytes(password, "utf-8"),
            hash=bytes(test_hash, "utf-8")
        )
    except VerifyMismatchError:
        return False


def get_user_password(database: Database, user: str):
    query = database.select_col_where("user", "password", "username", user)
    try:
        return query[0][0]
    except IndexError:
        return None

