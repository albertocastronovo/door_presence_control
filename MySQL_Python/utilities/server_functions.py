from argon2 import hash_password, verify_password
from argon2.exceptions import VerifyMismatchError
from MySQL_Python.utilities.database import Database
from re import compile, match

password_validator = compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,32}$")


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


def get_user_password(database: Database, user: str) -> str | None:
    query = database.select_col_where("user", "password", "username", user)
    try:
        return query[0]["password"]
    except IndexError:
        return None


def is_password_secure(test_password: str) -> bool:
    return match(password_validator, test_password) is not None

