from secrets import choice
from random import SystemRandom as sr
from string import ascii_uppercase, ascii_lowercase, digits
from argon2 import hash_password, verify_password
from argon2.exceptions import VerifyMismatchError
from re import compile, match


password_validator = compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,32}$")


def random_secure_password(length: int = 16):
    n_upper = sr().randint(1, length - 5)
    n_lower = sr().randint(1, length - 4 - n_upper)
    n_numbers = sr().randint(1, length - 3 - n_upper - n_lower)
    n_symbols = length - n_upper - n_lower - n_numbers

    password_list = \
        [choice(ascii_uppercase) for _ in range(n_upper)] + \
        [choice(ascii_lowercase) for _ in range(n_lower)] + \
        [choice(digits) for _ in range(n_numbers)] + \
        [choice("@$!%*?&") for _ in range(n_symbols)]
    sr().shuffle(password_list)
    return "".join(password_list)


def is_password_secure(test_password: str) -> bool:
    return match(password_validator, test_password) is not None


def password_hash(password: str) -> str:
    hash_bytes = hash_password(
        bytes(password, "utf-8"),
        hash_len=55
    )
    return hash_bytes.decode("utf-8")


def password_verify(password: str, test_hash: str | None) -> bool:
    if test_hash is None:
        return False
    try:
        return verify_password(
            password=bytes(password, "utf-8"),
            hash=bytes(test_hash, "utf-8")
        )
    except VerifyMismatchError:
        return False
