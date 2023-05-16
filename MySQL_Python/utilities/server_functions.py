from argon2 import hash_password, verify_password
from argon2.exceptions import VerifyMismatchError
from MySQL_Python.utilities.database import Database
from re import compile, match
from string import ascii_uppercase, ascii_lowercase, digits
from secrets import choice
from random import SystemRandom as sr
from datetime import datetime

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


def date_to_str(date: datetime):
    return date.strftime("%Y-%m-%d %H:%M:%S")


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


def get_user_password(database: Database, user: str) -> str | None:
    query = database.select_col_where("user", "password", "username", user)
    print(query)
    try:
        return query[0]["password"]
    except IndexError:
        return None


def get_id_from_user(database: Database, user: str) -> str | None:
    query = database.select_col_where("user", "fiscal_code", "username", user)
    try:
        return query[0]["fiscal_code"]
    except IndexError:
        return None


def get_role_from_ids(database: Database, user: str, company: str) -> str | None:
    query = database.select_wheres("user_to_customer", "cusID", company, "userID", user)
    try:
        return query[0]["role"]
    except IndexError:
        return None


def is_password_secure(test_password: str) -> bool:
    return match(password_validator, test_password) is not None


def is_time_valid(
        time_1: str,
        time_2: str,
        to_check: str | None = None
) -> bool:
    time_1_dt = datetime.strptime(time_1, "%Y-%m-%d %H:%M:%S")
    time_2_dt = datetime.strptime(time_2, "%Y-%m-%d %H:%M:%S")
    if to_check is None:
        to_check_dt = datetime.now()
    else:
        to_check_dt = datetime.strptime(to_check, "%Y-%m-%d %H:%M:%S")
    return time_1_dt <= to_check_dt <= time_2_dt


def is_date_valid(
        date_1: str,
        date_2: str,
        to_check: str | None = None
) -> bool:
    date_format = "%Y-%m-%d"
    date_1_dt = datetime.strptime(date_1, date_format)
    date_2_dt = datetime.strptime(date_2, date_format)
    if to_check is None:
        to_check_dt = datetime.now()
    else:
        to_check_dt = datetime.strptime(to_check, date_format)
    return date_1_dt <= to_check_dt <= date_2_dt


def is_hour_valid(
        hour_1: str,
        hour_2: str,
        to_check: str | None = None
) -> bool:
    hour_format = "%H:%M:%S"
    hour_1_t = datetime.strptime(hour_1, hour_format).time()
    hour_2_t = datetime.strptime(hour_2, hour_format).time()
    if to_check is None:
        to_check_t = datetime.now().time()
    else:
        to_check_t = datetime.strptime(to_check, hour_format).time()
    return hour_1_t <= to_check_t <= hour_2_t


def get_weekday(date_str: str | None = None):
    if date_str is None:
        date = datetime.now()
    else:
        date = datetime.strptime(date_str, "%Y-%m-%d")
    return date.ctime()[:3].lower()


def time_validation(
        user_dict: dict
):
    if int(user_dict["whitelist"]):     # if the user is only allowed to use the door in a specific time range
        dates = user_dict["whitelist_dates"].split("_")
        if not is_date_valid(dates[0], dates[1], None):
            return -1   # the user is in whitelist, and today is not included in the allowed days

    else:                               # the user is allowed to use the door on a regular basis
        dates = user_dict["vacation_dates"].split("_")
        if is_date_valid(dates[0], dates[1], None):
            return -2   # the user is not in whitelist, and he is supposed to be on vacation

    today_column = f"time_{get_weekday()}"
    hours = user_dict[today_column].split("_")
    if not is_hour_valid(hours[0], hours[1]):
        return -3       # the user can enter today, but not in this specific time instant

    return 0            # if none of the previous conditions apply, the user may interact with the door


def validate_rfid_event(
        db: Database,
        rfid: str,
        door_id: str
        ) -> int:

    door_data = db.select_where("doors", "door_code", door_id)
    if len(door_data) == 0:
        return -1   # the door does not exist in the database

    door_data = door_data[0]
    if not door_data["active"]:
        return -2   # the door exists in the database, but it's not active

    user = db.select_where("user", "RFID_key", rfid)
    if len(user) == 0:
        return -3   # the RFID is not associated to any user
    elif len(user) > 1:
        return -4   # database error: multiple users with the same RFID key!

    user_id = user[0]["fiscal_code"]
    company_id = door_data["company_id"]
    user_utc = db.select_wheres("user_to_customer", "cusID", company_id, "userID", user_id)
    if len(user_utc) == 0:
        return -5   # no user with that user ID in the company with that company ID

    if time_validation(user_utc) != 0:
        return -6   # the user may not enter today or at this time

    return 0        # if none of the previous conditions apply, the RFID event is valid




class User:
    def __init__(self,
                 user_id: int = -1,
                 name: str = "default",
                 surname: str = "default"):
        self.__userID = user_id
        self.__name = name
        self.__surname = surname
        self.__roles: dict[str, str] = {}

    @classmethod
    def from_query(cls, query: list[dict]):
        user_data = query[0]
        c = cls()
        # magic
        return c

    @property
    def userID(self) -> int:
        return self.__userID

    @property
    def name(self) -> str:
        return self.__name

    @property
    def surname(self) -> str:
        return self.__surname

    @property
    def roles(self) -> dict[str, str]:
        return self.__roles

    def role_at_company(self, company: str) -> str | None:
        return self.__roles.get(company, None)

    @userID.setter
    def userID(self, new_id: int):
        self.__userID = int(new_id)

    @name.setter
    def name(self, new_name: str):
        self.__name = str(new_name)

    @surname.setter
    def surname(self, new_surname: str):
        self.__surname = str(new_surname)

    @roles.setter
    def roles(self, new_roles: dict[str, str]):
        self.__roles = new_roles
