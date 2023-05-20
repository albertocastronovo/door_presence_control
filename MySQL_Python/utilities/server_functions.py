from MySQL_Python.utilities.database import Database
from .time_functions import time_validation, date_to_str
from .password_functions import *


def get_user_password(database: Database, user: str) -> str | None:
    query = database.select_col_where("user", "password", "username", user)
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
    user_utc = db.select_wheres("user_to_customer", "cusID", company_id, "userID", user_id)[0]

    if len(user_utc) == 0:
        return -5   # no user with that user ID in the company with that company ID

    if time_validation(user_utc) != 0:
        return -6   # the user may not enter today or at this time

    return 0        # if none of the previous conditions apply, the RFID event is valid
