from MySQL_Python.utilities.database import Database
from .time_functions import time_validation, date_to_str
from .password_functions import *
from .data_validation import validate_data


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


def get_geninfo_from_user(database: Database, user: str) -> dict[str, str]:
    query = database.select_where("user", "fiscal_code", user)
    try:
        geninfo = query[0]
        return {
            "name": geninfo["name"],
            "surname": geninfo["surname"],
            "email": geninfo["email"],
            "birthday": geninfo["birth_date"],
            "gender": geninfo["gender"]
        }
    except (IndexError, KeyError):
        return {}


def get_role_from_ids(database: Database, user: str, company: str) -> str | None:
    query = database.select_wheres("user_to_customer", "cusID", company, "userID", user)
    try:
        return query[0]["role"]
    except IndexError:
        return None


def get_all_roles(database: Database, user: str) -> list[dict]:
    return database.select_join_where(
        ("name", "role", "customer.cusID"), "user_to_customer", "customer", "cusID", "userID", user
    )


def get_user_from_email(database: Database, email: str) -> dict:
    query = database.select_where("user", "email", email)
    if len(query) != 1:
        return {}
    else:
        return query[0]


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


def day_interval(form, day) -> str | None:
    start = form.get(f"{day}_start", None)
    end = form.get(f"{day}_end", None)
    if start is not None and end is not None:
        return f"{start}-{end}"
    else:
        return None


def validate_new_user_form(req_form):
    req_form = req_form.to_dict()
    print(f"Req form: {req_form}")
    registration_type = req_form.get("registration_type", None)
    if registration_type is None or registration_type == "":
        return {}, "Missing registration type"

    fiscal_code = req_form.get("fiscal_code", None)
    if not validate_data(fiscal_code, "user_id"):
        return {}, "Missing user fiscal code"

    company_id = req_form.get("company_id", None)
    if not validate_data(company_id, "customer_id"):
        return {}, "Missing company ID"

    if registration_type == "manual":
        rfid = req_form.get("rfid", None)
        temp_password = req_form.get("temp_password", None)
        if not validate_data(temp_password, "password"):
            return {}, "Missing temporary password"
        door_id = "none"
    else:
        door_id = req_form.get("door_id", None)
        temp_password = None
        rfid = None
        if door_id is None or door_id == "":
            return {}, "Missing client ID"

    role = req_form.get("role", None)
    if role is None or role == "":
        return {}, "Missing new user role"

    is_whitelist = req_form.get("whitelist", None)
    if is_whitelist is not None and is_whitelist:
        whitelist_start = req_form.get("whitelist_start", None)
        whitelist_end = req_form.get("whitelist_end", None)
        if whitelist_start is not None and whitelist_end is not None:
            whitelist_dates = f"{whitelist_start}_{whitelist_end}"
        else:
            whitelist_dates = f"none"
    else:
        whitelist_dates = f"none"

    time_mon = day_interval(req_form, "monday")
    time_tue = day_interval(req_form, "tuesday")
    time_wed = day_interval(req_form, "wednesday")
    time_thu = day_interval(req_form, "thursday")
    time_fri = day_interval(req_form, "friday")
    time_sat = day_interval(req_form, "saturday")
    time_sun = day_interval(req_form, "sunday")

    return {
        "cusID": company_id,
        "userID": fiscal_code,
        "role": role,
        "whitelist": is_whitelist,
        "time_mon": time_mon,
        "time_tue": time_tue,
        "time_wed": time_wed,
        "time_thu": time_thu,
        "time_fri": time_fri,
        "time_sat": time_sat,
        "time_sun": time_sun,
        "whitelist_dates": whitelist_dates,
        "temp_password": temp_password,
        "rfid": rfid,
        "door_id": door_id

    }, f"OK_{registration_type}"
