from MySQL_Python.utilities.database import Database
from .time_functions import time_validation, date_to_str
from .password_functions import *
from .data_validation import validate_data
from .door_user import DoorUser
import json
from datetime import datetime


def get_user_password(database: Database, user: str) -> str | None:
    query = database.select_col_where("user", "password", "username", user)
    try:
        return query[0]["password"]
    except IndexError:
        return None


def change_password(database: Database, user: str, new_password: str) -> bool:
    new_password_hash = password_hash(new_password)
    query = database.update("user", "password", new_password_hash, "username", user)
    return query == 0


def name_from_rfid(database: Database, rfid: str) -> str | None:
    query = database.select_col_where("user", "name", "RFID_key", rfid)
    try:
        return str(query[0]["name"])
    except IndexError:
        return None

def get_user_rfid(database: Database, user: str) -> str | None:
    query = database.select_col_where("user", "RFID_key", "username", user)
    try:
        return str(query[0]["RFID_key"])
    except IndexError:
        return None


def interact_with_area(database: Database, user: str, company_id: str, door_id: str) -> bool:
    table_name = company_id.lower() + "_user_to_area"
    past_query = database.select_wheres(table_name, "user", user, "area_id", door_id)
    print("past query passed")
    try:
        last_time = past_query[0]["last_interaction_time"]
        last_state = int(past_query[0]["is_inside"])
        if last_state == 1:     # if the user was inside
            delta = datetime.now() - last_time
            seconds = int(delta.total_seconds())
            add_working_hours(database, user, company_id, door_id, seconds)  # add the amount to its working hours
        new_state = 1 - last_state
        new_query = database.update_multiple_wheres(
            table_name, ["is_inside", "last_interaction_time"], [new_state, datetime.now()], "user", user, "area_id", door_id
        )
        return new_query == 0
    except IndexError:
        last_time = datetime.now()
        last_state = 0
        insert_query = database.insert(
            table_name, ("user", "area_id", "is_inside", "last_interaction_time"), (user, door_id, 1, datetime.now())
        )
        return insert_query == 0


def add_working_hours(database: Database, user: str, company_id: str, area_id: str, seconds: int) -> bool:
    table_name = company_id.lower() + "_hours"
    past_hours = database.select_where_many(table_name, ["user", "area_id", "date"], [user, area_id, datetime.now()])
    try:
        past_secs = int(past_hours[0]["seconds_in"])
        new_query = database.update_where_many(
            table_name, "seconds_in", seconds + past_secs, ["user", "area_id", "date"], [user, area_id, datetime.now()]
        )
    except IndexError:
        new_query = database.insert(
            table_name, ("user", "area_id", "date", "seconds_in"), (user, area_id, datetime.now(), seconds)
        )
    return new_query == 0


def get_last_week_hours(database: Database, user: str, company_id: str, area_id: str | None = None):
    if area_id is None:
        table_name = company_id.lower() + "_defaults"
        default_query = database.select_where(table_name, "user_id", user)
        try:
            area_id = default_query[0]["default_area"]
        except IndexError:
            return None

    table_name = company_id.lower() + "_hours"
    all_hours = database.select_wheres_one_week(table_name, "user", user, "area_id", area_id)
    try:
        days = [d["date"].strftime("%Y-%m-%d") for d in all_hours]
        hours = [d["seconds_in"]/3600.0 for d in all_hours]
        return {"days": days, "hours": hours}
    except:
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


def get_demo_users(database: Database, user: str, role: str, company: str) -> list[dict]:
    pass


def validate_impersonation(
        database: Database,
        user_me: str,
        user_to_impersonate: str,
        selected_company: str
                            ) -> tuple[bool, str]:
    # check #1: origin and target user exist in database
    user_origin = door_user_from_db(database, user_me)
    user_target = door_user_from_db(database, user_to_impersonate)
    if user_origin is None or user_target is None:
        return False, "Origin or target user do not exist in database."

    # check #2: origin and target are both registered in origin's selected company
    user_1_in_company = get_role_from_ids(database, user_me, selected_company)
    user_2_in_company = get_role_from_ids(database, user_to_impersonate, selected_company)
    if user_1_in_company is None or user_2_in_company is None:
        return False, "Origin or target user is not registered to the selected company."

    # check #3: origin role can impersonate target role
    if user_1_in_company == "USR" or \
            user_1_in_company == "CO" and user_2_in_company not in ["USR", "CO"] or \
            user_1_in_company == "CA" and user_2_in_company not in ["USR", "CO", "CA"]:
        return False, "Origin user does not have permissions to impersonate target."
    return True, "Successfully impersonated."


def get_user_from_email(database: Database, email: str) -> dict:
    query = database.select_where("user", "email", email)
    if len(query) != 1:
        return {}
    else:
        return query[0]


def door_user_from_db(database: Database, user: str) -> DoorUser | None:
    user_info = database.select_where("user", "fiscal_code", user)
    if len(user_info) != 1:
        return None
    try:
        user_info = user_info[0]
        return DoorUser(
            name=user_info["name"],
            username=user_info["username"],
            fiscal_code=user_info["fiscal_code"],
            permissions={d["cusID"]: d["role"] for d in get_all_roles(database, user_info["fiscal_code"])}
        )
    except KeyError:
        return None


def validate_rfid_event(
        db: Database,
        rfid: str,
        door_id: str
) -> int:
    door_data = db.select_where("doors", "door_code", door_id)
    if len(door_data) == 0:
        return -1  # the door does not exist in the database

    door_data = door_data[0]
    if not door_data["active"]:
        return -2  # the door exists in the database, but it's not active

    user = db.select_where("user", "RFID_key", rfid)
    if len(user) == 0:
        return -3  # the RFID is not associated to any user
    elif len(user) > 1:
        return -4  # database error: multiple users with the same RFID key!

    user_id = user[0]["fiscal_code"]
    company_id = door_data["company_id"]
    user_utc = db.select_wheres("user_to_customer", "cusID", company_id, "userID", user_id)[0]

    if len(user_utc) == 0:
        return -5  # no user with that user ID in the company with that company ID

    if time_validation(user_utc) != 0:
        return -6  # the user may not enter today or at this time

    return 0  # if none of the previous conditions apply, the RFID event is valid


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


def get_user_working_hours():
    dic = {

        "days": ["15/6", "16/6", "17/6", "18/6", "19/6", "20/6", "21/6",
                 "22/6", "23/6"],
        "hours": [7.3, 3.9, 5.1, 8.1, 5.3, 6, 6.4, 5.9, 7.3]

    }

    return dic


def get_user_statistics(dictionary):
    hours = dictionary["hours"]

    mean = round(sum(hours) / len(hours), 3)
    mean_per_week = mean * 5
    giorno_max = dictionary["days"][hours.index(max(hours))]
    giorno_min = dictionary["days"][hours.index(min(hours))]

    statistics = {
        'Mean': mean,
        'Mean per week': mean_per_week,
        'Day with most working hours': giorno_max,
        'Day with less working hours': giorno_min
    }

    json_statistics = json.dumps(statistics)

    return json_statistics
