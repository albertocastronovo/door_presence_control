from MySQL_Python.utilities.database import Database
from .time_functions import time_validation, date_to_str
from .password_functions import *
from .data_validation import validate_data
from .door_user import DoorUser
import json
from datetime import datetime
from re import match


def does_username_exist(database: Database, username: str) -> bool:
    query = database.select_where("user", "username", username)
    return len(query) > 0


def am_i_sa(database: Database, user_id: str) -> bool:
    query = database.select_col_where("user_to_customer", "role", "userID", user_id)
    try:
        for q in query:
            if q["role"] == "SA":
                return True
        return False
    except (IndexError, KeyError):
        return False


def is_role_higher(role_1: str, role_2: str) -> bool:
    if role_1 == "SA" and role_2 == "SA":
        return False

    if role_1 == "USR":
        return False

    if role_1 == "SA" and role_2 != "SA":
        return True

    if role_1 == "CO" and role_2 in ["USR", "CO"]:
        return True

    if role_1 == "CA" and role_2 in ["USR", "CO", "CA"]:
        return True

    return False


def get_user_password(database: Database, user: str) -> str | None:
    query = database.select_col_where("user", "password", "username", user)
    try:
        return query[0]["password"]
    except IndexError:
        return None


def is_rfid_unique(database: Database, rfid: str) -> bool:
    query = database.select_where("user", "RFID_key", rfid)
    if query is None:
        return False
    return len(query) == 0


def change_password(database: Database, user: str, new_password: str) -> bool:
    print(f"new password: {new_password}")
    new_password_hash = password_hash(new_password)
    print(f"new password hash: {new_password_hash}")
    query = database.update("user", "password", new_password_hash, "fiscal_code", user)
    print(query)
    return query == 0


def name_from_rfid(database: Database, rfid: str) -> str | None:
    query = database.select_col_where("user", "name", "RFID_key", rfid)
    try:
        return str(query[0]["name"])
    except IndexError:
        return None


def fiscal_code_from_rfid(database: Database, rfid: str) -> str | None:
    query = database.select_col_where("user", "fiscal_code", "RFID_key", rfid)
    try:
        return str(query[0]["fiscal_code"])
    except IndexError:
        return None


def get_user_rfid(database: Database, user: str) -> str | None:
    query = database.select_col_where("user", "RFID_key", "username", user)
    try:
        return str(query[0]["RFID_key"])
    except IndexError:
        return None


def prefix_from_company(database: Database, company_id: str) -> str | None:
    query = database.select_col_where("customer", "door_prefix", "cusID", company_id)
    try:
        return str(query[0]["door_prefix"])
    except IndexError:
        return None


def company_from_prefix(database: Database, door_prefix: str) -> str | None:
    query = database.select_col_where("customer", "cusID", "door_prefix", door_prefix)
    try:
        return str(query[0]["cusID"])
    except IndexError:
        return None


def company_presence_in_areas(database: Database, company_id: str, roles: list | None = None) -> dict[str, int | dict]:
    if roles is None:
        roles = ["USR", "CO", "CA", "SA"]

    query_total_company_doors = database.select_all(company_id.lower() + "_doors")
    if query_total_company_doors is None:
        return {"totalUSR": 0, "active": {}}
    out_dict = {"active": {}}
    print(query_total_company_doors)
    for q in query_total_company_doors:
        door_code = q["door_id"]
        query_presence = database.select_wheres(
            company_id.lower() + "_user_to_area",
            "area_id", door_code,
            "is_inside", 1
        )
        if query_presence is None:
            people_count = 0
        else:
            people_count = 0
            for p in query_presence:
                user_id = p["user"]
                user_role = get_role_from_ids(database, user_id, company_id)
                if user_role is None:
                    user_role = "USR"
                if user_role in roles:
                    people_count += 1

        out_dict["active"][door_code] = people_count
        if q["is_main"] == 1:
            out_dict["totalUSR"] = people_count

    return out_dict


def interact_with_area(database: Database, user: str, door_id: str) -> bool:
    company_id = company_from_prefix(database, door_id[:4])
    table_name = company_id.lower() + "_user_to_area"
    past_query = database.select_wheres(table_name, "user", user, "area_id", door_id[4:])

    try:
        last_time = past_query[0]["last_interaction_time"]
        last_state = int(past_query[0]["is_inside"])
        if last_state == 1:     # if the user was inside
            delta = datetime.now() - last_time
            seconds = int(delta.total_seconds())
            if is_door_main(database, door_id):
                add_working_hours(database, user, company_id, door_id[4:], seconds)  # add the amount to its working hours
        new_state = 1 - last_state
        new_query = database.update_multiple_wheres(
            table_name, ["is_inside", "last_interaction_time"], [new_state, datetime.now()], "user", user, "area_id", door_id[4:]
        )
        return new_query == 0
    except IndexError:
        last_time = datetime.now()
        last_state = 0
        insert_query = database.insert(
            table_name, ("user", "area_id", "is_inside", "last_interaction_time"), (user, door_id[4:], 1, datetime.now())
        )
        return insert_query == 0


def is_door_main(database: Database, door_id_ex: str) -> bool:
    company_id = company_from_prefix(database, door_id_ex[:4])
    table = company_id.lower() + "_doors"
    door_id = door_id_ex[4:]
    door_data = database.select_where(table, "door_id", door_id)
    try:
        return door_data[0]["is_main"] == 1
    except (IndexError, KeyError):
        return False


def add_working_hours(database: Database, user: str, company_id: str, area_id: str, seconds: int) -> bool:
    table_name = company_id.lower() + "_hours"
    past_hours = database.select_where_many(table_name, ["user", "area_id", "date"], [user, area_id, datetime.now()])
    try:
        past_secs = int(past_hours[0]["seconds_in"])
        new_query = database.update_where_many(
            table_name, "seconds_in", seconds + past_secs, ["user", "area_id", "date"], [user, area_id, datetime.now()]
        )
    except (TypeError, IndexError):
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
    company_id = company_from_prefix(db, door_id[:4])
    door_table = company_id.lower() + "_doors"
    door_id = door_id[4:]
    door_data = db.select_where(door_table, "door_id", door_id)  # CAMBIARE PER CAMBIO TABELLA

    if len(door_data) == 0:
        return -1  # the door does not exist in the database

    door_data = door_data[0]
    if not door_data["is_active"]:
        return -2  # the door exists in the database, but it's not active

    user = db.select_where("user", "RFID_key", rfid)
    if len(user) == 0:
        return -3  # the RFID is not associated to any user

    elif len(user) > 1:
        return -4  # database error: multiple users with the same RFID key!

    user_id = user[0]["fiscal_code"]
    user_utc = db.select_wheres("user_to_customer", "cusID", company_id, "userID", user_id)[0]

    if len(user_utc) == 0:
        return -5  # no user with that user ID in the company with that company ID

    user_acc = db.select_where(company_id.lower() + "_access", "user_id", user_id)[0]

    if time_validation(user_acc) != 0:
        return -6  # the user may not enter today or at this time

    if not door_access_permissions(db, company_id, user_id, door_id):
        return -7   # the user has no permissions to enter the area

    # AGGIUNGERE

    return 0  # if none of the previous conditions apply, the RFID event is valid


def door_access_permissions(database: Database, company_id: str, user_id: str, door_id: str):
    query_regex = database.select_where(company_id.lower() + "_access", "user_id", user_id)
    try:
        access_permissions = str(query_regex[0]["access_permissions"])
    except (IndexError, KeyError):
        return False

    return match(access_permissions, door_id) is not None


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


def get_usernames_by_role_and_vat(
        db: Database,
        role: str,
        vat: str,
        user: str
):

    # Get rows where cusID equals vat from the user_to_customer table
    user_to_customer_rows = db.select_where('user_to_customer', 'cusID', vat)

    # Get the row where role equals the given role from the permissions table
    role_row = db.select_where('permissions', 'role', role)

    # Get the column names with value 1, except for the 'code' column
    columns_with_1 = [
        column_name for column_name, value in role_row[0].items() if value == 1 and column_name != 'code'
    ]

    # Filter the user_to_customer_rows based on the role
    filtered_rows = [
        row for row in user_to_customer_rows if row['role'] in columns_with_1
    ]

    # Get the userIDs from the filtered rows
    user_ids = [row['userID'] for row in filtered_rows]

    # Get the username values corresponding to the userIDs found in the user table
    result = [db.select_col_where("user", "username", "fiscal_code", user_id)[0]["username"] for user_id in
              user_ids if db.select_where('user', 'fiscal_code', user_id)]

    # Remove from the list the username that corresponds to the person who is performing the action
    if user in result:
        result.remove(user)

    # Convert in a dictionary
    result_dict = [{'username': usrnm} for usrnm in result]

    return result_dict


def get_only_users(
        db: Database,
        vat: str,
):
    # Get rows where cusID equals vat from the user_to_customer table
    user_to_customer_rows = db.select_where('user_to_customer', 'cusID', vat)

    # Get only USRs
    only_usrs_rows = [d for d in user_to_customer_rows if d["role"] == "USR"]

    # Get the userIDs from the filtered rows
    user_ids = [row['userID'] for row in only_usrs_rows]

    # Get the username values corresponding to the userIDs found in the user table
    result = [db.select_col_where("user", "username", "fiscal_code", user_id)[0]["username"] for user_id in
              user_ids if db.select_where('user', 'fiscal_code', user_id)]

    # Convert in a dictionary
    result_dict = [{'username': usrnm} for usrnm in result]

    return result_dict


def extract_name_from_string(data_string):
    try:
        data_dict = json.loads(data_string)
        value = next(iter(data_dict.values()))
        name = value.strip('"')
        return name
    except (json.JSONDecodeError, AttributeError, StopIteration):
        return None


def get_companies_by_role_and_vat(
        db: Database,
        role: str,
        vat: str,
        user: str
):

    # Get rows where cusID equals vat from the user_to_customer table
    user_to_customer_rows = db.select_where('user_to_customer', 'cusID', vat)

    # Get the row where role equals the given role from the permissions table
    role_row = db.select_where('permissions', 'role', role)

    # Get the column names with value 1, except for the 'code' column
    columns_with_1 = [
        column_name for column_name, value in role_row[0].items() if value == 1 and column_name != 'code'
    ]

    # Filter the user_to_customer_rows based on the role
    filtered_rows = [
        row for row in user_to_customer_rows if row['role'] in columns_with_1
    ]

    # Get the userIDs from the filtered rows
    user_ids = [row['userID'] for row in filtered_rows]

    # Get the username values corresponding to the userIDs found in the user table
    result = [db.select_col_where("user", "username", "fiscal_code", user_id)[0]["username"] for user_id in
              user_ids if db.select_where('user', 'fiscal_code', user_id)]

    # Remove from the list the username that corresponds to the person who is performing the action
    if user in result:
        result.remove(user)

    # Convert in a dictionary
    result_dict = [{'username': usrnm} for usrnm in result]

    return result_dict


def get_all_from_your_company(
        db: Database,
        vat: str,
        user: str
):

    # Get rows where cusID equals vat from the user_to_customer table
    user_to_customer_rows = db.select_where('user_to_customer', 'cusID', vat)

    # Get the userIDs from the filtered rows
    user_ids = [row['userID'] for row in user_to_customer_rows]

    # Get the username values corresponding to the userIDs found in the user table
    result = [db.select_col_where("user", "username", "fiscal_code", user_id)[0]["username"] for user_id in
              user_ids if db.select_where('user', 'fiscal_code', user_id)]

    # Remove from the list the username that corresponds to the person who is performing the action
    if user in result:
        result.remove(user)

    # Convert in a dictionary
    result_dict = [{'username': usrnm} for usrnm in result]

    return result_dict