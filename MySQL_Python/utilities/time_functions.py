from datetime import datetime


def date_to_str(date: datetime):
    return date.strftime("%Y-%m-%d %H:%M:%S")


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
        if len(dates) == 2 and is_date_valid(dates[0], dates[1], None):
            return -2   # the user is not in whitelist, and he is supposed to be on vacation

    today_column = f"time_{get_weekday()}"
    hours = user_dict[today_column].split("-")
    if not isinstance(hours, list) or len(hours) < 2:
        return -3       # Invalid hour format for the selected user in the database

    if not is_hour_valid(hours[0], hours[1]):
        return -4       # the user can enter today, but not in this specific time instant

    return 0            # if none of the previous conditions apply, the user may interact with the door
