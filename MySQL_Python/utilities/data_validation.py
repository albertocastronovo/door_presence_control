from re import compile, match


username_validator = compile(r"^(?=[a-zA-Z0-9_]{8,20}$)(?!.*_{2})[^_].*[^_]$")
password_validator = compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,32}$")
user_id_validator = compile(r"^(?=(?:[^AEIOU]*[A-Z]){6})[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]$")
customer_id_validator = compile(r"^[A-Z]{2}[0-9]{11}$")
email_validator = compile(r"^[\w\-\.]+@([\w-]+\.)+[\w-]{2,4}(?<![-._])$")
rfid_validator = compile(r"^[0-9]{10,12}$")
door_id_validator = compile(r"^[0-9]+$")

patterns = {
    "username": username_validator,
    "password": password_validator,
    "user_id": user_id_validator,
    "customer_id": customer_id_validator,
    "email": email_validator,
    "rfid": rfid_validator,
    "door_id": door_id_validator
}


def validate_data(data_string: str | None, data_type: str) -> bool:
    if not isinstance(data_string, str):
        return False
    if data_type not in patterns:
        return False
    return match(patterns[data_type], data_string) is not None

validate_data("pippo", "username")