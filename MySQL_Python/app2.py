# Import the Flask class and other extensions from the flask module
from flask import Flask, jsonify, request \
    # , render_template, url_for, redirect, flash, g, abort, session
from flask import make_response
from functools import wraps
import jwt
from pytz_deprecation_shim import PytzUsageWarning
from utilities.server_functions import get_user_password, password_verify, password_hash, get_user_statistics, \
    get_id_from_user, get_all_roles, get_user_working_hours \
    # , get_role_from_ids, random_secure_password, date_to_str, validate_rfid_event
from utilities.database import Database
from apscheduler.schedulers.background import BackgroundScheduler
import os
from datetime import datetime, timedelta
# import requests
import warnings
import json

warnings.filterwarnings("ignore", category=PytzUsageWarning)

# create the application object
app = Flask(__name__)
app.secret_key = os.getenv("door_secret")

# Configuring the secret and duration of the JWT token
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=10)

# Set session to be permanent and set its lifetime
# app.permanent_session_lifetime = timedelta(minutes=10)

db = Database(
    host="localhost",
    database="door_cntrl_system",
    port=3306
)

db.connect_as(
    user="root",
    password=""
)

users_permissions = {}
pending_user_creations = {}


# Function to verify the JWT token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].replace('Bearer ', '')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        except Exception as e:
            return jsonify({'message': str(e)}), 401
        return f(*args, **kwargs)

    return decorated


def update_users_permissions():
    global users_permissions
    users_permissions = {r["name"]: r for r in db.select_all("roles")}


update_users_permissions()
scheduler = BackgroundScheduler()
scheduler.add_job(
    func=update_users_permissions,
    trigger="cron",
    hour=3
)
scheduler.start()


# def permissions_required(flag_list):
#     def wrapper_function(f):
#         @wraps(f)
#         def wrapper(*args, **kwargs):
#             permissions = session["permissions"]
#             for flag in flag_list:
#                 print(f"flag: {flag}")
#                 if not permissions.get(flag, False):
#                     print(f"invalid flag: {flag}")
#                     return
#             return f(*args, **kwargs)
#
#         return wrapper
#
#     return wrapper_function


@app.route('/signup', methods=['POST'])
def signup():
    user = request.json["username"]
    print(user)
    saved_hash = get_user_password(db, user)
    if saved_hash is None:
        return jsonify({"exists": False, "registered": False})
    user_pw = request.json["password"]
    print(user_pw)
    is_correct = password_verify(user_pw, saved_hash)
    if not is_correct:
        return jsonify({"exists": False, "registered": False})
    flag_psw = db.select_col_where("user", "flag_password_changed", "username", user)[0]["flag_password_changed"]
    print(flag_psw)
    if flag_psw == 0:
        token = jwt.encode({'username': user, 'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']},
                           app.config['JWT_SECRET_KEY'], algorithm='HS256')
        return jsonify({"exists": True, "registered": False}, {"token": token})
    return jsonify({"exists": True, "registered": True})


@app.route('/update_user', methods=['POST'])
@token_required
def update_user():
    username = request.headers.get("username")
    user = request.json["new_username"]
    prefix = request.json["prefix"]
    phone_number = request.json["phone_number"]
    email = request.json["email"]
    address = request.json["address"]
    birth_date = request.json["birth_date"]
    gender = request.json["gender"]
    newPassword = request.json["new_password"]

    update = db.update_multiple(
        table="user",
        column_names=["username", "password", "phone_number", "email", "address", "birth_date", "gender",
                      "flag_phone", "flag_mail", "flag_password_changed"],
        column_values=[user, password_hash(newPassword), prefix + phone_number, email, address, birth_date,
                       gender, 1, 1, 1],
        where_column="fiscal_code",
        where_value=username
    )
    # Check if there is another person with the same username --> check_username()

    return jsonify({"status": "success", "message": "User information updated successfully!"})


#
# # --> here
# @app.route('/check_username', methods=['POST'])
# def check_username():
#     username = request.form["username"]
#     saved_hash = get_user_password(db, username)
#     if saved_hash is not None:
#         return jsonify({"exists": True})
#     return jsonify({"exists": False})


@app.route('/new_password', methods=['POST'])
@token_required
def new_password():
    username = request.headers.get("username")
    newPassword = request.json["new_password"]

    update = db.update(
        table="user",
        set_column="password",
        set_value=password_hash(newPassword),
        where_column="username",
        where_value=username
    )

    return jsonify({"status": "success", "message": "User information updated successfully!"})


@app.route('/change_profile_data', methods=['POST'])
@token_required
def change_profile_data():
    username = request.headers.get("username")
    user = request.json["new_username"]
    prefix = request.json["prefix"]
    phone_number = request.json["phone_number"]
    email = request.json["email"]
    address = request.json["address"]
    gender = request.json["gender"]

    update = db.update_multiple(
        table="user",
        column_names=["username", "phone_number", "email", "address", "gender",
                      "flag_phone", "flag_mail", "flag_password_changed"],
        column_values=[user, prefix + phone_number, email, address, gender, 1, 1, 1],
        where_column="username",
        where_value=username
    )

    return jsonify({"status": "success", "message": "User information updated successfully!"})


@app.route('/db_personal_data', methods=['GET'])
@token_required
def extract_from_db():
    user = request.headers.get("username")
    user_fetch = db.select_where(
        table="user",
        column="username",
        value=user
    )
    if user_fetch:
        return jsonify(user_fetch[0])
    else:
        return jsonify({"message": "User not found."})


@app.route('/view_statistics', methods=['GET'])
@token_required
def stats():
    user = request.headers.get("username")
    print(user)
    dictionary = get_user_working_hours()
    print(dictionary)
    json_statistics = get_user_statistics(dictionary)
    print(json_statistics)

    response = {
        'days': dictionary['days'],
        'hours': dictionary['hours'],
        'statistics': json_statistics
    }

    return jsonify(response)


@app.route('/usr_update', methods=['GET', 'POST', 'PUT', 'DELETE'])
@token_required
def usr_update():
    user = request.headers.get("username")
    print(user)
    fiscal_code_user = db.select_col_where("user", "fiscal_code", "username", user)[0]["fiscal_code"]
    vat = db.select_col_where("user_to_customer", "cusID", "userID", fiscal_code_user)[0]["cusID"]

    def extract_name_from_string(data_string):  # FA SCHIFO MA FUNZIONA
        try:
            data_dict = json.loads(data_string)
            value = next(iter(data_dict.values()))
            name = value.strip('"')
            return name
        except (json.JSONDecodeError, AttributeError, StopIteration):
            return None

    if request.method == 'GET':

        all_usrs = db.select_col("user", "username")
        return jsonify(all_usrs)

    elif request.method == 'POST':

        name = request.json['name']
        surname = request.json['surname']
        username = request.json['username']
        password = request.json['password']
        fiscal_code = request.json['fiscal_code']
        role = request.json['role']

        insert_usr = db.insert(
            "user",
            ("name", "surname", "username", "password", "fiscal_code"),
            (name, surname, username, password_hash(password), fiscal_code)
        )

        insert_usr_to_cstmr = db.insert(
            "user_to_customer",
            ("cusID", "userID", "role", "whitelist"),
            (vat, fiscal_code, role, 0)
        )

        return jsonify({"status": "success", "message": "User created successfully!"})

    elif request.method == 'PUT':

        json_to_string = request.headers.get("user")
        query = extract_name_from_string(json_to_string)
        print(query)

        name = request.json['name']
        surname = request.json['surname']
        username = request.json['username']
        password = request.json['password']
        fiscal_code = request.json['fiscal_code']
        prefix = request.json["prefix"]
        phone_number = request.json["phone_number"]
        email = request.json["email"]
        address = request.json["address"]
        gender = request.json["gender"]

        update_usr = db.update_multiple(
            table="user",
            column_names=["name", "surname", "username", "password", "fiscal_code",
                          "phone_number", "email", "address", "gender"],
            column_values=[name, surname, username, password_hash(password), fiscal_code,
                           prefix + phone_number, email, address, gender],
            where_column="username",
            where_value=query
        )

        ### COME INDIVIDUO UNIVOCAMENTE L'UTENTE SE DEVO CAMBIARE IL COD. FISCALE? ###

        # update_usr_to_cstmr = db.update(
        #     table="user_to_customer",
        #     set_column="userID",
        #     set_value=fiscal_code,
        #     where_column="userID",
        #     where_value="FISCALCODE" ???
        # )

        return jsonify({"status": "success", "message": "User information updated successfully!"})

    elif request.method == 'DELETE':

        try:
            username = request.get_json()["username"]

            if not username:
                return jsonify({"status": "error", "message": "Username parameter is missing."}), 400

            fiscal_code_result = db.select_col_where("user", "fiscal_code", "username", username)

            if not fiscal_code_result:
                return jsonify({"status": "error", "message": "User not found."}), 404

            fiscal_code = fiscal_code_result[0]["fiscal_code"]
            delete_usr = db.delete("user", "username", username)

            if not fiscal_code:
                return jsonify({"status": "error", "message": "Fiscalcode parameter is missing."}), 400

            delete_usr_to_cstmr = db.delete("user_to_customer", "userID", fiscal_code)

            if delete_usr and delete_usr_to_cstmr:
                return jsonify({"status": "success", "message": "User deleted successfully!"})

            else:
                return jsonify({"status": "error", "message": "Failed to delete user."}), 500

        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    else:
        return jsonify({'message': 'Method not allowed'}), 405


@app.route('/rfid_update', methods=['GET', 'POST', 'PUT', 'DELETE'])
@token_required
def rfid_card_management():
    user = request.headers.get("username")
    print(user)

    rfid_key = db.select_col_where("user", "RFID_key", "username", user)[0]["RFID_key"]

    if request.method == 'GET':
        if rfid_key is None:
            return jsonify({'message': 'No card associated'})
        return jsonify({'rfid_card': rfid_key})

    elif request.method == 'POST':
        # Delete the RFID card from the database
        update = db.update(
            table="user",
            set_column="RFID_key",
            set_value=None,
            where_column="username",
            where_value=user
        )
        return jsonify({'message': 'RFID card deleted'})

    elif request.method == 'PUT':
        data = request.get_json()
        new_rfid_card = data['rfid_card']

        # Update the RFID card in the database
        update = db.update(
            table="user",
            set_column="RFID_key",
            set_value=new_rfid_card,
            where_column="username",
            where_value=user
        )
        return jsonify({'message': 'RFID card updated'})

    elif request.method == 'DELETE':
        # Delete the RFID card from the database
        update = db.update(
            table="user",
            set_column="RFID_key",
            set_value=None,
            where_column="username",
            where_value=user
        )
        return jsonify({'message': 'RFID card deleted'})


@app.route('/login', methods=['POST'])
def login():
    user = request.json["username"]
    roles = {
        "name": "COMPANY",
        "role": "ROLE",
        "cusID": "CUSID"
    }
    saved_hash = get_user_password(db, user)
    if saved_hash is None:
        return jsonify({"exists": False}, {"registered": False}, roles)
    user_pw = request.json["password"]
    is_correct = password_verify(user_pw, saved_hash)
    if not is_correct:
        return jsonify({"exists": False}, {"registered": False}, roles)
    flag_psw = db.select_col_where("user", "flag_password_changed", "username", user)[0]["flag_password_changed"]
    print(flag_psw)

    response = make_response("success")

    # ??? #

    if flag_psw == 0:
        response.set_cookie("exists", "true")
        response.set_cookie("registered", "false")
        response.set_cookie("roles", "example_roles")

        return response

    # ??? #

    fiscal_code = get_id_from_user(db, user)
    roles = get_all_roles(db, fiscal_code)
    print(roles)
    # Generates the JWT token
    token = jwt.encode({'username': user, 'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']},
                       app.config['JWT_SECRET_KEY'], algorithm='HS256')
    return jsonify({"exists": True}, {"registered": True}, roles, {"token": token})


##### TO WRITE DOWN THE NEW LOGOUT FUNCTION #####
# --> logout is handled client-side, it removes the token from the header and bring the user back to the login page.
#
# @app.route('/logout')
# @login_required
# def logout():
#     session.pop("username", None)
#     flash('You were just logged out!')
#     return redirect(url_for('welcome'))


# @app.route("/door", methods=["POST"])
# def control_door():
#     print("door start")
#     rfid = request.json.get("rfid", None)
#     door_id = request.json.get("door_id", None)
#     print(request.json)
#     if rfid is None or door_id is None:
#         return "461"
#
#     print("rfid check pass")
#
#     request_status = validate_rfid_event(
#         db=db,
#         rfid=request.json["rfid"],
#         door_id=request.json["door_id"]
#     )
#     if request_status != 0:
#         return "460"
#
#     print("request status pass")
#
#     get_door_status = requests.get(f"http://{request.remote_addr}:5000/door")
#     if not get_door_status.ok:
#         return "462"  # Could not reach the door
#
#     print("reached door pass")
#
#     door_data = get_door_status.json()
#     if "state" not in door_data:
#         return "463"  # request misses critical information
#
#     print("critical info pass")
#
#     command = "open" if door_data["state"] == "closed" else "close"
#     door_command = {"command": command}
#     headers = {"Content-type": "application/json"}
#     set_door_status = requests.post(f"http://{request.remote_addr}:5000/door", json=door_command, headers=headers)
#     if not set_door_status.ok:
#         return "464"  # the door was not set
#
#     print("set door pass")
#
#     return "ok"
#
#
# @app.route("/cardforuser", methods=["POST"])
# def associate_new_card_to_user():
#     rfid = request.json.get("rfid", None)
#     door_id = request.json.get("door_id", None)
#     rfid_password = request.json.get("content", None)
#
#     if rfid is None or door_id is None or rfid_password is None:
#         return "461"
#
#     if door_id not in pending_user_creations:
#         return "460"
#
#     return "OK"
#
#
# def create_temp_user(
#         user_context: str = "IT98803960651",
#         user_fiscal_code: str = "CSTLRT98",
#         user_role: str = "USR",
#         rfid_number: int = 42,
#         set_password: str | None = "Paolo1!"
# ):
#     caller_role = get_role_from_ids(db, get_id_from_user(db, session["username"]), user_context)
#     if caller_role == "USR" or \
#             (caller_role == "CO" and user_role != "USR") or \
#             (caller_role == "CA" and user_role not in ["USR", "CO"]):
#         return "no permissions"  # no permissions to make the operation
#
#     user_fetch = db.select_where(
#         table="user",
#         column="fiscal_code",
#         value=user_fiscal_code
#     )
#
#     if len(user_fetch) < 1:  # se l'utente non esiste proprio
#         password = set_password if set_password is not None else random_secure_password()
#         db.insert(  # viene creato un utente nuovo, con password temporanea e RFID data
#             table="user",
#             columns=("username", "password", "fiscal_code", "RFID_key"),
#             values=(user_fiscal_code, password_hash(password), user_fiscal_code, rfid_number)
#         )
#
#     user_role_in_company = db.select_wheres(
#         table="user_to_customer",
#         column_1="cusID",
#         value_1=user_context,
#         column_2="userID",
#         value_2=user_fiscal_code
#     )
#     # se esiste già ma non nell'azienda, dagli il ruolo x nell'azienda
#     today = datetime.now()
#     tomorrow = today + timedelta(days=1)
#
#     if len(user_role_in_company) < 1:
#
#         db.insert(
#             table="user_to_customer",
#             columns=("cusID", "userID", "role", "time_in", "time_out"),
#             values=(user_context, user_fiscal_code, user_role, date_to_str(today), date_to_str(tomorrow))
#         )
#     else:
#         db.update_multiple_wheres(
#             table="user_to_customer",
#             column_names=["role", "time_out"],
#             column_values=[user_role, date_to_str(tomorrow)],
#             where_col_1="cusID",
#             where_val_1=user_context,
#             where_col_2="userID",
#             where_val_2=user_fiscal_code
#         )
#     return "OK"
#
#
# @app.route("/createuser", methods=["GET", "POST"])
# def create_user():
#     if request.method == "GET":
#         today = datetime.now().strftime("%Y-%m-%d")
#         tomorrow = datetime.now() + timedelta(days=1)
#         tomorrow = tomorrow.strftime("%Y-%m-%d")
#         return render_template("create_user.html", today=today, tomorrow=tomorrow)
#     else:
#         print(request.form.to_dict())
#
#         return "OK"


if __name__ == '__main__':
    try:
        app.run(host="localhost", debug=True)
    finally:
        scheduler.shutdown()
