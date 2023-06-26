# Import the Flask class and other extensions from the flask module
from flask import Flask, render_template, url_for, request, redirect, \
    session, flash, jsonify, g  # ,abort
from flask import make_response
from functools import wraps
import jwt
from pytz_deprecation_shim import PytzUsageWarning
from utilities.server_functions import get_user_password, password_verify, password_hash, validate_rfid_event, \
    get_role_from_ids, get_id_from_user, random_secure_password, date_to_str, get_all_roles, get_user_working_hours, \
    get_user_statistics
from utilities.database import Database
from apscheduler.schedulers.background import BackgroundScheduler
# import os
from datetime import datetime, timedelta
import requests
import warnings

warnings.filterwarnings("ignore", category=PytzUsageWarning)

# create the application object
app = Flask(__name__)
# app.secret_key = os.getenv("door_secret")
app.secret_key = "secret key"

# Configurazione del segreto e della durata del token JWT
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=10)

# Set session to be permanent and set its lifetime
app.permanent_session_lifetime = timedelta(minutes=10)

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


# Funzione per verificare il token JWT
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


# login required decorator
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "username" in session:
            return f(*args, **kwargs)
        else:
            flash('You need to login first.')
            return redirect(url_for('login'))

    return wrap


def permissions_required(flag_list):
    def wrapper_function(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            permissions = session["permissions"]
            for flag in flag_list:
                print(f"flag: {flag}")
                if not permissions.get(flag, False):
                    print(f"invalid flag: {flag}")
                    return
            return f(*args, **kwargs)

        return wrapper

    return wrapper_function


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        print(request.method)
        # session.pop("username", None)
        user = request.json["username"]
        print(user)
        session["username"] = user
        session.permanent = True  # Set session to be permanent
        print(session)
        print(session["username"])
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
            return jsonify({"exists": True, "registered": False})
        return jsonify({"exists": True, "registered": True})

    else:
        print(request.method)
        if "username" in session:
            username = session["username"]
            g.username = username
            # Altre operazioni per il metodo GET
            return jsonify({"username": username})
        else:
            # Altre operazioni per il metodo GET quando la sessione non contiene "username"
            return jsonify({"error": "Session username not found"})


# @app.before_request
# def before_request():
#     if 'username' in session:
#         username = session['username']
#         g.username = username
#         print(username)
#         session.permanent = True  # Set session to be permanent
#     else:
#         g.username = None
#
#     # return g.username


@app.route('/update_user', methods=['POST'])
@token_required
def update_user():
    print(session)
    if session:
        username = session["username"]
        user = request.json["username"]
        prefix = request.json["prefix"]
        phone_number = request.json["phone_number"]
        email = request.json["email"]
        address = request.json["address"]
        birth_date = request.json["birth_date"]
        gender = request.json["gender"]
        new_password = request.json["new_password"]

        print(username)
        print(user)
        print(new_password)
        print(prefix + phone_number)
        print(email)
        print(address)
        print(birth_date)
        print(gender)

        update = db.update_multiple(
            table="user",
            column_names=["username", "password", "phone_number", "email", "address", "birth_date", "gender",
                          "flag_phone", "flag_mail", "flag_password_changed"],
            column_values=[user, password_hash(new_password), prefix + phone_number, email, address, birth_date,
                           gender, 1, 1, 1],
            where_column="fiscal_code",
            where_value=username
            # where_value="FISCALCODE"
        )
        # Check if there is another person with the same username --> check_username()

        return jsonify({"status": "success", "message": "User information updated successfully!"})

    else:
        return jsonify({"error": "Session username not found"})


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
def new_password():
    if session:
        username = session["username"]
        new_password = request.json["new_password"]
        print(new_password)

        update = db.update(
            table="user",
            set_column="password",
            set_value=password_hash(new_password),
            where_column="username",
            where_value=username
        )

        return jsonify({"status": "success", "message": "User information updated successfully!"})

    else:
        return jsonify({"error": "Session username not found"})


@app.route('/change_profile_data', methods=['POST'])
def change_profile_data():
    if session:
        username = session["username"]
        user = request.json["username"]
        prefix = request.json["prefix"]
        phone_number = request.json["phone_number"]
        email = request.json["email"]
        address = request.json["address"]
        gender = request.json["gender"]

        print(username)
        print(user)
        print(prefix + phone_number)
        print(email)
        print(address)
        print(gender)

        update = db.update_multiple(
            table="user",
            column_names=["username", "phone_number", "email", "address", "gender",
                          "flag_phone", "flag_mail", "flag_password_changed"],
            column_values=[user, prefix + phone_number, email, address, gender, 1, 1, 1],
            where_column="username",
            where_value=username
        )

        return jsonify({"status": "success", "message": "User information updated successfully!"})

    else:
        return jsonify({"error": "Session username not found"})


@app.route('/db_personal_data', methods=['GET'])
@token_required
def extract_from_db():

    user = "utente2"
    # user = session["username"]
    user_fetch = db.select_where(
        table="user",
        column="username",
        value=user
    )

    return user_fetch[0]



@app.route('/view_statistics', methods=['GET'])
def stats():
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


@app.route('/rfid_update', methods=['GET', 'POST', 'PUT', 'DELETE'])
def rfid_card_management():

    if session:

        user = session["username"]
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

    else:
        return jsonify({"error": "Session username not found"})


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

    if flag_psw == 0:
        response.set_cookie("exists", "true")
        response.set_cookie("registered", "false")
        response.set_cookie("roles", "example_roles")

        return response

    session["username"] = user
    print(session)
    fiscal_code = get_id_from_user(db, user)
    roles = get_all_roles(db, fiscal_code)
    print(roles)
    # Genera il token JWT
    token = jwt.encode({'username': user, 'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']},
                       app.config['JWT_SECRET_KEY'], algorithm='HS256')
    return jsonify({"exists": True}, {"registered": True}, roles, {"token": token})


@app.route('/logout')
@login_required
def logout():
    session.pop("username", None)
    flash('You were just logged out!')
    return redirect(url_for('welcome'))


@app.route("/door", methods=["POST"])
def control_door():
    print("door start")
    rfid = request.json.get("rfid", None)
    door_id = request.json.get("door_id", None)
    print(request.json)
    if rfid is None or door_id is None:
        return "461"

    print("rfid check pass")

    request_status = validate_rfid_event(
        db=db,
        rfid=request.json["rfid"],
        door_id=request.json["door_id"]
    )
    if request_status != 0:
        return "460"

    print("request status pass")

    get_door_status = requests.get(f"http://{request.remote_addr}:5000/door")
    if not get_door_status.ok:
        return "462"  # Could not reach the door

    print("reached door pass")

    door_data = get_door_status.json()
    if "state" not in door_data:
        return "463"  # request misses critical information

    print("critical info pass")

    command = "open" if door_data["state"] == "closed" else "close"
    door_command = {"command": command}
    headers = {"Content-type": "application/json"}
    set_door_status = requests.post(f"http://{request.remote_addr}:5000/door", json=door_command, headers=headers)
    if not set_door_status.ok:
        return "464"  # the door was not set

    print("set door pass")

    return "ok"


@app.route("/cardforuser", methods=["POST"])
def associate_new_card_to_user():
    rfid = request.json.get("rfid", None)
    door_id = request.json.get("door_id", None)
    rfid_password = request.json.get("content", None)

    if rfid is None or door_id is None or rfid_password is None:
        return "461"

    if door_id not in pending_user_creations:
        return "460"

    return "OK"


def create_temp_user(
        user_context: str = "IT98803960651",
        user_fiscal_code: str = "CSTLRT98",
        user_role: str = "USR",
        rfid_number: int = 42,
        set_password: str | None = "Paolo1!"
):
    caller_role = get_role_from_ids(db, get_id_from_user(db, session["username"]), user_context)
    if caller_role == "USR" or \
            (caller_role == "CO" and user_role != "USR") or \
            (caller_role == "CA" and user_role not in ["USR", "CO"]):
        return "no permissions"  # no permissions to make the operation

    user_fetch = db.select_where(
        table="user",
        column="fiscal_code",
        value=user_fiscal_code
    )

    if len(user_fetch) < 1:  # se l'utente non esiste proprio
        password = set_password if set_password is not None else random_secure_password()
        db.insert(  # viene creato un utente nuovo, con password temporanea e RFID data
            table="user",
            columns=("username", "password", "fiscal_code", "RFID_key"),
            values=(user_fiscal_code, password_hash(password), user_fiscal_code, rfid_number)
        )

    user_role_in_company = db.select_wheres(
        table="user_to_customer",
        column_1="cusID",
        value_1=user_context,
        column_2="userID",
        value_2=user_fiscal_code
    )
    # se esiste già ma non nell'azienda, dagli il ruolo x nell'azienda
    today = datetime.now()
    tomorrow = today + timedelta(days=1)

    if len(user_role_in_company) < 1:

        db.insert(
            table="user_to_customer",
            columns=("cusID", "userID", "role", "time_in", "time_out"),
            values=(user_context, user_fiscal_code, user_role, date_to_str(today), date_to_str(tomorrow))
        )
    else:
        db.update_multiple_wheres(
            table="user_to_customer",
            column_names=["role", "time_out"],
            column_values=[user_role, date_to_str(tomorrow)],
            where_col_1="cusID",
            where_val_1=user_context,
            where_col_2="userID",
            where_val_2=user_fiscal_code
        )
    return "OK"


@app.route("/createuser", methods=["GET", "POST"])
def create_user():
    if request.method == "GET":
        today = datetime.now().strftime("%Y-%m-%d")
        tomorrow = datetime.now() + timedelta(days=1)
        tomorrow = tomorrow.strftime("%Y-%m-%d")
        return render_template("create_user.html", today=today, tomorrow=tomorrow)
    else:
        print(request.form.to_dict())

        return "OK"


if __name__ == '__main__':
    try:
        app.run(host="localhost", debug=True)
    finally:
        scheduler.shutdown()
