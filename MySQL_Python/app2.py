# Import the Flask class and other extensions from the flask module

from flask import Flask, render_template, url_for, request, redirect, \
    session, flash, jsonify, abort
from functools import wraps

from pytz_deprecation_shim import PytzUsageWarning

from utilities.server_functions import get_user_password, password_verify, password_hash, validate_rfid_event, \
    get_role_from_ids, get_id_from_user, random_secure_password, date_to_str, get_all_roles
from utilities.database import Database
from apscheduler.schedulers.background import BackgroundScheduler
import os
from datetime import datetime, timedelta
import requests
import warnings
warnings.filterwarnings("ignore", category=PytzUsageWarning)

# create the application object
app = Flask(__name__)
app.secret_key = os.getenv("door_secret")


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
"""
    {
        "door_id":  {
                        "fiscal_code":  dictionary with context (the company ID) and role, and info about time
                    }
    }
"""


def update_users_permissions():
    global users_permissions
    users_permissions = {r["role"]: r for r in db.select_all("roles")}


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


# use decorators to link the function to a URL
@app.route('/')
@login_required
def home():
    query = db.select_all("user")
    posts = [dict(id=row["userID"], name=row["name"], surname=row["surname"]) for row in query]
    return render_template('home.html', posts=posts)  # render a template


@app.route('/welcome')
def welcome():
    return render_template("welcome.html")  # render a template


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # print(request.method)
    if request.method == 'POST':
        user = request.form["username"]
        saved_hash = get_user_password(db, user)
        user_pw = request.form["password"]
        is_correct = password_verify(user_pw, saved_hash)
        if not is_correct or saved_hash is None:
            flash("The selected employee does not have those access permissions.")
            return render_template("signup.html")
        session["username"] = user
        flash("more fields to write")
        return render_template("signup.html")
    else:
        return render_template("signup.html")


@app.route('/check_auth', methods=['POST'])
def check_auth():
    user = request.form["username"]
    saved_hash = get_user_password(db, user)
    user_pw = request.form["password"]
    is_correct = password_verify(user_pw, saved_hash)
    if not is_correct or saved_hash is None:
        return jsonify({"error": "The selected employee does not have those access permissions."}), 401
    session["username"] = user
    return jsonify({"message": "Authenticated successfully"})


@app.route('/update_user', methods=['POST'])
def update_user():
    username = request.form["username"]
    prefix = request.form["prefix"]
    phone_number = request.form["phone_number"]
    email = request.form["email"]
    address = request.form["address"]
    birth_date = request.form["birth_date"]
    gender = request.form["gender"]
    new_password = request.form["new_password"]

    print(username)
    print(new_password)
    print(prefix + phone_number)
    print(email)
    print(address)
    print(birth_date)
    print(gender)

    update = db.update_multiple(
        table="user",
        column_names=["username", "password", "phone_number", "mail", "address", "birth_date", "gender"],
        column_values=[username, password_hash(new_password), prefix+phone_number, email, address, birth_date, gender],
        where_column="fiscal_code",
        where_value=session["username"]
    )
    # Check if there is another person with the same username --> check_username()

    return jsonify({"status": "success", "message": "User information updated successfully!"})


# --> here
@app.route('/check_username', methods=['POST'])
def check_username():
    username = request.form["username"]
    saved_hash = get_user_password(db, username)
    if saved_hash is not None:
        return jsonify({"exists": True})
    return jsonify({"exists": False})


@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        print(request.json)
        user = request.json["username"]
        # gestire errori se il form è incompleto (non c'è l'utente, la password...)
        saved_hash = get_user_password(db, user)
        if saved_hash is None:
            # gestire errore se l'utente è sbagliato (non esiste)
            return jsonify({"exists": False})
        user_pw = request.json["password"]
        is_correct = password_verify(user_pw, saved_hash)
        if not is_correct:
            return jsonify({"exists": False})
        # qui la roba che succede se il login è giusto
        session["username"] = user
        roles = log_to_page(user)
        print(roles)
        return jsonify({"exists": True}, roles)
    # else:
    #     return jsonify({"exists": False})


def log_to_page(user):
    fiscal_code = get_id_from_user(db, user)
    roles = get_all_roles(db, fiscal_code)
    return roles


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
        return "462"    # Could not reach the door

    print("reached door pass")

    door_data = get_door_status.json()
    if "state" not in door_data:
        return "463"    # request misses critical information

    print("critical info pass")

    command = "open" if door_data["state"] == "closed" else "close"
    door_command = {"command": command}
    headers = {"Content-type": "application/json"}
    set_door_status = requests.post(f"http://{request.remote_addr}:5000/door", json=door_command, headers=headers)
    if not set_door_status.ok:
        return "464"    # the door was not set

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
        return "no permissions"   # no permissions to make the operation

    user_fetch = db.select_where(
        table="user",
        column="fiscal_code",
        value=user_fiscal_code
    )

    if len(user_fetch) < 1:     # se l'utente non esiste proprio
        password = set_password if set_password is not None else random_secure_password()
        db.insert(              # viene creato un utente nuovo, con password temporanea e RFID data
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
        app.run(debug=True)
    finally:
        scheduler.shutdown()
