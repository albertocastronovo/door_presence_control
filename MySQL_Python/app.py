# Import the Flask class and other extensions from the flask module

from flask import Flask, render_template, url_for, request, redirect, \
    session, flash, jsonify, abort
from functools import wraps
from utilities.server_functions import get_user_password, password_verify, password_hash, validate_rfid_event, \
    get_role_from_ids, get_id_from_user, random_secure_password, date_to_str, validate_new_user_form, get_all_roles, \
    get_geninfo_from_user
from utilities.database import Database
from utilities.door_user import DoorUser, DoorUserSerializer
from apscheduler.schedulers.background import BackgroundScheduler
from utilities.custom_http_errors import DoorHTTPException
import os
import time
from datetime import datetime, timedelta
import requests
from copy import deepcopy

# create the application object
app = Flask(__name__)
app.secret_key = os.getenv("door_secret")
app.session_interface.serializer = DoorUserSerializer()

retry_seconds = 10
while True:
    db = Database(
        host="localhost",
        database="door_cntrl_system",
        port=3306
    )

    db.connect_as(
        user="alberto",
        password="root"
    )
    if db.is_connected():
        print(f"Connected to database.")
        break
    print(f"Could not connect to database. Retrying in {retry_seconds} seconds.")
    time.sleep(retry_seconds)

print(get_all_roles(db, "RTN1234ECC"))

pending_user_creations: dict[str, list[dict]] = {}
accepted_user_creations: dict[str, list[dict]] = {}
rejected_user_creations: dict[str, list[dict]] = {}
role_permissions: dict[str, dict[str, bool]] = {}


"""
    {
        "door_id":  dictionary with context (the company ID) and role, and info about time
                    
    }
"""


def update_users_permissions():
    role_data = db.select_all("roles")
    for role in role_data:
        role_permissions[role["name"]] = {k: v for k, v in role.items() if k != "name"}


update_users_permissions()
print(role_permissions)


def reset_user_creations():
    global accepted_user_creations
    global rejected_user_creations
    global pending_user_creations
    accepted_user_creations.clear()
    rejected_user_creations.clear()
    pending_user_creations.clear()


update_users_permissions()
reset_user_creations()
scheduler = BackgroundScheduler()
scheduler.add_job(      # update user permissions from database at 3 AM every day (local machine time)
    func=update_users_permissions,
    trigger="cron",
    hour=3
)
scheduler.add_job(      # clear RFID mode user creation dictionaries at 3 AM every day (local machine time)
    func=reset_user_creations,
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


def required_permissions(required_perm: tuple[str, ...], company_check: bool = True):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_object: DoorUser = session.get("user_object", None)
            if user_object is None:  # no user object inside the current session
                raise DoorHTTPException.user_object_not_found()

            if company_check:
                company_role = user_object.permissions_in_selected_company()
                if company_role == "none":  # user has no permissions for its selected company
                    raise DoorHTTPException.permissions_not_found()

                role_perm = role_permissions.get(company_role, {})
                if not all(role_perm[perm] for perm in required_perm):
                    raise DoorHTTPException.company_forbidden()

            return f(*args, **kwargs)

        return decorated_function

    return decorator


@app.errorhandler(DoorHTTPException)
def handle_error(error):
    return render_template("error.html", error=error)



@app.route('/')
@login_required
def home():
    roles = get_all_roles(db, session["user_object"].get_fiscal_code())
    id_to_name = {d["cusID"]: d["name"] for d in roles}
    return render_template('home.html', id_to_name=id_to_name)  # render a template


@app.route("/homepage")
@login_required
def homepage():
    return home()


@app.route("/usrpanel")
@login_required
@required_permissions(("see_self_info",))
def USR_panel():
    return "Hello from the USR panel"


@app.route("/copanel")
@login_required
@required_permissions(("see_self_info", "edit_company_USR", "see_as_USR"))
def CO_panel():
    return "Hello from the CO panel"


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

    update = db.update_multiple(
        table="user",
        column_names=["username", "password", "phone_number", "mail", "address", "birth_date", "gender"],
        column_values=[username, password_hash(new_password), prefix + phone_number, email, address, birth_date,
                       gender],
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


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form["username"]
        # gestire errori se il form è incompleto (non c'è l'utente, la password...)
        saved_hash = get_user_password(db, user)
        if saved_hash is None:
            # gestire errore se l'utente è sbagliato (non esiste)
            flash("Wrong username!")
            return render_template("login.html")
        user_pw = request.form["password"]
        is_correct = password_verify(user_pw, saved_hash)
        if not is_correct:
            # gestire errore se la password è sbagliata (ma l'utente esiste)
            flash("Wrong password!")
            return render_template("login.html")
        # qui la roba che succede se il login è giusto
        session["username"] = user
        user_fiscal_code = get_id_from_user(db, user)
        user_info = get_geninfo_from_user(db, user_fiscal_code)
        session["user_object"] = DoorUser(
            name=user_info["name"],
            username=user,
            fiscal_code=user_fiscal_code,
            permissions={d["cusID"]: d["role"] for d in get_all_roles(db, user_fiscal_code)}
        )
        return redirect(url_for("home"))
    else:
        return render_template("login.html")


@app.route("/show_permissions", methods=["GET"])
@login_required
def show_permissions():
    return render_template("permissions.html", perms=session["user_object"].get_permissions())


@app.route("/show_dooruser", methods=["GET"])
@login_required
def show_dooruser():
    return str(session["user_object"])


@app.route("/mycompanies", methods=["GET"])
@login_required
def select_company():
    user_roles = get_all_roles(db, session["user_object"].get_fiscal_code())
    name_to_role = {d["name"]: d["role"] for d in user_roles}
    name_to_id = {d["name"]: d["cusID"] for d in user_roles}
    return render_template(
        "mycompanies.html",
        companies=name_to_role,
        ids=name_to_id
    )


@app.route("/setcompany", methods=["POST"])
@login_required
def set_selected_company():
    set_company = request.form["selected_company"]
    if set_company not in session["user_object"].get_companies():
        flash("Company not in user object")
        return redirect(url_for("homepage"))
    print("arrived here")
    new_dooruser = session["user_object"]
    new_dooruser.set_selected_company(set_company)
    session["user_object"] = deepcopy(new_dooruser)
    return redirect(url_for("homepage"))


@app.route('/logout')
@login_required
def logout():
    session.pop("username", None)
    flash('You were just logged out!')
    return redirect(url_for('welcome'))


@app.route("/door", methods=["POST"])
def control_door():
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
        print(f"Request status: {request_status}")
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
    global accepted_user_creations
    global rejected_user_creations
    global pending_user_creations

    rfid = request.json.get("rfid", None)
    door_id = request.json.get("door_id", None)
    rfid_password = request.json.get("content", None)

    if rfid is None or door_id is None or rfid_password is None:
        return "461"

    if door_id not in pending_user_creations:
        return "460"

    if len(pending_user_creations[door_id]) < 1:
        return "460"

    # check if card is already associated to some user in the database
    card_in_database = db.select_where("user", "RFID_key", rfid)
    pending_user_creations[door_id][0]["rfid"] = rfid
    pending_user_creations[door_id][0]["temp_password"] = rfid_password
    pending_user_creations[door_id][0]["time"] = datetime.now()
    if len(card_in_database) == 0:
        creation_status = create_new_user(pending_user_creations[door_id][0])
    else:
        creation_status = -1

    if creation_status == 0:
        if door_id not in accepted_user_creations:
            accepted_user_creations[door_id] = [pending_user_creations[door_id][0]]
        else:
            accepted_user_creations[door_id].append(pending_user_creations[door_id][0])
    else:
        if door_id not in rejected_user_creations:
            rejected_user_creations[door_id] = [pending_user_creations[door_id][0]]
        else:
            rejected_user_creations[door_id].append(pending_user_creations[door_id][0])
    del pending_user_creations[door_id][0]

    return f"OK {creation_status}"


def create_new_user(params: dict):
    db_insert = db.insert(
        "user",
        ("username", "password", "fiscal_code", "flag_phone", "flag_mail", "RFID_key", "flag_password_changed"),
        (params["userID"], password_hash(params["temp_password"]), params["userID"], 0, 0, int(params["rfid"]), 0)
    )
    return db_insert


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


@app.route("/createdashboard", methods=["GET"])
def create_dashboard():
    print(f"Pending: {pending_user_creations}")
    print(f"Accepted: {accepted_user_creations}")
    print(f"Rejected: {rejected_user_creations}")
    return render_template("rfid_creation_dashboard.html",
                           now=datetime.now(),
                           terminal_ids=list(set(
                               list(accepted_user_creations.keys()) +
                               list(pending_user_creations.keys()) +
                               list(rejected_user_creations.keys())
                           )),
                           accepted_registrations=accepted_user_creations,
                           pending_registrations=pending_user_creations,
                           rejected_registrations=rejected_user_creations
                           )


@app.route("/createuser", methods=["GET", "POST"])
def create_user():
    today = datetime.now().strftime("%Y-%m-%d")
    tomorrow = datetime.now() + timedelta(days=1)
    tomorrow = tomorrow.strftime("%Y-%m-%d")

    if request.method == "GET":
        return render_template("create_user.html", today=today, tomorrow=tomorrow)

    else:
        parameters, err_message = validate_new_user_form(request.form)
        print(f"errore: {err_message}")
        user_id = parameters["userID"]
        if err_message == "OK_rfid":
            # check if the creation of this user is already pending
            users_with_same_id = [
                inner_dict for inner_list in pending_user_creations.values()
                for inner_dict in inner_list
                if user_id in inner_dict and inner_dict["userID"] == user_id
            ]
            if len(users_with_same_id) > 0:
                return render_template("create_user.html",
                                       today=today,
                                       tomorrow=tomorrow,
                                       err_message="This user is already being created")

            # check if the user already exists in the database
            if len(db.select_where("user", "fiscal_code", parameters["userID"])) > 0:
                return render_template("create_user.html",
                                       today=today,
                                       tomorrow=tomorrow,
                                       err_message="This user already exists in the database")

            parameters["time"] = datetime.now()
            door_id = parameters["door_id"]
            if door_id not in pending_user_creations:
                pending_user_creations[door_id] = []
            pending_user_creations[door_id].append(parameters)

            return redirect(url_for("create_dashboard"))
        elif err_message == "OK_manual":
            user_created = create_new_user(parameters)
            if user_created != 0:
                return f"Errore {user_created}"
            return "OK manual"

        else:
            return render_template("create_user.html", today=today, tomorrow=tomorrow, err_message=err_message)


if __name__ == '__main__':
    try:
        app.run(port=5000, debug=True)
    finally:
        scheduler.shutdown()
