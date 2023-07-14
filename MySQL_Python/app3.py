# standard libraries imports

from flask import (
    Flask, jsonify, request, render_template, make_response, url_for, redirect
)
from flask_mail import Mail, Message
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, get_jwt_identity, verify_jwt_in_request,
    create_refresh_token, get_jwt, decode_token
)
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
from copy import deepcopy
import time
import requests
import os
import json

# custom modules imports

from utilities.server_functions import (
    get_geninfo_from_user, change_password, get_user_password,
    validate_rfid_event, name_from_rfid, get_user_rfid, fiscal_code_from_rfid, is_rfid_unique,
    interact_with_area, company_from_prefix,
    password_hash,
    get_id_from_user, get_role_from_ids, am_i_sa, is_role_higher, does_username_exist,
    company_presence_in_areas, get_user_from_email
)
from utilities.database import Database
from utilities.custom_http_errors import DoorHTTPException
from utilities.mail import request_password_recovery, verify_recovery_code
from utilities.password_functions import password_verify
from utilities.data_validation import validate_data
from auth.auth import oauth_init

# app configuration

app_ip = "192.168.1.192"
app_port = 5000

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("door_secret")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET")
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_DEFAULT_SENDER"] = "DCS Password recovery dcs.reset@gmail.com"
app.config["MAIL_USERNAME"] = "dcs.reset@gmail.com"
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_APP_PASSWORD")
# app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
# app.config["JWT_ACCESS_COOKIE_PATH"] = "/"

jwt = JWTManager(app)
oauth = oauth_init(app)
mail = Mail(app)

# database connection

retry_seconds = 10
while True:
    db = Database(
        host="localhost",
        database="door_cntrl_system",
        port=3306
    )

    db.connect_as(
        user="root",
        password=""
    )
    if db.is_connected():
        print(f"Connected to database.")
        break
    print(f"Could not connect to database. Retrying in {retry_seconds} seconds.")
    time.sleep(retry_seconds)

# user creation and role permissions dictionaries

pending_user_creations: dict[str, list[dict] | None] = {}
accepted_user_creations: dict[str, list[dict] | None] = {}
rejected_user_creations: dict[str, list[dict] | None] = {}
role_permissions: dict[str, dict[str, bool] | None] = {}


def update_users_permissions():
    role_data = db.select_all("roles")
    for role in role_data:
        role_permissions[role["name"]] = {k: v for k, v in role.items() if k != "name"}


def reset_user_creations():
    global accepted_user_creations
    global rejected_user_creations
    global pending_user_creations
    accepted_user_creations.clear()
    rejected_user_creations.clear()
    pending_user_creations.clear()


# scheduler configuration

scheduler = BackgroundScheduler()
scheduler.add_job(  # update user permissions from database at 3 AM every day (local machine time)
    func=update_users_permissions,
    trigger="cron",
    hour=3
)
scheduler.add_job(  # clear RFID mode user creation dictionaries at 3 AM every day (local machine time)
    func=reset_user_creations,
    trigger="cron",
    hour=3
)
scheduler.start()

# token blacklist

token_blacklist = set()


@jwt.token_in_blocklist_loader
def is_token_in_blacklist(header, token):
    jti = token["jti"]
    return jti in token_blacklist


# adding the new HTTP errors


@app.errorhandler(DoorHTTPException)
def handle_error(error):
    return render_template("error.html", error=error)


update_users_permissions()
reset_user_creations()


# app routes


@app.route("/", methods=["GET"])
@jwt_required()
def home():
    return jsonify({"msg": "hello world"}), 200


@app.route("/testarea", methods=["GET"])
def testarea():
    return company_presence_in_areas(db, "IT98803960651")


@app.route("/cookies", methods=["GET"])
def cookies():
    return render_template("cookie_viewer.html")


@app.route("/test")
def test():
    interact_with_area(db, "CST1234ECC", "MVEF666")
    return "OK"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("basic_login.html")
    else:
        user = request.form.get("username", None)
        from_browser = True
        pw = request.form.get("password", None)
        if user is None:
            user = request.json.get("username", None)
            from_browser = False
        if pw is None:
            pw = request.json.get("password", None)
        if user is None or pw is None:
            return jsonify({"msg": "Invalid request"}), 400

        saved_hash = get_user_password(db, user)
        if saved_hash is None:
            return jsonify({"msg": "Wrong username/password"}), 401

        is_verified = password_verify(pw, saved_hash)
        if not is_verified:
            return jsonify({"msg": "Wrong username/password"}), 401

        flag_psw_query = db.select_col_where("user", "flag_password_changed", "username", user)
        try:
            flag_psw = flag_psw_query[0]["flag_password_changed"]
            if flag_psw == 0:
                return jsonify({"msg": "The user has to register first!"}), 461

        except (IndexError, KeyError):
            return jsonify({"msg": "Error in retrieving user flags"}), 461

        access_token = create_access_token(identity=user)
        refresh_token = create_refresh_token(identity=user)

        if from_browser:  # save the token in a secure cookie
            response = make_response("Login successful!")
            response.set_cookie("access_token", access_token, secure=True)
            return response

        return jsonify({"access_token": access_token,
                        "refresh_token": refresh_token,
                        "msg": "Login successful",
                        "logged_user": user,
                        "impersonated_user": user
                        }), 200


@app.route('/authorize/google')
def google_authorize():
    token = oauth.google.authorize_access_token()
    resp = oauth.google.get('userinfo')
    resp.raise_for_status()
    profile = resp.json()
    if "email" not in profile or not profile.get("verified_email", False):
        raise DoorHTTPException.failed_google_auth()

    user_data = get_user_from_email(db, profile["email"])
    if not user_data:
        raise DoorHTTPException.email_does_not_exist()

    access_token = create_access_token(identity=user_data["username"])
    refresh_token = create_refresh_token(identity=user_data["username"])

    return jsonify({"access_token": access_token,
                    "refresh_token": refresh_token,
                    "msg": "Login successful",
                    "logged_user": user_data["username"],
                    "impersonated_user": user_data["username"]
                    }), 200


@app.route('/login/google')
def google_login():
    redirect_uri = f"https://{app_ip}.nip.io:{app_port}/authorize/google"
    return oauth.google.authorize_redirect(redirect_uri)


@app.route("/refresh_token", methods=["POST"])
@jwt_required(refresh=True)
def refresh_token():
    current_user = get_jwt_identity()
    return jsonify({"access_token": create_access_token(identity=current_user)}), 200


@app.route("/logout", methods=["GET", "POST", "DELETE"])
@jwt_required()
def logout():
    if request.method == "GET":
        return render_template("logout.html")
    else:
        jti = get_jwt()["jti"]
        token_blacklist.add(jti)
        return jsonify({"msg": "Logout successful"}), 200


@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "GET":
        return render_template("request_password_change.html", error_message="none")
    else:
        print("entered post")
        user = request.json.get("username", None)
        print(f"user: {user}")
        if user is None:
            return jsonify({"msg": "Username not provided"}), 401
        route_link = f"https://{app_ip}:{app_port}/reset_link"
        geninfo = get_geninfo_from_user(db, user)
        email_address = geninfo.get("email", None)
        request_password_recovery(db, user, mail, email_address, route_link)
        return jsonify({"msg": "Password recovery requested. An email will be sent if the user exists."}), 200


@app.route("/reset_link/<user>/<code>", methods=["GET", "POST"])
def reset_link(user, code):
    if request.method == "GET":
        return render_template("change_password.html", user=user, code=code)
    else:
        print("entered reset POST")
        if user is None and code is None:
            str_args = request.json.get("verification_code")
            user = str_args[0]
            code = str_args[1]

        is_correct = verify_recovery_code(db, user, code)
        if not is_correct:
            return jsonify({"msg": "Invalid or expired code"}), 401
        print("the recovery code is correct")
        print(f"request json: {request.form}")
        new_password = request.form.get("confirm_password", None)
        print(f"password: {new_password}")
        if not new_password:
            return jsonify({"msg": "Missing password"}), 401
        print("the password is in the JSON")
        is_password_secure = validate_data(new_password, "password")
        if not is_password_secure:
            return render_template("change_password.html", user=user, code=code, error_code="Password not secure!")
        print("the password is secure")
        change_password(db, user, new_password)
        print("the password was changed")
        return jsonify({"msg": "Password successfully changed"}), 200


####    DOOR INTERFACE ROUTES   ####


@app.route("/door", methods=["POST"])
def access_door():
    print(request.json)
    rfid = request.json.get("rfid", None)
    door_id = request.json.get("door_id", None)
    door_id_ex = request.json.get("door_id_ex", None)
    is_qr = request.json.get("is_qr", False)
    is_dac = request.json.get("is_dac", False)

    if rfid is None or door_id is None or door_id_ex is None:
        return jsonify({"msg": "Invalid door parameters."}), 461
    print("before validate")
    request_status = validate_rfid_event(
        db=db,
        rfid=rfid,
        door_id=door_id_ex
    )
    print(request_status)
    if request_status != 0:
        return jsonify({"msg": "Invalid RFID event."}), 460
    print("after validate: {}")
    if not is_qr and not is_dac:
        remote_addr = request.remote_addr
    else:
        remote_addr = request.json.get("door_ip")
        if remote_addr is None:
            return jsonify({"msg": "Invalid door IP."}), 461
    print(remote_addr)
    door_status = requests.get(f"http://{remote_addr}:5000/door")
    if not door_status.ok:
        return jsonify({"msg": "Could not communicate with the door."}), 462

    door_command = {"command": "open"}
    headers = {"Content-type": "application/json"}
    set_door = requests.post(f"http://{remote_addr}:5000/door", json=door_command, headers=headers)
    if not set_door.ok:
        return jsonify({"msg": "Door status not set."}), 464
    username = name_from_rfid(db, rfid)
    if username is None or len(username) < 2:
        return jsonify({"msg": "Problems in the display name."}), 200
    try:
        send_name = requests.post(f"http://{remote_addr}:4999/welcome/{username}", headers=headers)
    except requests.exceptions.ConnectionError:
        print("Could not send name to the DAC interface.")
    fiscal_code = fiscal_code_from_rfid(db, rfid)
    interact_with_area(db, fiscal_code, door_id_ex)

    return jsonify({"msg": "success"}), 200


@app.route("/access_door_from_dac", methods=["POST"])
def access_door_from_dac():
    user = request.json.get("username", None)
    pw = request.json.get("password", None)
    door_id = request.json.get("door_id", None)
    if user is None or pw is None or door_id is None:
        return jsonify({"msg": "Invalid request. Username and password required."}), 400
    saved_hash = get_user_password(db, user)
    if saved_hash is None:
        return jsonify({"msg": "Invalid username or password."}), 401
    is_verified = password_verify(pw, saved_hash)
    if not is_verified:
        return jsonify({"msg": "Invalid username or password."}), 401

    rfid = get_user_rfid(db, user)
    request_data = {"rfid": rfid, "door_id": door_id, "is_dac": True, "door_ip": request.remote_addr}
    request_json = json.dumps(request_data)
    headers = {"Content-type": "application/json"}
    print("up to here, it's all fine")
    try:
        request_access = requests.post(f"https://{app_ip}:{app_port}/{url_for('access_door')}", json=request_data,
                                       verify=False, headers=headers)
    except:
        print("exception was here")
    print("fine even here?")
    return jsonify({"msg": "Request sent to main open function"}), 200


@app.route("/door_qr/<door_id>/<door_ip>", methods=["GET", "POST"])
def qr_request_from_browser(door_id, door_ip):
    access_token = request.cookies.get("access_token", None)
    if access_token is None:
        return jsonify({"msg": "No access token in cookies."}), 400
    headers = {"Authorization": f"Bearer {access_token}", "Content-type": "application/json"}
    json_data = {"door_id": door_id, "door_ip": door_ip}
    request_access = requests.post(
        f"https://{app_ip}:{app_port}/access_door_from_qr",
        json=json_data,
        headers=headers,
        verify=False
    )
    return jsonify({"msg": "Request sent."}), 200


@app.route("/access_door_from_qr", methods=["POST"])
@jwt_required()
def access_door_from_qr():
    door_id = request.json.get("door_id", None)
    door_ip = request.json.get("door_ip", None)

    if door_id is None or door_ip is None:
        return jsonify({"mag": "Invalid arguments"}), 461
    rfid = get_user_rfid(db, get_jwt_identity())
    if rfid is None:
        return jsonify({"msg": "Could not find user RFID."}), 460
    request_data = {
        "rfid": str(rfid),
        "door_id": str(door_id),
        "is_qr": True,
        "door_ip": door_ip
    }
    request_access = requests.post(f"https://{app_ip}:{app_port}/{url_for('access_door')}", json=request_data,
                                   verify=False)
    return jsonify({"msg": "Request sent to main open function"}), request_access.status_code



@app.route("/displayqueues", methods=["GET"])
def display_queues():
    return f"{accepted_user_creations}\n{pending_user_creations}\n{rejected_user_creations}"


@app.route("/createuser", methods=["GET", "POST"])
@jwt_required(optional=True)
def create_user_route():

    logged_user = get_jwt_identity()
    if logged_user is None:     # no token in the header. check the cookies.
        access_token = request.cookies.get("access_token", None)
        if access_token is None:
            return jsonify({"msg": "No valid access token."}), 400
        token = decode_token(access_token)
        if "sub" not in token or "exp" not in token:
            return jsonify({"msg": "Invalid token in cookies."}), 400
        expiration = datetime.fromtimestamp(token["exp"])
        if expiration < datetime.now():
            return jsonify({"msg": "Token has expired."}), 400
        if not does_username_exist(db, token["sub"]):
            return jsonify({"msg": "Invalid token in cookies."}), 400
        my_username = token["sub"]
    else:
        my_username = logged_user

    if request.method == "GET":
        return render_template("create_user.html")
    else:

        if not request.is_json:
            req_data = request.form.to_dict()
        else:
            req_data = request.json.to_dict()
        print(req_data)
        global pending_user_creations
        mode = req_data.get("registration_type")
        my_id = get_id_from_user(db, my_username)

        if am_i_sa(db, my_id):
            creation_permitted = True

        else:
            company_id = req_data.get("company_id")
            user_role = req_data.get("role")
            my_role = get_role_from_ids(db, my_id, company_id)
            creation_permitted = is_role_higher(my_role, user_role)

        if not creation_permitted:
            return jsonify({"msg": "You cannot create a user with that role."}), 462

        if mode == "rfid":
            print("rfid mode")
            door_id = req_data.get("door_id", None)
            if door_id is None:
                return jsonify({"msg": "No door id specified."})
            if door_id in pending_user_creations:
                pending_user_creations[door_id].append(req_data)
            else:
                pending_user_creations[door_id] = [req_data]
            exit_status = 0
        elif mode == "manual":
            print("manual mode")
            exit_status = create_user(req_data)
            print(f"manual exit status: {exit_status}")
        else:
            return jsonify({"msg": "Invalid creation mode."}), 400

        if exit_status == 0:
            return jsonify({"msg": "Request successful."}), 200
        else:
            return jsonify({"msg": "Creation unsuccessful."}), 400


@app.route("/cardforuser", methods=["POST"])
def assign_rfid_to_queued_user():
    global accepted_user_creations
    global rejected_user_creations
    global pending_user_creations

    door_id = request.json.get("door_id", None)
    door_id_ex = request.json.get("door_id_ex", None)
    rfid = request.json.get("rfid", None)
    #   timestamp_str = request.json.get("timestamp", None)
    content = request.json.get("content", None)
    if door_id is None or door_id_ex is None or rfid is None or content is None:
        return jsonify({"msg": "Invalid request. Missing arguments."}), 461
    #   timestamp = datetime.strptime(timestamp_str, "%y-%m-%d %H:%M:%S")
    if door_id_ex not in pending_user_creations:        # no user enqueued on the selected door
        return jsonify({"msg": "No user enqueued for this door interface."}), 460

    if len(pending_user_creations[door_id_ex]) < 1:     # same thing
        return jsonify({"msg": "No user enqueued for this door interface."}), 460

    # check if the RFID card is unique, not associated to any other user
    unique_rfid = is_rfid_unique(db, rfid)
    if not unique_rfid:
        return jsonify({"msg": "The RFID tag is already associated to another user."}), 461

    pending_data = deepcopy(pending_user_creations[door_id_ex][0])
    pending_data["rfid"] = rfid
    pending_data["temp_password"] = content

    creation_status = create_user(pending_data)
    print(f"creation status: {creation_status}")
    if creation_status == 0:
        if door_id_ex not in accepted_user_creations:
            accepted_user_creations[door_id_ex] = [pending_data]
        else:
            accepted_user_creations[door_id_ex].append(pending_data)
    else:
        if door_id_ex not in rejected_user_creations:
            rejected_user_creations[door_id_ex] = [pending_data]
        else:
            rejected_user_creations[door_id_ex].append(pending_data)
    del pending_user_creations[door_id_ex][0]

    return jsonify({"msg": "Request completed."}), 200

# end of routes


def create_user(user_data: dict) -> int:
    fiscal_code = user_data.get("fiscal_code", None)
    temp_password = user_data.get("temp_password", None)
    rfid = user_data.get("rfid", None)
    role = user_data.get("role", "USR")
    access_permissions = user_data.get("access_permissions", "^\d$")
    whitelist = user_data.get("whitelist", "on")
    if whitelist == "on":
        whitelist = True
    else:
        whitelist = False

    vacation_dates = user_data.get("vacation_start", "") + "_" + user_data.get("vacation_end", "")
    whitelist_dates = user_data.get("whitelist_start", "") + "_" + user_data.get("whitelist_end", "")
    time_mon = user_data.get("monday_start", "") + "-" + user_data.get("monday_end", "")
    time_tue = user_data.get("tuesday_start", "") + "-" + user_data.get("tuesday_end", "")
    time_wed = user_data.get("wednesday_start", "") + "-" + user_data.get("wednesday_end", "")
    time_thu = user_data.get("thursday_start", "") + "-" + user_data.get("thursday_end", "")
    time_fri = user_data.get("friday_start", "") + "-" + user_data.get("friday_end", "")
    time_sat = user_data.get("saturday_start", "") + "-" + user_data.get("saturday_end", "")
    time_sun = user_data.get("sunday_start", "") + "-" + user_data.get("sunday_end", "")

    if rfid is None:
        return -1

    flag_pw_changed = user_data.get("flag_pw_changed", False)
    company_id = user_data.get("company_id", None)
    if company_id is None:
        company_id = company_from_prefix(db, rfid[:4])
        if company_id is None:
            return -1

    if fiscal_code is None or temp_password is None:
        return -1

    # validate data against their regex
    is_data_valid = True
    is_data_valid = is_data_valid and validate_data(fiscal_code, "user_id")
    is_data_valid = is_data_valid and validate_data(temp_password, "password")
    is_data_valid = is_data_valid and validate_data(rfid, "rfid")
    is_data_valid = is_data_valid and validate_data(company_id, "customer_id")

    if not is_data_valid:
        return -2

    # check if the user exists in the tables

    user_query = db.select_where("user", "fiscal_code", fiscal_code)
    utc_query = db.select_wheres("user_to_customer", "userID", fiscal_code, "cusID", company_id)
    acc_query = db.select_where(company_id.lower() + "_access", "user_id", fiscal_code)
    if len(user_query) != 0 or len(utc_query) != 0 or len(acc_query) != 0:
        return -3

    # if not present anywhere, create it

    db.insert("user",
              ("password", "fiscal_code", "RFID_key", "flag_password_changed"),
              (password_hash(temp_password), fiscal_code, rfid, flag_pw_changed)
              )
    db.insert("user_to_customer",
              ("cusID", "userID", "role"),
              (company_id, fiscal_code, role)
              )
    db.insert(company_id.lower() + "_access",
              ("user_id", "access_permissions", "whitelist",
               "time_mon", "time_tue", "time_wed", "time_thu", "time_fri", "time_sat", "time_sun",
               "vacation_dates", "whitelist_dates"
               ),
              (fiscal_code, access_permissions, whitelist,
               time_mon, time_tue, time_wed, time_thu, time_fri, time_sat, time_sun,
               vacation_dates, whitelist_dates
               )
              )
    return 0


if __name__ == "__main__":
    app.run(host=app_ip, port=app_port, ssl_context="adhoc")
