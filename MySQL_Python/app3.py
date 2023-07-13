# standard libraries imports

from flask import (
    Flask, jsonify, request, render_template, make_response, url_for
)
from flask_mail import Mail, Message
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, get_jwt_identity, verify_jwt_in_request,
    create_refresh_token, get_jwt
)
from apscheduler.schedulers.background import BackgroundScheduler
import time
import requests
import os
import json

# custom modules imports

from utilities.server_functions import (
    get_geninfo_from_user, change_password, get_user_password,
    validate_rfid_event, name_from_rfid, get_user_rfid
)
from utilities.database import Database
from utilities.custom_http_errors import DoorHTTPException
from utilities.mail import request_password_recovery, verify_recovery_code
from utilities.password_functions import password_verify
from utilities.data_validation import validate_data
from auth.auth import oauth_init

# app configuration

app_ip = "192.168.43.56"
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


@app.route("/cookies", methods=["GET"])
def cookies():
    return render_template("cookie_viewer.html")


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

        access_token = create_access_token(identity=user)
        refresh_token = create_refresh_token(identity=user)

        if from_browser:    # save the token in a secure cookie
            response = make_response("Login successful!")
            response.set_cookie("access_token", access_token, secure=True)
            return response

        return jsonify({"access_token": access_token,
                        "refresh_token": refresh_token,
                        "msg": "Login successful",
                        "logged_user": user,
                        "impersonated_user": user
                        }), 200


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


#   DOOR ACCESS ROUTES


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
    except:
        print("exception was here")
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
        request_access = requests.post(f"https://{app_ip}:{app_port}/{url_for('access_door')}", json=request_data, verify=False, headers=headers)
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
    request_access = requests.post(f"https://{app_ip}:{app_port}/{url_for('access_door')}", json=request_data, verify=False)
    return jsonify({"msg": "Request sent to main open function"}), request_access.status_code


# end of routes


if __name__ == "__main__":
    app.run(host=app_ip, port=app_port, ssl_context="adhoc")
