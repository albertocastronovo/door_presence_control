# standard libraries imports

from flask import (
    Flask, jsonify, request, render_template, make_response
)
from flask_mail import Mail, Message
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, get_jwt_identity, verify_jwt_in_request
)
from apscheduler.schedulers.background import BackgroundScheduler
import time
import os

# custom modules imports

from utilities.server_functions import (
    get_geninfo_from_user, change_password, get_user_password
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
        user="alberto",
        password="root"
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


# adding the new HTTP errors

@app.errorhandler(DoorHTTPException)
def handle_error(error):
    return render_template("error.html", error=error)


update_users_permissions()
reset_user_creations()

# app routes


@app.route("/test_mail", methods=["GET", "POST"])
def test_mail():
    pass


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("basic_login.html")
    else:
        user = request.form.get("username", None)
        pw = request.form.get("password", None)
        if user is None:
            user = request.json.get("username", None)
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

        return jsonify({"access_token": access_token,
                        "msg": "Login successful",
                        "logged_user": user,
                        "impersonated_user": user
                        }), 200


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

# end of routes


if __name__ == "__main__":
    app.run(host=app_ip, port=app_port, ssl_context="adhoc")
