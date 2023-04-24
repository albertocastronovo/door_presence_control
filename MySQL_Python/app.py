# Import the Flask class and other extensions from the flask module
from flask import Flask, render_template, url_for, request, redirect, \
    session, flash
from functools import wraps
from utilities.server_functions import get_user_password, password_verify, password_hash
from utilities.database import Database
from apscheduler.schedulers.background import BackgroundScheduler
import os

# create the application object
app = Flask(__name__)
app.secret_key = os.getenv("door_secret")

#your_hashed_pw = password_hash("password2")
#print(your_hashed_pw)

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


def update_users_permissions():
    global users_permissions
    users_permissions = {r["role"]: r for r in db.select_all("roles")}


update_users_permissions()

scheduler = BackgroundScheduler()
scheduler.add_job(
    func=update_users_permissions,
    trigger="cron",
    hour=12
)


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


# use decorators to link the function to a URL
@app.route('/')
@login_required
def home():  # g is used in flask to store a temporary object or request ---> db connection

    query = db.select_all("user")
    posts = [dict(id=row["userID"], name=row["name"], surname=row["surname"]) for row in query]
    return render_template('index.html', posts=posts)  # render a template


@app.route('/welcome')
def welcome():
    return render_template("welcome.html")  # render a template


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
        return redirect(url_for("home"))
    else:
        return render_template("login.html")


@app.route('/logout')
@login_required
def logout():
    session.pop("username", None)
    flash('You were just logged out!')
    return redirect(url_for('welcome'))


if __name__ == '__main__':
    app.run(debug=True)
