# Import the Flask class and other extensions from the flask module
from flask import Flask, render_template, url_for, request, redirect, \
    session, flash, g
from functools import wraps
import mysql.connector

# create the application object
app = Flask(__name__)

app.secret_key = "secret_key"

app.database = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="door_cntrl_system"
)


# login required decorator
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('You need to login first.')
            return redirect(url_for('login'))
    return wrap


# use decorators to link the function to a URL
@app.route('/')
@login_required
def home():  # g is used in flask to store a temporary object or request ---> db connection
    g.db = connect_db()
    cursor = g.db.cursor()
    sql = 'SELECT * FROM user'
    cursor.execute(sql)
    posts = [dict(id=row[0], name=row[1], surname=row[2]) for row in cursor.fetchall()]
    g.db.close()
    return render_template('index.html', posts=posts)  # render a template


@app.route('/welcome')
def welcome():
    return render_template("welcome.html")  # render a template


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != 'admin' or request.form['password'] != 'password':
            error = 'Invalid credentials. Please try again.'
        else:
            session['logged_in'] = True
            flash('You were just logged in!')
            return redirect(url_for('home'))
    return render_template('login.html', error=error)


@app.route('/logout')
@login_required
def logout():
    session.pop('logged_in', None)
    flash('You were just logged out!')
    return redirect(url_for('welcome'))


def connect_db():
    return app.database


if __name__ == '__main__':
    app.run(debug=True)
