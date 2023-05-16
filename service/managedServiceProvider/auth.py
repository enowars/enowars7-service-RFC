import functools
import string
import random
import time
from . import totp_server

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from managedServiceProvider.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        #TODO do not allow question mark chars in username --> redirect could fail
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, password, init_time) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), time.time()),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
                dyn_url = rand + "?" + str(username)
                return redirect(url_for("auth.totp_registration", dyn_url=dyn_url))

        flash(error)

    return render_template('auth/register.html')


@bp.route('/completeRegistration/<dyn_url>', methods=('GET', 'POST'))
def totp_registration(dyn_url):
    #assume the dyn url contains username and init_time
    #This is okay for the prototype but not for the final service
    if request.method == 'POST':
        return redirect(url_for("auth.login"))

    init_time = dyn_url.split('?')[0]
    username = dyn_url.split('?')[1]
    g.user = get_db().execute(
        'SELECT * FROM user WHERE username = ?', (username,)
    ).fetchone()

    return render_template("auth/totp_registration.html")


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
            dyn_url = rand + "?" + str(username)
            return redirect(url_for("auth.totp_login", dyn_url=dyn_url))

        flash(error)

    return render_template('auth/login.html')


@bp.route('/login/<dyn_url>', methods=('GET', 'POST'))
def totp_login(dyn_url):
    if request.method == 'POST':
        db = get_db()
        username = dyn_url.split('?')[1]
        usercode = int(request.form['code'])
        query = db.execute(
            'SELECT init_time, shared_secret FROM user WHERE username = ?', (username,)
        ).fetchone()

        print("name: ", username)
        print("secret:", query['shared_secret'])
        print("usercode: ", usercode)

        totp = totp_server.Totp(init_time=query['init_time'])
        result = totp.validate_otp(int(usercode), totp.generate_shared_secret(str(query['shared_secret'])))
        error = None
        if not result:
            error = "failed to validate OTP. Try Again"
        else:
            return redirect(url_for("index"))

        flash(error)
    return render_template('auth/test_totp_login.html')
    #on successful totp, redirect as shown below
    #return redirect(url_for('index'))

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view
