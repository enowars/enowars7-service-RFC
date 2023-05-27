import functools
import string
import random
import time
from datetime import timezone
import datetime
from . import totp_server

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from managedServiceProvider.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view


def check_registration_data(username, password, rpassword, secret_phrase):
    error = None
    if not username or len(username) < 3:
        error = 'Username is required and has to be at least 3 characters long.'
    elif not password or len(password) < 5:
        error = 'Password is required and has to be at least 5 characters long.'
    elif password != rpassword:
        error = 'Passwords do not match.'
    elif not secret_phrase or len(secret_phrase) < 20:
        error = "A secret phrase is required and has to be at least 20 characters long."
    return error


@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        rpassword = request.form['rpassword']
        secret_phrase = request.form['secret phrase']
        error = check_registration_data(username, password, rpassword, secret_phrase)

        db = get_db()
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
                #rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
                #dyn_url = rand + "?" + str(username)
                #return redirect(url_for("auth.totp_registration", dyn_url=dyn_url))
                return redirect(url_for("auth.login"))
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
            return redirect(url_for("blog.index"))
            #return redirect(url_for("auth.totp_login", dyn_url=dyn_url))

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

        totp = totp_server.Totp(init_time=query['init_time'])
        result = totp.validate_otp(int(usercode), totp.generate_shared_secret(str(query['shared_secret'])))
        error = None
        if not result:
            error = "Wrong passcode. Try again!"
        else:
            return redirect(url_for("index"))

        flash(error)
    return render_template('auth/test_totp_login.html')
    #on successful totp, redirect as shown below
    #return redirect(url_for('index'))

def convert_str_to_unixtimestamp(timestr: str):
    date, timec = timestr.split(' ', 1)
    datecomp=date.split('-')
    timec = timec.split('.', 1)[0]
    timecomp=timec.split(':')
    dto = datetime.datetime(int(datecomp[0]), int(datecomp[1]), int(datecomp[2]), int(timecomp[0]), int(timecomp[1]), int(timecomp[2]), tzinfo=timezone.utc)
    print("returning")
    return dto.timestamp()

@bp.route('/accessblogpost/<int:id>', methods=('GET', 'POST'))
@login_required
def accessblogpost(id):
    #What information must be included in eventinfo? And what user info do we need?
    # 1. we do not need any user info. whoever has the correct totp can access
    # 2. we need to check whether the event is private. If it is notm forward right away
    #check totp

    #TODO when post, we should ONLY attempt to validate TOTP
    if request.method == 'POST':
        print("processing post...")
        db = get_db()
        query = db.execute(
            'SELECT title, body, created, author_id, key, is_private, id FROM post WHERE id = ?', (id,)
        ).fetchone()

        usercode = request.form['code']
        print("usercode: ", usercode)
        blogpost_creation_time = convert_str_to_unixtimestamp(str(query['created']))
        print("this is: ", blogpost_creation_time)
        totp = totp_server.Totp(init_time=blogpost_creation_time)
        result = totp.validate_otp(int(usercode), totp.generate_shared_secret(query['key']))
        error = None
        if not result:
            error = "Wrong passcode. Try again!"
        else:
            return render_template('blog/blogpost.html', post=query)
        flash(error)

    elif request.method == 'GET':
        db = get_db()

        #change query to make username displayable in html
        query = db.execute(
            'SELECT title, body, created, author_id, is_private, id FROM post WHERE id = ?', (id,)
        ).fetchone()

        if g.user['id'] == query['author_id']:
            return render_template('blog/blogpost.html', post=query)
        elif query['is_private'] == "FALSE":
            return render_template('blog/blogpost.html', post=query)
        else:
            return render_template('auth/test_totp_login.html')

    return render_template('auth/test_totp_login.html')

@bp.route('/accessEvent')
def access_event(eventinfo):
    #What information must be included in eventinfo? And what user info do we need?
    # 1. we do not need any user info. whoever has the correct totp can access
    # 2. we need to check whether the event is private. If it is notm forward right away
    #check totp
    if request.method == 'POST':
        db = get_db()
        query = db.execute(
            'SELECT created, is_private, init_time, event_key FROM event WHERE id = ?', (eventinfo['id'],)
        ).fetchone()

        if not is_private:
            #forward to event page immediately
            return redirect(url_for("index"))
        else:
            usercode = request.method['usercode']
            totp = totp_server.Totp(init_time=query['init_time'])
            result = totp.validate_otp(int(usercode), totp.generate_shared_secret(str(query['event_key'])))
            error = None
            if not result:
                error = "failed to validate OTP. Try Again"
            else:
                return redirect(url_for("index"))
            flash(error)

    #need a similar template to the totp login
    return render_template('auth/test_totp_login.html')

@bp.route('/accountInfo', methods=('GET', 'POST'))
def account_info():
    if request.method == 'POST':
        if g.user == None:
            abort(404, "You have to be logged in to view this page")
        else:
            error = None
            username = request.form['username']
            db = get_db()
            try:
                db.execute("UPDATE user SET username = ? WHERE user.id = ?",
                           (username, g.user['id'],)
                )
                db.commit()
                error = "successfully updated the username"
            except db.IntegrityError:
                error = "Failed to update the username..."

            flash(error)
    return render_template('auth/account.html')


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
