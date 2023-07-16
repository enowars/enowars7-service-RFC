import functools
import string
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

def check_registration_data(username, password, rpassword):
    error = None
    if not username or len(username) < 3 or len(username) > 35:
        error = 'Username is required and has to be at least 3 characters long.'
    elif not password or len(password) < 5 or len(password) > 35:
        error = 'Password is required and has to be at least 5 characters long.'
    elif password != rpassword:
        error = 'Passwords do not match.'
    return error


@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        rpassword = request.form['rpassword']
        error = check_registration_data(username, password, rpassword)

        if error is None:
            dt = datetime.datetime.now(timezone.utc)
            init_time = int(dt.timestamp())
            try:
                db = get_db()
#                password_hash = generate_password_hash(password)
                db.execute(
                    "INSERT INTO user (username, password, init_time) VALUES (?, ?, ?)",
                    (username, password, init_time),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))
        flash(error)

    return render_template('auth/register.html')

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
#        elif not check_password_hash(user['password'], password):
        elif password != user['password']:
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for("blog.index"))

        flash(error)

    return render_template('auth/login.html')

def convert_str_to_unixtimestamp(timestr: str):
    date, timec = timestr.split(' ', 1)
    datecomp=date.split('-')
    timec = timec.split('.', 1)[0]
    timecomp=timec.split(':')
    dto = datetime.datetime(int(datecomp[0]), int(datecomp[1]), int(datecomp[2]), int(timecomp[0]), int(timecomp[1]), int(timecomp[2]), tzinfo=timezone.utc)
    return dto.timestamp()

@bp.route('/accessblogpost/<int:id>', methods=('GET', 'POST'))
@login_required
def accessblogpost(id):

    if request.method == 'POST':
        db = get_db()
        try:
            query = db.execute(
                'SELECT title, body, created, author_id, key, is_private, is_hidden, id FROM post WHERE id = ?', (id,)
            ).fetchone()
        except:
            abort(403, 'Forbidden')

        usercode = request.form['code']
        blogpost_creation_time = int(convert_str_to_unixtimestamp(str(query['created'])))
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
        try:
            query = db.execute(
            'SELECT title, body, created, author_id, is_private, is_hidden, p.id, username'
            ' FROM post p JOIN user u ON p.author_id = u.id'
            ' WHERE p.id = ?', (id,)
            ).fetchone()

            query2 = db.execute(
                'SELECT id FROM invitation WHERE user_id = ? AND post_id = ?',
                (g.user['id'], id,)
            ).fetchone()
        except:
            flash("a db error occured")
            return render_template('auth/test_totp_login.html')

        if query is None:
            return redirect(url_for('index'))

        if g.user['id'] == query['author_id']:
            return render_template('blog/blogpost.html', post=query)
        elif query['is_hidden'] == "FALSE" and query['is_private'] == "FALSE":
            return render_template('blog/blogpost.html', post=query)
        else:
            return render_template('auth/test_totp_login.html', title=query['title'])

    return render_template('auth/test_totp_login.html')

@bp.route('/accountInfo', methods=('GET', 'POST'))
@login_required
def account_info():
    db = get_db()
    error = None
    try:
        #THIS query currently fetches ALL posts
        #posts = db.execute(
        #    'SELECT p.id, title, created, author_id, is_hidden, key, username'
        #    ' FROM post p JOIN user u ON p.author_id = u.id'
        #    ' ORDER BY created DESC'
        #).fetchall()

        posts = db.execute(
            'SELECT p.id, title, created, author_id, is_hidden, key, username'
            ' FROM post p JOIN user u ON p.author_id = u.id'
            ' WHERE u.id = ?'
            ' ORDER BY created DESC',
            (g.user['id'],)
        ).fetchall()

        invitations = db.execute(
            'SELECT i.post_id, i.user_id, p.id, title, key, created'
            ' FROM post p JOIN invitation i ON p.id = i.post_id'
            ' WHERE i.user_id = ?',
            (g.user['id'],)
        ).fetchall()

        #invitations = db.execute(
        #    'SELECT i.post_id, i.user_id, p.id, title, key, created'
        #    ' FROM post p JOIN invitation i ON p.id = i.post_id'
        #).fetchall()
    except:
        error = "An error occured when fetching post information."
        flash(error)

    if error is not None:
        render_template('auth/account.html', posts=None, invitations=None)


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
    return render_template('auth/account.html', posts=posts, invitations=invitations)


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
@login_required
def logout():
    session.clear()
    return redirect(url_for('index'))
