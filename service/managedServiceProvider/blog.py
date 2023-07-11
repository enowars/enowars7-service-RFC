from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from datetime import timezone
import datetime
from werkzeug.exceptions import abort

from managedServiceProvider.auth import login_required
from managedServiceProvider.db import get_db

bp = Blueprint('blog', __name__)

@bp.route('/', methods=('GET', 'POST'))
def index():
    limit=100
    offset=0
    db = get_db()
    posts = db.execute(
            'SELECT p.id, title, body, created, author_id, is_hidden, username'
            ' FROM post p JOIN user u ON p.author_id = u.id'
            ' ORDER BY created DESC'
            ' LIMIT ? OFFSET ?',
            (limit, offset,)
        ).fetchall()
    return render_template('blog/index.html', posts=posts, limit=limit, offset=offset)

@bp.route('/page/<int:limit>', methods=('GET', 'POST'))
def pages(limit=100):
    if limit > 9223372036854775807 or limit < 0:
        flash("No further posts to show!")
        limit = 100

    offset=0
    db = get_db()
    posts = db.execute(
            'SELECT p.id, title, body, created, author_id, is_hidden, username'
            ' FROM post p JOIN user u ON p.author_id = u.id'
            ' ORDER BY created DESC'
            ' LIMIT ? OFFSET ?',
            (limit, offset,)
        ).fetchall()
    return render_template('blog/index.html', posts=posts, limit=limit, offset=offset)

def check_event_params(title, body, invited, secret_phrase, ispublic):
    error = None
    inv_bool = True
    default_key = "Correct horse battery staple!"
    if not invited:
        inv_bool = False
    if not title or len(title) > 50:
        return "The title must neither be empty, nor exceed 50 characters."
    elif not body or len(body) > 500:
        return "The events needs a concise description."
    elif inv_bool and (len(invited) < 3 or len(invited) > 15):
        return "The invited username is invalid."
    elif invited == g.user['username']:
        return "You cannot invite yourself to an event."

    if not ispublic:
        if not secret_phrase or len(secret_phrase) < 20 or secret_phrase == default_key:
            return "A secret phrase is required. It has to be at least 20 characters long and must not be the default key!"
    return error


def handle_invite(invited, title, ferror):
    error = ferror
    database = get_db()
    try:
        postquery = database.execute('SELECT id FROM post WHERE title = ?',
                                     (title,)
                                     ).fetchone()
        userquery = database.execute('SELECT id FROM user WHERE username = ?',
                                (invited,)
                                ).fetchone()
        query3 = database.execute('INSERT INTO invitation (user_id, post_id)'
                            ' VALUES (?, ?)',
                            (userquery['id'], postquery['id'])
                            )
        database.commit()
    except:
        error = "Oops! Seems like the user you wanted to invite does not exist."

    return error


def insert_event(is_public, is_hidden, is_private, title, body, postkey):

    if is_public == "TRUE":
        try:
            db = get_db()
            db.execute(
                'INSERT INTO post (title, body, author_id, is_private, is_hidden)'
                ' VALUES (?, ?, ?, ?, ?)',
                (title, body, g.user['id'], is_private, is_hidden)
            )
            db.commit()
        except:
            return "The given title already exists. Try a different one!"

    elif is_hidden == "TRUE":
        try:
            db = get_db()
            db.execute(
                'INSERT INTO post (title, body, author_id, key, is_private, is_hidden)'
                ' VALUES (?, ?, ?, ?, ?, ?)',
                (title, body, g.user['id'], postkey, is_private, is_hidden)
            )
            db.commit()
        except:
            return "The given title already exists. Try a different one!"

    else:
        try:
            db = get_db()
            db.execute(
                'INSERT INTO post (title, body, author_id, is_private, is_hidden)'
                ' VALUES (?, ?, ?, ?, ?)',
                (title, body, g.user['id'], is_private, is_hidden)
            )
            db.commit()
        except:
            return "The given title already exists. Try a different one!"

    return None

def update_user_post_count(query):
    try:
        db = get_db()
        num_posts = query['num_posts'] + 1
        db.execute(
            'UPDATE user SET num_posts = ?'
            ' WHERE id = ?',
            (num_posts, g.user['id'])
        )
        db.commit()
    except:
        return "Could not update number of posts for user"


@bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    query=None
    try:
        db = get_db()
        query = db.execute(
            'SELECT num_posts FROM user WHERE id = ?',
            (g.user['id'],)
        ).fetchone()
    except:
        flash("Ooops, somewthing went wrong!")

    if query is None:
        flash("hmpf")
    elif query['num_posts'] >= 5:
        flash("You have created the maximum of five events. Consider upgrading to premium for unlimited posts")
        return render_template('blog/create.html')

    if request.method == 'POST':
        title = request.form['title']
        title = title.strip()
        body = request.form['body']
        invited = request.form['inviteuser']
        postkey = request.form['secret phrase']

        is_hidden = "FALSE"
        if 'hidden' in request.form:
            if request.form['hidden'] == "True":
                is_hidden = "TRUE"

        is_private = "FALSE"
        if 'private' in request.form:
            if request.form['private'] == "True":
                is_private = "TRUE"

        if is_private == "TRUE" or is_hidden == "TRUE":
            error = check_event_params(title, body, invited, postkey, False)
        else:
            error = check_event_params(title, body, invited, postkey, True)

        if error is not None:
            flash(error)

        else:
            if is_hidden == "TRUE":
                error = insert_event("FALSE", is_hidden, is_private, title, body, postkey)
            elif is_private == "TRUE":
                error = insert_event("FALSE", is_hidden, is_private, title, body, postkey)
            else:
                error = insert_event("TRUE", is_hidden, is_private, title, body, postkey)

            if error is None:
                error = update_user_post_count(query)

            if len(invited) != 0:
                error = handle_invite(invited, title, error)
            if error is not None:
                flash(error)
                return render_template('blog/create.html')
            else:
                postquery = db.execute('SELECT id, body FROM post WHERE title = ? AND author_id = ?',
                                       (title, g.user['id'])
                                        ).fetchone()
                return redirect(url_for('auth.accessblogpost', id=postquery['id']))

    return render_template('blog/create.html')


def get_post(id, check_author=True):
    post = get_db().execute(
        'SELECT p.id, title, body, created, author_id, is_private, username, is_hidden'
        ' FROM post p JOIN user u ON p.author_id = u.id'
        ' WHERE p.id = ?',
        (id,)
    ).fetchone()

    if post is None:
        abort(404, f"Post id {id} doesn't exist.")

    if check_author and post['author_id'] != g.user['id']:
        abort(403)
    return post

def check_update_params(body, invited, postkey, ispublic):
    error = None
    inv_bool = True
    default_key = "Correct horse battery staple!"
    if not invited:
        inv_bool = False
    elif not body or len(body) > 500:
        return "The events needs a concise description."
    elif inv_bool and (len(invited) < 3 or len(invited) > 15):
        return "The invited username is invalid."
    elif invited == g.user['username']:
        return "You cannot invite yourself to an event."

    if not ispublic:
        if postkey == default_key or (len(postkey) > 0 and len(postkey) < 20):
            return "The new secret phrase must have at least 20 characters and must not match the default key."
    return error

@bp.route('/<int:id>/update', methods=('GET', 'POST'))
@login_required
def update(id):
    post = get_post(id)

    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']
        invited = request.form['inviteuser']
        postkey = request.form['secret phrase']

        is_private = "FALSE"
        if 'private' in request.form:
            if request.form['private'] == "True":
                is_private = "TRUE"

        is_hidden = "FALSE"
        if 'hidden' in request.form:
            if request.form['hidden'] == "True":
                is_hidden = "TRUE"

        if is_private == "TRUE" or is_hidden == "TRUE":
            error = check_update_params(body, invited, postkey, False)
        else:
            error = check_update_params(body, invited, postkey, True)

        if error is not None:
            flash(error)
            return render_template('blog/update_nodel.html', post=post)

        if len(postkey) == 0:
            try:
                db = get_db()
                db.execute(
                    'UPDATE post SET body = ?, is_private = ?, is_hidden = ?'
                    ' WHERE id = ?',
                    (body, is_private, is_hidden, id)
                )
                db.commit()
            except:
                error = "Oops, something went wrong!"
                flash(error)
                return render_template('blog/update_nodel.html', post=post)
        else:
            try:
                db = get_db()
                db.execute(
                    'UPDATE post SET body = ?, is_private = ?, is_hidden = ?, key = ?'
                    ' WHERE id = ?',
                    (body, is_private, is_hidden, postkey, id)
                )
                db.commit()
            except:
                error = "Oops, something went wrong!"
                flash(error)
                return render_template('blog/update_nodel.html', post=post)

        if len(invited) != 0:
            error = handle_invite(invited, title, error)

        if error is not None:
            flash(error)
            return redirect(url_for('blog.update', id=id))
        else:
            return redirect(url_for('auth.accessblogpost', id=id))

    return render_template('blog/update_nodel.html', post=post)
