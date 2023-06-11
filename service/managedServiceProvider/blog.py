from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from datetime import timezone
import datetime
from werkzeug.exceptions import abort

from managedServiceProvider.auth import login_required
from managedServiceProvider.db import get_db

bp = Blueprint('blog', __name__)

@bp.route('/')
def index():
    db = get_db()
    # TODO limit the number of displayed events, reduce strain  on db.
    # TODO then introduce a button that loads more posts on demand on the bottom of the page
    posts = db.execute(
        'SELECT p.id, title, body, created, author_id, is_hidden, username'
        ' FROM post p JOIN user u ON p.author_id = u.id'
        ' ORDER BY created DESC'
    ).fetchall()
    return render_template('blog/index.html', posts=posts)

def check_event_params(title, body, invited):
    error = None
    inv_bool = True
    if not invited:
        inv_bool = False
    if not title or len(title) > 50:
        error = "The title must neither be empty, nor exceed 50 characters."
    elif not body or len(body) > 500:
        error = "The events needs a concise description."
    elif inv_bool and (len(invited) < 3 or len(invited) > 15):
        error = "The invited username is invalid."
    elif invited == g.user['username']:
        error = "You cannot invite yourself to an event."
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

@bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        title = title.strip()
        body = request.form['body']
        invited = request.form['inviteuser']
        error = check_event_params(title, body, invited)

        is_private = "FALSE"
        if 'private' in request.form:
            if request.form['private'] == "True":
                is_private = "TRUE"

        is_hidden = "FALSE"
        if 'hidden' in request.form:
            if request.form['hidden'] == "True":
                is_hidden = "TRUE"
#        try:
#            checkbox = request.form['private']
#            if checkbox == "True":
#                is_private = "TRUE"
#            else:
#                is_private = "FALSE"
#        except:
#            is_private = "FALSE"
#
#        try:
#            checkbox = request.form['hidden']
#            if checkbox == "True":
#                is_hidden = "TRUE"
#            else:
#                is_hidden = "FALSE"
#        except:
#            is_hidden = "FALSE"

        if error is not None:
            flash(error)
        else:
            postkey = request.form['title'] + g.user['username']
            db = get_db()
            try:
                db.execute(
                    'INSERT INTO post (title, body, author_id, key, is_private, is_hidden)'
                    ' VALUES (?, ?, ?, ?, ?, ?)',
                    (title, body, g.user['id'], postkey, is_private, is_hidden)
                )
                db.commit()
            except:
                error = "The given title already exists. Try again!"
                #flash(error)
                #fixes vulnerability
                #return render_template('blog/create.html')

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

@bp.route('/<int:id>/update', methods=('GET', 'POST'))
@login_required
def update(id):
    post = get_post(id)

    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']
        invited = request.form['inviteuser']
        error = check_event_params(title, body, invited)

        is_private = "FALSE"
        if 'private' in request.form:
            if request.form['private'] == "True":
                is_private = "TRUE"

        is_hidden = "FALSE"
        if 'hidden' in request.form:
            if request.form['hidden'] == "True":
                is_hidden = "TRUE"

#        is_hidden = None
#        is_private = "FALSE"
#
#        try:
#            checkbox = request.form['private']
#            if checkbox == "True":
#                is_private = "TRUE"
#            else:
#                is_private = "FALSE"
#        except:
#            is_private = "FALSE"
#
#        try:
#            checkbox = request.form['hidden']
#            if checkbox == "True":
#                is_hidden = "TRUE"
#            else:
#                is_hidden = "FALSE"
#        except:
#            is_hidden = "FALSE"

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE post SET title = ?, body = ?, is_private = ?, is_hidden = ?'
                ' WHERE id = ?',
                (title, body, is_private, is_hidden, id)
            )
            db.commit()

            if len(invited) != 0:
                error = handle_invite(invited, title, error)
            if error is not None:
                flash(error)
                return redirect(url_for('blog.update', id=id))
            else:
                return redirect(url_for('auth.accessblogpost', id=id))

        return redirect(url_for('blog.index'))

    return render_template('blog/update.html', post=post)

@bp.route('/<int:id>/delete', methods=('POST',))
@login_required
def delete(id):
    get_post(id)
    db = get_db()
    db.execute('DELETE FROM post WHERE id = ?', (id,))
    db.commit()
    return redirect(url_for('blog.index'))
