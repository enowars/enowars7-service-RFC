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
    posts = db.execute(
        'SELECT p.id, title, body, created, author_id, is_hidden, username'
        ' FROM post p JOIN user u ON p.author_id = u.id'
        ' ORDER BY created DESC'
    ).fetchall()
    return render_template('blog/index.html', posts=posts)

def check_event_params(title, body):
    error = None
    if not title or len(title) > 50:
        error = "The title must neither be empty, nor exceed 50 characters."
    elif not body or len(body) > 500:
        error = "The events needs a concise description."
    return error

@bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']
        error = check_event_params(title, body)
        is_private = None
        is_hidden = None

        try:
            checkbox = request.form['private']
            if checkbox == "True":
                is_private = "TRUE"
            else:
                is_private = "FALSE"
        except:
            is_private = "FALSE"

        try:
            checkbox = request.form['hidden']
            if checkbox == "True":
                is_hidden = "TRUE"
            else:
                is_hidden = "FALSE"
        except:
            is_hidden = "FALSE"

        if error is not None:
            flash(error)
        else:
            key = request.form['title'] + g.user['username']
            print("created the following key: ", key)
            db = get_db()
            try:
                db.execute(
                    'INSERT INTO post (title, body, author_id, key, is_private, is_hidden)'
                    ' VALUES (?, ?, ?, ?, ?, ?)',
                    (title, body, g.user['id'], key, is_private, is_hidden)
                )
                db.commit()
            except:
                error = "The given title already exists. Try again!"
                flash(error)
                return render_template('blog/create.html')

            query = db.execute('SELECT id, body FROM post WHERE title = ? AND author_id = ?', (title, g.user['id'])).fetchone()

            return redirect(url_for('auth.accessblogpost', id=query['id']))

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
        error = check_event_params(title, body)
        is_private = None
        is_hidden = None

        try:
            checkbox = request.form['private']
            if checkbox == "True":
                is_private = "TRUE"
            else:
                is_private = "FALSE"
        except:
            is_private = "FALSE"

        try:
            checkbox = request.form['hidden']
            if checkbox == "True":
                is_hidden = "TRUE"
            else:
                is_hidden = "FALSE"
        except:
            is_hidden = "FALSE"

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
