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
        'SELECT p.id, title, body, created, author_id, username'
        ' FROM post p JOIN user u ON p.author_id = u.id'
        ' ORDER BY created DESC'
    ).fetchall()
    return render_template('blog/index.html', posts=posts)

@bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    if request.method == 'POST':
        error = None
        title = request.form['title']
        if len(title) > 100:
            error = "The title length exceeds the character limit."
        body = request.form['body']
        is_private = None

        try:
            checkbox = request.form['private']
            if checkbox == "True":
                is_private = "TRUE"
            else:
                is_private = "FALSE"
        except:
            is_private = "FALSE"

        if not title:
            error = 'Title is required.'
        if not body:
            error = 'The post must not be empty!'
        if error is not None:
            flash(error)
        else:
            key = title + g.user['username']
            print("created the following key: ", key)
            db = get_db()
            db.execute(
                'INSERT INTO post (title, body, author_id, key, is_private)'
                ' VALUES (?, ?, ?, ?, ?)',
                (title, body, g.user['id'], key, is_private)
            )
            db.commit()
            return redirect(url_for('blog.index'))

    return render_template('blog/create.html')

def get_post(id, check_author=True):
    post = get_db().execute(
        'SELECT p.id, title, body, created, author_id, is_private, username'
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
        error = None

        if not title:
            error = 'Title is required.'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE post SET title = ?, body = ?'
                ' WHERE id = ?',
                (title, body, id)
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
