import glob
import hashlib
import imghdr
import os
import shutil
import tempfile

from flask import (Blueprint, Response, abort, current_app, flash, g, redirect,
                   render_template, request, send_file, session, url_for)
from werkzeug.utils import secure_filename

from flaskrer.auth import login_required
from flaskrer.db import get_db

bp = Blueprint('pics', __name__)

allowed_file_extensions = {'png', 'jpg', 'jpeg'}


class FlaskrerError(Exception):
    pass


@bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        alternative_text = request.form['alternative_text']
        description = request.form['description']
        if not description:
            description = ''
        picture = request.files['picture']

        try:
            if not picture or picture.filename == '':
                raise FlaskrerError('No picture selected for upload')
            if not title:
                raise FlaskrerError('Title required')
            if not alternative_text:
                raise FlaskrerError('Alternative text required')

            original_filename = picture.filename
            if not allowed_file(original_filename):
                raise FlaskrerError('File extension not allowed')

            # XXX: There may be a way to hash the file without saving it first
            _, temp_filename = tempfile.mkstemp()

            picture.save(temp_filename)

            picture_extension = imghdr.what(temp_filename)
            if picture_extension is None or \
               picture_extension not in allowed_file_extensions:
                raise FlaskrerError(
                    'File is not of one of the supported types'
                )

            picture_hash = generate_hash(temp_filename)

            # Check that the file has not been uploaded before
            db = get_db()
            if db.execute(
                    'SELECT * FROM image_post'
                    ' WHERE author_id = ? AND hash = ?',
                    (session.get('user_id'), picture_hash)
            ).fetchone() is not None:
                raise FlaskrerError(
                    f'You have already uploaded {original_filename}.'
                )

        except FlaskrerError as e:
            flash(str(e))
            return render_template('pics/create.html')

        user_pictures_directory = get_user_upload_directory(g.user['username'])
        try:
            os.makedirs(user_pictures_directory)
        except OSError:
            pass

        picture_store_location = os.path.join(
            user_pictures_directory,
            f'{picture_hash}.{picture_extension}'
        )
        shutil.move(temp_filename, picture_store_location)

        db = get_db()
        db.execute(
            'INSERT INTO image_post'
            ' (author_id, hash, original_filename, title, alternative_text,'
            ' description)'
            ' VALUES (?, ?, ?, ?, ?, ?)',
            (session['user_id'], picture_hash, original_filename, title,
             alternative_text, description)
        )
        db.commit()

        return redirect(url_for('index'))

    return render_template('pics/create.html')


@bp.route('/')
def index():
    db = get_db()
    # TODO: Getting all the pictures at the same time is not a good idea if
    #       there are a lot
    pics = db.execute(
        'SELECT p.id, p.author_id, p.hash, p.created, p.title,'
        ' p.alternative_text, p.description, u.username'
        ' FROM image_post p'
        ' JOIN user u ON p.author_id = u.id'
        ' ORDER BY created DESC'
    ).fetchall()

    return render_template('pics/index.html', pics=pics)


@bp.route('/uploads')
def uploads():
    user = request.args.get('user')
    pic_hash = request.args.get('pic_hash')

    if not user or not pic_hash:
        return abort(400, "Missing parameters")

    pic_hash = secure_filename(pic_hash)

    user_directory = get_user_upload_directory(user)
    try:
        pic_location = next(glob.iglob(os.path.join(user_directory,
                                                    f'{pic_hash}.*')))
    except StopIteration:
        return abort(404, "File does not exist")

    return send_file(pic_location)


@bp.route('/update/<int:id>', methods=('GET', 'POST'))
@login_required
def update(id):
    pic = get_image_post(id)

    if request.method == 'POST':
        title = request.form['title']
        alternative_text = request.form['alternative_text']
        description = request.form['description']
        if not description:
            description = ''

        error = None
        if not title:
            error = 'Title required'
        elif not alternative_text:
            error = 'Alternative text required'

        if error is None:
            db = get_db()
            db.execute(
                'UPDATE image_post'
                ' SET title = ?, alternative_text = ?, description = ?'
                ' WHERE id = ?',
                (title, alternative_text, description, id)
            )
            db.commit()

            return redirect(url_for('index'))

        flash(error)

    return render_template('pics/update.html', pic=pic)


@bp.route('/delete/<int:id>', methods=('POST',))
@login_required
def delete(id):
    get_image_post(id)
    db = get_db()
    db.execute(
        'DELETE FROM image_post WHERE id = ?',
        (id,)
    )
    db.commit()

    return redirect(url_for('index'))


@bp.route('/user/<username>', methods=('GET',))
def user(username):
    db = get_db()
    user = db.execute(
        'SELECT * FROM user WHERE username = ?',
        (username,)
    ).fetchone()

    if user is None:
        flash(f'User "{username}" does not exist')
        return redirect(url_for('index'))

    user_pics = db.execute(
        'SELECT p.id, p.author_id, p.hash, p.created, p.title,'
        ' p.alternative_text, p.description, u.username'
        ' FROM image_post p'
        ' JOIN user u ON p.author_id = u.id'
        ' WHERE author_id = ?'
        ' ORDER BY created DESC',
        (user['id'],)
    ).fetchall()

    return render_template('pics/user.html', user=user, user_pics=user_pics)


# XXX: This is the same as in auth.py. There may be a way to refactore it.
@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?',
            (user_id,)
        ).fetchone()


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1] in allowed_file_extensions


def generate_hash(filename):
    h = hashlib.sha256()

    with open(filename, 'rb') as fp:
        while True:
            chunk = fp.read(h.block_size)
            if not chunk:
                break
            h.update(chunk)

    return h.hexdigest()


def get_user_upload_directory(username):
    return os.path.join(current_app.config['UPLOAD_FOLDER'],
                        username)


def get_image_post(id, check_author=True):
    image_post = get_db().execute(
        'SELECT id, author_id, hash, created, title, alternative_text,'
        ' description'
        ' FROM image_post'
        ' WHERE id = ?',
        (id,)
    ).fetchone()

    if image_post is None:
        abort(404, f"Picture id {id} does not exist")

    if check_author and image_post['author_id'] != g.user['id']:
        abort(403)

    return image_post
