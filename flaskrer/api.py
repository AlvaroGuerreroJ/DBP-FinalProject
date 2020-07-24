import base64
import functools
import imghdr
import os
import shutil
import tempfile

from flask import (Blueprint, Response, abort, current_app, g, jsonify,
                   request, session)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskrer.db import get_db
from flaskrer.pics import generate_hash, get_user_upload_directory

bp = Blueprint('api', __name__, url_prefix='/api')


def require_request_json(*required_keys):
    required_keys = set(required_keys)

    def decorator(f):
        @functools.wraps(f)
        def ret(*args, **kwargs):
            if (request.json is None
                    or any(k not in request.json for k in required_keys)):
                abort(400)

            return f(*args, **kwargs)

        return ret

    return decorator


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return abort(401, 'Not logged in')

        return view(**kwargs)

    return wrapped_view


@bp.route('/login', methods=('POST',))
@require_request_json('username', 'password')
def login():
    username = request.json['username']
    password = request.json['password']

    db = get_db()
    user = db.execute(
        'select * from user where username = ?',
        (username,)
    ).fetchone()

    if user is None:
        abort(401)
    if not check_password_hash(user['password'], password):
        abort(401)

    session.clear()
    session['user_id'] = user['id']

    return {'msg': 'Logged in',
            'username': user['username'],
            'full_name': user['full_name']}


@bp.route('/register', methods=('POST',))
@require_request_json('username', 'full_name', 'password')
def register():
    username = request.json['username']
    full_name = request.json['full_name']
    password = request.json['password']

    db = get_db()

    if db.execute(
            'SELECT id FROM user WHERE username = ?',
            (username,)
    ).fetchone() is not None:
        abort(400, f'The username "{username}" is already used')

    db.execute(
        '''INSERT INTO user (username, full_name, password)
        VALUES (?, ?, ?)''',
        (username, full_name, generate_password_hash(password))
    )
    db.commit()

    return {'msg': 'Successfully registered'}


@bp.route('/log_out', methods=('GET',))
@login_required
def log_out():
    session.clear()
    return {'msg': 'Logged out'}


@bp.route('/post', methods=('GET',))
def get_posts():
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

    return jsonify(
        [{k: row[k] for k in row.keys()} for row in pics]
    )


@bp.route('/post', methods=('POST',))
@require_request_json('title', 'alternative_text', 'picture')
@login_required
def create_post():
    title = request.json['title']
    alternative_text = request.json['alternative_text']
    description = request.json.get('description')
    if description is None:
        description = ''
    picture = request.json['picture']

    _, temp_filename = tempfile.mkstemp()
    decoded = base64.b64decode(picture)
    with open(temp_filename, 'wb') as fp:
        fp.write(decoded)

    picture_extension = imghdr.what(temp_filename)
    if picture_extension is None or \
       picture_extension not in current_app.config['ALLOWED_FILE_EXTENSIONS']:
        abort(400, 'File is not of one of the supported types')

    # TODO: This should be refactored, is the same as in pics
    picture_hash = generate_hash(temp_filename)

    # Check that the file has not been uploaded before
    db = get_db()
    if db.execute(
            'SELECT * FROM image_post'
            ' WHERE author_id = ? AND hash = ?',
            (session.get('user_id'), picture_hash)
    ).fetchone() is not None:
        abort(415, f'File has already been uploaded')

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
        (session['user_id'], picture_hash, '', title,
            alternative_text, description)
    )
    db.commit()

    return {'msg': 'Post created'}


@bp.route('/comment/<int:post_id>', methods=('GET',))
def get_comments(post_id):
    comments = get_db().execute(
        'SELECT c.content, c.created, c.post_id, u.username'
        ' FROM comment c'
        ' JOIN user u ON c.author_id = u.id'
        ' WHERE c.post_id = ?'
        ' ORDER BY created DESC',
        (post_id,)
    ).fetchall()

    # TODO: Refactor this into a function
    return jsonify(
        [{k: row[k] for k in row.keys()} for row in comments]
    )


@bp.route('/comment/<int:post_id>', methods=('POST',))
@require_request_json('content')
@login_required
def create_comment(post_id):
    content = request.json['content']

    db = get_db()

    if db.execute(
            'SELECT * FROM image_post WHERE id = ?',
            (post_id,)
    ).fetchone() is None:
        abort(400, 'Post does not exist')

    db.execute(
        'INSERT INTO comment'
        ' (content, author_id, post_id)'
        ' VALUES (?, ?, ?)',
        (content, g.user['id'], post_id)
    )
    db.commit()

    return {'msg': 'Created comment'}


# XXX: This is the same as in auth.py. There may be a way to refactor it.
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
