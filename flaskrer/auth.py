import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskrer.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        full_name = request.form['full_name']
        password = request.form['password']

        db = get_db()
        error = None

        if not username:
            error = 'Username required'
        elif not full_name:
            error = 'Full name required'
        elif not password:
            error = 'Password required'
        elif db.execute(
                'SELECT id FROM user WHERE username = ?',
                (username,)
        ).fetchone() is not None:
            error = f'The username "{username}" is already used'

        if error is None:
            db.execute(
                '''INSERT INTO user (username, full_name, password)
                VALUES (?, ?, ?)''',
                (username, full_name, generate_password_hash(password))
            )
            db.commit()
            return redirect(url_for('auth.login'))

        flash(error)

    return render_template('auth/register.html')
