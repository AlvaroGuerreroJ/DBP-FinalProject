#!/usr/bin/env python3
import os

from flask import Flask


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flaskrer.sqlite'),
        MAX_CONTENT_LENGTH=(128 * 1024 * 1024),  # 128MB
        UPLOAD_FOLDER=os.path.join(app.instance_path, 'Pics'),
        ALLOWED_FILE_EXTENSIONS={'png', 'jpg', 'jpeg'}
    )

    if test_config is None:
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    @app.route('/hello')
    def hello():
        return 'Hello, world'

    from . import db
    db.init_app(app)

    from . import auth
    app.register_blueprint(auth.bp)

    from . import pics
    app.register_blueprint(pics.bp)
    app.add_url_rule('/', endpoint='index')

    return app
