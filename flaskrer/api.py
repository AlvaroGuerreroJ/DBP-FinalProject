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
