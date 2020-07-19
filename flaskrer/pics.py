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
