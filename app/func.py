from urllib.parse import urlparse, urljoin
from flask import request
from .models import User
from . import db

ALLOWED_EXTENSIONS = {'png', 'jpg'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

def getusersinhtml():
    users = User.query.all()
    html = ''
    for user in users:
        html = html + '<li><a href="">' + user + '</a></li><br> \n'

    return html