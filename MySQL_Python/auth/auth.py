from authlib.integrations.flask_client import OAuth
from .google_auth import google_register
from .facebook_auth import facebook_register


def oauth_init(app) -> OAuth:
    oauth = OAuth(app)
    google_register(oauth)
    facebook_register(oauth)
    return oauth
