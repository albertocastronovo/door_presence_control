from os import getenv
from authlib.integrations.flask_client import OAuth

google_client_id = getenv("GOOGLE_CLIENT_ID")
google_client_secret = getenv("GOOGLE_CLIENT_SECRET")
google_client_discovery = getenv("GOOGLE_CLIENT_DISCOVERY")


def google_register(oauth: OAuth):
    oauth.register(
        name="google",
        client_id=google_client_id,
        client_secret=google_client_secret,
        access_token_url="https://accounts.google.com/o/oauth2/token",
        access_token_params=None,
        authorize_url="https://accounts.google.com/o/oauth2/auth",
        authorize_params=None,
        api_base_url="https://www.googleapis.com/oauth2/v1/",
        userinfo_endpoint="https://openidconnect.googleapis.com/v1/userinfo",
        server_metadata_url=google_client_discovery,
        client_kwargs={"scope": "email profile"}
    )
