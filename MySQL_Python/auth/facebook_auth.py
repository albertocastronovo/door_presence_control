from os import getenv

facebook_client_id = getenv("FACEBOOK_CLIENT_ID")
facebook_client_secret = getenv("FACEBOOK_CLIENT_SECRET")


def facebook_register(oauth):
    oauth.register(
        name="facebook",
        client_id=facebook_client_id,
        client_secret=facebook_client_secret,
        authorize_url="https://www.facebook.com/v17.0/dialog/oauth",
        authorize_params=None,
        access_token_url="https://graph.facebook.com/v17.0/oauth/access_token",
        access_token_params=None,
        api_base_url="https://graph.facebook.com/v17.0/",
        client_kwargs={"scope": "email"}
    )
