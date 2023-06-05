from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException


class DoorHTTPException(HTTPException):
    def __init__(
            self,
            code: int | None = None,
            description: str | None = None,
            response=None
    ):
        self.code: int | None = code
        self.description: str | None = description
        HTTPException.__init__(self, description, response)

    @classmethod
    def generic_failure(cls):
        return cls(code=460, description="Generic failure of the request.")

    @classmethod
    def missing_required_params(cls):
        return cls(code=461, description="the client reached the server with a POST request, but the provided form is missing 1+ required key(s)")

    @classmethod
    def user_object_not_found(cls):
        return cls(code=465, description="no user object inside current session. Maybe something went wrong. Try to log out and log in again.")

    @classmethod
    def company_forbidden(cls):
        return cls(code=470, description="Invalid company permission level for the requested page.")

    @classmethod
    def permissions_not_found(cls):
        return cls(code=471, description="no permissions for selected company. Try selecting a different company, or contact your customer operator.")

    @classmethod
    def failed_google_auth(cls):
        return cls(code=462, description="Failed Google Authentication.")

    @classmethod
    def email_does_not_exist(cls):
        return cls(code=463, description="Email address does not exist.")

    @classmethod
    def clashing_selected_companies(cls):
        return cls(code=464, description="Selected company in demo user does not match that of main user")
