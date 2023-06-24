from functools import wraps
from flask import session, redirect, url_for, flash
import sys
from os import path
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
from utilities.door_user import DoorUser
from utilities.custom_http_errors import DoorHTTPException

role_permissions: dict[str, dict[str, bool]] = {}


def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "user_object" in session:
            return f(*args, **kwargs)
        else:
            flash('You need to login first.')
            return redirect(url_for('login'))

    return wrap


def required_permissions(required_perm: tuple[str, ...], company_check: bool = True, demo: bool = False):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if demo:
                user_object: DoorUser = session.get("demo_object", None)
            else:
                user_object: DoorUser = session.get("user_object", None)
            if user_object is None:  # no user object inside the current session
                raise DoorHTTPException.user_object_not_found()

            if demo and (user_object.get_selected_company() != session["user_object"].get_selected_company()):
                raise DoorHTTPException.clashing_selected_companies()

            if company_check:
                company_role = user_object.permissions_in_selected_company()
                if company_role == "none":  # user has no permissions for its selected company
                    raise DoorHTTPException.permissions_not_found()

                role_perm = role_permissions.get(company_role, {})
                if not all(role_perm[perm] for perm in required_perm):
                    raise DoorHTTPException.company_forbidden()

            return f(*args, **kwargs)

        return decorated_function

    return decorator