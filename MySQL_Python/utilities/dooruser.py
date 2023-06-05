from abc import ABC

from flask_security import UserMixin, RoleMixin, current_user
from functools import wraps
from flask import abort
from flask_security.datastore import UserDatastore


class DoorUser(UserMixin):
    def __init__(self, *args, **kwargs):
        self.roles: list[DoorRole] = kwargs.pop("roles", [])
        self.selected_company: str | None = kwargs.pop("selected_company", None)
        super(DoorUser, self).__init__(*args, **kwargs)


class DoorRole(RoleMixin):
    def __init__(self, **kwargs):
        super().__init__()
        self.name: str | None = kwargs.pop("name", None)
        self.permissions: dict = {k: v for k, v in kwargs.items() if k not in ["name", "role"]}


class DoorUserDatastore(UserDatastore):
    def __init__(self):
        super().__init__(DoorUser, DoorRole)
        self.users = {}
        self.roles = {}

    def get_user(self, id_or_email):
        """Returns a user matching the specified ID or email address."""
        return self.users.get(id_or_email, None)

    def find_user(self, *args, **kwargs):
        """Returns a user matching the provided parameters."""
        for user in self.users.values():
            if all(getattr(user, k) == v for k, v in kwargs.items()):
                return user
        return None

    def find_role(self, role):
        """Returns a role matching the provided name."""
        raise self.roles.get(role, None)

    def create_or_update_role(self, **kwargs):
        if "name" not in kwargs:
            return
        self.roles[kwargs["name"]] = DoorRole(**kwargs)


def required_permissions(required_perm: tuple[str, ...], company_check: bool = True):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if "admin" in required_perm and not company_check:
                if not any(role.permissions["admin"] for role in current_user.roles):
                    abort(403)
            else:
                permitted = False
                for role in current_user.roles:
                    if all(role.permissions[perm] for perm in required_perm) and (not company_check or role.company == current_user.selected_company):
                        permitted = True
                        break
                if not permitted:
                    abort(403)

            return f(*args, **kwargs)

        return decorated_function
    return decorator
