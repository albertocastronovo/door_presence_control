from copy import deepcopy
from functools import wraps
from flask import session, abort
import jsonpickle
from textwrap import dedent


class DoorUser:
    def __init__(self, **kwargs):
        self.__name: str = kwargs.get("name", "default")
        self.__username: str = kwargs.get("username", "default")
        self.__fiscal_code: str = kwargs.get("fiscal_code", "default")
        self.__permissions: dict[str, str] = kwargs.get("permissions", {})
        self.__selected_company: str = "none"

    def set_permissions(self, new_permissions: dict):
        self.__permissions = deepcopy(new_permissions)

    def set_username(self, new_username: str):
        self.__username = new_username

    def set_fiscal_code(self, new_fiscal_code: str):
        self.__fiscal_code = new_fiscal_code

    def set_selected_company(self, new_selected_company: str):
        self.__selected_company = new_selected_company

    def get_selected_company(self) -> str:
        return self.__selected_company

    def get_permissions(self) -> dict:
        return self.__permissions

    def get_fiscal_code(self) -> str:
        return self.__fiscal_code

    def get_name(self) -> str:
        return self.__name

    def get_companies(self) -> list[str]:
        return list(self.__permissions.keys())

    def permissions_in_company(self, company: str) -> str:
        return self.__permissions.get(company, "none")

    def permissions_in_selected_company(self) -> str:
        return self.__permissions.get(self.__selected_company, "none")

    def __repr__(self):
        return "repr of DoorUser"

    def __str__(self):
        return dedent(f"""\
            Name:               {self.__name}
            Username:           {self.__username}
            Fiscal Code:        {self.__fiscal_code}
            Selected Company:   {self.__selected_company}
            Permissions:        {self.__permissions}
        """)


class DoorUserSerializer:
    @staticmethod
    def dumps(obj_to_json):
        return jsonpickle.encode(obj_to_json)

    @staticmethod
    def loads(json_to_obj):
        return jsonpickle.decode(json_to_obj)



