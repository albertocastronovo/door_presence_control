from argon2 import hash_password, verify_password
from argon2.exceptions import VerifyMismatchError
from MySQL_Python.utilities.database import Database
from re import compile, match

password_validator = compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,32}$")


def password_hash(password: str) -> str:
    hash_bytes = hash_password(
        bytes(password, "utf-8"),
        hash_len=55
    )
    return hash_bytes.decode("utf-8")


def password_verify(password: str, test_hash: str | None) -> bool:
    if test_hash is None:
        return False
    try:
        return verify_password(
            password=bytes(password, "utf-8"),
            hash=bytes(test_hash, "utf-8")
        )
    except VerifyMismatchError:
        return False


def get_user_password(database: Database, user: str) -> str | None:
    query = database.select_col_where("user", "password", "username", user)
    print(query)
    try:
        return query[0]["password"]
    except IndexError:
        return None


def is_password_secure(test_password: str) -> bool:
    return match(password_validator, test_password) is not None


class User:
    def __init__(self,
                 user_id: int = -1,
                 name: str = "default",
                 surname: str = "default"):

        self.__userID = user_id
        self.__name = name
        self.__surname = surname
        self.__roles: dict[str, str] = {}

    @classmethod
    def from_query(cls, query: list[dict]):
        user_data = query[0]
        c = cls()
        # magic
        return c

    @property
    def userID(self) -> int:
        return self.__userID

    @property
    def name(self) -> str:
        return self.__name

    @property
    def surname(self) -> str:
        return self.__surname

    @property
    def roles(self) -> dict[str, str]:
        return self.__roles

    def role_at_company(self, company: str) -> str | None:
        return self.__roles.get(company, None)

    @userID.setter
    def userID(self, new_id: int):
        self.__userID = int(new_id)

    @name.setter
    def name(self, new_name: str):
        self.__name = str(new_name)

    @surname.setter
    def surname(self, new_surname: str):
        self.__surname = str(new_surname)

    @roles.setter
    def roles(self, new_roles: dict[str, str]):
        self.__roles = new_roles
