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
