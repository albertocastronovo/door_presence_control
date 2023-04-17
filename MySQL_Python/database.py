import mysql.connector as con
from mysql.connector import errorcode as ec
from mysql.connector.connection_cext import CMySQLConnection
from mysql.connector.cursor_cext import CMySQLCursor


class Database:
    def __init__(
            self,
            host: str | None = None,
            database: str | None = None,
            port: int | None = None
                ):
        self.__host:        str = host
        self.__database:    str = database
        self.__port:        int = port
        self.__connection:  CMySQLConnection | None = None
        self.__cursor:      CMySQLCursor | None = None

    def connect_as(
            self,
            user: str | None = None,
            password: str | None = None
                    ):
        if self.__connection is None or not self.__connection.is_connected():
            try:
                new_connection = con.connect(
                    user=user,
                    password=password,
                    host=self.__host,
                    database=self.__database,
                    port=self.__port
                )
                self.__connection = new_connection
                self.__cursor = self.__connection.cursor()
                return 0
            except con.Error as err:
                if err.errno == ec.ER_ACCESS_DENIED_ERROR:  # the user has no access permissions
                    print(f"Access error. {err}")
                elif err.errno == ec.ER_BAD_DB_ERROR:       # the database name is wrong
                    print(f"Database error. {err}")
                else:
                    print(f"Generic error. {err}")
                return -1

        else:
            return 1        # already connected

    def close_connection(self):
        if self.__connection is not None and self.__connection.is_connected():
            self.__connection.close()

    def __execute_query(
            self,
            query: str,
            params: dict[str, str] | None = None
                     ):
        try:
            self.__cursor.execute(query, params)
            self.__connection.commit()
            return self.__cursor.fetchall()
        except con.Error as err:
            print(f"Error: {err}")
            return None

    def insert(
            self,
            table: str,
            values: list[str]
               ):
        values_str = ", ".join(["%s"])

