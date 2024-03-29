import logging
from datetime import datetime
import mysql.connector as con
from mysql.connector import errorcode as ec
from mysql.connector.connection_cext import CMySQLConnection
from mysql.connector.cursor_cext import CMySQLCursor

for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logger = logging.getLogger("mysql.connector")
logger.setLevel(logging.INFO)
formatter_str = "[%(asctime)s] [%(name)s] [%(levelname)s] - %(message)s"
formatter = logging.Formatter(formatter_str)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)
file_name = "logs/DCS_" + datetime.now().strftime("%y_%m") + ".log"
file_handler = logging.FileHandler(file_name)


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

    def is_connected(self):
        return self.__connection.is_connected() if self.__connection is not None else False

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
                self.__cursor = self.__connection.cursor(buffered=True, dictionary=True)
                logger.info("Connection to database was successful.")
                return 0

            except con.Error as err:
                if err.errno == ec.ER_ACCESS_DENIED_ERROR:  # the user has no access permissions
                    logger.error("User has no access permissions.")
                elif err.errno == ec.ER_BAD_DB_ERROR:       # the database name is wrong
                    logger.error("Wrong database name.")
                else:
                    logger.error("Generic error.")
                return -1

        else:
            logger.info("Already connected to database.")
            return 1        # already connected

    def close_connection(self):
        if self.__connection is not None and self.__connection.is_connected():
            self.__cursor.close()
            self.__connection.close()
            self.__cursor = None
            self.__connection = None
            logger.info("Connection closed.")

    def __db_log(self, level: str, message: str):
        if not self.__connection.is_connected():
            logger.warning("Cannot save log to database: not connected.")
        table_name = "LOG_" + datetime.now().strftime("%y_%m")
        create_str = f"CREATE TABLE IF NOT EXISTS {table_name} (id INT AUTO_INCREMENT PRIMARY KEY, timestamp DATETIME NOT NULL, level VARCHAR(10) NOT NULL, message TEXT NOT NULL);"
        self.__cursor.execute(create_str)
        self.__connection.commit()
        timestamp = datetime.now().strftime("%y-%m-%d %H:%M:%S")
        log_into_table = f"INSERT INTO {table_name} (timestamp, level, message) VALUES (%s, %s, %s)"
        insert_data = (timestamp, level, message)
        self.__cursor.execute(log_into_table, insert_data)
        self.__connection.commit()

    def __execute_query(
            self,
            query: str,
            params: tuple | None = None,
            disable_fetchall: bool = False
                     ):
        try:
            logger.info(f"Executing query: {query} with parameters: {params}")
            self.__db_log("INFO", f"Executing query: {query} with parameters: {params}")
            self.__cursor.execute(query, params)
            self.__connection.commit()
            if not disable_fetchall:
                return self.__cursor.fetchall()
            else:
                return 1
        except con.Error as err:
            logger.error(f"Error in query execution: {err}")
            self.__db_log("ERROR", f"Error in query execution: {err}")
            return None

    def insert(
            self,
            table: str,
            columns: tuple[str, ...],
            values: tuple
               ):
        columns_str = ", ".join(columns)
        parameters = ", ".join(["%s" for _ in range(len(values))])
        print(parameters)
        query = f"INSERT INTO {table} ({columns_str}) VALUES ({parameters})"
        try:
            print(query)
            print(values)
            self.__execute_query(query, values, disable_fetchall=True)
            return 0
        except Exception as e:
            print(e)
            return -1

    def select_all(self, table: str):
        query = f"SELECT * FROM {table}"
        return self.__execute_query(query)

    def description(self):
        return self.__cursor.description

    def select_where(
            self,
            table: str,
            column: str,
            value
                    ):
        query = f"SELECT * FROM {table} WHERE {column} = %s"
        return self.__execute_query(query, (value,))

    def select_wheres(
            self,
            table: str,
            column_1: str,
            value_1,
            column_2: str,
            value_2,
            mode: str = "AND"
                    ):
        query = f"SELECT * FROM {table} WHERE {column_1} = %s {mode} {column_2} = %s"
        return self.__execute_query(query, (value_1, value_2))

    def select_wheres_one_week(
        self,
        table: str,
        column_1: str,
        value_1,
        column_2: str,
        value_2,
        mode: str = "AND"
    ):
        query = f"SELECT * FROM {table} WHERE {column_1} = %s {mode} {column_2} = %s AND date >= DATE_SUB(DATE(NOW()), INTERVAL 1 WEEK)"
        return self.__execute_query(query, (value_1, value_2))

    def select_where_many(
            self,
            table: str,
            columns: list[str],
            values: list,
            mode: str = "AND"
    ):
        query = f"SELECT * FROM {table} WHERE "
        query += f" {mode} ".join([f"{col} = %s" for col in columns])
        print(query)
        return self.__execute_query(query, tuple(values))

    def select_col_where(
            self,
            table: str,
            column_return: str,
            column_condition: str,
            value
    ):
        query = f"SELECT {column_return} FROM {table} WHERE {column_condition} = %s"
        return self.__execute_query(query, (value,))
    
    def select_col(
            self,
            table: str,
            column_return: str
    ):
        query = f"SELECT {column_return} FROM {table}"
        return self.__execute_query(query)

    def select_join_where(
            self,
            requested_cols: tuple[str, ...],
            table_1: str,   # quella che contiene utente e VAT
            table_2: str,   # quella che contiene VAT e nome azienda
            col_join:  str,    # company VAT
            col_where: str, # userID
            col_value: str  # codice fiscale
    ):
        cols = ", ".join(requested_cols)
        query = f"SELECT {cols} FROM {table_1} " \
                f"JOIN {table_2} ON {table_1}.{col_join} = {table_2}.{col_join} " \
                f"WHERE {table_1}.{col_where} = %s"
        return self.__execute_query(query, (col_value,))

    def select_subquery(
            self,
            table_data: str,
            col_join_1: str,
            col_join_2: str,
            table_join: str,
            col_where: str,
            where_value: str,
            order_by: str | None = None,
            offset: int | None = None,
            limit: int | None = None,
            count_only: bool = False
    ):
        if count_only:
            query = "SELECT COUNT(*)\n"
        else:
            query = "SELECT *\n"
        query += f"""\
            FROM {table_data}
            WHERE {col_join_1} IN (
                SELECT {col_join_2}
                FROM {table_join}
                WHERE {col_where} = %s
            )
        """
        if order_by is not None:
            query += f" ORDER BY {order_by}"
        if limit is not None:
            query += f" LIMIT {limit}"
        if offset is not None:
            query += f" OFFSET {offset}"
            print(f"Query: {query}")
        return self.__execute_query(query, (where_value,))

    def update(
            self,
            table: str,
            set_column: str,
            set_value,
            where_column: str,
            where_value
                ):
        query = f"UPDATE {table} SET {set_column} = %s WHERE {where_column} = %s"
        try:
            self.__execute_query(query, (set_value, where_value))
            return 0
        except:
            return -1

    def update_multiple(
            self,
            table: str,
            column_names: list[str],
            column_values: list,
            where_column: str,
            where_value
                ):
        column_assignments = ", ".join([f"{key} = %s" for key in column_names])
        query = f"UPDATE {table} SET {column_assignments} WHERE {where_column} = %s"
        param_tuple_1 = tuple(column_values)
        param_tuple_2 = (where_value,)
        param_tuple = param_tuple_1 + param_tuple_2
        try:
            self.__execute_query(query, param_tuple)
            #return 0
            return {"status": "success", "message": "Update successful"}
        except Exception as e:
            #return -1
            return {"status": "error", "message": str(e)}

    def update_multiple_wheres(
            self,
            table: str,
            column_names: list[str],
            column_values: list,
            where_col_1: str,
            where_val_1,
            where_col_2: str,
            where_val_2,
            mode: str = "AND"
                ):
        column_assignments = ", ".join([f"{key} = %s" for key in column_names])
        query = f"UPDATE {table} SET {column_assignments} WHERE {where_col_1} = %s {mode} {where_col_2} = %s"
        param_tuple_1 = tuple(column_values)
        param_tuple_2 = (where_val_1, where_val_2)
        param_tuple = param_tuple_1 + param_tuple_2
        try:
            self.__execute_query(query, param_tuple)
            return 0
        except:
            return -1

    def update_where_many(
            self,
            table: str,
            set_column: str,
            set_value,
            columns: list[str],
            values: list,
            mode: str = "AND"
    ):
        query = f"UPDATE {table} SET {set_column} = %s WHERE "
        params_tuple = (set_value,) + tuple(values)
        query += f" {mode} ".join([f"{col} = %s" for col in columns])
        try:
            self.__execute_query(query, params_tuple)
            return 0
        except:
            return -1

    def insert_or_update(self, table: str, update_column: str, values: list):
        query = f"INSERT INTO {table} VALUES (%s, %s, %s, %s) ON DUPLICATE KEY UPDATE {update_column} = %s"
        params = tuple(values)
        try:
            self.__execute_query(query, params, disable_fetchall=True)
            return 0
        except:
            return -1

    def delete(
            self,
            table: str,
            column: str,
            value
                ):
        query = f"DELETE FROM {table} WHERE {column} = %s"
        try:
            self.__execute_query(query, (value,), disable_fetchall=True)
            return 0
        except:
            return -1
