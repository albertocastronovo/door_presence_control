import mysql.connector as con
from mysql.connector import errorcode as ec


def main():
    try:
        db_con = con.connect(
            user="Manager",
            password="Manager",
            host="172.21.142.41",
            database="door_ctrl_system",
            port=3306
        )
        print("ok!")
        db_con.close()
    except con.Error as err:
        if err.errno == ec.ER_ACCESS_DENIED_ERROR:
            print("Wrong username / password.")
        elif err.errno == ec.ER_BAD_DB_ERROR:
            print("The DB does not exist.")
        else:
            print("we are in error!")
            print(err)


if __name__ == "__main__":
    main()
