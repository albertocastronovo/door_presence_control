import mysql.connector as con
from mysql.connector import errorcode as ec
from server_functions import password_hash, password_verify
from textwrap import dedent


def main():
    password = "esempio"
    hashed = password_hash(password)
    ctrl = password_verify("esempio", hashed)
    print(dedent(f"""\
        Password:   {password}
        Hash:       {hashed}
        Is correct: {ctrl}
    """))


if __name__ == "__main__":
    main()
