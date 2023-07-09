from utilities.database import Database
from utilities.server_functions import password_hash

db = Database(
    host="localhost",
    database="door_cntrl_system",
    port=3306
)

print(db.connect_as(
    user="root",
    password=""
))

db.update(
    table="user",
    set_column="password",
    set_value=password_hash("Asdf1234!"),
    where_column="username",
    where_value="maurizio"
)

print(password_hash("password4"))
