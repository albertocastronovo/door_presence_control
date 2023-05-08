from utilities.database import Database
from utilities.server_functions import password_hash

db = Database(
    host="192.168.24.156",
    database="door_cntrl_system",
    port=3306
)

print(db.connect_as(
    user="root",
    password="root"
))

db.update(
    table="user",
    set_column="password",
    set_value=password_hash("Asdf1234!"),
    where_column="username",
    where_value="maurizio"
)
