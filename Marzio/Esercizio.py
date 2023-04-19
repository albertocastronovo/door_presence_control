import sys

sys.path.insert(0, 'C:/Users/marzi/PycharmProjects/IoT/door_presence_control/MySQL_Python/utilities')
from database import Database
from server_functions import get_user_password

db = Database(
    host="localhost",
    database="door_cntrl_system",
    port=3306
)

db.connect_as(
    user="root",
    password=""
)


pw = get_user_password(db, "utente1")
print(pw)
