from utilities.database import Database
from utilities.server_functions import *

db = Database(
    host="localhost",
    database="door_cntrl_system",
    port=3306
)

db.connect_as(
    user="root",
    password=""
)

all_usrs = db.select_col("user", "username")
# list of json dictionaties: [{'username': 'utente1'}, ... , {'username': 'yasmin'}]

print(all_usrs)

all_usrs_except_you = [d for d in all_usrs if d["username"] != "utente1"]

print(all_usrs_except_you)


# filtered_usrs = db.select_col_where("user", "username", "gender", "Male")
#
# print(filtered_usrs)