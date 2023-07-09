from utilities.database import Database

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
# it return a list of json dictionaties: [{'username': 'utente1'}, ... , {'username': 'yasmin'}]

print(all_usrs)

filtered_usrs = db.select_col_where("user", "username", "gender", "Male")

print(filtered_usrs)