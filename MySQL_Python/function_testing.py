from utilities.database import Database

db = Database(
    host="192.168.24.156",
    database="door_cntrl_system",
    port=3306
)

print(db.connect_as(
    user="root",
    password="root"
))

db.update_multiple(
    table="user",
    column_names=["fiscal_code", "phone_number", "mail"],
    column_values=["A", "B", "C"],
    where_column="name",
    where_value="Alberto"
)