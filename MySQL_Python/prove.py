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


user = "utente3"
fiscal_code_user = db.select_col_where("user", "fiscal_code", "username", user)[0]["fiscal_code"]
role = db.select_col_where("user_to_customer", "role", "userID", fiscal_code_user)[0]["role"]
vat = db.select_col_where("user_to_customer", "cusID", "userID", fiscal_code_user)[0]["cusID"]


all_companies = db.select_col("customer", "name")
print(all_companies)

result_dict = get_usernames_by_role_and_vat(db, role, vat, user)
print(result_dict)