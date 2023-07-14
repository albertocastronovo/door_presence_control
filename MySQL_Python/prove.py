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

result_dict = get_usernames_by_role_and_vat(db, role, vat, user)
print(result_dict)
result_lst_dict = [[d] for d in result_dict]
print(result_lst_dict)
fiscal_codes = [get_id_from_user(db, guy["username"]) for guy in result_dict]
roles = [get_all_roles(db, fiscal_code) for fiscal_code in fiscal_codes]
print(roles)
user_and_roles = [[result[0], [role for role in role_list]] for result, role_list in zip(result_lst_dict, roles)]
print(user_and_roles)


print("\n")
print("-----------------------------")
print("\n")

result_dict = [{"username": user}]
print(result_dict)
fiscal_codes = [get_id_from_user(db, guy["username"]) for guy in result_dict]
print(fiscal_codes)
roles = [get_all_roles(db, fiscal_code) for fiscal_code in fiscal_codes]
print(roles)
user_and_roles = [[result, [role for role in role_list]] for result, role_list in zip(result_dict, roles)]
print(user_and_roles)