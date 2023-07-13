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

# all_usrs = db.select_col("user", "username")
# # list of json dictionaties: [{'username': 'utente1'}, ... , {'username': 'yasmin'}]
#
# print(all_usrs)
#
# all_usrs_except_you = [d for d in all_usrs if d["username"] != "utente1"]
#
# print(all_usrs_except_you)


user = "utente2"
fiscal_code_user = db.select_col_where("user", "fiscal_code", "username", user)[0]["fiscal_code"]
# role = db.select_col_where("user_to_customer", "role", "userID", fiscal_code_user)[0]["role"]
vat = db.select_col_where("user_to_customer", "cusID", "userID", fiscal_code_user)[0]["cusID"]

# Get rows where cusID equals vat from the user_to_customer table
user_to_customer_rows = db.select_where('user_to_customer', 'cusID', vat)

# Get the userIDs from the filtered rows
user_ids = [row['userID'] for row in user_to_customer_rows]
print(user_ids)

# Get the username values corresponding to the userIDs found in the user table
result = [db.select_col_where("user", "username", "fiscal_code", user_id)[0]["username"] for user_id in
          user_ids if db.select_where('user', 'fiscal_code', user_id)]

print(result)

# Remove from the list the username that corresponds to the person who is performing the action
if user in result:
    result.remove(user)

# Convert in a dictionary
result_dict = [{'username': usrnm} for usrnm in result]
print(result_dict)

# filtered_usrs = db.select_col_where("user", "username", "gender", "Male")
#
# print(filtered_usrs)