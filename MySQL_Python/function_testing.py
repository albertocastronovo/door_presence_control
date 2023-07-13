from utilities.database import Database
from utilities.server_functions import password_hash, password_verify
import secrets
import requests

r = requests.post("http://192.168.43.51:4999/welcome/Alberto")
print(r)
