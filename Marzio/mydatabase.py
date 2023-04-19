import mysql.connector

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="door_cntrl_system"
    # database="azienda_db"
)

cursor = db.cursor()
sql = "SELECT * FROM user"  # makes queries in sql
cursor.execute(sql)
for x in cursor: print(x[3], x[4])

# sql = "insert into user(userID,	nome, cognome, username, password, fiscal_code, phone_number, mail, address, birth_date, " \
#      "gender, flag_phone, flag_mail, google_authenticator) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"

# values = [(2, "Alberto", "Castronovo", "utente2", "password2", "CST1234ECC", 345677, "alberto@mail.com", "via viale 2/3", "1998/08/31", "M", "V", "V", "goggle_AUT")]

# cursor.executemany(sql, values)

#db.commit()
