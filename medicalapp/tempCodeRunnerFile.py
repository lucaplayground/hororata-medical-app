from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, datetime, timedelta, time
import mysql.connector
import connect
import re
from re import search
import bcrypt

app = Flask(__name__)
app.secret_key = 'group_project2'
dbconn = None
connection = None


def getCursor():
    global dbconn
    global connection
    connection = mysql.connector.connect(user=connect.dbuser, password=connect.dbpass, host=connect.dbhost, database=connect.dbname, autocommit=True)
    dbconn = connection.cursor(buffered=True)
    return dbconn

connection = getCursor()
connection.execute('SELECT dob from patients WHERE patient_id = 1')
dob = connection.fetchone()
today = datetime.today().date()
print (today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day)))