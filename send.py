import socket
import binascii
import json

# used to encode commands with autokey cipher
def encode(msg):
    ret = ""
    for i in range(len(msg)):
        if i == 0:
            ret += chr(ord(msg[i]) ^ 171)
        else:
            ret += chr(ord(msg[i]) ^ ord(ret[i-1]))
    return ret

def send_cmd(cmd, ip = "255.255.255.255")
    s.sendto(encode(cmd), (ip,9999))

# List of enumerated commands
GET_INFO = '{"system":{"get_sysinfo":{}}}'
RESET = '{"system":{"reset":{"delay":1}}}'
TURN_ON = '{"system":{"set_relay_state":{"state":1}}}'
TURN_OFF = '{"system":{"set_relay_state":{"state":0}}}'

ENABLE_NIGHT_MODE = '{"system":{"set_led_off":{"off":1}}}'
DISABLE_NIGHT_MODE = '{"system":{"set_led_off":{"off":1}}}'

SET_ALIAS = '{"system":{"set_dev_alias":{"alias":"New alias here"}}}'

GET_CLOUD_INFO = '{"cnCloud":{"get_info":{}}}'
DISCONNECT_CLOUD = '{"cnCloud":{"unbind":{}}}'

GET_TIMER = '{"count_down":{"get_rules":{}}}'
ADD_60S_TIMER = '{"count_down":{"add_rule":{"enable":1,"delay":60,"act":1,"name":"newtimer"}}}'
DELETE_TIMERS = '{"count_down":{"delete_all_rules":{}}}'


# send to broadcast address, port 9999
UDP_IP = "255.255.255.255"
UDP_PORT = 9999

# create socket
s = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # Enable sending to broadcast addr
s.settimeout(2) # timeout after 2 seconds

# get system info from all Wi-Fi plugs on the network
send_cmd(GET_INFO)

devices = []
# receive responses from all devices and record the IP addresses
while True:
    try:
        msg,ip = s.recvfrom(1024)
        print ip, decode(msg)
        devices.append(ip)
    except socket.timeout:
        break

# if we have devices who responded
if len(devices) > 0:
    # Turn off the first device to respond
    send_cmd(TURN_OFF, ip = devices[0])
