import socket as sk 
from cryptography.fernet import Fernet  
import time  
import threading
import netifaces as ni
import os

from config.config import *

def getNetMask(host_IP):
    '''
    Get the netmask of the host.
    host_IP: the IP address of the host.
    '''
    assert(host_IP is not None)
    netmask = ''
    nicfaces = ni.interfaces()

    for faces in nicfaces:
        message = ni.ifaddresses(faces)
        iface_addr = message.get(ni.AF_INET)
        if iface_addr:
            iface_dict = iface_addr[0]
            ipaddr = iface_dict.get('addr')
            # print(ipaddr,host_IP)
            if ipaddr == host_IP:
                netmask = iface_dict.get('netmask')
    return netmask

def iter2string(ip):
    ip_s = [0,0,0,0]
    ip_s[0] = (ip&0xff000000)>>24
    ip_s[1] = (ip&0x00ff0000)>>16
    ip_s[2] = (ip&0x0000ff00)>>8
    ip_s[3] = (ip&0x000000ff)
    return "%d.%d.%d.%d" % tuple(ip_s)

def string2iter(ip):
    ip_i = [int(x) for x in ip.split('.')]
    return (ip_i[0]<<24)+(ip_i[1]<<16)+(ip_i[2]<<8)+ip_i[3]
    
class AuthenticationError(Exception):  
    def __init__(self, Errorinfo):  
        super().__init__()  
        self.errorinfo = Errorinfo  
    def __str__(self):  
        return self.errorinfo  

def get_ip_address(hostname=None):
    '''
    Get the IP address of the hostname.
    hostname: the hostname of the target.
    '''
    assert(hostname is not None)
    try:
        ip_address = sk.gethostbyname(hostname)
    except sk.gaierror:
        ip_address = 'Unknown'
    return ip_address

class Logger:
    def __init__(self, log_file):
        self.log_file = log_file

    def log(self, msg):
        with open(self.log_file, 'a') as f:
            f.write(msg+"\n")


def parse_msg(timestamp, msg, addr,sym_key,is_debug=False,encoding='utf-8'):
    '''
    Parse the message from the server.
    timestamp: the timestamp of the message.
    msg: the message from the server.
    '''
    assert(timestamp is not None)
    assert(msg is not None)
    assert(sym_key is not None)
    assert(addr is not None)
    if is_debug: print(time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime(timestamp))), msg, addr)
    
    time_msg = time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime(timestamp)))
    f = Fernet(sym_key)  # Create a Fernet object with the key.
    decrypt_msg = f.decrypt(eval(msg))  # Decrypt the message.

    return time_msg, msg, decrypt_msg, addr 

class MsgParserThreadWorker(threading.Thread):
    '''
    define the method for multi-thread to parse the raw msg.
    '''
    def __init__(self, ts, data, addr, sym_key, is_debug=False):
        super(MsgParserThreadWorker, self).__init__()
        self.result = None
        self.ts = ts
        self.data = data
        self.addr = addr
        self.sym_key = sym_key
        self.is_debug = is_debug

    def run(self):
        self.result = parse_msg(self.ts, self.data, self.addr, self.sym_key, self.is_debug)

    def get_result(self):
        return self.result

if __name__ == '__main__':
    pass

