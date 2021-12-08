import os 
import socket as sk 
import rsa  
import pickle  
from cryptography.fernet import Fernet  
import hashlib   
import time  
import threading


from config.config import  MAXSIZE, server_port


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
            f.write(msg)


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


def handle_login_request(sock, addr, ts, msg,user_info, lock, is_debug=False, encoding='utf-8'):
    '''
    Handle the login request from the client.
    sock: the socket of the client.
    addr: the address of the client.
    msg: the message from the client.
    '''
    assert(sock is not None)
    assert(addr is not None)
    assert(msg is not None)
    assert(user_info is not None)
    username = str(msg[1])
    public_key, public_key_sha256 = eval(msg[2])
    if is_debug: print('[+] public_key, public_key_sha256:', public_key, public_key_sha256)
    if hashlib.sha256(public_key).hexdigest() != public_key_sha256:
        if is_debug: print('[-] Server recv wrong public key')
        raise AuthenticationError('[-] Authentication failed.')
    public_key = pickle.loads(public_key)

    sym_key = Fernet.generate_key()  # Generate the symmetric key.
    if is_debug: print('[+] sym_key:', sym_key)
    
    # Encrypt the symmetric key with the public key of the client.
    lock.acquire()
    user_info[addr[0]+username] = [sym_key,username,addr[0],addr[1],1,time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime(ts))),0] 
    lock.release()

    if is_debug: print('[+] User dict update in server :',user_info)    

    # Encrypt the symmetric key with the public key of the client.
    sym_key_encrypted = rsa.encrypt(sym_key, public_key)
    sym_key_encrypted_sha256 = hashlib.sha256(sym_key_encrypted).hexdigest()
    if is_debug: print('[+] sym_key_encrypted, sym_key_encrypted_sha256:', sym_key_encrypted, sym_key_encrypted_sha256)
    sock.sendto(b'SYMKEY##'+(repr((sym_key_encrypted,sym_key_encrypted_sha256))).encode(encoding), addr)
    
    time.sleep(0.1) # Wait for the client to receive the symmetric key.
    
    send_user_dict = {}
    for key in user_info.keys():
        if user_info[key][4] == 1:
            send_user_dict[key] = user_info[key][:4]  # Send the user dict to the client.

    for key in send_user_dict.keys():
        f = Fernet(send_user_dict[key][0])  # Create a Fernet object with the key.
        msg = b'USERLIST##'+ repr(f.encrypt(pickle.dumps(send_user_dict))).encode(encoding) 
        sock.sendto(msg,(send_user_dict[key][2],send_user_dict[key][3]))
        if is_debug: print('[+] Server send msg to ',(send_user_dict[key][2],send_user_dict[key][3])," : ", msg)

def listen_thread_for_server(sock, event,is_debug=False, user_info = None,encoding='utf-8'):
    '''
    Listen the message from the client.
    '''
    assert(sock is not None)
    assert(event is not None)
    while True:
        if event.is_set():
            ts = time.time()  # Get the timestamp of the package.
            try: 
                data, addr = sock.recvfrom(MAXSIZE)  # Get the data and the address of the package.
                if data.decode(encoding).startswith('LOGIN'):
                    msg = data.decode(encoding).split('##')
                    lock = threading.Lock()
                    handle_thread = threading.Thread(target=handle_login_request, args=(sock, addr, ts, msg,user_info,lock, is_debug,encoding))
                    handle_thread.setDaemon(True)
                    handle_thread.start()
                elif  data.decode(encoding).startswith('LOGOUT'):
                    username = data.decode(encoding).split('##')[1]
                    key = addr[0]+username
                    if key not in user_info.keys():
                        sock.sendto(b'FAILED',addr)
                    else:
                        sock.sendto(b'OK',addr)
                        user_info[key][3] = 0
                        user_info[key][5] = time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime(ts)))
                else:
                    if is_debug: print('[+] wrong msg from client:', addr, ':', data)
                          
            except sk.timeout:
                if is_debug: print(time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime(ts))),'No data captured')
        else:
            return 

def listen_thread_for_client(sock, event, is_logined, sym_key_of_client=None ,private_key = None, is_debug=False, task_list=None, user_info = None,encoding='utf-8'):
    '''
    Listen the socket of the client.
    '''
    assert(sock is not None)
    assert(event is not None)
    while True:
        if event.is_set():
            ts = time.time()  # Get the timestamp of the package.
            try: 
                assert(sock is not None)
                data, addr = sock.recvfrom(MAXSIZE)  # Get the data and the address of the package.
                assert(task_list is not None)
                assert(user_info is not None)
                assert(private_key is not None)
                if data.decode(encoding).startswith('SYMKEY'):
                    assert(sym_key_of_client is None)
                    msg = data.decode(encoding).split('##')
                    sym_key_encrypted, sym_key_encrypted_sha256 = eval(msg[1])
                    if hashlib.sha256(sym_key_encrypted).hexdigest() != sym_key_encrypted_sha256:
                        if is_debug: print('[-] Client recv wrong public key')
                        raise AuthenticationError('[-] Authentication failed.')
                    sym_key_of_client = rsa.decrypt(sym_key_encrypted, private_key)
                elif  data.decode(encoding).startswith('USERLIST'): # update the user directory
                    assert(sym_key_of_client is not None)
                    f = Fernet(sym_key_of_client)  # Create a Fernet object with the key.
                    recv_user_info = pickle.loads(f.decrypt(eval(data.decode(encoding).split('##')[1])))
                    for key in recv_user_info.keys():
                        if key not in user_info.keys():
                            user_info[key] = recv_user_info[key]
                    if is_debug: print('[+] User dict update in client :', user_info)
                    is_logined.set()
                elif  data.decode(encoding).startswith('OK'):
                    is_logined.clear()
                    if is_debug: print('[+] User logout successful')
                elif  data.decode(encoding).startswith('FAILED'):
                    if is_debug: print('[+] User logout failed:')
                else:  # msg from client 
                    assert(sym_key_of_client is not None)
                    task = MsgParserThreadWorker(ts, data, addr, sym_key_of_client, is_debug)
                    task_list.append(task)   # add the task to the list
                    task.setDaemon(True)     # if the Daemon is set to True, the thread will be terminated when the main thread is terminated
                    task.start()             # start the thread and begin to parse the raw package                    
            except sk.timeout:
                if is_debug: print(time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime(ts))),'No data captured')
        else:
            return 

class ClientMainWorker:
    def __init__(self, host, port,event,timeout=5,encoding='utf-8',debugging=False):
        self.host = host
        self.port = port
        self.sock = self._create_socket(timeout)
        self.__encoding = encoding
        self.event = event
        self.__debugging = debugging
        self.user_dict = {}
        self.task_list = []
        self.server_addr = None
        self.username = None
        self.is_logined = threading.Event()

        # rsa decryption
        self.rsa_key =  rsa.newkeys(2048)
        self.public_key = self.rsa_key[0]  # public key
        self.private_key = self.rsa_key[1] # private key
        self.sym_key = None
    
    def clear(self):
        self.user_dict = {}
        self.task_list = []
        self.server_addr = None
        self.username = None

    def get_host(self):
        return self.host
    
    def get_port(self):
        return self.port

    def get_state(self):
        return self.is_logined.is_set()

    def _create_socket(self, timeout):
        sock_void =  False
        while not sock_void:
            try:
                self.sock = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)
                self.sock.bind((self.host, self.port))
                self.sock.settimeout(timeout)
                sock_void = True
            except Exception:
                sock_void = False
                self.port+=1
        return self.sock

    def login(self,host,port,username):
        self.username = username
        self.server_addr = (host,port)
        sendkey = pickle.dumps(self.public_key)
        sendkeySha256 = hashlib.sha256(sendkey).hexdigest()
        msg = b'LOGIN##'+username.encode(self.__encoding)+b'##'+repr((sendkey,sendkeySha256)).encode(self.__encoding)
        self.sock.sendto(msg, self.server_addr)
        count = 30
        while(count>0):
            if  self.is_logined.is_set():
                return
            time.sleep(0.1)        
        raise AuthenticationError('[-] Login failed.')
        
    def logout(self):
        assert(self.server_addr is not None)
        assert(self.username is not None)
        self.sock.sendto(b'LOGOUT##'+self.username.encode(self.__encoding), self.server_addr) 
        count = 30
        while(count>0):
            if  not self.is_logined.is_set():
                return
            time.sleep(0.1)        
        raise AuthenticationError('[-] Logout failed.')

    def send(self, host, port, user_name, msg):
        if host+user_name not in self.user_dict.keys():
            if self.__debugging: print('[-] User not in user dict', host+user_name)
            return False
        encrypt_key = self.user_dict[host+user_name][0]
        f = Fernet(encrypt_key)
        sendmsg =  repr(f.encrypt(msg.encode(self.__encoding))).encode(self.__encoding)
        self.sock.sendto(sendmsg, (host, port))

    def send_to_all(self, msg):
        for user in self.get_user_list():
            if (user[2],user[3]) != (self.host,self.port):
                f = Fernet(user[0])
                sendmsg =  repr(f.encrypt(msg.encode(self.__encoding))).encode(self.__encoding)
                self.sock.sendto(sendmsg, (user[2], user[3]))

    def send_to_selected(self, msg, user_list):
        for user in user_list:
            if (user[2],user[3]) != (self.host,self.port):
                f = Fernet(user[0])
                sendmsg = repr(f.encrypt(msg.encode(self.__encoding))).encode(self.__encoding)
                self.socket.sendto(sendmsg, (user[2], user[3]))

    def run(self):
        self.recv_thread = threading.Thread(target=listen_thread_for_client, args=(self.sock, self.event, self.is_logined, self.sym_key, self.private_key, self.__debugging,self.task_list, self.user_dict))
        self.recv_thread.start()

    def get_task_list(self):
        return self.task_list
    
    def get_user_list(self):
        user_list = []
        for key in self.user_dict.keys():
            user_list.append(self.user_dict[key][:4])  #public_key , username , ip, port
        return user_list

    def get_msg(self):
        return [result.get_result() for result in self.task_list]

class SeverMainWorker:
    def __init__(self, host, port, event,is_debuging=False):
        self.host = host
        self.port = port
        self.__debugging = is_debuging
        self.event = event
        self.user_dict = {}

    def get_host(self):
        return self.host
    
    def get_port(self):
        return self.port

    def run(self):
        try:
            self.sock = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)
            self.sock.bind((self.host, self.port))
            self.sock.settimeout(5)
        except Exception as e:
            if self.__debugging: print('Run Server Error', e)
            return
        self.recv_thread = threading.Thread(target=listen_thread_for_server, args=(self.sock, self.event,  self.__debugging,  self.user_dict))
        self.recv_thread.start()
        if self.__debugging: print('Server is running!')

    def get_user_list(self):
        return self.user_dict.values()

    def close(self):
        self.sock.close()

if __name__ == '__main__':
    host = get_ip_address(sk.gethostname())
    print("host: ",host)
    cport = 1234
    sport = server_port
    cevent = threading.Event()
    sevent = threading.Event()
    cevent.set()
    sevent.set()
    
    sworker = SeverMainWorker(host, sport, sevent,True)
    cworker1 = ClientMainWorker(host, cport, cevent,5,'utf-8',True)
    cworker2 = ClientMainWorker(host, cport, cevent,5,'utf-8',True)
    cworker3 = ClientMainWorker(host, cport, cevent,5,'utf-8',True)
    
    cworker1.run()
    cworker2.run()
    cworker3.run()
    sworker.run()

    cworker1.login(host, sport, 'liwei')
    cworker2.login(host, sport, 'lisi')
    cworker3.login(host, sport, 'wangwu')

    time.sleep(2)    

    print("c1 user list:",cworker1.get_user_list())
    print("c2 user list:",cworker2.get_user_list())
    print("c3 user list:",cworker3.get_user_list())


  
    cworker1.send(host, cport+1,'lisi', 'hello lisi, I am liwei')
    cworker2.send(host, cport, 'liwei', 'hello liwei, I am lisi')
    cworker3.send(host,cport, 'liwei', 'hello liwei, I am wangwu')
    cworker1.send_to_all('hello all')

    time.sleep(3)

    print("c1 msg: ", cworker1.get_msg())
    print("c2 msg:", cworker2.get_msg())
    print("c3 msg:", cworker3.get_msg())
    time.sleep(2)
    
    cworker1.logout()
    cworker2.logout()
    time.sleep(2)
    print("server user list:", sworker.get_user_list())
    time.sleep(5)
    sevent.clear()
    cevent.clear()