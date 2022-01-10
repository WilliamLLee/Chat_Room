from PyQt5.QtWidgets import QApplication, QTableWidgetItem,QLineEdit, QTableWidget, QTextEdit,QWidget,QVBoxLayout,QHBoxLayout, QLabel,QPushButton
from PyQt5.QtGui import QFont, QIcon, QTextCursor,QCloseEvent
from PyQt5.QtCore import QRect, QSize

import threading
import time
from tools.utls import iter2string,string2iter,getNetMask,get_ip_address,AuthenticationError,Logger
import socket as sk
from config.config import MAXSIZE, server_port,encoding,log_path,client_port
import rsa  
import pickle  
from cryptography.fernet import Fernet  
import hashlib  
import os 

class ServerWindow(QWidget):
    '''
        design the main frame window
    '''
    def __init__(self,window_name,debug_flag=False,parent=None):
        super().__init__(parent)
        # the window title
        self.setWindowTitle(window_name)

        # basic componet
        self.ip_address = QLineEdit(self)
        self.ip_address.setDisabled(True)
        self.port = QLineEdit(self)
        self.log_display = QTextEdit(self)
        self.log_display.setReadOnly(True)
        self.user_list_table = QTableWidget(self)
        self.state_info = QLabel(self)

        # get the resulotion of the screen
        self.screen_resolution = QApplication.desktop().screenGeometry()
        self.width = self.screen_resolution.width()
        self.height = self.screen_resolution.height()

        # get the size of the window
        self.window_width = self.width*0.5
        self.window_height = self.height*0.5
        # get the start position of the window
        self.window_start_x = self.width/2 - self.window_width/2
        self.window_start_y = self.height/2 - self.window_height/2
        # set the size  of the window
        self.window_rect = QRect(self.window_start_x,self.window_start_y,self.window_width,self.window_height)
        self.window_size = QSize(self.window_width,self.window_height)

        # set debug flag
        self.debug_flag = debug_flag

        # set the icon path
        self.icon_path = "icon_server.ico"

        # set the threading event
        self.thread_event = threading.Event()

        # user list 
        self.user_list = []

        # init the ui of main frame window
        self.init_ui()

        # set the font
        self.font = QFont()
        self.font.setPointSize(12)
        self.font.setFamily("Consolas")

        # set the log_text
        self.log_text = ""

        # set the logger
        if not os.path.exists(log_path):
            os.makedirs(log_path)
        self.logger = Logger(log_path+"/server.log")

        
        self.log_display_append("Server IP Address: %s,IP Mask: %s ,Server Port: %s"%(self.ip_address.text(),self.ip_mask,self.port.text()))
        if self.debug_flag:
            print("Debug mode is set now!")

    def init_ui(self):
        # set the size of the window
        self.setGeometry(self.window_rect)
        self.setFixedSize(self.window_size)

        # set icon of this window
        self.setWindowIcon(QIcon(self.icon_path))

        # set the layout
        total_layout = QVBoxLayout()
        top_layout = QHBoxLayout()
        middle_layout = QVBoxLayout()
        bottom_layout = QHBoxLayout()     

        # set the top layout
        top_layout.addWidget(QLabel("IP Address:"))
        top_layout.addWidget(self.ip_address)
        top_layout.addWidget(QLabel("Port:"))
        top_layout.addWidget(self.port)


        self.start_button = QPushButton("Start Server",self)
        self.start_button.clicked.connect(self.start_button_clicked)
        top_layout.addWidget(self.start_button)

        self.end_button = QPushButton("End Server",self)
        self.end_button.clicked.connect(self.end_button_clicked)
        top_layout.addWidget(self.end_button)

        
        # set the middle layout
        middle_layout.addWidget(QLabel("User List (Click the user to send message to him/her):"))
        middle_layout.addWidget(self.user_list_table)
        self.user_list_table.setColumnCount(6)
        self.user_list_table.setHorizontalHeaderLabels(["User Name","IP Address","Port","State","Login time","Logout time"])
        self.user_list_table.setSortingEnabled (True)

        middle_layout.addWidget(QLabel("Log Display:"))
        middle_layout.addWidget(self.log_display)


        # set the bottom layout
        state_info_hint = QLabel("Running Status:",self)
        bottom_layout.addWidget(state_info_hint)
        bottom_layout.addWidget(self.state_info)

        # set the total layout
        total_layout.addLayout(top_layout)
        total_layout.addLayout(middle_layout)
        total_layout.addLayout(bottom_layout)

        # set the widget
        self.setLayout(total_layout)

        

        # set the ip_address
        ipaddr = get_ip_address(sk.gethostname())
        self.set_ip_address(ipaddr)
        self.ip_mask = getNetMask(ipaddr)
        self.set_port(server_port)
        
        # set the user dict 
        self.user_dict = {}
        # show the window
        self.show()
        

    def start_button_clicked(self):
        if self.ip_address.text() == "":
            self.log_display_append("Please input the ip address!")
            return
        if self.port.text() == "":
            self.log_display_append("Please input the port!")
            return
        self.log_display_append("Start Server!")
        try:
            self.server = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)
            self.server.bind((self.ip_address.text(),int(self.port.text())))
            self.server.settimeout(5)
        except Exception as e:
            self.log_display_append("Start Server Error: "+str(e))
            return

        self.thread_event.set()
        # start the listen thread
        self.disp_thread = threading.Thread(target=self.disp_thread_func,args=(self.thread_event,))
        self.disp_thread.start()

        lock = threading.Lock()
        # keep the server activate and keep waking for the client
        self.keep_thread = threading.Thread(target=self.keep_thread_func,args=(self.thread_event,self.user_dict,lock))
        self.keep_thread.start()

        # broadcast the server info
        self.keep_broadcast_server_Info_thread = threading.Thread(target=self.keep_broadcast_server_Info,args=(self.thread_event,))
        self.keep_broadcast_server_Info_thread.start()

        self.log_display_append("Start Server Successfully on "+self.ip_address.text()+":"+self.port.text())
        self.set_state_info("Running")
        self.start_button.setDisabled(True)
        self.end_button.setEnabled(True)
        pass
    

    def keep_thread_func(self,thread_event,user_info,lock):
        count = 0
        while True:
            if  thread_event.is_set():
                ts = time.time()
                flag = 0
                
                for key in user_info.keys():
                    if  user_info[key][4] == 1 and ts - user_info[key][7] > 15:
                        lock.acquire()
                        user_info[key][4] = 0    # lose active
                        user_info[key][7] = 0   # set the logout time
                        lock.release() 
                        flag = 1
                count+=1
                if flag == 1 or count%10 == 0:
                    send_user_dict = {}

                    for key in user_info.keys():
                        if user_info[key][4] == 1:
                            send_user_dict[key] = user_info[key][:4]  # Send the user dict to the client.
                   
                    print("keep send_user_dict:",send_user_dict)
                    for key in send_user_dict.keys():      
                            f = Fernet(send_user_dict[key][0])  # Create a Fernet object with the key.
                            msg = b'USERLIST##'+ repr(f.encrypt(pickle.dumps(send_user_dict))).encode(encoding) 
                            self.server.sendto(msg,(send_user_dict[key][2],send_user_dict[key][3]))
                    user_list = [user[1:] for user in user_info.values()]
                    self.set_user_list_table(user_list)
                    count = 0
                time.sleep(1)
            else:
                return 
        pass

    def keep_broadcast_server_Info(self,thread_event):
        while True:
            if thread_event.is_set():
                msg = b'SERVERINFO##'+ repr((self.ip_address.text(),int(self.port.text()))).encode(encoding)
                des_ip = string2iter(self.ip_address.text())|(string2iter(self.ip_mask)^0xffffffff)
                des_ip = iter2string(des_ip)
                self.server.sendto(msg,(des_ip,client_port))
                self.log_display_append("[+]Server: Broadcast Server Info to "+des_ip+":"+str(client_port))
                time.sleep(35)
            else:
                return


    def handle_login_request(self,sock, addr, ts, msg,user_info, lock, is_debug=False, encoding='utf-8'):
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
        self.log_display_append("[+]Client: Generated Symkey: "+sym_key.decode(encoding))
        
        # Encrypt the symmetric key with the public key of the client.
        lock.acquire()
        user_info[addr[0]+str(addr[1])+username] = [sym_key,username,addr[0],addr[1],1,time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime(ts))),0,ts] 
        lock.release()
        user_list = [user[1:] for user in user_info.values()]
        self.set_user_list_table(user_list)

        if is_debug: print('[+] User dict update in server :',user_info)    

        # Encrypt the symmetric key with the public key of the client.
        sym_key_encrypted = rsa.encrypt(sym_key, public_key)
        sym_key_encrypted_sha256 = hashlib.sha256(sym_key_encrypted).hexdigest()
        if is_debug: print('[+] sym_key_encrypted, sym_key_encrypted_sha256:', sym_key_encrypted, sym_key_encrypted_sha256)
        sock.sendto(b'SYMKEY##'+(repr((sym_key_encrypted,sym_key_encrypted_sha256))).encode(encoding), addr)
        
        send_user_dict = {}
        lock.acquire()
        for key in user_info.keys():
            if user_info[key][4] == 1:
                send_user_dict[key] = user_info[key][:4]  # Send the user dict to the client.
        
        
        for key in send_user_dict.keys():
            f = Fernet(send_user_dict[key][0])  # Create a Fernet object with the key.
            msg = b'USERLIST##'+ repr(f.encrypt(pickle.dumps(send_user_dict))).encode(encoding) 
            sock.sendto(msg,(send_user_dict[key][2],send_user_dict[key][3]))
            if is_debug: print('[+] Server send msg to ',(send_user_dict[key][2],send_user_dict[key][3])," : ", msg)
        lock.release()

    def handle_keep_alive_request(self,sock, addr, ts, msg,user_info, lock, is_debug=False, encoding='utf-8'):
        '''
        Handle the logout request from the client.
        sock: the socket of the client.
        addr: the address of the client.
        msg: the message from the client.
        '''
        assert(sock is not None)
        assert(addr is not None)
        assert(msg is not None)
        assert(user_info is not None)
        username = str(msg[1])
        key = addr[0]+str(addr[1])+username
        lock.acquire()
        if user_info[key][4] == 1:
            user_info[key][7] = time.time()
        lock.release()
        self.set_user_list_table([user[1:-1] for user in user_info.values()])

    def handle_logout_request(self,sock, addr, ts, user_name,user_info, lock, is_debug=False, encoding='utf-8'):
        '''
            handle the logout request from the client.
            sock: the socket of the client.
            addr: the address of the client.
            msg: the message from the client.
        '''
        assert(sock is not None)
        assert(addr is not None)
        assert(user_name is not None)
        assert(user_info is not None)
        timestamp = time.strftime('%Y-%m-%d %H: %M:%S', (time.localtime(ts)))
        lock.acquire()
        user_info[addr[0]+str(addr[1])+user_name][4] = 0
        user_info[addr[0]+str(addr[1])+user_name][6] = timestamp
        user_info[addr[0]+str(addr[1])+user_name][7] = 0
        lock.release()
        self.set_user_list_table([user[1:-1] for user in user_info.values()])
        
        send_user_dict = {}
        lock.acquire()
        for key in user_info.keys():
            if user_info[key][4] == 1:
                send_user_dict[key] = user_info[key][:4]  # Send the user dict to the client.
        
        print('[+]logout send_user_dict:',send_user_dict)
        for key in send_user_dict.keys():
            f = Fernet(send_user_dict[key][0])  # Create a Fernet object with the key.
            msg = b'USERLIST##'+ repr(f.encrypt(pickle.dumps(send_user_dict))).encode(encoding) 
            sock.sendto(msg,(send_user_dict[key][2],send_user_dict[key][3]))
            if is_debug: print('[+] Server send msg to ',(send_user_dict[key][2],send_user_dict[key][3])," : ", msg)

        lock.release()

    # 服务器侦听线程
    def disp_thread_func(self,event):
        while True:
            if event.is_set():
                ts = time.time()  # Get the timestamp of the package.
                try:
                    data, addr = self.server.recvfrom(MAXSIZE) 
                    lock = threading.Lock()
                    if data.decode(encoding).startswith('LOGIN'):
                        self.log_display_append("Receive a login request from "+addr[0]+":"+str(addr[1]))
                        msg = data.decode(encoding).split('##')
                        handle_thread = threading.Thread(target=self.handle_login_request, args=(self.server, addr, ts, msg,self.user_dict,lock, self.debug_flag,encoding))
                        handle_thread.setDaemon(True)
                        handle_thread.start()
                    elif data.decode(encoding).startswith('KEEP'):
                        msg = data.decode(encoding).split('##')
                        if addr[0]+str(addr[1])+str(msg[1]) not in self.user_dict.keys():
                            continue
                        self.log_display_append("Receive a keep alive request from "+addr[0]+":"+str(addr[1]))
                        resp = b'KEEPALIVE'
                        self.server.sendto(resp, addr)
                        # lock = threading.Lock()
                        handle_keep_thread = threading.Thread(target=self.handle_keep_alive_request, args=(self.server, addr, ts, msg,self.user_dict,lock, self.debug_flag,encoding))
                        handle_keep_thread.setDaemon(True)
                        handle_keep_thread.start()
                    elif data.decode(encoding).startswith('LOGOUT'):
                        self.log_display_append("Receive a logout request from "+addr[0]+":"+str(addr[1]))
                        username = data.decode(encoding).split('##')[1]
                        key = addr[0]+str(addr[1])+username
                        if key not in self.user_dict.keys():
                            self.server.sendto(b'FAILED',addr)
                            self.log_display_append("Logout failed, user %s not exist!"%username)
                        else:
                            self.server.sendto(b'OK',addr)
                            # lock = threading.Lock()
                            handle_logout_thread= threading.Thread(target=self.handle_logout_request, args=(self.server, addr, ts, username,self.user_dict,lock, self.debug_flag,encoding))
                            handle_logout_thread.setDaemon(True)
                            handle_logout_thread.start()
                    else:
                        if self.debug_flag: print('[+] wrong msg from client:', addr, ':', data)
                except Exception as e:
                    if self.debug_flag: print('[-] Server recv error :', e)
                    pass
            else:
                return

    def end_button_clicked(self):
        self.log_display_append("End Server!")
        self.set_state_info("End Server!")
        if self.server is not None:
            self.server.close()
        if self.thread_event.is_set():
            self.thread_event.clear()
        self.user_list_table_clear()
        self.user_dict.clear()
        self.log_display_append("End Server Success!")
        self.set_state_info("End Server Success!")
        self.start_button.setEnabled(True)
        self.end_button.setDisabled(True)
        pass

    def log_display_append(self,text):
        ts = time.time()
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime(ts)))
        
        self.log_display.append("$%s>> %s"%(timestamp,text))
        self.log_display.moveCursor(QTextCursor.End)
       

        self.logger.log("$%s>> %s"%(timestamp,text))

    def log_display_clear(self):
        self.log_display.clear()

    def user_list_table_clear(self):
        self.user_list_table.clearContents()

    def set_user_list_table(self,display_table):
        self.user_list_table.setRowCount(len(display_table))
        for i in range(len(display_table)):
            for j in range(6):
                self.user_list_table.setItem(i,j,QTableWidgetItem(str(display_table[i][j])))

    def set_user_list_table_item(self,row,column,text):
        self.user_list_table.setItem(row,column,QTableWidgetItem(text))

    def set_state_info(self,text):
        self.state_info.setText(text)

    def set_ip_address(self,ip_address):
        self.ip_address.setText(ip_address)

    def set_port(self,port):
        self.port.setText(str(port))

    def closeEvent(self, a0: QCloseEvent) -> None:
        if self.server is not None:
            self.server.close()
        if self.thread_event.is_set():
            self.thread_event.clear()
        self.user_list_table_clear()
        self.user_dict.clear()
        return super().closeEvent(a0)
    
  
if __name__ == "__main__":
    '''
        Test the function.
    '''
    import sys
    app = QApplication(sys.argv)
    window = ServerWindow('server')
    sys.exit(app.exec_())
    
