from PyQt5.QtWidgets import QApplication, QTableWidgetItem,QLineEdit, QTableWidget, QTextEdit,QWidget,QVBoxLayout,QHBoxLayout, QLabel,QPushButton
from PyQt5.QtGui import QFont, QIcon, QTextCursor,QCloseEvent
from PyQt5.QtCore import QRect, QSize, Qt
import threading
import os
import socket as sk
import time
import rsa  
import pickle  
from cryptography.fernet import Fernet  
import hashlib  

from tools.utls import  get_ip_address, Logger,AuthenticationError,MsgParserThreadWorker
from config.config import client_port, server_port, icon_client_path, MAXSIZE,encoding

class ClientWindow(QWidget):
    '''
        design the main frame window
    '''
    def __init__(self,window_name, logger_path = None, log_flag = False, parent=None):
        super().__init__(parent)
        # the window title
        self.setWindowTitle(window_name)

        # basic componet
        self.ip_address = QLineEdit(self)
        self.port = QLineEdit(self)
        self.name = QLineEdit(self)
        self.log_display = QTextEdit(self)
        self.log_display.setReadOnly(True)
        self.user_list_table = QTableWidget(self)
        self.message_content = QTextEdit(self)
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

        # set the icon path
        self.icon_path = icon_client_path

        # set the threading event
        # 监听线程控制事件
        self.thread_event = threading.Event()
        # 监听服务器通知报文线程控制事件
        self.listen_serverinfo_thread_event = threading.Event()


        # init the ui of main frame window
        self.init_ui()

        # set the font
        self.font = QFont()
        self.font.setPointSize(12)
        self.font.setFamily("Consolas")


        # for test
        self.ip_address.setText(get_ip_address(sk.gethostname()))
        self.port.setText(str(server_port))

        # for host config
        self.host_ip = get_ip_address(sk.gethostname())
        self.host_port = client_port
        self.__encoding = encoding 
        self.user_dict = {}
        self.task_list = []
        self.is_logined = threading.Event()
        self.server_addr = None


        # set the logger
        self.log_flag = log_flag
        if self.log_flag:
            assert(logger_path != None)
            if not os.path.exists(logger_path):
                os.makedirs(logger_path)
            self.logger = Logger(logger_path+"/client.log")

        # create the client device 
        self.device = self._create_socket(5)
        self.log_display_append("[+]Client: Successfully create socket. Host ip: %s, Host port: %s"%(self.host_ip,self.host_port))
   
        # set state
        self.set_state_info("bind the socket and listen the port %d"%self.host_port)

        # # rsa decryption
        self.rsa_key =  rsa.newkeys(2048)
        self.public_key = self.rsa_key[0]  # public key
        self.private_key = self.rsa_key[1] # private key
        self.sym_key = None

        # setlf wake time
        self.wake_time = time.time()

        # set the threading worker
        self.thread_event.set()
        self.listen_serverinfo_thread_event.set()
        self.recv_thread = threading.Thread(target=self.listen_thread_for_client, args=(self.thread_event,))
        self.recv_thread.start()

    def init_ui(self):
        # set the size of the window
        self.setGeometry(self.window_rect)
        self.setFixedSize(self.window_size)

        # set icon of this window
        self.setWindowIcon(QIcon(self.icon_path))

        # set the layout
        total_layout = QVBoxLayout()
        top_layout = QHBoxLayout()
        middle_layout = QHBoxLayout()
        middle_layout_left = QVBoxLayout()
        middle_layout_right = QVBoxLayout()
        middle_layout_right_top = QVBoxLayout()
        middle_layout_right_bottom = QVBoxLayout()
        bottom_layout = QHBoxLayout()

        # set the top layout
        top_layout.addWidget(QLabel("Server IP:"))
        top_layout.addWidget(self.ip_address)
        top_layout.addWidget(QLabel("Server Port:"))
        top_layout.addWidget(self.port)
        top_layout.addWidget(QLabel("Your Name:"))
        top_layout.addWidget(self.name)


        login_button = QPushButton("Login",self)
        login_button.clicked.connect(self.login_button_clicked)
        top_layout.addWidget(login_button)

        logout_button = QPushButton("Logout",self)
        logout_button.clicked.connect(self.logout_button_clicked)
        top_layout.addWidget(logout_button)

        
        # set the middle layout

        middle_layout_left.addWidget(QLabel("Log Display:"))
        middle_layout_left.addWidget(self.log_display)

        middle_layout_right_top.addWidget(QLabel("User List (Click the user to send message to him/her):"))
        middle_layout_right_top.addWidget(self.user_list_table)
        self.user_list_table.setColumnCount(3)
        self.user_list_table.setHorizontalHeaderLabels(["    User Name    ","    IP Address    ","    Port    "])
        self.user_list_table.setSortingEnabled (True)
        self.user_list_table.setAlternatingRowColors(True)


        middle_layout_right_bottom.addWidget(QLabel("Message Content:"))
        middle_layout_right_bottom.addWidget(self.message_content)
        
        
        send_button = QPushButton("Send",self)
        send_button.clicked.connect(self.send_button_clicked)
        send_to_all_button = QPushButton("Send to All",self)
        send_to_all_button.clicked.connect(self.send_to_all_button_clicked)
        middle_layout_right_bottom.addWidget(send_button)
        middle_layout_right_bottom.addWidget(send_to_all_button)

        middle_layout_right.addLayout(middle_layout_right_top)
        middle_layout_right.addLayout(middle_layout_right_bottom)
        
        middle_layout.addLayout(middle_layout_left)
        middle_layout.addLayout(middle_layout_right)

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

        # show the window
        self.show()

    
    def _create_socket(self,timeout):
        sock_void =  False
        while not sock_void:
            try:
                sock = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)
                sock.bind((self.host_ip, self.host_port))
                sock.settimeout(timeout)
                sock_void = True
            except Exception:
                sock_void = False
                import random
                self.host_port+=random.randint(1,100)
        return sock

    def handle_sym_key(self,msg,lock):
        sym_key_encrypted, sym_key_encrypted_sha256 = eval(msg[1])
        if hashlib.sha256(sym_key_encrypted).hexdigest() != sym_key_encrypted_sha256:
            lock.acquire()
            self.log_display_append("[-]Client: The sym key is not correct.")
            lock.release()
            raise AuthenticationError('[-] Authentication failed.')
            return
        lock.acquire()
        self.sym_key = rsa.decrypt(sym_key_encrypted, self.private_key)
        lock.release()
        self.is_logined.set()

     # 客户端侦听线程
    def listen_thread_for_client(self,thread_event):
        '''
        Listen the socket of the client.
        '''
        while True:
            if thread_event.is_set():
                ts = time.time()  # Get the timestamp of the package.
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime(ts)))
                try: 
                    data, addr = self.device.recvfrom(MAXSIZE)  # Get the data and the address of the package.
                    if data.decode(encoding).startswith('SYMKEY'):
                        msg = data.decode(encoding).split('##')
                        lock = threading.Lock()
                        sym_key_thread = threading.Thread(target=self.handle_sym_key,args=(msg,lock))
                        sym_key_thread.setDaemon(True)
                        sym_key_thread.start()
                    elif data.decode(encoding).startswith('USERLIST'): # update the user directory
                        assert(self.sym_key != None)
                        f = Fernet(self.sym_key)  # Create a Fernet object with the key.
                        recv_user_info = pickle.loads(f.decrypt(eval(data.decode(encoding).split('##')[1])))
                        lock = threading.Lock()
                        lock.acquire()
                        for key in recv_user_info.keys():
                            if key not in self.user_dict.keys():
                                self.user_dict[key] = recv_user_info[key]
                                self.log_display_append("[+] Client: User %s (%s,%s) is online."%(self.user_dict[key][1],self.user_dict[key][2],self.user_dict[key][3]))
                        del_list= []
                        for key in self.user_dict.keys():
                            if key not in recv_user_info.keys():
                                self.log_display_append("[+] Client: User %s (%s,%s) is offline."%(self.user_dict[key][1],self.user_dict[key][2],self.user_dict[key][3]))
                                del_list.append(key)
                        for key in del_list:
                            self.user_dict.pop(key)
                        lock.release()
                        user_list = [user[1:4] for user in self.user_dict.values()]
                        self.set_user_list_table(user_list)    
                    elif data.decode(encoding).startswith('KEEPALIVE'):
                        self.wake_time = time.time()
                    elif  data.decode(encoding).startswith('OK'):
                        self.is_logined.clear()
                        self.log_display_append("[+]Client << Server(%s): Logout success response."%str(addr))
                    elif  data.decode(encoding).startswith('FAILED'):
                        self.log_display_append("[-]Client << Server(%s): Logout failed response."%str(addr))
                    elif data.decode(encoding).startswith('SERVERINFO'):
                        if self.listen_serverinfo_thread_event.is_set():
                            self.log_display_append("[-]Client << Server(%s): Server info response."%str(addr))
                        else:
                            continue  # ignore the server info here
                    else:  # msg from client 
                        if not self.is_logined.is_set():
                            continue
                        assert(self.sym_key is not None)
                        f = Fernet(self.sym_key)  # Create a Fernet object with the key.
                        decrypt_msg = f.decrypt(eval(data.decode(encoding)))  # Decrypt the message.
                        self.log_display_append("[+]Client << (%s): %s (decrypted msg: %s) "%(str(addr),eval(data.decode(encoding)),decrypt_msg.decode(encoding)))
                except Exception as e:
                    if self.log_flag:
                        print("%s [-] Client Recv MSG Error: %s"%(timestamp,e))
            else:
                return

    def login_button_clicked(self):
        if self.is_logined.is_set():
            self.set_state_info("You have already logined.")
            return
        if self.ip_address.text() == "" or self.port.text() == "" or self.name.text() == "":
            self.state_info.setText("Please fill in the blank. (server ip, server port, your name)")
            return
        self.wake_time = time.time()
        
        self.server_addr=(self.ip_address.text(), int(self.port.text()))
        try:
            self.login_opt(username=self.name.text())
        except Exception as e:
            self.set_state_info("Login failed, please ensure the server is running.")
            self.log_display_append("[-] Client: Login failed, please ensure the server is running.")
            return
        self.set_state_info("Login successfully.")
        # 停止监听服务器通知报文
        self.listen_serverinfo_thread_event.clear()
        # 活跃状态检测线程
        self.keep_active_thread = threading.Thread(target=self.keep_thread, args=(self.is_logined,))
        self.keep_active_thread.start()

        self.log_display_append("[+] Client: Login successfully, Server IP: %s, Server Port: %d, Local IP: %s, Local Port: %d"%(self.ip_address.text(),int(self.port.text()),self.host_ip,self.host_port))
        self.ip_address.setDisabled(True)
        self.port.setDisabled(True)
        self.name.setDisabled(True)

        username = self.name.text()
        msg = b'KEEP##'+username.encode(self.__encoding)
        self.device.sendto(msg, self.server_addr)

    def keep_thread(self,event):
        while True:
            if event.is_set():
                username = self.name.text()
                msg = b'KEEP##'+username.encode(self.__encoding)
                self.device.sendto(msg, self.server_addr)
                
                time.sleep(5)

                if time.time() -  self.wake_time > 15:
                    self.log_display_append("[-] Client: Server is not responding.")
                    self.set_state_info("Server is not responding.")
                    self.is_logined.clear()
                    self.user_dict.clear()
                    self.ip_address.setEnabled(True)
                    self.port.setEnabled(True)
                    self.name.setEnabled(True)
                    self.user_list_table.clearContents()
            else:
                return

    def login_opt(self,username):
        assert(self.server_addr is not None)
        sendkey = pickle.dumps(self.public_key)
        sendkeySha256 = hashlib.sha256(sendkey).hexdigest()
        msg = b'LOGIN##'+username.encode(self.__encoding)+b'##'+repr((sendkey,sendkeySha256)).encode(self.__encoding)
        self.device.sendto(msg, self.server_addr)
        count = 50
        while(count>0):
            if  self.is_logined.is_set():
                return
            time.sleep(0.1)        
        raise AuthenticationError('[-] Login failed.')
        
    def logout_opt(self):
        if not self.is_logined.is_set():
            return
        username = self.name.text()
        self.device.sendto(b'LOGOUT##'+username.encode(self.__encoding), self.server_addr) 
        count = 50
        while(count>0):
            if  not self.is_logined.is_set():
                return
            time.sleep(0.1)        
        raise AuthenticationError('[-] Logout failed.')

    def logout_button_clicked(self):
        if self.device == None:
            self.set_state_info(" You have not login yet!")
            return
        try:
            self.logout_opt()
        except Exception:
            self.set_state_info("Logout failed!, Please try again.")
            self.log_display_append("[-] Client: Logout failed.")
            return

        self.set_state_info("Logout successfully.")
        self.listen_serverinfo_thread_event.set()

        self.log_display_append("[+] Client: Logout successfully, Server IP: %s, Server Port: %d, Local IP: %s, Local Port: %d"%(self.ip_address.text(),int(self.port.text()),self.host_ip,self.host_port))
        self.user_dict.clear()
        self.ip_address.setEnabled(True)
        self.port.setEnabled(True)
        self.name.setEnabled(True)
        self.user_list_table.clearContents()

    def send(self, host, port, user_name, msg):
        if host+user_name not in self.user_dict.keys():
            if self.debugging: print('[-] User not in user dict', host+user_name)
            return False
        encrypt_key = self.user_dict[host+str(port)+user_name][0]
        f = Fernet(encrypt_key)
        sendmsg =  repr(f.encrypt(msg.encode(self.__encoding))).encode(self.__encoding)
        self.device.sendto(sendmsg, (host, port))

    def send_to_all(self, msg):
        for user in self.user_dict.values():
            if (user[2],user[3]) != (self.host_ip,self.host_port):
                f = Fernet(user[0])
                sendmsg =  repr(f.encrypt(msg.encode(self.__encoding))).encode(self.__encoding)
                self.log_display_append("[+] Client>> %s: %s(encrypted msg:%s)"%(str((user[2],user[3])),msg,sendmsg))
                self.device.sendto(sendmsg, (user[2], int(user[3])))
    
    def send_to_all_button_clicked(self):
        if not self.is_logined.is_set():
            self.set_state_info(" You have not login yet!")
            return
        if self.message_content.toPlainText() == "":
            self.set_state_info("Please input the message you want to send.")
            return
        msg = self.message_content.toPlainText()
        self.send_to_all(msg)
        self.log_display_append("[+] Client: Send to all: %s"%msg)
        self.message_content.clear()


    def send_to_selected(self, msg, user_list):
        for user in user_list:
            if (user[1],user[2]) != (self.host_ip,self.host_port):
                f = Fernet(user[0])
                sendmsg = repr(f.encrypt(msg.encode(self.__encoding))).encode(self.__encoding)
                self.device.sendto(sendmsg, (user[1], user[2]))
                self.log_display_append("[+] Client>> %s: %s(encrypted msg:%s)"%(str((user[1],user[2])),msg,sendmsg))

    def send_button_clicked(self):
        if not self.is_logined.is_set():
            self.set_state_info(" You have not login yet!")
            return
        if self.message_content.toPlainText() == '':
            self.set_state_info(" Please input message!")
            return
        msg = self.message_content.toPlainText()
        sender_list = []
        for i in range(self.user_list_table.rowCount()):
            if self.user_list_table.item(i,0).checkState() == Qt.Checked:
                key = self.user_list_table.item(i,1).text()+self.user_list_table.item(i,2).text()+self.user_list_table.item(i,0).text()
                sender_list.append([self.user_dict[key][0],self.user_list_table.item(i,1).text(),int(self.user_list_table.item(i,2).text())])      
        if len(sender_list) == 0:
            self.set_state_info(" Please select users!")
            return
        
        self.send_to_selected(msg, sender_list)
        self.message_content.clear()
        pass 


    def set_user_list_table(self,user_list):
        print(user_list)
        self.user_list_table.setRowCount(len(user_list))
        for i in range(len(user_list)):
            for j in range(3):
                if j==0:
                    check =  QTableWidgetItem()
                    check.setCheckState(Qt.Unchecked)
                    check.setText(user_list[i][0])
                    
                    self.user_list_table.setItem(i,j,check)
                else:
                    self.user_list_table.setItem(i,j,QTableWidgetItem(str(user_list[i][j])))

    def set_log_display(self,log_text):
        self.log_display.setText(log_text)
        

    def log_display_append(self,log_text):
        ts = time.time()
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime(ts)))
        
        self.log_display.append("$%s>> %s"%(timestamp,log_text))
        self.log_display.moveCursor(QTextCursor.End)
        if self.log_flag:
            self.logger.log("$%s>> %s"%(timestamp,log_text))

    def set_state_info(self,state_info):
        self.state_info.setText(state_info)

    def closeEvent(self, a0: QCloseEvent) -> None:
        if self.is_logined.is_set():
            self.is_logined.clear()
        if self.device != None:
            self.device = None
        if self.thread_event.is_set():
            self.thread_event.clear()
        self.user_dict.clear()
        self.user_list_table.clearContents()
        if self.listen_serverinfo_thread_event.is_set():
            self.listen_serverinfo_thread_event.clear()
        return super().closeEvent(a0)

    
if __name__ == "__main__":
    '''
        Test the function.
    '''
    import sys
    app = QApplication(sys.argv)
    window = ClientWindow('Client')
    sys.exit(app.exec_())
    
