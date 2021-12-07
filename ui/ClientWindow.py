from PyQt5.QtWidgets import QApplication, QTableWidgetItem,QLineEdit, QTableWidget, QTextEdit,QWidget,QVBoxLayout,QHBoxLayout, QLabel,QPushButton
from PyQt5.QtGui import QFont, QIcon, QTextCursor
from PyQt5.QtCore import QRect, QSize, Qt
import threading
import os
import socket as sk
import time

from tools.utls import ClientMainWorker, get_ip_address, Logger
from config.config import client_port, server_port, icon_client_path 

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
        self.send_ip_address = QLineEdit(self)
        self.send_port = QLineEdit(self)
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
        self.thread_event = threading.Event()

        # init the ui of main frame window
        self.init_ui()

        # set the font
        self.font = QFont()
        self.font.setPointSize(12)
        self.font.setFamily("Consolas")

        # the client device 
        self.device = None 

        # for test
        self.ip_address.setText(get_ip_address(sk.gethostname()))
        self.port.setText(str(server_port))

        # set the logger
        self.log_flag = log_flag
        if self.log_flag:
            assert(logger_path != None)
            if not os.path.exists(logger_path):
                os.makedirs(logger_path)
            self.logger = Logger(logger_path+"/client.log")


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
        middle_layout_right_bottom_l1 = QHBoxLayout()
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


        middle_layout_right_bottom.addWidget(QLabel("Message Sender:"))
        middle_layout_right_bottom_l1.addWidget(QLabel("IP Address:"))
        middle_layout_right_bottom_l1.addWidget(self.send_ip_address)
        middle_layout_right_bottom_l1.addWidget(QLabel("Port:"))
        middle_layout_right_bottom_l1.addWidget(self.send_port)

        middle_layout_right_bottom.addLayout(middle_layout_right_bottom_l1)
        middle_layout_right_bottom.addWidget(QLabel("Message Content:"))
        middle_layout_right_bottom.addWidget(self.message_content)
        
        
        send_button = QPushButton("Send",self)
        send_button.clicked.connect(self.send_button_clicked)
        middle_layout_right_bottom.addWidget(send_button)

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

    def _display_user_list(self, event):
        while event.is_set():
            try:
                user_list = [user[1:4] for user in self.device.get_user_list()]
                if self.device.get_state() == False:   # if the device is not connected
                    event.clear()
                    self.device = None
                    if self.log_flag:
                        ts = time.time()
                        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime(ts)))
                        self.logger.info("$%s [-] Error: The device is not connected, please connect it first."%timestamp)
                    self.state_info.setText("Running Status: Not Connected, please ensure the server is running.")
                    self.ip_address.setEnabled(True)
                    self.port.setEnabled(True)
                    self.name.setEnabled(True)
                    return 
                if len(user_list) != self.user_list_table.rowCount():
                    print("user list changed",user_list)
                    self.set_user_list_table(user_list)
                else:
                    time.sleep(5)  # refresh every 5 seconds
            except Exception as e:
                self.set_state_info("Get user list failed! %s"%e)
                return


    def login_button_clicked(self):
        if self.device != None:
            self.set_state_info("You have already login!")
            return 
        if self.ip_address.text() == "" or self.port.text() == "" or self.name.text() == "":
            self.state_info.setText("Please fill in the blank. (server ip, server port, your name)")
            return
        ts = time.time()
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime(ts)))

        self.host_ip = get_ip_address(sk.gethostname())
        self.device = ClientMainWorker(self.host_ip,client_port,self.thread_event,debugging=True)
        self.host_port = self.device.get_port()

        self.thread_event.set()
        self.device.run()
        
        try:
            self.device.login(self.ip_address.text(),int(self.port.text()),self.name.text()) 
        except Exception as e:
            self.set_state_info("Login failed, please ensure the server is running.")
            self.device = None
            return
        self.set_state_info("Login successfully.")
        self.log_display_append("$%s [+] Client: Login successfully, Server IP: %s, Server Port: %d, Local IP: %s, Local Port: %d"%(timestamp,self.ip_address.text(),int(self.port.text()),self.host_ip,self.host_port))
        if self.log_flag: self.logger.log("$%s [+] Client: Login successfully, Server IP: %s, Server Port: %d, Local IP: %s, Local Port: %d"%(timestamp,self.ip_address.text(),int(self.port.text()),self.host_ip,self.host_port))
        self.ip_address.setDisabled(True)
        self.port.setDisabled(True)
        self.name.setDisabled(True)
        self.disp_thread = threading.Thread(target=self._display_user_list,args=(self.thread_event,))
        self.disp_thread.start()

    def logout_button_clicked(self):
        if self.device == None:
            self.set_state_info(" You have not login yet!")
            return
        ts = time.time()
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime(ts)))

        try:
            self.device.logout()
        except Exception:
            self.set_state_info("Logout failed!, Please try again.")
            return

        self.set_state_info("Logout successfully.")
        self.log_display_append("$%s [+] Client: Logout successfully, Server IP: %s, Server Port: %d, Local IP: %s, Local Port: %d"%(timestamp,self.ip_address.text(),int(self.port.text()),self.host_ip,self.host_port))
        if self.log_flag: self.logger.log("$%s [+] Client: Logout successfully, Server IP: %s, Server Port: %d, Local IP: %s, Local Port: %d"%(timestamp,self.ip_address.text(),int(self.port.text()),self.host_ip,self.host_port))
        self.device = None
        self.thread_event.clear()
        self.ip_address.setEnabled(True)
        self.port.setEnabled(True)
        self.name.setEnabled(True)

    def send_button_clicked(self):
        pass 

    def set_user_list_table(self,user_list):
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
        self.log_display.append(log_text)
        self.log_display.moveCursor(QTextCursor.End)

    def set_state_info(self,state_info):
        self.state_info.setText(state_info)

    

    
if __name__ == "__main__":
    '''
        Test the function.
    '''
    import sys
    app = QApplication(sys.argv)
    window = ClientWindow('Client')
    sys.exit(app.exec_())
    
