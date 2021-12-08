from PyQt5.QtWidgets import QApplication, QTableWidgetItem,QLineEdit, QTableWidget, QTextEdit,QWidget,QVBoxLayout,QHBoxLayout, QLabel,QPushButton
from PyQt5.QtGui import QFont, QIcon, QTextCursor
from PyQt5.QtCore import QRect, QSize

import threading

class ServerWindow(QWidget):
    '''
        design the main frame window
    '''
    def __init__(self,window_name,debug_flag=False,parent=None):
        super().__init__(parent)
        # the window title
        self.setWindowTitle(window_name)

        # the mails that get from the pop3 server
        self.mails = []

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
        self.icon_path = "icon.ico"

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

        # set the pop3 device valid flag as false
        self.device_valid = False

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


        start_button = QPushButton("Start Server",self)
        start_button.clicked.connect(self.start_button_clicked)
        top_layout.addWidget(start_button)

        end_button = QPushButton("End Server",self)
        end_button.clicked.connect(self.end_button_clicked)
        top_layout.addWidget(end_button)

        
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

        # show the window
        self.show()

    def start_button_clicked(self):
        pass 

    def end_button_clicked(self):
        pass

    def log_display_append(self,text):
        self.log_display.append(text)
        self.log_display.moveCursor(QTextCursor.End)

    def log_display_clear(self):
        self.log_display.clear()

    def user_list_table_clear(self):
        self.user_list_table.clear()

    def set_user_list_tabel(self,display_table):
        self.display_table.setRowCount(len(display_table))
        for i in range(len(display_table)):
            for j in range(6):
                self.display_table.setItem(i,j,QTableWidgetItem(display_table[i][j]))

    def set_user_list_table_item(self,row,column,text):
        self.user_list_table.setItem(row,column,QTableWidgetItem(text))

    def set_state_info(self,text):
        self.state_info.setText(text)

    
  
if __name__ == "__main__":
    '''
        Test the function.
    '''
    import sys
    app = QApplication(sys.argv)
    window = ServerWindow('server')
    sys.exit(app.exec_())
    
