import sys
sys.path.append('../')

from ui.ServerWindow import ServerWindow
from PyQt5.QtWidgets import QApplication
from config.config import *

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ServerWindow(server_window_name,True)
    sys.exit(app.exec_())