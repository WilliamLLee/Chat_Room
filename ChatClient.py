import sys
sys.path.append('../')

from ui.ClientWindow import ClientWindow
from PyQt5.QtWidgets import QApplication
from config.config import *

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ClientWindow(client_window_name, logger_path=log_path, log_flag=True)
    sys.exit(app.exec_())
