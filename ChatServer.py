

import sys
sys.path.append('../')

from ui.ServerWindow import ServerWindow
from PyQt5.QtWidgets import QApplication
from config.config import *

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ServerWindow(server_window_name,True)
    sys.exit(app.exec_())


    # app = QApplication(sys.argv)
    # from tools.utls import SeverMainWorker,get_ip_address
    # import threading
    # import socket as sk
    # host = get_ip_address(sk.gethostname())
    # sport = server_port
    # sevent = threading.Event()
    # sevent.set()
    # sworker = SeverMainWorker(host, sport, sevent,True)
    # sworker.run()
    # import time
    # time.sleep(60)
    # sevent.clear()