
from PyQt5 import QtCore
from scapy.all import *
class sniff_object(QtCore.QThread):
    packet_signal=QtCore.pyqtSignal(object)
    errorsignal=QtCore.pyqtSignal(str)
    def run(self):
        try:
            print("loop is about to run")
            sniff(prn=self.packet_handler,store=0)
        except Exception as e:
            print(f"Excetion occured: {e}")
    def packet_handler(self,packet):
        self.packet_signal.emit(packet)

