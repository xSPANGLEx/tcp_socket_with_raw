import socket
import sys
import random
import time
import logging
import threading
from struct import *


class TcpController:

    def __init__(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL,1)
        except Exception as e:
            print("Socket initialize error. [%s]" % e)
            sys.exit(1)
        self.from_dest_ip = None
        self.from_src_ip = None
        self.from_dest_addr = None
        self.from_src_addr = None
        self.from_dest_port = None
        self.from_src_port = None
        self.to_dest_ip = None
        self.to_src_ip = None 
        self.to_dest_addr = None
        self.to_src_addr = None
        self.to_dest_port = None
        self.to_src_port = None
        self.dest_packet = []
        self.src_packet = []
        self.packet_ident = {}
        self.global_counter = 0

    def set_from_host(self, src, dest):
        self.from_dest_ip = dest[0]
        self.from_src_ip = src[0]
        self.from_dest_addr = socket.inet_aton(self.from_dest_ip)
        self.from_src_addr = socket.inet_aton(self.from_src_ip)
        self.from_dest_port = dest[1]
        self.from_src_port = src[1]

    def set_to_host(self, src, dest):
        self.to_dest_ip = dest[0]
        self.to_src_ip = src[0]
        self.to_dest_addr = socket.inet_aton(self.to_dest_ip)
        self.to_src_addr = socket.inet_aton(self.to_src_ip)
        self.to_dest_port = dest[1]
        self.to_src_port = src[1]

    def checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + (msg[i+1])
            s = s + w
        s = (s>>16) + (s & 0xffff);
        s = ~s & 0xffff
        return s 

    def get_service_ident(self, packet):
        packet = [b for b in list(packet)]
        source_port = int.from_bytes(bytes(packet[20:22]), "big")
        dest_port = int.from_bytes(bytes(packet[22:24]), "big")
        ident = int.from_bytes(bytes(packet[4:6]), "big")
        service_ident = str(source_port) + str(dest_port) + str(ident)
        return service_ident

    def reciever(self):
        while 1:
            response_raw = self.socket.recv(65000)
            response = [b for b in list(response_raw)]
            src_addr = bytes(response[12:16])
            dest_addr = bytes(response[16:20])
            source_port = int.from_bytes(bytes(response[20:22]), "big")
            dest_port = int.from_bytes(bytes(response[22:24]), "big")
            service_ident = self.get_service_ident(response_raw)
            if dest_addr == self.from_dest_addr and dest_port == self.from_dest_port:
                if service_ident in self.packet_ident:
                    continue
                else:
                    self.packet_ident[service_ident] = self.global_counter
                if self.from_src_port == 0:
                    self.from_src_port = source_port
                self.global_counter += 1
                self.src_packet.append(response)
            if src_addr == self.to_dest_addr and source_port == self.to_dest_port:
                if service_ident in self.packet_ident:
                    continue
                else:
                    self.packet_ident[service_ident] = self.global_counter
                self.global_counter += 1
                self.dest_packet.append(response)
               
    def recv(self):
        th = threading.Thread(target=self.reciever)
        th.setDaemon(True)
        th.start()

    def re_checksum(self, packet):
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        packet[36:38] = [b for b in list(pack("!H", 0))]
        total_length = int.from_bytes(bytes(packet[2:4]), "big")
        tcp_header = bytes(packet[20:total_length])
        tcp_length = len(tcp_header)
        src_addr = bytes(packet[12:16])
        dest_addr = bytes(packet[16:20])
        psh = pack("!4s4sBBH", src_addr, dest_addr, placeholder, protocol, tcp_length)
        psh = psh + tcp_header
        checksum = self.checksum(psh)
        packet[36:38] = [b for b in list(pack("!H", checksum))]
        return packet


    def send_to(self, packet):
        packet[12] = self.to_dest_addr[0]
        packet[13] = self.to_dest_addr[1]
        packet[14] = self.to_dest_addr[2]
        packet[15] = self.to_dest_addr[3]
        port_binary = [b for b in list(pack(">H", self.to_src_port))]
        packet[20] = port_binary[0]
        packet[21] = port_binary[1]
        packet[16] = self.to_src_addr[0]
        packet[17] = self.to_src_addr[1]
        packet[18] = self.to_src_addr[2]
        packet[19] = self.to_src_addr[3]
        port_binary = [b for b in list(pack(">H", self.to_dest_port))]
        packet[22] = port_binary[0]
        packet[23] = port_binary[1]
        packet = self.re_checksum(packet)
        self.socket.sendto(bytes(packet), (self.to_dest_ip,0))
        

    def send_from(self, packet):
        packet[12] = self.from_dest_addr[0]
        packet[13] = self.from_dest_addr[1]
        packet[14] = self.from_dest_addr[2]
        packet[15] = self.from_dest_addr[3]
        port_binary = [b for b in list(pack(">H", self.from_dest_port))]
        packet[20] = port_binary[0]
        packet[21] = port_binary[1]
        packet[16] = self.from_src_addr[0]
        packet[17] = self.from_src_addr[1]
        packet[18] = self.from_src_addr[2]
        packet[19] = self.from_src_addr[3]
        port_binary = [b for b in list(pack(">H", self.from_src_port))]
        packet[22] = port_binary[0]
        packet[23] = port_binary[1]
        packet = self.re_checksum(packet)
        self.socket.sendto(bytes(packet), (self.from_dest_ip,0))

    def check_tcp_flags(self, flag):
        result = []
        if int(flag[0]):
            result.append("URG")
        if int(flag[1]):
            result.append("ACK")
        if int(flag[2]):
            result.append("PSH")
        if int(flag[3]):
            result.append("RST")
        if int(flag[4]):
            result.append("SYN")
        if int(flag[5]):
            result.append("FIN")
        return result

    def send_ident(self, ident):
        for i in range(len(self.dest_packet)):
            packet = self.dest_packet[i]
            service_ident = self.get_service_ident(packet)
            if self.packet_ident[service_ident] == ident:
                return self.dest_packet.pop(i), "from"
        for i in range(len(self.src_packet)):
            packet = self.src_packet[i]
            service_ident = self.get_service_ident(packet)
            if self.packet_ident[service_ident] == ident:
                return self.src_packet.pop(i), "to"
        return None, None


    def print(self):
        print("[Dest] " + "[src:" + str(self.to_src_port) + "] [dest:" + str(self.to_dest_port) + "]")
        for packet in self.dest_packet:
            flag = list(format(packet[33], "08b"))[2:]
            for flag_name in self.check_tcp_flags(flag):
                print(flag_name, end=" ")
            print(" :" + str(self.packet_ident[self.get_service_ident(packet)]))
        print("[Source]" + "[src:" + str(self.from_src_port) + "] [dest:" + str(self.from_dest_port) + "]")
        for packet in self.src_packet:
            flag = list(format(packet[33], "08b"))[2:]
            for flag_name in self.check_tcp_flags(flag):
                print(flag_name, end=" ")
            print(" :" + str(self.packet_ident[self.get_service_ident(packet)]))

if __name__ == "__main__":
    tcp = TcpController()
    tcp.set_from_host(("127.0.0.1", 0),("127.0.0.1", 18080))
    tcp.set_to_host(("127.0.0.1", random.randint(49152, 65535)), ("127.0.0.1", 8080))
    tcp.recv()
    while 1:
        key = input()
        keys = key.split(" ")
        if key == "print":
            tcp.print()
        if key == "send_to":
            tcp.send_to(tcp.src_packet.pop(0))
        if key == "send_from":
            tcp.send_from(tcp.dest_packet.pop(0))
        if key == "drop_to":
            tcp.src_packet.pop(0)
        if key == "drop_from":
            tcp.dest_packet.pop(0)
        if len(keys) > 1:
            if keys[0] == "send":
                packet, target = tcp.send_ident(int(keys[1]))
                if target == "to":
                    tcp.send_to(packet)
                if target == "from":
                    tcp.send_from(packet)
            if keys[0] == "drop":
                packet, target = tcp.send_ident(int(keys[1]))