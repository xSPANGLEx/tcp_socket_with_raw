import socket
import sys
import random
import threading
import argparse
from struct import pack
import ois_console


class TcpController:

    def __init__(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except Exception as e:
            print("Socket initialize error. [%s]" % str(e))
            sys.exit(1)
        self.screen = ois_console.Screen(2)
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
        self.mode_status = "manual"
        self.print_counter = 0

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
            try:
                w = (msg[i] << 8) + (msg[i+1])
            except:
                w = (msg[i] << 8) + 0
            s = s + w
        s = (s >> 16) + (s & 0xffff)
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
            if self.from_src_port == 0:
                if dest_addr == self.from_dest_addr and dest_port == self.from_dest_port:
                    if service_ident in self.packet_ident:
                        continue
                    else:
                        self.packet_ident[service_ident] = self.global_counter
                    self.from_src_port = source_port
                    self.global_counter += 1
                    self.src_packet.append(response)
                    self.print()
            elif dest_addr == self.from_dest_addr and dest_port == self.from_dest_port:
                if service_ident in self.packet_ident:
                    continue
                else:
                    self.packet_ident[service_ident] = self.global_counter
                self.global_counter += 1
                self.src_packet.append(response)
                self.print()
            if src_addr == self.to_dest_addr and source_port == self.to_dest_port:
                if service_ident in self.packet_ident:
                    continue
                else:
                    self.packet_ident[service_ident] = self.global_counter
                self.global_counter += 1
                self.dest_packet.append(response)
                self.print()

    def recv(self):
        th = threading.Thread(target=self.reciever)
        th.setDaemon(True)
        th.start()

    def re_checksum(self, packet):
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        packet[36:38] = [b for b in list(pack("!H", 0))]
        total_length = int.from_bytes(bytes(packet[2:4]), "big")
        src_addr = bytes(packet[12:16])
        dest_addr = bytes(packet[16:20])
        tcp_header = bytes(packet[20:total_length])
        tcp_length = len(tcp_header)
        psh = pack("!4s4sBBH", src_addr, dest_addr, placeholder, protocol, tcp_length)
        psh = psh + tcp_header
        checksum = self.checksum(psh)
        packet[36:38] = [b for b in list(pack("!H", checksum))]
        return packet

    def send_to(self, packet):
        packet[12] = self.to_src_addr[0]
        packet[13] = self.to_src_addr[1]
        packet[14] = self.to_src_addr[2]
        packet[15] = self.to_src_addr[3]
        port_binary = [b for b in list(pack(">H", self.to_src_port))]
        packet[20] = port_binary[0]
        packet[21] = port_binary[1]
        packet[16] = self.to_dest_addr[0]
        packet[17] = self.to_dest_addr[1]
        packet[18] = self.to_dest_addr[2]
        packet[19] = self.to_dest_addr[3]
        port_binary = [b for b in list(pack(">H", self.to_dest_port))]
        packet[22] = port_binary[0]
        packet[23] = port_binary[1]
        packet = self.re_checksum(packet)
        self.socket.sendto(bytes(packet), (self.to_dest_ip, 0))

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
        self.socket.sendto(bytes(packet), (self.from_dest_ip, 0))

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
        self.screen.clear(screen=0)
        self.screen.clear(screen=1)
        output = "Source [%s:%s] to [%s:%s]\n\n" % (self.from_src_ip, self.from_src_port,
                                                    self.from_dest_ip, self.from_dest_port)
        self.screen.print(output.encode("utf-8"), screen=0)
        for packet in self.dest_packet:
            flag = list(format(packet[33], "08b"))[2:]
            for flag_name in self.check_tcp_flags(flag):
                self.screen.print(flag_name.encode("utf-8"), screen=0)
            output = " :" + str(self.packet_ident[self.get_service_ident(packet)]) + "\n"
            self.screen.print(output.encode("utf-8"), screen=0)
        output = "Dest [%s:%s] to [%s:%s]\n\n" % (self.to_src_ip, self.to_src_port,
                                                  self.to_dest_ip, self.to_dest_port)
        self.screen.print(output.encode("utf-8"), screen=1)
        for packet in self.src_packet:
            flag = list(format(packet[33], "08b"))[2:]
            for flag_name in self.check_tcp_flags(flag):
                self.screen.print(flag_name.encode("utf-8"), screen=1)
            output = " :" + str(self.packet_ident[self.get_service_ident(packet)]) + "\n"
            self.screen.print(output.encode("utf-8"), screen=1)

    def manual_mode(self):
        self.mode_status = "manual"
        while 1:
            key = self.screen.input()
            keys = key.split(" ")
            if key == "auto":
                break
            if key == "exit":
                self.mode_status = "exit"
                self.screen.screen_finalize()
                return
            if key == "send_to":
                self.send_to(self.src_packet.pop(0))
                self.print()
            if key == "send_from":
                self.send_from(self.dest_packet.pop(0))
                self.print()
            if key == "drop_to":
                self.src_packet.pop(0)
                self.print()
            if key == "drop_from":
                self.dest_packet.pop(0)
                self.print()
            if len(keys) > 1:
                if keys[0] == "send":
                    packet, target = self.send_ident(int(keys[1]))
                    if target == "to":
                        self.send_to(packet)
                    if target == "from":
                        self.send_from(packet)
                    self.print()
                if keys[0] == "drop":
                    packet, target = self.send_ident(int(keys[1]))
                    self.print()

    def auto_transfer(self):
        while 1:
            if self.mode_status == "manual":
                break
            for i in range(len(self.src_packet)):
                self.send_to(self.src_packet.pop(0))
            for i in range(len(self.dest_packet)):
                self.send_from(self.dest_packet.pop(0))

    def auto_mode(self):
        self.mode_status = "auto"
        th = threading.Thread(target=self.auto_transfer)
        th.setDaemon(True)
        th.start()
        while 1:
            key = self.screen.input()
            if key == "manual":
                break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TCP Controller")
    parser.add_argument("src", help="Source host:port", type=str)
    parser.add_argument("dest", help="Dest host:port", type=str)
    args = parser.parse_args()
    try:
        source_host = args.src.split(":")[0]
        source_port = int(args.src.split(":")[1])
        dest_host = args.dest.split(":")[0]
        dest_port = int(args.dest.split(":")[1])
    except:
        print("Args error")
        sys.exit(1)
    tcp = TcpController()
    tcp.set_from_host((source_host, 0), (source_host, source_port))
    tcp.set_to_host((source_host, random.randint(49152, 65535)), (dest_host, dest_port))
    tcp.recv()
    tcp.print()
    while 1:
        tcp.manual_mode()
        if tcp.mode_status == "exit":
            break
        tcp.auto_mode()
