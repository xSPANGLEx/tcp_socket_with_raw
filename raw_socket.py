import socket
import sys
import random
from struct import *

class RawSocket:

    def __init__(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL,1)
        except Exception as e:
            print("Socket initialize error. [%s]" % e)
            sys.exit(1)
        self.dest_ip = "127.0.0.1"
        self.src_ip = "127.0.0.1"
        self.dest_addr = socket.inet_aton(self.dest_ip)
        self.src_addr = socket.inet_aton(self.src_ip)
        self.dest_port = 8080

    def checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + (msg[i+1])
            s = s + w

        s = (s>>16) + (s & 0xffff);
        s = ~s & 0xffff
        return s


    def make_ip_header(self, ihl=5, version=4, tos=0, tot_len=20, ident=1, frag_off=16384, ttl=255, check=10):
        protocol = socket.IPPROTO_TCP
        ihl_version = (version << 4) + ihl
        ip_header = pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, ident, frag_off, ttl, protocol, check, self.src_addr, self.dest_addr)
        return ip_header

    def make_tcp_header(self, seq=0, ack_seq=0, doff=5, fin=0, syn=0, rst=0, psh=0, ack=0, urg=0, check=0, urg_ptr=0):
        source = random.randint(49152,65535)
        window = socket.htons(5840)
        offset_res = (doff << 4) + 0
        tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)
        tcp_header = pack('!HHLLBBHHH' , source, self.dest_port, seq, ack_seq, offset_res, tcp_flags,  window, check, urg_ptr)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        psh = pack('!4s4sBBH' ,self.src_addr ,self.dest_addr, placeholder , protocol , tcp_length)
        psh = psh + tcp_header
        tcp_checksum = self.checksum(psh)
        tcp_header = pack('!HHLLBBHHH' , source, self.dest_port, seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr)
        return tcp_header

    def make_packet(self, ip_header, tcp_header, payload=b''):
        return ip_header + tcp_header + payload

    def send(self, packet):
        self.socket.sendto(packet, (self.dest_ip, 0))

if __name__ == "__main__":
    raw = RawSocket()
    tcp_header = raw.make_tcp_header(syn=1)
    total_len = len(tcp_header) + 20
    ip_header = raw.make_ip_header(tot_len=total_len)
    packet = raw.make_packet(ip_header, tcp_header)
    raw.send(packet)
    input()
    #tcp_header = raw.make_tcp_header(ack=1)
    #total_len = len(tcp_header) + 20
    #ip_header = raw.make_ip_header(tot_len=total_len)
    #packet = raw.make_packet(ip_header, tcp_header)
    #raw.send(packet)
