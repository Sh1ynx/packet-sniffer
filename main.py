import  ipaddress
import socket
import struct
import sys
import argparse


parser = argparse.ArgumentParser(description='Packet sniffer')
parser.add_argument('--ip', help="IP address", required=True)
parser.add_argument('--protocol', help="Protocol (TCP/ICMP/UDP)", required=True)
parser.add_argument('--data', help="Display the packet data", action='store_true')

options = parser.parse_args()


class Packet:
    def __init__(self, packet):
        self.packet = packet
        header = struct.unpack('<BBHHHBBH4s4s', packet[0:20])
        self.version = header[0] >> 4
        self.header_length = header[0] & 0xF
        self.type_of_service = header[1]
        self.bit_total_length = header[2]
        self.bit_identification = header[3]
        self.flag_and_fragment_offset = header[4]
        self.time_to_live = header[5]
        self.bit_protocol = header[6]
        self.checksum = header[7]
        self.source = header[8]
        self.dest = header[9]


        self.source_ip = ipaddress.ip_address(self.source)
        self.dest_ip = ipaddress.ip_address(self.dest)

        self.protocols = {
            1: "ICMP",
            6: "TCP",
            17:"UDP"
        }

        try:
            self.protocol = self.protocols[self.bit_protocol]
        except Exception as e:
            print(f"{e} Protocol doesn't exist or not supported")
            self.protocol = str(self.bit_protocol)

    def show_some_header_data(self):
        print(f"{self.protocols[self.bit_protocol]} {self.source_ip} -> {self.dest_ip}")

    def print_data(self):
        data = self.packet[20:]
        print("-" * 15 ,"START OF DATA", "-"*15)
        for d in data:
            if (d < 128):
                print(chr(d), end='')
            else:
                print(".", end='')
        print("\n","-" * 15 ,"END OF DATA", "-"*15)


def sniff(host):
    if options.protocol == 'tcp':
        socket_protocol = socket.IPPROTO_TCP
    elif options.protocol == 'udp':
        socket_protocol = socket.IPPROTO_UDP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer_socket.bind((host,0))
    sniffer_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL,1)

    try:
        while True:
            raw_data = sniffer_socket.recv(65535)
            packet = Packet(raw_data)
            packet.show_some_header_data()
            if options.data:
                packet.print_data()
    except KeyboardInterrupt:
        sys.exit(1)


if __name__ == "__main__":
    sniff(options.ip)


