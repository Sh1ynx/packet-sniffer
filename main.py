import  ipaddress
import socket
import struct
import sys
import argparse


parser = argparse.ArgumentParser(description='Packet sniffer')
parser.add_argument('--ip', help="Ip address", required=True)
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
        self.source_ip = header[8]
        self.dest_ip = header[9]

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


def sniff():
    pass

if __name__ == "__main__":
    sniff()


