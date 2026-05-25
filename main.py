import  ipaddress
import socket
import struct
import sys
import argparse


parser = argparse.ArgumentParser(description='Packet sniffer')
parser.add_argument('--ip', help="Ip address", required=True)
options = parser.parse_args()


class Packet:
    pass

def sniff():
    pass


if __name__ == "__main__":
    sniff()


