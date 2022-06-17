#!/usr/bin/env python3

import argparse
from codecs import ascii_encode
import sys
import socket
import random
import struct
import re

from scapy.all import sendp, send, srp1
from scapy.all import Packet, hexdump
from scapy.all import Ether, StrFixedLenField, XByteField, IntField, BitField
from scapy.all import bind_layers


class P4scramb(Packet):
    name = "P4scramb"
    fields_desc = [ StrFixedLenField("P", "P", length=1),
                    StrFixedLenField("Four", "4", length=1),
                    XByteField("version", 0x01),
                    StrFixedLenField("secret", "1111", length=4)]
                    # BitField('secret', 0, 32)] 

bind_layers(Ether, P4scramb, type=0x1234)

class NumParseError(Exception):
    pass

class OpParseError(Exception):
    pass

class Token:
    def __init__(self,type,value = None):
        self.type = type
        self.value = value

def tobits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result


def main():

    s = ''
    iface = 'eth0'

    while True:
        s = input('> ')
        if s == "quit":
            break
        print(s)
        try:
            # i,ts = p(s,0,[])
            # s = ascii_encode(s)
            pkt = Ether(dst='00:04:00:00:00:00', type=0x1234) / P4scramb(secret = s)
            pkt = pkt/' '

            pkt.show()
            resp = srp1(pkt, iface=iface, timeout=1, verbose=False)
        except Exception as error:
            print(error)


if __name__ == '__main__':
    main()

