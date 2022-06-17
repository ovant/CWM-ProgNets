#!/usr/bin/env python3

import argparse
import sys
import socket
import random
import struct
import re

from scapy.all import *
from scapy.all import sendp, send, srp1
from scapy.all import Packet, hexdump
from scapy.all import Ether, StrFixedLenField, XByteField, IntField
from scapy.all import bind_layers
import time

from bitstring import BitArray

my_key = (0xFFFFFFFF)  #.to_bytes(8, byteorder='big')
my_key_f = 0x11111111

class P4scramb(Packet):
    name = "P4scramb"
    fields_desc = [ StrFixedLenField("P", "P", length=1),
                    StrFixedLenField("Four", "4", length=1),
                    XByteField("version", 0x02),
                    StrFixedLenField("secret", "abcd", length=4)]

bind_layers(Ether, P4scramb, type=0x1234)

class NumParseError(Exception):
    pass

class OpParseError(Exception):
    pass

class Token:
    def __init__(self,type,value = None):
        self.type = type
        self.value = value

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def feistel_dec(secret_t):
    # secret = int.from_bytes(secret,'big')
    secret = BitArray(secret_t)
    left = secret >> 16
    right = secret & '{:032b}'.format(65535)

    new_right = right
    new_left = left ^ new_right ^ 0xDEADBABE

    right = new_left
    left = new_right ^ my_key_f ^ right

    return ((left << 16) | right) #.to_bytes(4, 'big')

def caesar_dec(sec):
    # print(int.from_bytes(sec, 'big')-my_key)
    return (int.from_bytes(sec, 'big') - my_key_f).to_bytes(6,'big')

def main():
    
    # p = make_seq(num_parser, make_seq(op_parser,num_parser))
    s = ''
    iface = 'eth0'

    while True:
        time.sleep(0.5)
        try:
            resp2 = sniff(filter = "ether dst 00:04:00:00:00:00", iface=iface,count = 2, timeout=10)
            resp = resp2[1]
            if resp:
                p4scramb=resp[P4scramb]
                if p4scramb:
                    print((p4scramb.secret)) 

                    if p4scramb.version == 1:
                    # decrypt simple xor
                        print((int.from_bytes(p4scramb.secret, 'big') ^ my_key_f).to_bytes(4,'big'))

                    elif p4scramb.version == 2:
                    # decrypt caesar
                        print(caesar_dec(p4scramb.secret))

                    elif p4scramb.version == 3:
                    # decrypt feistel
                        print(feistel_dec(p4scramb.secret))

                    
                    resp.show()
                else:
                    print("cannot find P4scramb header in the packet")
            else:
                print("Didn't receive response")
        except Exception as error:
            print(error)


if __name__ == '__main__':
    main()

