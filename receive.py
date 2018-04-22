#!/usr/bin/env python
import sys
import struct

from scapy.all import sniff, sendp, send, hexdump, get_if_list, get_if_hwaddr, srp1
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR


from scapy.all import Packet, hexdump
from scapy.all import StrFixedLenField, XByteField, IntField, BitField
from scapy.all import bind_layers


import argparse
import socket
import random
import struct

'''
TENANT HEADER

    bit<32> id;

    bit<32> enq_timestamp;  // 32 bit
    bit<32> enq_qdepth;     // 19      typecast
    bit<32>deq_timedelta;   // 32
    bit<32> deq_qdepth;     // 19      typecast
    bit<32> total_packet_length;
    bit<48> inter_packet_gap;
    bit<96> total_inter_packet_gap;
    bit<32> queue_occupancy;
    bit<32> ack_flag;
'''

'''

tenant dictionary:

ten_dict = {
              rctenant_id1 : {
                                  host SRC_IP1 :  Packet Count
                                  host SRC_IP2 :  Packet Count
                             }

              rctenant_id2 : {
                                  host SRC_IP1 :  Packet Count
                                  host SRC_IP2 :  Packet Count
                             }

           }

'''


iface = 'h2-eth0'
pkt_count = 0
ten_dict = {}

class tenant(Packet):
    name = "tenant"
    fields_desc = [ IntField("id", 10),
		    IntField("enq_timestamp",0),
                    IntField("enq_qdepth",0),
                    IntField("deq_timedelta",0),
                    IntField("deq_qdepth",0),
		    IntField("total_pkt_count",0),
		    IntField("total_packet_length",0),
		    BitField("inter_packet_gap",0x0000000000000,48),
		    BitField("total_inter_packet_gap",0x00000000000000000000000000,96),
		    IntField("queue_occupancy",0),
		    IntField("ack_flag",0)
                  ]

bind_layers(UDP, tenant, )

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface


def send_Custom_pkt(dstaddr, t_id):
    addr = socket.gethostbyname(dstaddr)
    iface = get_if()

    
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff') /IP(dst=dstaddr) / UDP(dport=5321, sport=1235) / tenant(id=t_id, ack_flag=999) / "ACK"
    #pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


def expand(x):
    yield x.name
    while x.payload:
        x = x.payload
        yield x.name

def handle_pkt(pkt):
    print "got a packet"
    global pkt_count 

    pkt_count = pkt_count + 1
    rctenant_id = pkt[tenant].id
    dst = pkt[IP].src

    if (rctenant_id not in ten_dict.keys()):
        temp_ip_dict = {}
        temp_ip_dict[dst] = 1
        ten_dict[rctenant_id] = temp_ip_dict
    else:
        if (dst not in ten_dict[rctenant_id].keys()):

            ten_dict[rctenant_id][dst] = 1
        else:    
            ten_dict[rctenant_id][dst] = ten_dict[rctenant_id][dst] + 1

            if(ten_dict[rctenant_id][dst] % 10 == 0):
                send_Custom_pkt(dst, rctenant_id)
    
    #print Recieved packet
    pkt.show2()


 

    

#    print "llllllll\n"
#    data = pkt[Raw].load
#    print "\n data", data

    print "\nHeaders: ", list(expand(pkt))

#    hexdump(pkt)
    sys.stdout.flush()


def main():
    #iface = 'h2-eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()

    sniff(filter="udp and port 4321", iface = iface,
          prn = lambda x: handle_pkt(x))

    print "\n ten dict :", ten_dict

if __name__ == '__main__':
    main()