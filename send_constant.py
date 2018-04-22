#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
from threading import Thread
from collections import deque
from time import sleep
from scapy.all import sniff, sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP
from scapy.all import Packet, hexdump
from scapy.all import  StrFixedLenField, XByteField, IntField, BitField
from scapy.all import bind_layers


'''
TENANT HEADER

    bit<32> id;
    bit<32> enq_timestamp;  // 32 bit
    bit<32> enq_qdepth;     // 19      typecast
    bit<32>deq_timedelta;   // 32
    bit<32> deq_qdepth;     // 19      typecast
    bit<32> total_pkt_count;
    bit<32> total_packet_length;
    bit<48> inter_packet_gap;  
    bit<96> total_inter_packet_gap;
    bit<32> queue_occupancy;
    bit<32> ack_flag
'''

'''
global vars
'''
dq1 = deque()
dq1_wnd = 10

dq2 = deque()
dq2_wnd = 10

dq3 = deque()
dq3_wnd = 10



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

'''
func: populate tenant 1 queue
'''
def populate_que1():
    tid =1
    print "tid :", tid
    global dq1
    global dq1_wnd

    while(1):
        for i in range(0, dq1_wnd):
            dq1.append(0)

        #sleep after populating 
        sleep(1)


'''
func: populate tenant 2 queue
'''
def populate_que2():
    tid =2
    print "tid :", tid
    global dq2
    global dq2_wnd

    while(1):
        for i in range(0, dq2_wnd):
            dq2.append(1)

        #sleep after populating 
        sleep(1)


'''
func: populate tenant queue
'''
def populate_que3():
    tid =3
    print "tid :", tid
    global dq3
    global dq3_wnd

    while(1):
        for i in range(0, dq3_wnd):
            dq3.append(2)

        #sleep after populating 
        sleep(1)



    
'''
func: to send packets:
'''
def send_Custom_pkt():
    global dq1
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    
    while(1):
        if len(dq1) > 0:
            currtid = dq1.popleft()

            pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff') /IP(dst=addr) / UDP(dport=4321, sport=1234) / tenant(id=currtid) / sys.argv[2]
            #pkt.show2()
            sendp(pkt, iface=iface, verbose=False)

        if len(dq2) > 0:
            currtid = dq2.popleft()

            pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff') /IP(dst=addr) / UDP(dport=4321, sport=1234) / tenant(id=currtid) / sys.argv[2]
            #pkt.show2()
            sendp(pkt, iface=iface, verbose=False)

        if len(dq3) > 0:
            currtid = dq3.popleft()

            pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff') /IP(dst=addr) / UDP(dport=4321, sport=1234) / tenant(id=currtid) / sys.argv[2]
            #pkt.show2()
            sendp(pkt, iface=iface, verbose=False)



'''
func: to obtain interface details
'''
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

'''
func: to handle ACKs from recv.py 
      and change tenant queue len
'''
def handle_pkt(pkt):

    #print Recieved packet

    #print "\n### data ack flag ###\n"
    if(pkt[tenant].ack_flag != 0):
        print "got a packet\n"
        pkt.show2()
        print "ack_flag val :", pkt[tenant].ack_flag

        '''
        # feedback for every tenant
        if pkt[tenant].id == 1:
                global dq1 
                dq1_wnd = pkt[tenant].ack_flag
                dq1.clear()

        '''

'''
Main Func
'''
def main():
    


    if len(sys.argv)<3:
        print 'pass 2 arguments: <destination> "<message>"'
        exit(1)
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()


    print "sending on interface %s to %s" % (iface, str(addr))
 
    #Main thread sending out packets from each tenant queue
    pgen = Thread(target = send_Custom_pkt, args = ())
    pgen.start()

    #threads for tenant1

    q1thread = Thread(target = populate_que1, args = ())   
    q1thread.start()

    #threads for tenant2

    q2thread = Thread(target = populate_que2, args = ())   
    q2thread.start()

    #threads for tenant3

    q3thread = Thread(target = populate_que3, args = ())   
    q3thread.start()

    #sniffing for acks   
    sniff(filter="src port 1235", iface = iface,
          prn = lambda x: handle_pkt(x))


if __name__ == '__main__':
	main()
