#! /usr/bin/env python
from __future__ import division
import pexpect
import sys
import math
from time import sleep

queue_thresh = int(sys.argv[1])
child = pexpect.spawn('simple_switch_CLI --thrift-port 9091')
child.expect ('RuntimeCmd: ')
child.sendline ('show_tables')
child.expect ('RuntimeCmd: ')
x = child.before  
register_name =['pkt_count_reg', 'pkt_length_reg' ,'last_seen','total_last_seen']
register_values = []

enque_depth = 0
child.sendline('register_read timestamp 0')
child.expect('RuntimeCmd: ')
cur_time =  int(child.before.split()[-1])
while 1:
	backoff_priority = []
	child.sendline('register_read enque_depth')
	child.expect('RuntimeCmd: ')
	string = child.before
	enque_depth = int(string.split()[-1])
	if enque_depth > queue_thresh:
		for tenant in range(0,3):
			register_value = []

			for index,reg in enumerate(register_name):
				child.sendline('register_read '+ reg +' ' + str(tenant))
				child.expect('RuntimeCmd: ')
				register_value.insert(index, (int(child.before.split()[-1])))
			backoff_priority.insert(tenant, (3*register_value[0]*2*register_value[1])/(10*(register_value[2])))
		print "After calculation, backoff transmission rate values : ",backoff_priority
		for tenant in range(0,3):
			if sum(backoff_priority)==0:
				total_backoff_multiplier = 0
			else:
				total_backoff_multiplier=backoff_priority[tenant]/sum(backoff_priority) 
			backoff_reqd = int(math.ceil((enque_depth - queue_thresh)*total_backoff_multiplier))
			child.sendline('register_write congestion_control_rate_reg ' + str(tenant) + ' ' + str(backoff_reqd))
			child.expect('RuntimeCmd: ')
			print(child.before)
		print "Total back off needed",(enque_depth - queue_thresh)
	else:
		for tenant in range(0,3):
			child.sendline('register_write congestion_control_rate_reg ' + str(tenant) + ' 0')
			child.expect('RuntimeCmd: ')
			print(child.before)
	
	sleep(2)
			

