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
#print x

register_name =['pkt_count_reg', 'pkt_length_reg' ,'last_seen','total_last_seen']
register_values = []


#total_backoff_multiplier = []
#backoff_reqd = []

enque_depth = 0
child.sendline('register_read timestamp 0')
child.expect('RuntimeCmd: ')
cur_time =  int(child.before.split()[-1])
print "cur_time=",cur_time



while 1:
	backoff_priority = []
	child.sendline('register_read enque_depth')
	child.expect('RuntimeCmd: ')
	string = child.before
	enque_depth = int(string.split()[-1])
	if enque_depth > queue_thresh:
		for tenant in range(0,3):
			register_value = []
			print "tenant =",tenant
			for index,reg in enumerate(register_name):
				child.sendline('register_read '+ reg +' ' + str(tenant))
				child.expect('RuntimeCmd: ')
				register_value.insert(index, (int(child.before.split()[-1])))
		
			#register_values[tenant].append(register_value)
			print "register_value=",register_value
			print "last_seen=",register_value[2]
			print "total_last_seen=",register_value[3]
			#backoff_priority.insert(tenant, (3*register_value[0]*2*register_value[1])/(10*(cur_time+1 - register_value[2])*5*(register_value[3])))
                        
			backoff_priority.insert(tenant, (3*register_value[0]*2*register_value[1])/(10*(register_value[2])))
			
			
		print "after calculation, backoff_priorities are = ",backoff_priority
		#print "after calculation, backoff_priorities indexs are = ",backoff_priority.keys()
		for tenant in range(0,3):
                        print "tenant bkof :", tenant
			print "backoff_priority[tenant] = ",backoff_priority[tenant]
			print "sum(backoff_priority)",sum(backoff_priority)
			if sum(backoff_priority)==0:
				total_backoff_multiplier = 0
			else:
				total_backoff_multiplier=backoff_priority[tenant]/sum(backoff_priority) 
			print "bo_mul=",total_backoff_multiplier
			backoff_reqd = int(math.ceil((enque_depth - queue_thresh)*total_backoff_multiplier))
			child.sendline('register_write congestion_control_rate_reg ' + str(tenant) + ' ' + str(backoff_reqd))
			child.expect('RuntimeCmd: ')
			print(child.before)
		print "Total BO needed",(enque_depth - queue_thresh)
			
		
		#child.sendline('register_read congestion_control_rate_reg 0')
		#child.expect('RuntimeCmd: ')
		#print(child.before)
	else:
		for tenant in range(0,3):
			child.sendline('register_write congestion_control_rate_reg ' + str(tenant) + ' 0')
			child.expect('RuntimeCmd: ')
			print(child.before)
	
	sleep(2)
			

