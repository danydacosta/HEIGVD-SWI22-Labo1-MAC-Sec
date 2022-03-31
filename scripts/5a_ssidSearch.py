#! /usr/bin/python3

import sys
from scapy.all import *

iface="wlan0mon"

if len(sys.argv != 2):
    print("Need 1 parameter, SSID name")
    exit(1)

ssidToFind = sys.argv[1]

stas = set()
def analyseProbeRequ(packet):
    if packet[Dot11Elt].info.decode() == ssidToFind:
        source_mac = packet[Dot11].addr2
        stas.add(source_mac)
        print("STAs looking for {} SSID : \n {}".format(ssidToFind, stas))
    


sniff(iface=iface, filter="wlan type mgt subtype probe-req", prn=analyseProbeRequ)