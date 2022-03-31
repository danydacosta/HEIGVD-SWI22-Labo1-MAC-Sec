#! /usr/bin/python3

from scapy.all import *


iface="wlan0mon"


APs = {}

def analysePacket(packet):

    if packet.haslayer(Dot11Beacon):    # Il s'agit d'un AP
        bssid = bssid = packet[Dot11].addr3

        if bssid not in APs:
            APs[bssid] = set()
        else:
            return
    elif packet[Dot11].type == 2:       # Il s'agit de données
        src = packet[Dot11].addr2
        dest = packet[Dot11].addr1


        if src in APs:                  # Communication AP --> STA
            APs[src].add(dest)
        elif dest in APs:
            APs[dest].add(src)          # Communication STA --> AP


    print(APs)



sniff(iface=iface, prn=analysePacket)