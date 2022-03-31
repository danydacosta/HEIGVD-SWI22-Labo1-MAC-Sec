#! /usr/bin/python3

import sys
from scapy.all import *


# A modifier si nécessaire
iface = 'wlan0mon'      # interface wlan où les paquets seront envoyés (mode monitor nécessaire)


if len(sys.argv) != 2:
    print("Need 1 parameter, SSID name")
    exit(1)

ssidToFind = sys.argv[1]
print("Looking for probe request for SSID : " + ssidToFind)

stas = set()            # Contiendra la liste des STAs
def analyseProbeRequ(packet):
    if packet[Dot11Elt].info.decode() == ssidToFind:    # Check si le probe cherche le bon SSID
        src = packet[Dot11].addr2                       # Extraction de la source
        stas.add(src)
        print("STAs looking for {} SSID : \n {}".format(ssidToFind, stas))
    


sniff(iface=iface, filter="wlan type mgt subtype probe-req", prn=analyseProbeRequ)  # Capture des frames, on filtre pour avoir que les probe request