#! /usr/bin/env python
from scapy.all import *

# Dresser une liste des SSID disponibles à proximité
ap_list = []

def PacketHandler(pkt) :
    if pkt.haslayer(Dot11) :
        print('yes')
        if pkt.type == 0 and pkt.subtype == 8 :
            if pkt.addr2 not in ap_list :
                ap_list.append(pkt.addr2)
                print(pkt.addr2)


sniff(iface="en0", prn = PacketHandler)

# Présenter à l'utilisateur la liste, avec les numéros de canaux et les puissances
# Permettre à l'utilisateur de choisir le réseau à attaquer
# Générer un beacon concurrent annonçant un réseau sur un canal différent se trouvant à 6 canaux de séparation du réseau original
