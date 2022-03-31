#! /usr/bin/python3

from numpy import empty
from scapy.all import *


# A modifier si nécessaire
iface = 'wlan0mon'      # interface wlan où les paquets seront envoyés (mode monitor nécessaire)


APs = {}                # Contiendra la liste des BSSID

def analysePacket(packet):

    if packet.haslayer(Dot11Beacon):    # Il s'agit d'un beacon d'un AP
        bssid = bssid = packet[Dot11].addr3

        if bssid not in APs:
            APs[bssid] = set()          # Ajout dans la liste si pas présent
        else:
            return

    elif packet[Dot11].type == 2:       # Il s'agit de données
        src = packet[Dot11].addr2
        dest = packet[Dot11].addr1

        if dest == "ff:ff:ff:ff:ff:ff": # Ignorer les frames broadcast (pas possible d'extraire une STA)
            return

        if src in APs:                  # Communication AP --> STA
            APs[src].add(dest)
        elif dest in APs:
            APs[dest].add(src)          # Communication STA --> AP

    for ap in APs:                      # Affichage
        clients = APs[ap]
        if len(clients) > 0:
            print("AP : {} Clients : {}".format(ap, clients))
            print("-------------------")
    
    print("*****************************************")

    



sniff(iface=iface, prn=analysePacket)   # Capture des frames