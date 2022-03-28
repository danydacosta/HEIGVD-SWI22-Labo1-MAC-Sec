#! /usr/bin/env python
from socket import timeout
from scapy.all import *

# Dresser une liste des SSID disponibles à proximité avec les numéros de canaux et les puissances
ssid_list = []
channel_list = []

print('Scanning surrounding for 10sec...')
def PacketHandler(pkt) :
    if pkt.haslayer(Dot11Beacon) :
        ssid = pkt[Dot11Elt].info.decode()

        try:
            dbm_signal = pkt.dBm_AntSignal
        except:
            dbm_signal = "N/A"

        # if ssid not in ssid_list :
        #     ssid_list.append(ssid)
        
        # extract network stats
        stats = pkt[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")

        # if channel not in channel_list:
        #     channel_list.append(channel)

        print("SSID : " + ssid + " | Channel : " + str(channel) + " | Puissance (dBm) : " + str(dbm_signal))
  
sniff(iface="en0", prn=PacketHandler, monitor=True)

print(ssid_list)
print(channel_list)

# https://www.thepythoncode.com/code/building-wifi-scanner-in-python-scapy

# Permettre à l'utilisateur de choisir le réseau à attaquer
# Générer un beacon concurrent annonçant un réseau sur un canal différent se trouvant à 6 canaux de séparation du réseau original
