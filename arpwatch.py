import os, re
from scapy.all import *

conf.verb = 0

interface = 'ens33'

if len(sys.argv) > 1:
    interface = sys.argv[len(sys.argv)- 1]
'''
ADDRESS RESOLUTION PROTOCOL
arp -a
_gateway

arp -i
_gateway              ether   ff:ff:ff:ff:ff:ff   CM                    ens33
ddd.ddd.d             ether   ff:ff:ff:ff:ff:ff   CM                    ens33
ddd.ddd.ddd           ether   ff:ff:ff:ff:ff:ff   C                     ens33

'''

pattern = re.compile('\((.*)\)\sat\s([0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]).*')
pattern2 = re.compile('\\b([^\s]+).*([0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]).*')
addres_to_mac = dict()

#https://scapy.readthedocs.io/en/latest/usage.html



command = 'arp -i ' + interface
lines = os.popen(command)
lines = lines.read().split('\n');
lines.pop(0)

for line in lines:

    if len(line) == 0:
        continue

    parsed_values = pattern2.findall(line)[0]
    addres_to_mac[parsed_values[0]] = parsed_values[1]


def arp_scan(pkt):

    #https://scapy.readthedocs.io/en/latest/usage.html
    if ARP in pkt:
        ip_src = pkt[ARP].psrc
        MAC_src = pkt[ARP].hwsrc
        if ip_src in addres_to_mac:
            if addres_to_mac[ip_src] != MAC_src:
                print(ip_src, 'changed from', addres_to_mac[ip_src], 'to', MAC_src)
                #addres_to_mac[ip_src] = MAC_src
        else:
            addres_to_mac[ip_src] = MAC_src


sniff(iface=interface , prn = arp_scan, store=0)
