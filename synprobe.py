import sys, socket, time, ipaddress

from scapy.all import *
from scapy.layers.inet import IP, ICMP


#level of verbosity, from 0 (almost mute) to 3 (verbose)
conf.verb = 0

'''FLAGS
SA -> SYNC-ACK
RA -> BLOCKED :)
'''

'''
common ports: https://collaborate.mitre.org/attackics/index.php/Technique/T0885
TCP:80 (HTTP)
TCP:443 (HTTPS)
TCP/UDP:53 (DNS)
TCP:23 (TELNET)
UDP:161 (SNMP)
TCP:502 (MODBUS)
'''
ports = [80, 443, 53, 23, 161, 502]
target = sys.argv[-1]


def sendDummy(p, i, r):
    res = None
    for x in range(r):
        time.sleep(2**x)
        try:
            #http://zetcode.com/python/socket/
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((str(i), p))
                s.sendall(b"GET / HTTP/1.1\r\nHost: webcode.me\r\nAccept: text/html\r\nConnection: close\r\n\r\n")
                data = s.recv(1024)

                if len(data) == 0 or data is None:
                    continue
                else:
                    return data
        except:
            continue;
    return None



#search -p flag
for i in range(len(sys.argv)):
    if sys.argv[i] == "-p":
        #check tpe of range
        if "-" in sys.argv[i+1]:
            ports = [*range(int(sys.argv[i+1].split('-')[0]), int(sys.argv[i+1].split('-')[1]) + 1)]
        elif "," in sys.argv[i+1]:
            ports = sys.argv[i+1].split(',')
            ports = list(map(lambda x: int(x), ports))
        else:
            ports = []
            ports.append(int(sys.argv[i+1]))

values = []
try:
    #ipaddress.ip_address(target)
    list_of_targets = ipaddress.IPv4Network(target)

    for x in list_of_targets:
        values.append(str(x))
except ValueError:
    values.append(target)

for x in values:
    print(f'Host: {x}')
    print('{:<10s}{:<10s}{:>10s}'.format('PORT', 'STATUS', 'FINGERPRINT'))
    for port in ports:

        #https://scapy.readthedocs.io/en/latest/usage.html#starting-scapy
        res = None
        try:
            res = sr1(IP(dst=x)/TCP(sport=RandShort(),dport=port, flags="S"), timeout=2)
        except:
            res = None

        #no responce
        # if res is None:
        #     res = sendDummy(port, x, 3)
        #     if res is None:
        #         print('{:<10d}{:<10s}{:>10s}'.format(port, 'filtered', f"Port: {port}, 3 requests transmitted, 0 bytes received"))
        #         continue
        #     else:
        #          print('{:<10d}{:<10s}{:>10s}'.format(port, 'closed', str(res)))
        #          continue
        if res is None:
            print('{:<10d}{:<10s}{:>10s}'.format(port, 'filtered', 'N/A'))
            continue

        flags = res['TCP'].flags

        if flags == 'SA':
            res = sendDummy(port, x, 3)
            if res is None or bytes.hex(res) == '':
                print('{:<10d}{:<10s}{:>10s}'.format(port, 'open', f"Port: {port}, 3 requests transmitted, 0 bytes received"))
            else:
                print('{:<10d}{:<10s}{:>10s}'.format(port, 'open', bytes.hex(res)))
            send(IP(dst=x)/TCP(sport=RandShort(),dport=port, flags="R"))
        elif flags == 'RA':
            # res = sendDummy(port, x, 3)
            # if res in None:
            #     print('{:<10d}{:<10s}{:>10s}'.format(port, 'closed', f"Port: {port}, 3 requests transmitted, 0 bytes received"))
            # else:
            #     print('{:<10d}{:<10s}{:>10s}'.format(port, 'closed', bytes.hex(res)))
            print('{:<10d}{:<10s}{:>10s}'.format(port, 'closed', 'N/A'))
            send(IP(dst=x)/TCP(sport=RandShort(),dport=port, flags="R"))





#print("SUMMARY IS: \n", res.summary( lambda s,r: r.sprintf("%TCP.sport% \t %TCP.flags%")))
