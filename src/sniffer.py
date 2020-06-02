import socket
import struct
import textwrap
import time
import requests
import re

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
DTAB_1 = '\t '
DTAB_3 = '\t\t\t '

def main() :
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True :
        rawData, addr = conn.recvfrom(65536)
        destMac, srcMac, ethProto, data = ethernetFrame(rawData)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(destMac, srcMac, ethProto))
        blacklistedIPs = 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt'
        ip_list = requests.get(blacklistedIPs)
        for ip in ip_list.iter_lines():
            ip_formatted = ip.split("\t",1)[0]
            if ip_formatted == destMac or ip_formatted == srcMac or str(destMac) == "172.217.17.142" or str(srcMac) == "172.217.17.142":
                time.sleep(2)
                print()


        if ethProto == 8 :
            (version, headerLength, ttl, proto, src, target, data) = ipv4Packet(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, headerLength, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # ICMP
            if proto == 1 :
                (type, code, checksum, data) = icmpPacket(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(type, code, checksum))
                print(TAB_2 + 'Data:')
                print(formatMultiLine(DTAB_3, data))

            # TCP
            elif proto == 6 :
                (srcPort, destPort, sequence, ack, flagUrg, flagAck, flagPsh, flagRst, flagSyn, flagFin, data) = tcpPacket(data)
                print(TAB_1 + 'TCP Packet:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(srcPort, destPort))
                print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, ack))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flagUrg, flagAck, flagPsh, flagRst, flagSyn, flagFin))
                print(TAB_2 + 'Data:')
                print(formatMultiLine(DTAB_3, data))

            # UDP
            elif proto == 17 :
                (srcPort, destPort, length, data) = udpPacket(data)
                print(TAB_1 + 'UDP Packet:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(srcPort, destPort, length))

            # Other
            else :
                print(TAB_1 + 'Data:')
                print(formatMultiLine(DTAB_1, data))

        else :
            print('Data:')
            print(formatMultiLine(DTAB_1, data))

# properely formats MAC address
def getAddr(addr) :
    str = map('{:02x}'.format, addr)
    return ':'.join(str).upper()

# properely formats IPv4 address
def ipv4(addr) :
    return '.'.join(map(str, addr))

# unpacks ICMP packet
def icmpPacket(data) :
    type, code, checksum = struct.unpack('! B B H', data[:4])
    return type, code, checksum, data[4:]

# unpacks TCP
def tcpPacket(data) :
    srcPort, destPort, sequence, ack, bunch = struct.unpack('! H H L L H', data[:14])
    offset = (bunch >> 12) * 4
    flagUrg = (bunch & 32) >> 5
    flagAck = (bunch & 16) >> 4
    flagPsh = (bunch & 8) >> 3
    flagRst = (bunch & 4) >> 2
    flagSyn = (bunch & 2) >> 1
    flagFin = bunch & 1
    return srcPort, destPort, sequence, ack, flagUrg, flagAck, flagPsh, flagRst, flagSyn, flagFin, data[offset:]

# unpacks UDP
def udpPacket(data) :
    srcPort, destPort, size = struct.unpack('! H H 2x H', data[:8])
    return srcPort, destPort, size, data[8:]

#unpacks IPv4 packet
def ipv4Packet(data) :
    versionHeaderLength = data[0]
    version = versionHeaderLength >> 4
    headerLength = (versionHeaderLength & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, headerLength, ttl, proto, ipv4(src), ipv4(target), data[headerLength:]

# unpacks ethernet frame
def ethernetFrame(data) :
    destMac, srcMac, proto = struct.unpack('! 6s 6s H', data[:14])
    return getAddr(destMac), getAddr(srcMac), socket.htons(proto), data[14:]

# formats multi line data
def formatMultiLine(prefix, str, size=80) :
    size -= len(prefix)
    if isinstance(str, bytes) :
        str = ''.join(r'\x{:02x}'.format(byte) for byte in str)
        if size % 2 :
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(str, size)])

main()
