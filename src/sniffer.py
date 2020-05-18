import socket
import struct
import textwrap

def main() :
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True :
        rawData, addr = conn.recvfrom(65536)
        destMac, srcMac, proto, data = ethernetFrame(rawData)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(destMac, srcMac, proto))

# properely formats MAC address
def getAddr(addr) :
    str = map('{:02x}'.format, addr)
    return ':'.join(str).upper()

# properely formats IPv4 address
def ipv4(addr) :
    return '.'.join(mao(str, addr))

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
