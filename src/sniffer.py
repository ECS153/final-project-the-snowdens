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

# unpacks ethernet frame
def ethernetFrame(data) :
    destMac, srcMac, proto = struct.unpack('! 6s 6s H', data[:14])
    return getAddr(destMac), getAddr(srcMac), socket.htons(proto), data[14:]

main()
