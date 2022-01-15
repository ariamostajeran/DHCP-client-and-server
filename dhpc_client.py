import socket, struct
from uuid import getnode as get_mac
import random
import threading

MAX_BYTES = 65535
Src = "0.0.0.0"
Dest = "255.255.255.255"
clientPort = 67
serverPort = 68


def generate(random_chars=8, alphabet="0123456789abcdef"):
    r = random.SystemRandom()
    return ''.join([r.choice(alphabet) for i in range(random_chars)])


class DHCP_client(object):

    def client(self):
        print("DHCP client is running.")
        print("*******************************************************************")
        dest = (Dest, clientPort)
        XID = generate().encode()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((Src, serverPort))

        print("\nsend DHCP_DISCOVER")
        data = self.discover_msg(XID)

        sock.sendto(data, dest)
        print("\nwait for DHCP_OFFER")
        initial_interval = 1

        while True:
            sock.settimeout(initial_interval)
            try:
                data, address = sock.recvfrom(MAX_BYTES)
                break
            except socket.timeout:
                print("initial interval :", initial_interval)
                initial_interval = initial_interval * (random.random() + 1) * 2
                if initial_interval > 12:
                    initial_interval = 12


        print("\nreceive DHCP_OFFER")
        print(data)
        print("*******************************************************************")

        print("\nsend DHCP_REQUEST")
        data = self.dhcprequest(XID)
        sock.sendto(data, dest)

        print("\nwait for DHPC_ACK")

        initial_interval = 1

        while True:
            sock.settimeout(initial_interval)
            try:
                data, address = sock.recvfrom(MAX_BYTES)
                break
            except socket.timeout:
                print("initial interval :", initial_interval)
                initial_interval = initial_interval * (random.random() + 1) * 2
                if initial_interval > 12:
                    initial_interval = 12
        print("\nreceive DHCP_ACK")
        print(data)

    def discover_msg(self, xid):

        macb = self.getMac()
        # macb = bin(hex(str(macb)))
        OP = b'01'  # Message type: Boot Request (1)
        HTYPE = b'01'  # Hardware type: Ethernet
        HLEN = b'06'  # Hardware address length: 6
        HOPS = b'00'  # Hops: 0

        XID = b'3903F326'  # Transaction ID
        XID = xid
        print(XID)
        # ss = bytes(random.randint(0, 9))

        SECS = b'0000'  # Seconds elapsed: 0
        FLAGS = b'0000'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
        CIADDR = b'00000000'  # Client IP address: 0.0.0.0
        YIADDR = b'00000000'  # Your (client) IP address: 0.0.0.0
        SIADDR = b'00000000'  # Next server IP address: 0.0.0.0
        GIADDR = b'00000000'  # Relay agent IP address: 0.0.0.0
        CHADDR1 = macb
        CHADDR2 = b'0000'
        CHADDR3 = b'00000000'
        CHADDR4 = b'00000000'
        SNAME = b'00' * 64
        FILE = b'00' * 128

        DHCPOptions1 = b'350101'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        DHCPOptions2 = b'320400000000'  # Option: (t=50,l=4) Requested IP Address
        End = b'ff'  # End Option

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1 \
                  + CHADDR2 + CHADDR3 + CHADDR4 + SNAME + FILE + DHCPOptions1 + DHCPOptions2 + End

        return package

    def dhcprequest(self, xid):
        macb = self.getMac()
        # macb = bin(hex(str(macb)))
        OP = b'01'  # Message type: Boot Request (1)
        HTYPE = b'01'  # Hardware type: Ethernet
        HLEN = b'06'  # Hardware address length: 6
        HOPS = b'00'  # Hops: 0
        XID = b'3903F326'  # Transaction ID
        XID = xid
        SECS = b'0000'  # Seconds elapsed: 0
        FLAGS = b'0000'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
        CIADDR = b'00000000'  # Client IP address: 0.0.0.0
        YIADDR = b'00000000'  # Your (client) IP address: 0.0.0.0
        SIADDR = b'00000000'  # Next server IP address: 0.0.0.0
        GIADDR = b'00000000'  # Relay agent IP address: 0.0.0.0
        CHADDR1 = macb
        CHADDR2 = b'0000'
        CHADDR3 = b'00000000'
        CHADDR4 = b'00000000'
        SNAME = b'00' * 64
        FILE = b'00' * 128

        DHCPOptions1 = b'350103'  # Option: (t=53,l=1) DHCP Message Type = DHCP Request
        DHCPOptions2 = b'3204c0a80164'  # Option: (t=50,l=4) Requested IP Address
        DHCPOptions3 = b'3604c0a80101'  # Option: (t=54,l=4) DHCP Server Identifier
        End = b'ff'  # End option

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1 \
                  + CHADDR2 + CHADDR3 + CHADDR4 + SNAME + FILE + DHCPOptions1 + DHCPOptions2 + DHCPOptions3 + End

        return package

    def getMac(self):
        mac = str(hex(get_mac()))
        print(mac)
        mac = mac[2:]
        while len(mac) < 12:
            mac = '0' + mac
        macb = b''
        for i in range(0, 12, 2):
            m = int(mac[i:i + 2], 16)
            macb += struct.pack('!B', m)
        return macb


if __name__ == '__main__':
    dhcp_client = DHCP_client()
    dhcp_client.client()