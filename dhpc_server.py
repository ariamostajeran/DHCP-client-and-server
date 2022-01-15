import socket
import json
import ipaddress
import time
import threading
MAX_BYTES = 1024

Dest = "255.255.255.255"

serverPort = 67
clientPort = 68
# packet = {}


def getBaseTen(binaryVal):
    count = 0
    binaryVal = binaryVal[::-1]
    for i in range(0, len(binaryVal)):
        count += 2 ** i * int(binaryVal[i])
    return count


def get_config():
    with open('config.json') as json_file:
        data = json.load(json_file)
    return data


class DHCP_server(object):

    def __init__(self):
        self.config_data = get_config()
        self.assigned_ips = {}
        self.assigned_time_out = {}
        th = threading.Thread(target=self.show_clients)
        th.start()

    def show_clients(self):
        while True:
            inp = input()
            # print("input gerefta")
            if inp == "show_clients":
                for mac in self.assigned_ips:
                    print("MAC ", mac, "IP ", ipaddress.IPv4Address(self.assigned_ips[mac]), "time out ", self.assigned_time_out[mac] - time.time())

    def server(self):
        print("DHCP server is starting...\n")
        # print(self.config_data)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(('', serverPort))
        dest = (Dest, clientPort)

        while 1:
            try:
                print("Wait DHCP discover msg.")
                data, address = s.recvfrom(MAX_BYTES)
                print("Received DHCP discover msg.")
                print(data)
                packet = self.decode_data(data)
                time.sleep(3)
                print("Send DHCP offer.")
                print(packet)
                # mac = packet['MAC']
                # print("MAC : ", mac)

                def get_ack_thread():
                    data = self.handle_msg(packet)
                    s.sendto(data, dest)
                th = threading.Thread(get_ack_thread())
                th.start()
                # data = self.offer_get(mac)

                # while 1:
                #     try:
                #         print("Waiting for DHCP request.")
                #         data, address = s.recvfrom(MAX_BYTES)
                #         print("Received DHCP request.")
                #         print(data)
                #         packet = self.decode_data(data)
                #         print("Send DHCP ack.\n")
                #         data = self.pack_get()
                #         data = self.handle_msg(packet)
                #         print(data)
                #         s.sendto(data, dest)
                #         break
                #     except:
                #         raise
            except:
                raise

    def handle_msg(self, packet):
        option = packet['OPTIONS']
        print(option)
        if int(option[:2]) == 35:# option = 53
            option_len = getBaseTen(str(int(option[2:4])))
            option_len *= 2
            print("option_len : ", option_len)

            option_type = getBaseTen(str(int(option[4:4 + option_len])))
            print(option_type)
            if option_type == 1:
                print("Handle discovery : ", option[:2], int(option[:2]))
                mac = packet['XID']
                print("MAC : ", mac)
                ip = str(self.get_ip(mac=mac))

                return self.offer_get(mac)
            if option_type == 3:
                mac = packet['XID']
                return self.pack_get(mac)

    def decode_data(self, data):
        packet = {}
        packet['OP'] = data[:2]
        packet['HTYPE'] = data[2:4]
        packet['HLEN'] = data[4:6]
        packet['HOPS'] = data[6:8]
        packet['XID'] = data[8:16]
        packet['SECS'] = data[16:20]
        packet['FLAGS'] = data[20:24]
        packet['CIADDR'] = data[24:32]
        packet['YIADDR'] = data[32:40]
        packet['SIADDR'] = data[40:48]
        packet['GIADDR'] = data[48:56]
        packet['MAC'] = data[56:62]
        packet['CHADDR'] = data[62:82]
        packet['SNAME'] = data[82:210]
        packet['FILE'] = data[210:466]
        packet['OPTIONS'] = data[466:]
        return packet

    def release_ip(self, mac):
        time.sleep(self.config_data['lease_time'])
        self.assigned_ips.pop(mac)
        self.assigned_time_out.pop(mac)
        return

    def get_ip(self, mac):
        if mac in self.config_data['black_list']:
            return -1
        if mac in self.config_data['reservation_list']:
            return self.config_data['reservation_list'][mac]

        elif self.config_data['pool_mode'] == "range":
            start = ipaddress.IPv4Address(self.config_data['range']['from'])
            end = ipaddress.IPv4Address(self.config_data['range']['to'])
            # print("CHECK JAAM : ", end+10)
            for ip in range(int(start), int(end)):
                if ip in self.assigned_ips.values():
                    continue
                else:
                    self.assigned_ips[mac] = ip
                    self.assigned_time_out[mac] = time.time() + self.config_data['lease_time']
                    th = threading.Thread(target=self.release_ip, args=(mac, ))
                    th.start()
                    return ipaddress.IPv4Address(ip)

        elif self.config_data['pool_mode'] == "subnet":
            start = ipaddress.IPv4Address(self.config_data['subnet']['ip_block'])
            ip_count = int(ipaddress.IPv4Address('255.255.255.255') - int(ipaddress.IPv4Address(self.config_data['subnet']['subnet_mask'])))
            end = ipaddress.IPv4Address(self.config_data['subnet']['ip_block']) + ip_count
            for ip in range(int(start), int(end)):
                if ip in self.assigned_ips.values():
                    continue
                else:
                    self.assigned_ips[mac] = ip

                    # def release_ip(mac):
                    #     time.sleep(self.config_data['lease_time'])
                    #     self.assigned_ips.pop(mac)
                    #     return

                    th = threading.Thread(target=self.release_ip, args=(mac,))
                    th.start()
                    return ipaddress.IPv4Address(ip)

        return ipaddress.IPv4Address('222.222.222.222')

    def offer_get(self, mac):

        OP = bytes([0x02])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])
        XID = bytes([0x39, 0x03, 0xF3, 0x26])
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])

        ip = str(ipaddress.IPv4Address(self.assigned_ips[mac]))
        print(self.assigned_ips)
        print("IP, ", ip)
        YIADDR = bytes(map(int, ip.split('.')))  # 192.168.1.100
        # SIADDR = bytes([0xC0, 0xA8, 0x01, 0x01])  # 192.168.1.1
        SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR1 = bytes([0x00, 0x05, 0x3C, 0x04])
        CHADDR2 = bytes([0x8D, 0x59, 0x00, 0x00])
        CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
        SNAME = bytes(b'\x00' * 64)
        FILE = bytes(b'\x00' * 128)
        DHCPOptions1 = bytes([53, 1, 2])  # DHCP Offer
        # DHCPOptions2 = bytes([1, 4, 0xFF, 0xFF, 0xFF, 0x00])  # 255.255.255.0 subnet mask
        # DHCPOptions3 = bytes([3, 4, 0xC0, 0xA8, 0x01, 0x01])  # 192.168.1.1 router
        DHCPOptions4 = bytes([51, 4, 0x00, 0x01, 0x51, 0x80])  # 86400s(1 day) IP address lease time
        DHCPOptions5 = bytes([54, 4, 0xC0, 0xA8, 0x01, 0x01])  # DHCP server

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1 \
                  + CHADDR2 + CHADDR3 + CHADDR4 + SNAME + FILE + DHCPOptions1 \
                  + DHCPOptions4 + DHCPOptions5

        return package

    def pack_get(self, mac):
        OP = bytes([0x02])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])
        XID = bytes([0x39, 0x03, 0xF3, 0x26])
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        ip = str(ipaddress.IPv4Address(self.assigned_ips[mac]))
        print(self.assigned_ips)
        print("IP, ", ip)
        # SIADDR = bytes([0xC0, 0xA8, 0x01, 0x01])  # 192.168.1.1
        YIADDR = bytes(map(int, ip.split('.')))
        SIADDR = bytes([0x00, 0x00, 0x00, 0x00])

        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR1 = bytes([0x00, 0x05, 0x3C, 0x04])
        CHADDR2 = bytes([0x8D, 0x59, 0x00, 0x00])
        CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR5 = bytes(192)
        DHCPOptions1 = bytes([53, 1, 5])  # DHCP ACK(value = 5)
        DHCPOptions2 = bytes([1, 4, 0xFF, 0xFF, 0xFF, 0x00])  # 255.255.255.0 subnet mask
        DHCPOptions3 = bytes([3, 4, 0xC0, 0xA8, 0x01, 0x01])  # 192.168.1.1 router
        DHCPOptions4 = bytes([51, 4, 0x00, 0x01, 0x51, 0x80])  # 86400s(1 day) IP address lease time
        DHCPOptions5 = bytes([54, 4, 0xC0, 0xA8, 0x01, 0x01])  # DHCP server

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR +\
                  CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + DHCPOptions1 +\
                  DHCPOptions2 + DHCPOptions3 + DHCPOptions4 + DHCPOptions5

        return package


if __name__ == '__main__':
    dhcp_server = DHCP_server()
    dhcp_server.server()