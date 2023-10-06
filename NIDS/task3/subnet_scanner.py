import socket
import ipaddress
import struct
import sys
import time
import threading

# used for parsing an IP header
class IP:
    def __init__(self, buf=None):
        header = struct.unpack('<BBHHHBBH4s4s', buf)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # human readable IP addresses
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s No protocol for %s' % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)

# used for parsing an ICMP header
class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

# sniffer: used to capture all ICMP packets come to this host.
def sniffer():
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sniffer.bind(("0.0.0.0", 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    discovered_hosts = set([])
    try:
        while True:
            raw_buffer = sniffer.recvfrom(1500)[0]

            #TODO: your code here
            ip = IP(buf=raw_buffer[:20])
            ipheaderlen = ip.ihl
            ipheaderlen *= 4
            protocol = ip.protocol            
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)

            if protocol == 'ICMP':
                offset = ipheaderlen
                icmp = ICMP(buff = raw_buffer[offset:][:8])
                icmp_type = icmp.type
                icmp_code = icmp.code
                if icmp_type == 3 and icmp_code == 3:
                    t1 = struct.unpack('!12s', raw_buffer[-12:])
                    print('%s -> %s : ICMP: Type[%d], Code[%d]'%(src_ip, dst_ip,icmp_type,icmp_code))
                    discovered_hosts.add('%s -> %s : ICMP: Type[%d], Code[%d]'%(src_ip, dst_ip,icmp_type,icmp_code))

            
    except KeyboardInterrupt:
        print(f'\n\nSummary: Discovered Hosts')
        for host in sorted(discovered_hosts):
            print(f'{host}')
        sys.exit()


# udp_sender: used to send UDP packets to all the hosts of a given subnet.
def udp_sender(subnet):
    STRING="KNOCK!KNOCK!"
    PORT=19999
    #TODO: your code here
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for ip in ipaddress.ip_network(subnet).hosts():
        
        try:
            udp_socket.sendto(STRING.encode('utf-8'), ('%s'%ip, PORT))
            print('SENDING to [%s]' %ip)

        except Exception as e:
            print(e)




if __name__ == '__main__':
    subnet = sys.argv[1]
    # subnet = '10.0.100.0/24'
    time.sleep(3)

    # execute a udp sender thread
    t = threading.Thread(target=udp_sender, args=(subnet,))
    t.start()

    # start sniffing
    print('start sniffing')
    sniffer()
