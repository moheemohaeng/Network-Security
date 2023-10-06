# Skeleton code for NIDS
import socket
import sys
import ipaddress
from scapy.all import *
from datetime import datetime

protocol_dict = {1:'icmp', 6:'tcp', 17: 'udp'}
option_dict = {'tcp': ['seq', 'ack', 'window', 'flags'],
               'ip': ['id', 'tos', 'ttl'],
               'icmp': ['itype', 'icode']}

# You can utilize this class to parse the Snort rule and build a rule set.
class Rule:
    def __init__(self, action, protocol, src_ip, src_port, direction, dst_ip, dst_port, options, msg, original_rule):
        self.action = action
        self.protocol = protocol
        self.src_ip = src_ip
        self.src_port = src_port
        self.direction = direction
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.options = options
        self.msg = msg

        self.original_rule = original_rule

    def __str__(self):
        return (f"action: {self.action}\n"
                 f"protocol: {self.protocol}\n"
                 f"src_ip: {self.src_ip}\n"
                 f"src_port: {self.src_port}\n"
                 f"direction: {self.direction}\n"
                 f"dst_ip: {self.dst_ip}\n"
                 f"dst_port: {self.dst_port}\n"
                 f"msg: {self.msg}\n"
                 f"options: {self.options}")

def parse_rule(line):
    #TODO: your code here

    if (len(line) >= 7):
        word = line.split(' ')

        action = word[0]
        protocol = word[1]
        src_ip=word[2]
        src_port=word[3]
        direction=word[4]
        dst_ip=word[5]
        dst_port=word[6]
        # Options
        strs = line.split('(')
        if (len(strs) >= 2):
            # remove trailing ')' if present
            if (strs[-1][-1] == ')'):
                strs[-1] = strs[-1][:-1]

            # options may be present
            options = {'tos':None, 'len':None, 'offset':None, 'seq':None, 'ack':None, 'itype':None,\
                        'icode':None, 'flags':None, 'http_request':None, 'content':None}
            opts = strs[1].split(';')
            for opt in opts:
                kv = opt.split(':',1)
                if (len(kv) >= 2):
                    option = kv[0].strip()
                    value = kv[1].strip()
                    # print(option, value)

                    if (option == "msg"):
                        msg = value
                    elif (option == "tos"):
                        options['tos'] = int(value)
                    elif (option == "len"):
                        options['len'] = int(value)
                    elif (option == "offset"):
                        options['offset'] = int(value)
                    elif (option == "seq"):
                        options['seq'] = int(value)
                    elif (option == "ack"):
                        options['ack'] = int(value)
                    elif (option == "itype"):
                        options['itype'] = int(value)
                    elif (option == "icode"):
                        options['icode'] = int(value)
                    elif (option == "flags"):
                        options['flags'] = value
                    elif (option == "http_request"):
                        options['http_request'] = value
                        # remove starting and ending ["]
                        if (options['http_request'].endswith('"')):
                            options['http_request'] = options['http_request'][:-1]
                        if (http_request.startswith('"')):
                            options['http_request'] = options['http_request'][1:]
                    elif (option == "content"):
                        options['content'] = value
                        # remove starting and ending ["]
                        if (options['content'].endswith('"')):
                            options['content'] = options['content'][:-1]
                        if (options['content'].startswith('"')):
                            options['content'] = options['content'][1:]
                    else:
                        raise ValueError("Invalid rule : incorrect option : '" + option + "'.")
        # Done
    else:
        raise ValueError("Invalid rule : a rule must include mandatory elements : action protocol src_ips src_ports -> dst_ips dst_ports")



    rule = Rule(action=action, protocol=protocol, src_ip=src_ip,
                src_port=src_port, direction=direction, dst_ip=dst_ip,
                dst_port=dst_port, options = options, msg = msg,
                original_rule = line)
    return rule




    pass

def parse_packet(packet, rule_set):
    #TODO: your code here


    # print(packet)
    # print('detection_data_time',' ','msg',' ','protocol',' ',\
    #     packet[IP].src,' ',packet[TCP].sport,' ','direction',\
    #     packet[IP].dst,' ',packet[TCP].dport)

    for rule in rule_set:

        mached = True
        #check protocol
        f = False
        answer_protocol = ''
        if rule.protocol == 'icmp' and ICMP in packet:
            f = True
            answer_protocol = 'icmp'
        elif rule.protocol == 'tcp' and TCP in packet:
            f= True
            answer_protocol = 'tcp'
        elif rule.protocol == 'udp' and UDP in packet:
            f = True
            answer_protocol = 'udp'
        if not(f): 
            mached = False
            continue
        # print('check protocol----------', answer_protocol)

        #check Ip_src and destination
        f= False
        answer_src_ip = ''
        answer_dst_ip = ''
        if (IP not in packet):
            f = False
        else:
            srcIP = packet[IP].src
            dstIP = packet[IP].dst
            ipSrc = ipaddress.ip_address(srcIP)
            ipDst = ipaddress.ip_address(dstIP)
            if (((str(ipSrc) in rule.src_ip) or rule.src_ip=='any') and ((str(ipDst) in rule.dst_ip)) or rule.dst_ip=='any'):
                f = True
                answer_src_ip = srcIP
                answer_dst_ip = dstIP
            else:
                f = False
        if not(f): 
            ached = False
            continue
        # print('check ip----------', answer_src_ip, answer_dst_ip)


        #check source Port
        f= False
        answer_src_port = ''
        answer_dst_port = ''
        if (UDP in packet):
            srcPort = packet[UDP].sport
            dstPort = packet[UDP].dport
            if (((str(srcPort) in rule.src_port) or rule.src_port=='any') and ((str(dstPort) in rule.dst_port) or rule.dst_port=='any')):
                f = True
                answer_src_port = srcPort
                answer_dst_port = dstPort
        elif (TCP in packet):
            srcPort = packet[TCP].sport
            dstPort = packet[TCP].dport
            if (((str(srcPort) in rule.src_port) or rule.src_port=='any') and ((str(dstPort) in rule.dst_port) or rule.dst_port=='any')):
                f = True
                answer_src_port = srcPort
                answer_dst_port = dstPort
        elif (ICMP in packet):
            srcPort = packet[ICMP].sport
            dstPort = packet[ICMP].dport
            if (((str(srcPort) in rule.src_port) or rule.src_port=='any') and ((str(dstPort) in rule.dst_port) or rule.dst_port=='any')):
                f = True             
                answer_src_port = srcPort
                answer_dst_port = dstPort
        if not(f): 
            mached = False
            continue
        # print('check port----------', answer_src_port, answer_dst_port)


        #check options
        f = True
        if (rule.options['tos'] is not None):
            if (IP in packet):
                if(rule.options['tos'] != int(packet[IP].tos)):
                    f = False
            else : f = False
        if (rule.options['len'] is not None):
            if (IP in packet):
                if(rule.options['len'] != int(packet[IP].ihl)):
                    f = False
            else : f= False
        if (rule.options['offset'] is not None):
            if (IP in packet):
                if(rule.options['offset'] != int(packet[IP].frag)):
                    f = False
            else : f= False
        if (rule.options['seq'] is not None):
            if (TCP not in packet):
                f = False
            else:
                if(rule.options['seq'] != int(packet[TCP].seq)):
                    f = False
        if (rule.options['ack'] is not None):
            if (TCP not in packet):
                f = False
            else:
                if(rule.options['ack'] != int(packet[TCP].ack)):
                    f = False
        if (rule.options['flags'] is not None):
            if (TCP not in packet):
                f = False
            else:
                for c in rule.options['flags']:
                    pktFlags = packet[TCP].underlayer.sprintf('%TCP.flags%')
                    if (c not in pktFlags):
                        return False
        # if (rule.options["http_request"] is not None):
        #     if (not isHTTP(pkt)):
        #         f = False
        #     elif (TCP in packet and packet[TCP].payload):
        #         data = str(packet[TCP].payload)
        #         words = data.split(' ')
        #         if ((len(words) < 1) or (words[0].rstrip() !=  rule.options['http_request'])):
        #             f = False
        #     else:
        #         f = False

        if (rule.options['content'] is not None):
            payload = None
            if (TCP in packet):
                payload = packet[TCP].payload
            elif (UDP in packet):
                payload = packet[UDP].payload
            if (payload):
                if (rule.options['content'] not in str(payload)):
                    f = False
            else:
                f = False

        if not(f): 
            matched = False
            continue
        # print('check options----------')

        # 알림!!!
        if (mached):    
            print(datetime.now().strftime('%c'),' ',rule.msg,' ',answer_protocol,' ',\
                answer_src_ip,' ',answer_src_port,' ','->',\
                answer_dst_ip,' ',answer_dst_port)



    # print('=================================')





    pass






































if __name__ == '__main__':
    rule_file = sys.argv[1] 

    f = open(rule_file, 'r')

    rule_set = []
    lines = f.readlines()
    for line in lines:
        rule = parse_rule(line)
        rule_set.append(rule)

    # print(rule_set) 

    print("Start sniffing")
    sniff(iface='eth0', prn=lambda p: parse_packet(p, rule_set), filter='ip')

    f.close()

