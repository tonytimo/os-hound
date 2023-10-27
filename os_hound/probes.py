from scapy.sendrecv import *
from scapy.layers.inet import IP, TCP, ICMP, UDP
import random
from time import sleep


class Probes:
    """Class for generating, sending probes and collecting the response for OS fingerprinting."""
    def __init__(self, target_ip, open_ports: list):
        self.target_ip = target_ip
        self.open_ports = open_ports

    def tcp_syn_probe(self):
        """Generate and send 6 SYN packets with different TCP options and collect the responses."""
        res_list = []
        probe_type = "SYN"
        open_port = random.choice(self.open_ports)
        # Generate random sequence and acknowledgment numbers
        seq_num = random.randint(0, (2 ** 32) - 1)
        ack_num = random.randint(0, (2 ** 32) - 1)

        # Creating 6 SYN packets with different TCP options
        pkt1 = IP(dst=self.target_ip) / TCP(
            options=[('WScale', 10), ('NOP', None), ('MSS', 1460), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')],
            window=1, flags="S", dport=open_port, seq=seq_num, ack=ack_num,)
        pkt2 = IP(dst=self.target_ip) / TCP(
            options=[('MSS', 1400), ('WScale', 0), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('EOL', None)],
            window=63, flags="S", dport=open_port, seq=seq_num, ack=ack_num,)
        pkt3 = IP(dst=self.target_ip) / TCP(
            options=[('Timestamp', (0xFFFFFFFF, 0)), ('NOP', None), ('NOP', None), ('WScale', 5), ('NOP', None), ('MSS', 640)],
            window=4, flags="S", dport=open_port, seq=seq_num, ack=ack_num,)
        pkt4 = IP(dst=self.target_ip) / TCP(
            options=[('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)],
            window=4, flags="S", dport=open_port, seq=seq_num, ack=ack_num,)
        pkt5 = IP(dst=self.target_ip) / TCP(
            options=[('MSS', 536), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)],
            window=16, flags="S", dport=open_port, seq=seq_num, ack=ack_num,)
        pkt6 = IP(dst=self.target_ip) / TCP(
            options=[('MSS', 265), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0))],
            window=512, flags="S", dport=open_port, seq=seq_num, ack=ack_num,)

        pkt_list = [pkt1, pkt2, pkt3, pkt4, pkt5, pkt6]

        # Send 6 SYN packets and collect responses
        for pkt in pkt_list:
            response = sr1(pkt, verbose=0, timeout=2)
            if response:
                res_list.append(response)
            sleep(0.1)

        return res_list, probe_type

    def icmp_echo_probe(self):
        """Generate and send 2 ICMP Echo Request packets with different ICMP options and collect the responses."""
        probe_type = "IE"
        # First ICMP Echo Request
        icmp_1 = ICMP(type=8, code=9, id=random.randint(0, 65535), seq=295)  # type=8 means Echo Request
        payload_1 = b'\x00' * 120
        ip_1 = IP(dst=self.target_ip, flags="DF", tos=0, id=random.randint(0, 65535))
        pkt1 = ip_1 / icmp_1 / payload_1

        # Send the first ICMP request
        response1 = sr1(pkt1, timeout=1, verbose=0)

        # Extracting ICMP request ID and sequence number
        icmp_request_id = icmp_1.id
        icmp_seq = icmp_1.seq

        # Second ICMP Echo Request
        icmp_2 = ICMP(type=8, code=0, id=icmp_request_id + 1, seq=icmp_seq + 1)
        payload_2 = b'\x00' * 150
        ip_2 = IP(dst=self.target_ip, flags="DF", tos=4, id=random.randint(0, 65535))
        pkt2 = ip_2 / icmp_2 / payload_2

        # Send the second ICMP request
        response2 = sr1(pkt2, timeout=1, verbose=0)

        return [response1, response2], probe_type

    def tcp_ecn_probe(self):
        """Generate and send a TCP packet with ECN flag set and collect the response."""
        probe_type = "ECN"
        open_port = random.choice(self.open_ports)

        # Defining the TCP options
        tcp_options = [('WScale', 10), ('NOP', None), ('MSS', 1460), ('SAckOK', ''), ('NOP', None), ('NOP', None)]

        tcp_pkt = TCP(sport=random.randint(1024, 65535),
                      dport=open_port,
                      flags='SEC',
                      seq=random.randint(0, 4294967295),
                      ack=0,
                      urgptr=0xF7F5,
                      reserved=1,  # Set the reserved bit before CWR
                      window=3,
                      options=tcp_options)

        # Constructing the IP packet
        ip_pkt = IP(dst=self.target_ip)

        # Combine IP and TCP to create the full packet
        pkt = ip_pkt / tcp_pkt

        # Send the packet
        response = sr1(pkt, timeout=1, verbose=0)

        return response, probe_type

    def tcp_probe(self, probe_type: str):
        """Generate and send a TCP packet with the specified probe type ['T2', 'T3', 'T4', 'T5', 'T6', 'T7'] and collect the response."""
        if probe_type not in ['T2', 'T3', 'T4', 'T5', 'T6', 'T7']:
            print("Invalid probe type.")
            return None

        open_port = random.choice(self.open_ports)

        # Common TCP options for T2-T7 except T7's window scale
        tcp_options = [('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')]

        # Constructing the IP packet
        ip_pkt = IP(dst=self.target_ip)

        # Constructing the TCP packet based on the probe type
        if probe_type == 'T2':
            tcp_pkt = TCP(sport=random.randint(1024, 65535), dport=open_port, window=128, flags='', options=tcp_options)
            ip_pkt.flags = 'DF'  # Setting IP DF bit

        elif probe_type == 'T3':
            tcp_pkt = TCP(sport=random.randint(1024, 65535), dport=open_port, window=256, flags='SFUP', options=tcp_options)

        elif probe_type == 'T4':
            tcp_pkt = TCP(sport=random.randint(1024, 65535), dport=open_port, window=1024, flags='A', options=tcp_options)
            ip_pkt.flags = 'DF'  # Setting IP DF bit

        elif probe_type == 'T5':
            tcp_pkt = TCP(sport=random.randint(1024, 65535), dport=open_port, window=31337, flags='S', options=tcp_options)

        elif probe_type == 'T6':
            tcp_pkt = TCP(sport=random.randint(1024, 65535), dport=open_port, window=32768, flags='A', options=tcp_options)
            ip_pkt.flags = 'DF'  # Setting IP DF bit

        elif probe_type == 'T7':
            tcp_options[0] = ('WScale', 15)  # Changing the window scale for T7
            tcp_pkt = TCP(sport=random.randint(1024, 65535), dport=open_port, window=65535, flags='FPU', options=tcp_options)

        else:
            print("Invalid probe type.")
            return None

        # Combine IP and TCP to create the full packet
        pkt = ip_pkt / tcp_pkt

        # Send the packet
        response = sr1(pkt, timeout=1, verbose=0)

        return response, probe_type, pkt[TCP].seq

    def udp_probe(self):
        """Generate and send a UDP packet with 300 bytes of data and collect the response."""
        probe_type = "U1"
        # Constructing the IP packet
        ip_pkt = IP(dst=self.target_ip, id=0x1042)

        # Pick a random port that is not open
        target_port = (random.randint(0, 65535))
        while target_port in self.open_ports:
            target_port = random.randint(0, 65535)

        # Constructing the UDP packet with 'C' repeated 300 times as data
        udp_pkt = UDP(sport=random.randint(1024, 65535), dport=target_port) / ("C" * 300)

        # Combine IP and UDP to create the full packet
        pkt = ip_pkt / udp_pkt

        # Send the packet and capture the response
        response = sr1(pkt, timeout=1, verbose=0)

        # Checking the response for ICMP port unreachable
        if response and response.haslayer(ICMP) and response[ICMP].type == 3 and response[ICMP].code == 3:
            return response, probe_type
        else:
            return None
