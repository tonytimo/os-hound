from scapy.sendrecv import *
from scapy.layers.inet import IP, TCP
from helper import HelperFunctions


class Probes:
    def __init__(self, target_ip, open_ports: list):
        self.target_ip = target_ip
        self.open_ports = open_ports

    def tcp_syn_probe(self):
        """Send SYN packets and compute differences between ISN responses."""
        differences = []
        previous_isn = None

        # Creating 6 SYN packets with different TCP options
        pkt1 = IP(dst=self.target_ip) / TCP(
            options=[('WScale', 10), ('NOP', None), ('MSS', 1460), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')], window=1, flags="S")
        pkt2 = IP(dst=self.target_ip) / TCP(
            options=[('MSS', 1400), ('WScale', 0), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('EOL', None)], window=63, flags="S")
        pkt3 = IP(dst=self.target_ip) / TCP(
            options=[('Timestamp', (0xFFFFFFFF, 0)), ('NOP', None), ('NOP', None), ('WScale', 5), ('NOP', None), ('MSS', 640)], window=4, flags="S")
        pkt4 = IP(dst=self.target_ip) / TCP(
            options=[('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)], window=4, flags="S")
        pkt5 = IP(dst=self.target_ip) / TCP(
            options=[('MSS', 536), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)], window=16, flags="S")
        pkt6 = IP(dst=self.target_ip) / TCP(
            options=[('MSS', 265), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0))], window=512, flags="S")

        pkt_list = [pkt1, pkt2, pkt3, pkt4, pkt5, pkt6]

        # Send 6 SYN packets and collect responses
        for i in self.open_ports:
            for pkt in pkt_list:
                pkt[TCP].dport = i
                response = sr1(pkt, verbose=0, timeout=2)

                if response and response.haslayer(TCP):
                    current_isn = response[TCP].seq
                    if previous_isn is not None:
                        diff = current_isn - previous_isn
                        # Adjust for wrapping of 32-bit counter
                        diff = min(diff, 0x100000000 - diff)
                        differences.append(diff)
                    previous_isn = current_isn

        print(f"ISN Differences: {differences}")

        if differences:
            gcd_value = HelperFunctions().compute_gcd_list(differences)
            print(f"GCD of differences: {gcd_value}")
            return differences, gcd_value
        else:
            print("Failed to compute ISN differences.")

        return differences
