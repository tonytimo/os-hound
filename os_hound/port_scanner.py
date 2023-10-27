from scapy.volatile import RandShort
from scapy.sendrecv import *
from scapy.layers.inet import IP, TCP

# TODO: Add scan that gets a list of ports as an argument and scans them all
# TODO: Add Docstrings
class PortScanner:
    def __init__(self):
        pass

    def syn_scan(self, target_ip, start_port, end_port):
        open_ports = []

        for port in range(start_port, end_port + 1):
            # Use a random source port for each scan
            src_port = RandShort()

            # Crafting the SYN packet
            pkt = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags='S')

            try:
                # Sending the packet and waiting for a response
                resp = sr1(pkt, timeout=2, verbose=0, retry=2)

                if resp:
                    # SYN-ACK indicates the port is open
                    if resp[TCP].flags == 'SA':
                        open_ports.append(port)
                    elif resp[TCP].flags == 'RA':
                        pass

            except Exception as e:
                print(f"port {port} is closed.")
                continue

        return open_ports
