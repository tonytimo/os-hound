from scapy.volatile import RandShort
from scapy.sendrecv import *
from scapy.layers.inet import IP, TCP


class PortScanner:
    """Class for scanning ports."""
    def __init__(self):
        pass

    def syn_scan(self, target_ip: str, start_port: int = None, end_port: int = None, ports_list: list = None):
        """
        Scan ports using the SYN scan method.

        :param target_ip: The target IP address.
        :param start_port: The start port to scan.
        :param end_port:  The end port to scan.
        :param ports_list: A list of ports to scan.
        :return: A list of open ports.
        """
        open_ports = []
        if not ports_list and start_port and end_port:
            for port in range(start_port, end_port + 1):
                res = None
                res = self.__scan(target_ip, port)
                if res:
                    open_ports.append(port)
                else:
                    pass

        else:
            for port in ports_list:
                res = None
                res = self.__scan(target_ip, port)
                if res:
                    open_ports.append(port)
                else:
                    pass

        return open_ports

    def __scan(self, target_ip, port: int):
        """
        Scan a single port.
        :param target_ip: The target IP address.
        :param port: The port to scan.
        :return: The list of open ports.
        """
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
                    return port
                elif resp[TCP].flags == 'RA':
                    pass

        except Exception:
            print(f"port {port} is closed.")
