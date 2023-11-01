import pytest
import unittest
from unittest.mock import patch, MagicMock
from scapy.layers.inet import TCP

from os_hound.port_scanner import PortScanner


class TestPortScanner(unittest.TestCase):
    # Mocking the __scan method
    @patch.object(PortScanner, '_PortScanner__scan')
    def test_syn_scan_with_port_range(self, mock_scan):
        scanner = PortScanner()

        # Setting mock responses
        mock_scan.side_effect = lambda ip, port: port if port == 80 else None

        result = scanner.syn_scan("192.168.1.1", start_port=79, end_port=81)
        assert result == [80]

    @patch('os_hound.port_scanner.sr1')
    def test_syn_scan_with_port_list(self, mock_scan):
        scanner = PortScanner()

        common_ports = [7, 20, 21, 22, 23, 25, 42, 53, 67, 68, 69, 80, 88, 102, 110, 119,
                        123, 135, 137, 138, 139, 143, 161, 162, 179, 389,
                        443, 444, 445, 464, 465, 512, 513, 514, 515, 587, 636, 771, 953,
                        989, 990, 993, 995, 3389, 5222, 5269, 5432, 3306, 8443, 6660, 6669]

        def side_effect(pkt, timeout=2, verbose=0, retry=2):
            res = MagicMock()
            if pkt[TCP].dport in [445, 135, 5432]:
                res[TCP].flags = "SA"
            else:
                res[TCP].flags = "RA"
            return res

        mock_scan.side_effect = side_effect

        result = scanner.syn_scan("192.168.1.1", ports_list=common_ports)
        assert result.sort() == [5432, 445, 135].sort()

    @patch.object(PortScanner, '_PortScanner__scan')
    def test_syn_scan_with_no_open_ports(self, mock_scan):
        scanner = PortScanner()

        # Setting mock to always return None (no open ports)
        mock_scan.return_value = None

        result = scanner.syn_scan("192.168.1.1", start_port=1000, end_port=1005)
        assert result == []


if __name__ == '__main__':
    pytest.main()
