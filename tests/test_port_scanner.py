import pytest
import unittest
from unittest.mock import patch
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

    @patch.object(PortScanner, '_PortScanner__scan')
    def test_syn_scan_with_port_list(self, mock_scan):
        scanner = PortScanner()

        # Setting mock responses for ports 22 and 80
        mock_scan.side_effect = lambda ip, port: port if port in [22, 80] else None

        result = scanner.syn_scan("192.168.1.1", ports_list=[21, 22, 23, 80, 81])
        assert result == [22, 80]

    @patch.object(PortScanner, '_PortScanner__scan')
    def test_syn_scan_with_no_open_ports(self, mock_scan):
        scanner = PortScanner()

        # Setting mock to always return None (no open ports)
        mock_scan.return_value = None

        result = scanner.syn_scan("192.168.1.1", start_port=1000, end_port=1005)
        assert result == []


if __name__ == '__main__':
    pytest.main()
