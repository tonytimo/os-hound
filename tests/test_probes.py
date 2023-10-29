import unittest
from scapy.layers.inet import IP, ICMP
import pytest
from unittest.mock import patch

import scapy.sendrecv

from os_hound.probes import Probes


class TestProbes(unittest.TestCase):

    def setUp(self):
        self.target_ip = "192.168.0.1"
        self.open_ports = [22, 80, 443]
        self.probes = Probes(self.target_ip, self.open_ports)

    @patch('os_hound.probes.sr1')
    def test_tcp_syn_probe(self, mock_sr1):
        # Mock the response from sr1
        mock_sr1.return_value = 'fake_response'

        responses, probe_type = self.probes.tcp_syn_probe()

        # There are 6 SYN packets sent, so we should get 6 responses
        self.assertEqual(len(responses), 6)
        self.assertEqual(probe_type, "SYN")

    @patch('os_hound.probes.sr1')
    def test_icmp_echo_probe(self, mock_sr1):
        mock_sr1.return_value = 'fake_response'

        responses, probe_type = self.probes.icmp_echo_probe()

        self.assertEqual(len(responses), 2)
        self.assertEqual(probe_type, "IE")

    @patch('os_hound.probes.sr1')
    def test_tcp_ecn_probe(self, mock_sr1):
        mock_sr1.return_value = 'fake_response'

        response, probe_type = self.probes.tcp_ecn_probe()

        self.assertEqual(response, 'fake_response')
        self.assertEqual(probe_type, "ECN")

    @patch('os_hound.probes.sr1')
    def test_tcp_probe(self, mock_sr1):
        mock_sr1.return_value = 'fake_response'

        for probe_type in ['T2', 'T3', 'T4', 'T5', 'T6', 'T7']:
            response, resp_probe_type, seq = self.probes.tcp_probe(probe_type)
            self.assertEqual(response, 'fake_response')
            self.assertEqual(resp_probe_type, probe_type)

    @patch('os_hound.probes.sr1')
    def test_udp_probe(self, mock_sr1):
        # Arrange
        mock_sr1.return_value = IP(src="192.168.0.1") / ICMP(type=3, code=3)

        # Act
        response, probe = self.probes.udp_probe()

        # Assert
        self.assertEqual(probe, "U1")
        self.assertEqual(response[ICMP].type, 3)
        self.assertEqual(response[ICMP].code, 3)


if __name__ == "__main__":
    pytest.main()
