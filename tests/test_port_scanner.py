import pytest
from scapy.layers.inet import TCP
from os_hound.port_scanner import PortScanner


# Mocked responses
class MockedResponse:
    def __init__(self, flags):
        self.flags = flags


SYN_ACK = MockedResponse('SA')
RST_ACK = MockedResponse('RA')
NO_RESP = None


def mock_sr1(packet, *args, **kwargs):
    target_port = packet[TCP].dport

    # Simulated responses based on target ports
    responses = {
        22: SYN_ACK,   # Mock port 22 as open
        80: RST_ACK,   # Mock port 80 as closed
        443: NO_RESP  # Mock port 443 as no response
    }
    flags = responses[target_port]

    return {TCP: flags}



def test_syn_scan(monkeypatch):
    # Using monkeypatch to replace the sr1 function
    monkeypatch.setattr("os_hound.port_scanner.sr1", mock_sr1)

    target_ip = "127.0.0.1"
    start_port = 80
    end_port = 100

    result = PortScanner().syn_scan(target_ip, start_port, end_port)

    assert 22 in result
    assert 80 not in result
    assert 443 not in result
