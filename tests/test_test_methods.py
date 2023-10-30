import math
import zlib

import pytest
import unittest
from scapy.layers.inet import IP, TCP, ICMP, IPerror, UDPerror
from scapy.packet import Raw

from os_hound.test_methods import TestMethods


class TestTestMethods(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.instance = TestMethods()

    # GCD Test
    def test_tcp_isn_gcd_empty_list(self):
        # Act
        result = self.instance.tcp_isn_gcd([])

        # Assert
        assert result == "None"

    def test_tcp_isn_gcd_no_tcp_layer(self):
        # Arrange
        responses = [IP(src="192.168.0.1"), IP(src="192.168.0.2")]

        # Act
        result = self.instance.tcp_isn_gcd(responses)

        # Assert
        assert result == "None"

    def test_tcp_isn_gcd_at_least_two_tcp_responses(self):
        # Arrange
        responses = [IP(src="192.168.0.1")/TCP(seq=100), IP(src="192.168.0.2")/TCP(seq=500)]

        # Act
        differences, gcd_value = self.instance.tcp_isn_gcd(responses)

        # Assert
        assert differences == [400]
        assert gcd_value == 400

    # ISR Test
    def test_tcp_isn_isr_valid_diff(self):
        # Arrange
        diff = [5, 10, 15]
        expected_seq_rates = [50, 100, 150]
        avg_rate = sum(expected_seq_rates) / len(expected_seq_rates)
        expected_isr = round(8 * math.log2(avg_rate))

        # Act
        isr, seq_rates = self.instance.tcp_isn_isr(diff)

        # Assert
        assert isr == expected_isr
        assert seq_rates == expected_seq_rates

    def test_tcp_isn_isr_empty_diff(self):
        # Arrange
        diff = []

        # Act
        result = self.instance.tcp_isn_isr(diff)

        # Assert
        assert result == "None"

    # SP Test
    def test_tcp_isn_sp_gcd_less_than_nine(self):
        # Arrange
        seq_rates = [10, 20, 30]
        gcd_value = 5
        expected_sp = 27

        # Act
        sp = self.instance.tcp_isn_sp(seq_rates, gcd_value)

        # Assert
        assert sp == expected_sp

    def test_tcp_isn_sp_gcd_greater_than_nine(self):
        # Arrange
        seq_rates = [10, 20, 30]
        gcd_value = 10
        expected_sp = 0

        # Act
        sp = self.instance.tcp_isn_sp(seq_rates, gcd_value)

        # Assert
        assert sp == expected_sp

    def test_tcp_isn_sp_empty_seq_rates(self):
        # Arrange
        seq_rates = []
        gcd_value = 5

        # Act
        result = self.instance.tcp_isn_sp(seq_rates, gcd_value)

        # Assert
        assert result == "None"

    def test_tcp_isn_sp_no_gcd_value(self):
        # Arrange
        seq_rates = [10, 20, 30]
        gcd_value = None

        # Act
        result = self.instance.tcp_isn_sp(seq_rates, gcd_value)

        # Assert
        assert result == "None"

    # TI,CI,II Test
    def test_ip_id_sequence_all_zero(self):
        # Arrange
        responses = [IP(id=0)/TCP(), IP(id=0)/TCP(), IP(id=0)/TCP()]
        test_type = "TI"

        # Act
        result = self.instance.ip_id_sequence(responses, test_type)

        # Assert
        assert result == "Z"

    def test_ip_id_sequence_sequence_increases(self):
        # Arrange
        responses = [IP(id=10000)/TCP(), IP(id=31000)/TCP(), IP(id=51000)/TCP()]
        test_type = "TI"

        # Act
        result = self.instance.ip_id_sequence(responses, test_type)

        # Assert
        assert result == "RD"

    def test_ip_id_sequence_identical_ids(self):
        # Arrange
        responses = [IP(id=12345)/TCP(), IP(id=12345)/TCP(), IP(id=12345)/TCP()]
        test_type = "TI"

        # Act
        result = self.instance.ip_id_sequence(responses, test_type)

        # Assert
        assert result == hex(12345)

    def test_ip_id_sequence_ri_case(self):
        # Arrange
        responses = [IP(id=2000)/TCP(), IP(id=3500)/TCP(), IP(id=5000)/TCP()]
        test_type = "TI"

        # Act
        result = self.instance.ip_id_sequence(responses, test_type)

        # Assert
        assert result == "RI"

    def test_ip_id_sequence_bi_case(self):
        # Arrange
        responses = [IP(id=256)/TCP(), IP(id=512)/TCP(), IP(id=768)/TCP()]
        test_type = "TI"

        # Act
        result = self.instance.ip_id_sequence(responses, test_type)

        # Assert
        assert result == "BI"

    def test_ip_id_sequence_small_differences(self):
        # Arrange
        responses = [IP(id=1)/TCP(), IP(id=2)/TCP(), IP(id=3)/TCP()]
        test_type = "TI"

        # Act
        result = self.instance.ip_id_sequence(responses, test_type)

        # Assert
        assert result == "I"

    def test_ip_id_sequence_no_matching_pattern(self):
        # Arrange
        responses = [IP(id=4000)/TCP(), IP(id=7000)/TCP()]
        test_type = "TI"

        # Act
        result = self.instance.ip_id_sequence(responses, test_type)

        # Assert
        assert result == "None"

    def test_ip_id_sequence_empty_responses(self):
        # Arrange
        responses = []
        test_type = "TI"

        # Act
        result = self.instance.ip_id_sequence(responses, test_type)

        # Assert
        assert result == "None"

    # SS Test
    def test_shared_ip_id_shared_sequence(self):
        # Arrange
        tcp_responses = [IP(id=1), IP(id=4), IP(id=7)]
        icmp_responses = [IP(id=9)]

        # Act
        result = self.instance.shared_ip_id(tcp_responses, icmp_responses)

        # Assert
        assert result == 'S'

    def test_shared_ip_id_not_shared_sequence(self):
        # Arrange
        tcp_responses = [IP(id=1), IP(id=4), IP(id=7)]
        icmp_responses = [IP(id=23)]

        # Act
        result = self.instance.shared_ip_id(tcp_responses, icmp_responses)

        # Assert
        assert result == 'O'

    def test_shared_ip_id_no_tcp_responses(self):
        # Arrange
        tcp_responses = []
        icmp_responses = [IP(id=9)]

        # Act
        result = self.instance.shared_ip_id(tcp_responses, icmp_responses)

        # Assert
        assert result == "None"

    def test_shared_ip_id_no_icmp_responses(self):
        # Arrange
        tcp_responses = [IP(id=1), IP(id=4), IP(id=7)]
        icmp_responses = []

        # Act
        result = self.instance.shared_ip_id(tcp_responses, icmp_responses)

        # Assert
        assert result == "None"

    def test_shared_ip_id_no_responses(self):
        # Arrange
        tcp_responses = []
        icmp_responses = []

        # Act
        result = self.instance.shared_ip_id(tcp_responses, icmp_responses)

        # Assert
        assert result == "None"

    # TS Test
    def test_calculate_ts_unsupported_values(self):
        # Arrange
        response1 = IP()/TCP()
        response2 = IP()/TCP()
        response1.time = 1
        response2.time = 2
        response1[TCP].time = None
        response2[TCP].time = 10
        responses = [response1, response2]

        # Act
        result = self.instance.calculate_ts(responses)

        # Assert
        assert result == 'U'

    def test_calculate_ts_zero_values(self):
        # Arrange
        response1 = IP() / TCP()
        response2 = IP() / TCP()
        response1.time = 1
        response2.time = 2
        response1[TCP].time = 0
        response2[TCP].time = 10
        responses = [response1, response2]

        # Act
        result = self.instance.calculate_ts(responses)

        # Assert
        assert result == '0'

    def test_calculate_ts_increment_1(self):
        # Arrange
        response1 = IP() / TCP()
        response2 = IP() / TCP()
        response1.time = 1
        response2.time = 4
        response1[TCP].time = 1
        response2[TCP].time = 4
        responses = [response1, response2]

        # Act
        result = self.instance.calculate_ts(responses)

        # Assert
        assert result == '1'

    def test_calculate_ts_increment_7(self):
        # Arrange
        response1 = IP() / TCP()
        response2 = IP() / TCP()
        response1.time = 1
        response2.time = 2
        response1[TCP].time = 1
        response2[TCP].time = 110
        responses = [response1, response2]

        # Act
        result = self.instance.calculate_ts(responses)

        # Assert
        assert result == '7'

    def test_calculate_ts_increment_8(self):
        # Arrange
        response1 = IP() / TCP()
        response2 = IP() / TCP()
        response1.time = 1
        response2.time = 2
        response1[TCP].time = 1
        response2[TCP].time = 200
        responses = [response1, response2]

        # Act
        result = self.instance.calculate_ts(responses)

        # Assert
        assert result == '8'

    def test_calculate_ts_increment_other(self):
        # Arrange
        response1 = IP() / TCP()
        response2 = IP() / TCP()
        response1.time = 1
        response2.time = 2
        response1[TCP].time = 1
        response2[TCP].time = 1000
        responses = [response1, response2]

        # Act
        result = self.instance.calculate_ts(responses)

        # Assert
        assert isinstance(result, str)
        assert int(result) > 8  # This assumes avg_increment > 350, adjust as needed

    def test_calculate_ts_no_responses(self):
        # Arrange
        responses = []

        # Act
        result = self.instance.calculate_ts(responses)

        # Assert
        assert result == "None"

    # O Test
    def test_extract_tcp_options_single_response(self):
        # Arrange
        options = [("MSS", 1460), ("Timestamp", (1, 1)), ("SAckOK", ''), ("NOP", None)]
        response = IP()/TCP(options=options)

        # Act
        result = self.instance.extract_tcp_options(response)

        # Assert
        assert result == 'M0xT11SN'

    def test_extract_tcp_options_multiple_responses(self):
        # Arrange
        options1 = [("MSS", 1460), ("Timestamp", (1, 0)), ("NOP", None)]
        options2 = [("WScale", 8), ("SAckOK", ''), ("Timestamp", (0, 1))]
        response1 = IP()/TCP(options=options1)
        response2 = IP()/TCP(options=options2)
        responses = [response1, response2]

        # Act
        result = self.instance.extract_tcp_options(responses)

        # Assert
        assert result == ['M5b4T10N', 'W8ST01']

    def test_extract_tcp_options_none(self):
        # Arrange
        responses = None

        # Act
        result = self.instance.extract_tcp_options(responses)

        # Assert
        assert result == "None"

    # W Test
    def test_extract_tcp_window_size_single_response(self):
        # Arrange
        response = IP()/TCP(window=8192)

        # Act
        result = self.instance.extract_tcp_window_size(response)

        # Assert
        assert result == 8192

    def test_extract_tcp_window_size_multiple_responses(self):
        # Arrange
        response1 = IP()/TCP(window=4096)
        response2 = IP()/TCP(window=8192)
        responses = [response1, response2]

        # Act
        result = self.instance.extract_tcp_window_size(responses)

        # Assert
        assert result == [4096, 8192]

    def test_extract_tcp_window_size_none(self):
        # Arrange
        responses = None

        # Act
        result = self.instance.extract_tcp_window_size(responses)

        # Assert
        assert result == "None"

    # R Test
    def test_ie_no_response(self):
        assert self.instance.check_responsiveness("IE", None, True) == ""

    def test_u1_no_response(self):
        assert self.instance.check_responsiveness("U1", None, True) == ""

    def test_t5_no_response_with_closed_port(self):
        assert self.instance.check_responsiveness("T5", None, True) == "N"

    def test_t5_no_response_without_closed_port(self):
        assert self.instance.check_responsiveness("T5", None, False) == ""

    def test_t6_no_response_without_closed_port(self):
        assert self.instance.check_responsiveness("T6", None, False) == ""

    def test_t7_no_response_without_closed_port(self):
        assert self.instance.check_responsiveness("T7", None, False) == ""

    def test_ie_with_response(self):
        assert self.instance.check_responsiveness("IE", IP(), True) == "Y"

    def test_u1_with_response(self):
        assert self.instance.check_responsiveness("U1", IP(), True) == "Y"

    def test_t5_with_response(self):
        assert self.instance.check_responsiveness("T5", IP(), True) == "Y"

    # DF Test
    def test_df_bit_set(self):
        # Arrange
        packet = IP(flags="DF")

        # Act
        result = self.instance.check_dont_fragment_bit(packet)

        # Assert
        assert result == "Y"

    def test_df_bit_not_set(self):
        # Arrange
        packet = IP()

        # Act
        result = self.instance.check_dont_fragment_bit(packet)

        # Assert
        assert result == "N"

    def test_no_response(self):
        # Act
        result = self.instance.check_dont_fragment_bit(None)

        # Assert
        assert result == "None"

    # DFI Test
    def test_dfi_no_response(self):
        # Act
        result = self.instance.dfi_test_value(None)

        # Assert
        assert result == "None"

    def test_response_length_not_two(self):
        # Arrange
        packet = [IP(flags="DF")]

        # Act
        result = self.instance.dfi_test_value(packet)

        # Assert
        assert result == "None"

    def test_both_df_bits_unset(self):
        # Arrange
        packets = [IP(), IP()]

        # Act
        result = self.instance.dfi_test_value(packets)

        # Assert
        assert result == "N"

    def test_both_df_bits_set(self):
        # Arrange
        packets = [IP(flags="DF"), IP(flags="DF")]

        # Act
        result = self.instance.dfi_test_value(packets)

        # Assert
        assert result == "S"

    def test_first_df_bit_set(self):
        # Arrange
        packets = [IP(flags="DF"), IP()]

        # Act
        result = self.instance.dfi_test_value(packets)

        # Assert
        assert result == "O"

    def test_second_df_bit_set(self):
        # Arrange
        packets = [IP(), IP(flags="DF")]

        # Act
        result = self.instance.dfi_test_value(packets)

        # Assert
        assert result == "O"

    # T Test
    def test_compute_initial_ttl(self):
        # Arrange
        response = IP(ttl=50)
        u1_response = IP(ttl=40)/ICMP()
        u1_response[ICMP].ttl = 35

        # Act
        result = self.instance.compute_initial_ttl(response, u1_response)

        # Assert
        expected_initial_ttl = 55  # Computed from above values (50 + (40 - 35))
        assert result == expected_initial_ttl

    def test_compute_initial_ttl_no_response(self):
        # Arrange
        response = None
        u1_response = None

        # Act
        result = self.instance.compute_initial_ttl(response, u1_response)

        # Assert
        assert result == "None"

    # TG Test
    def test_ttl_guess_test_32(self):
        # Arrange
        response = IP(ttl=20)  # Example TTL <= 32

        # Act
        result = self.instance.ttl_guess_test(response)

        # Assert
        assert result == 32

    def test_ttl_guess_test_64(self):
        # Arrange
        response = IP(ttl=40)  # Example 32 < TTL <= 64

        # Act
        result = self.instance.ttl_guess_test(response)

        # Assert
        assert result == 64

    def test_ttl_guess_test_128(self):
        # Arrange
        response = IP(ttl=100)  # Example 64 < TTL <= 128

        # Act
        result = self.instance.ttl_guess_test(response)

        # Assert
        assert result == 128

    def test_ttl_guess_test_255(self):
        # Arrange
        response = IP(ttl=200)  # Example TTL > 128

        # Act
        result = self.instance.ttl_guess_test(response)

        # Assert
        assert result == 255

    def test_ttl_guess_test_none(self):
        # Arrange
        response = None

        # Act
        result = self.instance.ttl_guess_test(response)

        # Assert
        assert result == "None"

    # CC Test
    def test_congestion_control_Y(self):
        # Arrange
        packet = IP()/TCP(flags='E')  # Setting only ECE flag

        # Act
        result = self.instance.congestion_control_test(packet)

        # Assert
        assert result == 'Y'

    def test_congestion_control_N(self):
        # Arrange
        packet = IP()/TCP(flags='')  # Neither ECE nor CWR flags set

        # Act
        result = self.instance.congestion_control_test(packet)

        # Assert
        assert result == 'N'

    def test_congestion_control_S(self):
        # Arrange
        packet = IP()/TCP(flags='EC')  # Both ECE and CWR flags set

        # Act
        result = self.instance.congestion_control_test(packet)

        # Assert
        assert result == 'S'

    def test_congestion_control_O(self):
        # Arrange
        packet = IP()/TCP(flags='C')  # Setting only CWR flag

        # Act
        result = self.instance.congestion_control_test(packet)

        # Assert
        assert result == 'O'

    def test_congestion_control_none(self):
        # Arrange
        packet = None

        # Act
        result = self.instance.congestion_control_test(packet)

        # Assert
        assert result == "None"

    # Q Test
    def test_tcp_quirks_R(self):
        # Arrange
        packet = IP()/TCP(reserved=1)  # Set the reserved field non-zero

        # Act
        result = self.instance.check_tcp_quirks(packet)

        # Assert
        assert result == 'R'

    def test_tcp_quirks_U(self):
        # Arrange
        packet = IP()/TCP(flags='', urgptr=1)  # URG flag is not set but urgent pointer is non-zero

        # Act
        result = self.instance.check_tcp_quirks(packet)

        # Assert
        assert result == 'U'

    def test_tcp_quirks_RU(self):
        # Arrange
        packet = IP()/TCP(reserved=1, flags='', urgptr=1)  # Both quirks are present

        # Act
        result = self.instance.check_tcp_quirks(packet)

        # Assert
        assert result == 'RU'

    def test_tcp_quirks_none(self):
        # Arrange
        packet = IP()/TCP()  # Neither of the quirks are present

        # Act
        result = self.instance.check_tcp_quirks(packet)

        # Assert
        assert result == ""

    # S Test
    def test_sequence_Z(self):
        # Arrange
        packet = IP()/TCP(ack=12345)
        seq_number = 0

        # Act
        result = self.instance.sequence_test(packet, seq_number)

        # Assert
        assert result == 'Z'

    def test_sequence_A(self):
        # Arrange
        seq_number = 12345
        packet = IP()/TCP(ack=seq_number)

        # Act
        result = self.instance.sequence_test(packet, seq_number)

        # Assert
        assert result == 'A'

    def test_sequence_A_plus(self):
        # Arrange
        seq_number = 12345
        packet = IP()/TCP(ack=seq_number - 1)

        # Act
        result = self.instance.sequence_test(packet, seq_number)

        # Assert
        assert result == 'A+'

    def test_sequence_O(self):
        # Arrange
        seq_number = 12345
        packet = IP()/TCP(ack=54321)

        # Act
        result = self.instance.sequence_test(packet, seq_number)

        # Assert
        assert result == 'O'

    def test_sequence_no_response(self):
        # Act
        result = self.instance.sequence_test(None, 12345)

        # Assert
        assert result == "None"

    def test_sequence_no_tcp_layer(self):
        # Arrange
        packet = IP()

        # Act
        result = self.instance.sequence_test(packet, 12345)

        # Assert
        assert result == "None"

    # A Test
    def test_ack_Z(self):
        # Arrange
        seq_number = 12345  # Arbitrary sequence number
        packet = IP()/TCP(ack=0)  # Ack number is 0

        # Act
        result = self.instance.ack_test(packet, seq_number)

        # Assert
        assert result == 'Z'

    def test_ack_S(self):
        # Arrange
        seq_number = 12345
        packet = IP()/TCP(ack=seq_number)  # Acknowledgment number matches sequence number

        # Act
        result = self.instance.ack_test(packet, seq_number)

        # Assert
        assert result == 'S'

    def test_ack_S_plus(self):
        # Arrange
        seq_number = 12345
        packet = IP()/TCP(ack=seq_number + 1)  # Acknowledgment number is one greater than sequence number

        # Act
        result = self.instance.ack_test(packet, seq_number)

        # Assert
        assert result == 'S+'

    def test_ack_O(self):
        # Arrange
        seq_number = 12345
        packet = IP()/TCP(ack=54321)  # Acknowledgment number doesn't match any of the predefined conditions

        # Act
        result = self.instance.ack_test(packet, seq_number)

        # Assert
        assert result == 'O'

    def test_ack_no_response(self):
        # Act
        result = self.instance.ack_test(None, 12345)  # No response

        # Assert
        assert result == "None"

    def test_ack_no_tcp_layer(self):
        # Arrange
        packet = IP()  # No TCP layer

        # Act
        result = self.instance.ack_test(packet, 12345)

        # Assert
        assert result == "None"

    def test_ack_no_seq_number(self):
        # Arrange
        packet = IP()/TCP(ack=12345)  # Arbitrary acknowledgment number

        # Act
        result = self.instance.ack_test(packet, None)  # No sequence number

        # Assert
        assert result == "None"

    # F Test
    def test_extract_flags_all(self):
        # Arrange
        packet = IP()/TCP(flags="EUAPRSF")  # All flags set

        # Act
        result = self.instance.extract_tcp_flags(packet)

        # Assert
        assert result == 'EUAPRSF'

    def test_extract_flags_some(self):
        # Arrange
        packet = IP()/TCP(flags="EUA")

        # Act
        result = self.instance.extract_tcp_flags(packet)

        # Assert
        assert result == 'EUA'

    def test_extract_flags_none(self):
        # Arrange
        packet = IP()/TCP(flags=0)

        # Act
        result = self.instance.extract_tcp_flags(packet)

        # Assert
        assert result == ''

    def test_extract_flags_no_response(self):
        # Act
        result = self.instance.extract_tcp_flags(None)

        # Assert
        assert result == "None"

    def test_extract_flags_no_tcp_layer(self):
        # Arrange
        packet = IP()  # No TCP layer

        # Act
        result = self.instance.extract_tcp_flags(packet)

        # Assert
        assert result == "None"

    # RD Test
    def test_rst_with_data(self):
        # Arrange
        packet = IP()/TCP(flags="R")/Raw(load="test_data")

        # Act
        result = self.instance.get_rst_data_checksum(packet)

        # Assert
        assert result == zlib.crc32(b"test_data")

    def test_rst_without_data(self):
        # Arrange
        packet = IP()/TCP(flags="R")

        # Act
        result = self.instance.get_rst_data_checksum(packet)

        # Assert
        assert result == 0

    def test_non_rst_with_data(self):
        # Arrange
        packet = IP()/TCP(flags="A")/Raw(load="test_data")

        # Act
        result = self.instance.get_rst_data_checksum(packet)

        # Assert
        assert result == 0

    def test_non_rst_without_data(self):
        # Arrange
        packet = IP()/TCP(flags="A")

        # Act
        result = self.instance.get_rst_data_checksum(packet)

        # Assert
        assert result == 0

    def test_rd_no_tcp_layer(self):
        # Arrange
        packet = IP()

        # Act
        result = self.instance.get_rst_data_checksum(packet)

        # Assert
        assert result == "None"

    def test_rd_no_response(self):
        # Act
        result = self.instance.get_rst_data_checksum(None)  # No response

        # Assert
        assert result == "None"

    # IPL Test
    def test_icmp_port_unreachable(self):
        # Arrange
        packet = IP(len=320)/ICMP(type=3)  # ICMP type 3 is "port unreachable"

        # Act
        result = self.instance.get_ip_total_length(packet)

        # Assert
        assert result == 20  # Expected length is 320 - 300 = 20

    def test_icmp_not_port_unreachable(self):
        # Arrange
        packet = IP(len=320)/ICMP(type=4)  # Any ICMP type other than 3

        # Act
        result = self.instance.get_ip_total_length(packet)

        # Assert
        assert result is None  # Expecting None as it's not "port unreachable"

    def test_no_icmp_layer(self):
        # Arrange
        packet = IP(len=320)  # Only IP layer, no ICMP

        # Act
        result = self.instance.get_ip_total_length(packet)

        # Assert
        assert result is None  # Expecting None as there's no ICMP layer

    def test_ipl_no_response(self):
        # Act
        result = self.instance.get_ip_total_length(None)  # No response

        # Assert
        assert result == "None"

    # UN Test
    def test_icmp_type_3_non_zero_unused_field(self):
        # Arrange
        unused_value = b'\x01\x02\x03\x04'
        icmp_payload = ICMP(type=3)  # Start with a regular ICMP type 3 payload
        raw_icmp = bytes(icmp_payload)  # Convert it to bytes
        modified_icmp = raw_icmp[:4] + unused_value + raw_icmp[8:]  # Modify bytes 5 to 8 with the unused_value
        packet = IP() / ICMP(modified_icmp)  # Create the packet with the modified ICMP layer

        # Act
        result = self.instance.check_icmp_unused_field(packet)

        # Assert
        assert result == unused_value

    def test_icmp_type_3_zero_unused_field(self):
        # Arrange
        packet = IP()/ICMP(type=3)  # default unused field value is zero

        # Act
        result = self.instance.check_icmp_unused_field(packet)

        # Assert
        assert result is None

    def test_icmp_not_type_3(self):
        # Arrange
        packet = IP()/ICMP(type=4)  # Any ICMP type other than 3

        # Act
        result = self.instance.check_icmp_unused_field(packet)

        # Assert
        assert result is None

    def test_un_no_icmp_layer(self):
        # Arrange
        packet = IP()  # Only IP layer, no ICMP

        # Act
        result = self.instance.check_icmp_unused_field(packet)

        # Assert
        assert result is None

    def test_un_no_response(self):
        # Act
        result = self.instance.check_icmp_unused_field(None)  # No response

        # Assert
        assert result == "None"

    # RIPL Test
    def test_check_returned_ip_length_good_value(self):
        # Arrange
        icmp_payload = ICMP(type=3) / IPerror(src="1.1.1.1", dst="2.2.2.2", len=0x148) / ICMP()  # This should make the length 328 bytes (0x148)
        packet = IP() / icmp_payload

        # Act
        result = self.instance.check_returned_ip_length(packet)

        # Assert
        assert result == "G"

    def test_check_returned_ip_length_bad_value(self):
        # Arrange
        icmp_payload = ICMP(type=3) / IPerror(src="1.1.1.1", dst="2.2.2.2", len=0x149) / ICMP()  # Any value other than 0x148 should do
        packet = IP() / icmp_payload

        # Act
        result = self.instance.check_returned_ip_length(packet)

        # Assert
        assert result == hex(0x149)

    def test_check_returned_ip_length_none(self):
        # Arrange
        packet = IP() / ICMP()  # A random packet without an IPerror layer

        # Act
        result = self.instance.check_returned_ip_length(packet)

        # Assert
        assert result == "None"

    # RID Test
    def test_check_returned_ip_id_good_value(self):
        # Arrange
        icmp_payload = ICMP(type=3) / IPerror(src="1.1.1.1", dst="2.2.2.2", id=0x1042) / ICMP()
        packet = IP() / icmp_payload

        # Act
        result = self.instance.check_returned_ip_id(packet)

        # Assert
        assert result == "G"

    def test_check_returned_ip_id_bad_value(self):
        # Arrange
        icmp_payload = ICMP(type=3) / IPerror(src="1.1.1.1", dst="2.2.2.2", id=0x1043) / ICMP()  # Any value other than 0x1042 should do
        packet = IP() / icmp_payload

        # Act
        result = self.instance.check_returned_ip_id(packet)

        # Assert
        assert result == hex(0x1043)

    def test_check_returned_ip_id_no_iperror_layer(self):
        # Arrange
        packet = IP() / ICMP(type=3)  # Missing the IPerror layer

        # Act
        result = self.instance.check_returned_ip_id(packet)

        # Assert
        assert result == "None"

    def test_check_returned_ip_id_no_icmp_layer(self):
        # Arrange
        packet = IP()  # Missing the ICMP layer

        # Act
        result = self.instance.check_returned_ip_id(packet)

        # Assert
        assert result == "None"

    # RIPCK Test
    def test_check_returned_ip_checksum_good(self):
        # Arrange
        embedded_ip = IPerror(src="1.1.1.1", dst="2.2.2.2", chksum=0x1234)
        icmp_payload = ICMP(type=3) / embedded_ip / ICMP()
        packet = IP(chksum=0x1234) / icmp_payload

        # Act
        result = self.instance.check_returned_ip_checksum(packet)

        # Assert
        assert result == "G"

    def test_check_returned_ip_checksum_zero(self):
        # Arrange
        embedded_ip = IPerror(src="1.1.1.1", dst="2.2.2.2", chksum=0)
        icmp_payload = ICMP(type=3) / embedded_ip / ICMP()
        packet = IP(chksum=0x1234) / icmp_payload

        # Act
        result = self.instance.check_returned_ip_checksum(packet)

        # Assert
        assert result == "Z"

    def test_check_returned_ip_checksum_invalid(self):
        # Arrange
        embedded_ip = IPerror(src="1.1.1.1", dst="2.2.2.2", chksum=0x5678)
        icmp_payload = ICMP(type=3) / embedded_ip / ICMP()
        packet = IP(chksum=0x1234) / icmp_payload

        # Act
        result = self.instance.check_returned_ip_checksum(packet)

        # Assert
        assert result == "I"

    def test_check_returned_ip_checksum_no_iperror_layer(self):
        # Arrange
        packet = IP() / ICMP(type=3)  # Missing the IPerror layer

        # Act
        result = self.instance.check_returned_ip_checksum(packet)

        # Assert
        assert result == "None"

    def test_check_returned_ip_checksum_no_icmp_layer(self):
        # Arrange
        packet = IP()  # Missing the ICMP layer

        # Act
        result = self.instance.check_returned_ip_checksum(packet)

        # Assert
        assert result == "None"

    # RUCK Test
    def test_check_returned_udp_checksum_good(self):
        # Arrange
        embedded_udp = UDPerror(sport=12345, dport=80, chksum=None)
        icmp_payload = ICMP(type=3) / IP() / embedded_udp
        packet = IP() / icmp_payload

        # Act
        result = self.instance.check_returned_udp_checksum(packet)

        # Assert
        assert result == "G"

    def test_check_returned_udp_checksum_invalid(self):
        # Arrange
        embedded_udp = UDPerror(sport=12345, dport=80, chksum=0x5678)
        icmp_payload = ICMP(type=3) / IP() / embedded_udp
        packet = IP() / icmp_payload

        # Act
        result = self.instance.check_returned_udp_checksum(packet)

        # Assert
        assert result == hex(0x5678)

    def test_check_returned_udp_checksum_no_udperror_layer(self):
        # Arrange
        packet = IP() / ICMP(type=3)  # Missing the UDPerror layer

        # Act
        result = self.instance.check_returned_udp_checksum(packet)

        # Assert
        assert result == "None"

    def test_check_returned_udp_checksum_no_icmp_layer(self):
        # Arrange
        packet = IP()  # Missing the ICMP layer

        # Act
        result = self.instance.check_returned_udp_checksum(packet)

        # Assert
        assert result == "None"

    # RUD Test
    def test_check_returned_udp_data_integrity_good(self):
        # Arrange
        data = b'CCCC'  # Some example payload
        embedded_udp = UDPerror(sport=12345, dport=80) / data
        icmp_payload = ICMP(type=3) / IP() / embedded_udp
        packet = IP() / icmp_payload

        # Act
        result = self.instance.check_returned_udp_data_integrity(packet)

        # Assert
        assert result == "G"

    def test_check_returned_udp_data_integrity_no_payload(self):
        # Arrange
        embedded_udp = UDPerror(sport=12345, dport=80)  # No payload
        icmp_payload = ICMP(type=3) / IP() / embedded_udp
        packet = IP() / icmp_payload

        # Act
        result = self.instance.check_returned_udp_data_integrity(packet)

        # Assert
        assert result == "G"

    def test_check_returned_udp_data_integrity_invalid_payload(self):
        # Arrange
        data = b'ABCD'  # Different payload data
        embedded_udp = UDPerror(sport=12345, dport=80) / data
        icmp_payload = ICMP(type=3) / IP() / embedded_udp
        packet = IP() / icmp_payload

        # Act
        result = self.instance.check_returned_udp_data_integrity(packet)

        # Assert
        assert result == "I"

    def test_check_returned_udp_data_integrity_no_udperror_layer(self):
        # Arrange
        packet = IP() / ICMP(type=3)  # Missing the UDPerror layer

        # Act
        result = self.instance.check_returned_udp_data_integrity(packet)

        # Assert
        assert result == "None"

    def test_check_returned_udp_data_integrity_no_icmp_layer(self):
        # Arrange
        packet = IP()  # Missing the ICMP layer

        # Act
        result = self.instance.check_returned_udp_data_integrity(packet)

        # Assert
        assert result == "None"

    # CD Test
    # TODO: end the cd test and check the results also make the test titles more pronounceable!!!
    def test_icmp_response_code_ZZ(self):
        # Arrange
        responses = [IP() / ICMP(type=0, code=0), IP() / ICMP(type=0, code=0)]

        # Act
        result = self.instance.icmp_response_code(responses)

        # Assert
        assert result == "ZZ"

    def test_icmp_response_code_ZO(self):
        # Arrange
        responses = [IP() / ICMP(type=0, code=0), IP() / ICMP(type=0, code=1)]

        # Act
        result = self.instance.icmp_response_code(responses)

        # Assert
        assert result == "ZO"

    # Continue this pattern for other combinations...

    def test_icmp_response_code_NN_format(self):
        # Arrange
        responses = [IP() / ICMP(type=0, code=5), IP() / ICMP(type=0, code=10)]

        # Act
        result = self.instance.icmp_response_code(responses)

        # Assert
        assert result == "0510"

    def test_icmp_response_code_none(self):
        # Arrange
        responses = []

        # Act
        result = self.instance.icmp_response_code(responses)

        # Assert
        assert result == "None"


if __name__ == "__main__":
    pytest.main()
