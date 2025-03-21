import zlib
from scapy.layers.inet import IP, TCP, ICMP, IPerror, UDPerror, UDP
import math
import statistics
from math import gcd
from functools import reduce


class TestMethods:
    def __init__(self):
        pass

    # Calculate the differences between consecutive ISN values considering 32-bit wrapping
    def __calculate_difference(self, a, b):
        # Convert to unsigned 32-bit integers
        a = a & 0xFFFFFFFF
        b = b & 0xFFFFFFFF

        # Calculate minimum difference considering the modular arithmetic space
        return min((a - b) & 0xFFFFFFFF, (b - a) & 0xFFFFFFFF)

    def tcp_isn_gcd(self, responses: list[IP]):
        """
        The GCD test.
        Calculate the differences between each of the two consecutive sequences in the give responses and
        compute the GCD value of the differences.

        :param responses: List of SYN ACK responses from the tcp_syn_probe.
        :return: GCD value and the differences array
        """
        isns = []
        if isinstance(responses, list):
            for response in responses:
                if response and response.haslayer(TCP):
                    isns.append(response[TCP].seq)

        # Create an array of differences
        diff1 = [self.__calculate_difference(isns[i + 1], isns[i]) for i in range(len(isns) - 1)]

        # Calculate the GCD of the differences
        if diff1:
            isn_gcd = reduce(gcd, diff1)
        else:
            isn_gcd = "None"

        return diff1, isn_gcd

    def tcp_isn_isr(self, diff1: list[int]):
        """
        The ISR test.
        Calculate the ISR based on the given diff array and the time_intervals.

        :param diff1: List of seq differences between each two consecutive probe responses.
        :return: ISR value
        """
        if diff1:
            seq_rates = [diff / 0.000012 for diff in diff1]

            # Calculate the average rate
            avg_rate = sum(seq_rates) / len(seq_rates)

            # Calculate ISR based on the average rate
            if avg_rate < 1:
                isr = 0
            else:
                isr = round(8 * math.log2(avg_rate) + 0.5)

            return isr, seq_rates
        else:
            return "None"

    def tcp_isn_sp(self, seq_rates: list[float], gcd_value: int) -> int:
        """
        The SP test.
        Calculate the SP value based on the given seq_rates and the GCD value.

        :param seq_rates: List of rate of ISN counter increases per 0.1 seconds.
        :param gcd_value: GCD value calculated from the diff.
        :return: SP value
        """
        if len(seq_rates) < 4:
            return "None"

        # Optionally divide by the GCD if it is greater than 9
        if gcd_value > 9:
            seq_rates = [rate / gcd_value for rate in seq_rates]

        # Calculate the standard deviation of seq_rates
        avg_rate = sum(seq_rates) / len(seq_rates)
        variance = sum((rate - avg_rate) ** 2 for rate in seq_rates) / (len(seq_rates) - 1)
        stddev = math.sqrt(variance)

        # Calculate SP
        if stddev <= 1:
            sp = 0
        else:
            sp = round(math.log(stddev, 2) * 8)

        return sp

    def ip_id_sequence(self, responses: list[IP], test_type: str):
        """
        The TI, CI, II tests.
        Calculate the IP ID sequence type based on the given ip_ids and the test type.

        :param responses: List of responses from the tcp_syn_probe or icmp_echo_probe.
        :param test_type: Test type ("TI", "CI", or "II").
        :return: IP ID sequence type
        """
        if responses:

            types = ["TI", "CI", "II"]

            if isinstance(responses, list) and test_type in types:
                # TI: needs at least 3 TCP SYN probe
                if test_type == "TI" and len(responses) < 3:
                    return "None"
                # CI: needs at least 2 out of the T5,T6,T7 probe
                if test_type == "CI" and len(responses) < 2:
                    return "None"
                # II: needs exactly 2 ICMP probe
                if test_type == "II" and len(responses) != 2:
                    return "None"
            else:
                return "None"

            ip_ids = []
            for response in responses:
                if response and response.haslayer(IP):
                    ip_ids.append(response[IP].id)
                else:
                    return "None"

            # Sort the IP ID values
            if not ip_ids:
                return "None"

            # Calculate the differences considering wrapping
            differences = [(ip_ids[i + 1] - ip_ids[i]) % 65536 for i in range(len(ip_ids) - 1)]

            # 1. If all the ID numbers are zero
            if all(id_val == 0 for id_val in ip_ids):
                return "Z"

            # 2. IP ID sequence ever increases by at least 20,000
            if any(diff >= 20000 for diff in differences) and test_type != "II":
                return "RD"

            # 3. If all the IP IDs are identical
            if len(set(ip_ids)) == 1:
                return ip_ids[0]

            # 4. Differences exceed 1,000 and not evenly divisible by 256
            if any((diff > 1000 and diff % 256 != 0) or (diff % 256 == 0 and diff >= 256000) for diff in differences):
                return "RI"

            # 5. All differences divisible by 256 and no greater than 5,120
            if all(diff % 256 == 0 and diff <= 5120 for diff in differences):
                return "BI"

            # 6. All differences are less than ten
            if all(diff < 10 for diff in differences):
                return "I"

            # 7. If none of the previous steps
            return "None"

        else:
            return "None"

    def shared_ip_id(self, responses: list[IP], icmp_responses: list[IP]):
        """
        The SS test.
        Calculate the Shared IP ID sequence Boolean (SS).

        :param responses: List of TCP SYN response objects from the tcp_syn_probe.
        :param icmp_responses: List of ICMP response objects.
        :return: 'S' if the sequence is shared, 'O' if it is not, and None if the test is not included.
        """
        if responses and icmp_responses:

            # Extract IP IDs from the responses
            tcp_ip_ids = []
            icmp_ip_ids = []
            for response in responses:
                if response and response.haslayer(IP):
                    tcp_ip_ids.append(response[IP].id)
                else:
                    return "None"

            for response in icmp_responses:
                if response and response.haslayer(IP):
                    icmp_ip_ids.append(response[IP].id)
                else:
                    return "None"

            # Calculate 'avg' based on TCP IP IDs
            avg = (tcp_ip_ids[-1] - tcp_ip_ids[0]) / (len(tcp_ip_ids) - 1)

            # Determine if sequences are shared or not
            if icmp_ip_ids[0] < tcp_ip_ids[-1] + 3 * avg:
                return 'S'
            else:
                return 'O'

        else:
            return "None"

    def calculate_ts(self, responses: list[IP]):
        """
        The TS test.
        Calculate the TCP timestamp option algorithm (TS).

        :param responses: List of TCP response objects containing the 'timestamp' field.
        :return: Calculated TS value.
        """
        if responses:
            # Extract TSvals from the responses
            tsvals = []
            tssents = []
            for response in responses:
                tssents.append(response.time)
                if response and response.haslayer(TCP):
                    for option in response[TCP].options:
                        if option[0] == "Timestamp":
                            tsvals.append(option[1][0])
                else:
                    return "None"

            # Check for unsupported or zero values
            if None in tsvals:
                return "U"
            if any(val == 0 for val in tsvals):
                return 0

            # Compute average increments per second
            increments = [(tsvals[i + 1] - tsvals[i]) / (tssents[i + 1] - tssents[i]) for i in range(len(tsvals) - 1)]
            if len(increments) != 0:
                avg_increment = sum(increments) / len(increments)
            else:
                return "None"

            # Assign TS value based on avg_increment
            if 0 <= avg_increment <= 5.66:
                return 1
            elif 70 <= avg_increment <= 150:
                return 7
            elif 150 <= avg_increment <= 350:
                return 8
            else:
                return round(math.log(avg_increment, 2))

        else:
            return "None"

    def extract_tcp_options(self, responses: list[IP] | IP):
        """
        The O test.
        Extract TCP options from the given responses.

        :param responses: List of TCP response objects from tcp_syn_probe.
        :return: List of options strings for each packet respectively.
        """
        if responses:
            options = {"EOL": "L", "NOP": "N", "MSS": "M", "WScale": "W", "Timestamp": "T", "SAckOK": "S"}
            options_string = ""

            if isinstance(responses, list):
                res_list = []
                for response in responses:
                    if response and response.haslayer(TCP):
                        option_list = response[TCP].options
                        options_string = ""
                        for option in option_list:
                            options_string += options[option[0]]
                            if option[0] == "Timestamp":
                                options_string += "1" if option[1][0] != 0 else "0"
                                options_string += "1" if option[1][1] != 0 else "0"
                                continue
                            if option[1] is not None:
                                if option[0] == "SAckOK" and option[1] == b'':
                                    continue
                                if option[0] == "MSS":
                                    options_string += str(hex(option[1]))[2:].upper()
                                    continue
                                options_string += str(option[1])
                    else:
                        return "None"
                    res_list.append(options_string)
                return res_list

            else:
                if responses and responses.haslayer(TCP):
                    option_list = responses[TCP].options
                    for option in option_list:
                        options_string += options[option[0]]
                        if option[0] == "Timestamp":
                            options_string += "1" if option[1][0] != 0 else "0"
                            options_string += "1" if option[1][1] != 0 else "0"
                            continue
                        if option[1] is not None:
                            if option[0] == "SAckOK" and option[1] == b'':
                                continue
                            if option[0] == "MSS":
                                options_string += str(hex(option[1]))[2:].upper()
                                continue
                            options_string += str(option[1])
                else:
                    return "None"
                return options_string
        else:
            return "None"

    def extract_tcp_window_size(self, responses: list[IP] | IP):
        """
        The W test.
        Extract the TCP window size from the packet.

        :param responses: List of TCP response objects from tcp_syn_probe.
        :return: List of window size values for each packet respectively or a single window size value.
        """
        if responses:
            if isinstance(responses, list):
                ws_list = []
                for response in responses:
                    if response and response.haslayer(TCP):
                        window_size = response[TCP].window
                        ws_list.append(window_size)
                    else:
                        return "None"
                return ws_list
            else:
                if responses and responses.haslayer(TCP):
                    window_size = responses[TCP].window
                    return window_size
        else:
            return "None"

    def check_responsiveness(self, probe_type: str, response: IP, has_closed_tcp_port: bool = True):
        """
        The R test.
        Checks the responsiveness of a target to a given probe.

        :param probe_type: The type of the probe. e.g. 'IE', 'U1', 'T5', etc.
        :param response:response was received for the probe.
        :param has_closed_tcp_port: Default is True. Indicates if there's a closed TCP port for a target.
        :return: 'Y' if the target responded, 'N' otherwise.
        """
        if probe_type not in ['IE', 'U1', 'T1', 'T2', 'T3', 'T4', 'T5', 'T6', 'T7', 'ECN', 'SYN']:
            print("Invalid probe type.")
            raise ValueError

        # If no response is received
        if response is None:
            # If it's IE or U1 probes, don't set R=N
            if probe_type in ['IE', 'U1']:
                return ""
            # If it's T5, T6, or T7 and we don't have a closed TCP port, don't set R=N
            elif probe_type in ['T5', 'T6', 'T7'] and not has_closed_tcp_port:
                return ""
            else:
                return "N"
        else:
            return "Y"

    def check_dont_fragment_bit(self, response: IP):
        """
        The DF test.
        Checks if the 'don't fragment' bit in the IP header of a packet is set.

        :param response: A representation of the IP packet. Assumes the packet has a key 'DF' indicating the state of the 'don't fragment' bit.
        :return: 'Y' if the 'don't fragment' bit is set, 'N' otherwise.
        """
        if response:
            if response.haslayer(IP):  # Check if packet has an IP layer
                if (response[IP].flags & 0x2) != 0:
                    return "Y"
                else:
                    return "N"
        else:
            return "None"

    def dfi_test_value(self, response: list[IP]):
        """
        The DFI test.
        Determine the DFI test value based on the DF bits of the two ICMP echo request probe responses.

        :param response: List of ICMP echo request probe responses.
        :return: DFI test value ('N', 'S', 'Y', or 'O')
        """
        if response[0]:
            if len(response) != 2:
                return "None"
            if response[0].haslayer(IP) and response[1].haslayer(IP):
                df1 = (response[0][IP].flags & 0x2) != 0
                df2 = (response[1][IP].flags & 0x2) != 0
            else:
                return "None"

            if not df1 and not df2:
                return 'N'
            elif df1 == df2:
                return 'S'
            elif df1 and df2:
                return 'Y'
            else:
                return 'O'
        else:
            return "None"

    def compute_initial_ttl(self, response: IP, u1_response):
        """
        The T test.
        Compute the initial TTL of the target's response.

        :param response: A response object from the tcp_probe, icmp_echo_probe, tcp_ecn_probe, udp_probe.
        :param u1_response: A response object from the udp_probe.
        :return: Initial TTL value.
        """
        if response and u1_response:
            # Determine hop count
            if u1_response.haslayer(IP) and u1_response.haslayer(IPerror):
                hop_count = u1_response[IP].ttl - u1_response[IPerror].ttl

                # Compute initial TTL of the target's response
                initial_ttl = 64 + hop_count

                return initial_ttl
        else:
            return "None"

    def ttl_guess_test(self, response: IP):
        """
        The TG test.
        Determine the TTL guess test value based on the TTL value of the target's response.

        :param response: A response object from the tcp_probe, icmp_echo_probe, tcp_ecn_probe, udp_probe.
        :return: TTL guess test value (32, 64, 128, or 255).
        """
        # If there's a response, extract the TTL
        if response and response.haslayer(IP):
            received_ttl = response[IP].ttl
        else:
            return "None"

        # Round up to the nearest value
        if received_ttl <= 32:
            tg = 32
        elif received_ttl <= 64:
            tg = 64
        elif received_ttl <= 128:
            tg = 128
        else:
            tg = 255

        return tg

    def congestion_control_test(self, response: IP):
        """
        The CC test.
        Extract the ECN-related flags from the TCP layer of the packet and determine
        the CC value.

        :param response: A response object from the tcp_ecn_probe.
        :return: CC value ('Y', 'N', 'S', or 'O').
        """
        if response:
            # Check if the packet has a TCP layer
            if response.haslayer(TCP):
                # Extract the flags
                ece_flag = (response[TCP].flags & 0x40) != 0  # ECE is the 7th bit of flags field in TCP (0x40 in hex)
                cwr_flag = (response[TCP].flags & 0x80) != 0  # CWR is the 8th bit of flags field in TCP (0x80 in hex)

                # Determine the CC value based on the flags
                if ece_flag and not cwr_flag:
                    return 'Y'
                elif not ece_flag and not cwr_flag:
                    return 'N'
                elif ece_flag and cwr_flag:
                    return 'S'
                else:
                    return 'O'
        else:
            return "None"

    def check_tcp_quirks(self, response: IP):
        """
        The Q test.
        Extract the TCP quirks from the TCP layer of the packet.
        :param response: Response object from the tcp_probe or tcp_ecn_probe.
        :return: returns a string of TCP quirks and if no quirks are found returns none.
        """
        q_string = ""
        if response:
            if response.haslayer(TCP):
                # Check if the reserved field in TCP header is non-zero
                if response[TCP].reserved != 0:
                    q_string += "R"

                # Check if the URG flag is not set but urgent pointer field is non-zero
                if not response[TCP].flags.URG and response[TCP].urgptr != 0:
                    q_string += "U"

        return q_string

    def sequence_test(self, response: IP, original_pkt: IP):
        """
        The S test.
        Determine the S test value based on the sequence number and the ack number of the response.

        :param response: Response object from the tcp_probe.
        :param original_pkt: Original packet sent by the tcp_probe.
        :return: returns the S test value ('Z', 'A', 'A+', 'O')
        """
        if response and original_pkt:
            if response.haslayer(TCP) and original_pkt.haslayer(TCP):
                ack_number = original_pkt[TCP].ack
                seq_number = response[TCP].seq

                # Check conditions and determine the S test value
                if seq_number == 0:
                    return 'Z'
                elif seq_number == ack_number:
                    return 'A'
                elif seq_number == ack_number + 1:
                    return 'A+'
                else:
                    return 'O'
            else:
                return "None"
        else:
            return "None"

    def ack_test(self, response: IP, original_pkt: IP):
        """
        The A test.
        Determine the A test value based on the sequence number and the ack number of the response.

        :param original_pkt: Original packet sent by the tcp_probe.
        :param response: Response object from the tcp_probe.
        :return: returns the S test value ('Z', 'S', 'S+', or 'O').
        """
        if response:
            if response.haslayer(TCP):
                ack_number = response[TCP].ack
                seq_number = original_pkt[TCP].seq

                # Check conditions and determine the S test value
                if ack_number == 0:
                    return 'Z'
                elif seq_number == ack_number:
                    return 'S'
                elif ack_number == seq_number + 1:
                    return 'S+'
                else:
                    return 'O'
            else:
                return "None"
        else:
            return "None"

    def extract_tcp_flags(self, response: IP):
        """
        The F test.
        Extract the TCP flags from the TCP layer of the response.

        :param response: response object from the tcp_probe.
        :return: returns a string of TCP flags.
        """
        if response:
            if response.haslayer(TCP):
                # Extract the flags from the TCP layer of the response
                flags = response[TCP].flags

                # Mapping of flag names to their respective byte values
                flag_map = {
                    'E': 0x40,  # 64 in hexadecimal
                    'U': 0x20,  # 32
                    'A': 0x10,  # 16
                    'P': 0x08,  # 8
                    'R': 0x04,  # 4
                    'S': 0x02,  # 2
                    'F': 0x01   # 1
                }

                # Extract the set flags
                set_flags = [flag for flag, value in flag_map.items() if flags & value]

                # Return the set flags as a string
                return ''.join(set_flags)
            else:
                return "None"
        else:
            return "None"

    def get_rst_data_checksum(self, response: IP):
        """
        The RD test.
        Checks if a given response is a TCP RST response with data.
        If data is present, computes and returns its CRC32 checksum.
        Otherwise, returns zero.

        :param response: The Scapy response object.
        :return: CRC32 checksum if data is present in the RST response; 0 otherwise.
        """
        if response:
            # Check if the response is a TCP RST response with data
            if response.haslayer(TCP):
                if response[TCP].flags == 'R' and response[TCP].payload:
                    data = bytes(response[TCP].payload)
                    return zlib.crc32(data)
                else:
                    return 0
            else:
                return "None"
        else:
            return "None"

    def get_ip_total_length(self, response: IP):
        """
        The IPL test.
        Extracts the total length of an IP response if it's a port unreachable
        response elicited by the U1 test.

        Args:
        - response: The Scapy response object.

        Returns:
        - The total length of the IP response if it's the required type; None otherwise.
        """
        if response:
            # Check if the response is an ICMP "port unreachable" response
            if response.haslayer(ICMP) and response[ICMP].type == 3:
                return response[IP].len
            else:
                return "None"
        else:
            return "None"

    def check_icmp_unused_field(self, response: IP):
        """
        The UN test.
        Checks if the ICMP unused field is non-zero.

        :param response: response object of the udp_probe.
        :return: returns the ICMP unused field if it's non-zero; None otherwise.
        """
        if response:
            # Check if the response is ICMP type 3 (destination unreachable)
            if response.haslayer(ICMP) and response[ICMP].type == 3:
                # Extract ICMP layer and take last four bytes before the embedded IP header
                icmp_layer = bytes(response[ICMP])
                unused_field = icmp_layer[4:8]  # Get bytes 5 to 8 of ICMP layer

                # Check if the bytes are non-zero
                if unused_field != b'\x00\x00\x00\x00':
                    print(f"Unused field has non-zero value: {unused_field}")
                    return unused_field
                else:
                    return 0
            else:
                return "None"
        else:
            return "None"

    def check_returned_ip_length(self, response: IP):
        """
        The RIPL test.
        Checks if the total length of the embedded IP response is 328 bytes.

        :param response: response object of the udp_probe.
        :return: returns 'G' if the total length is 328 bytes; the actual value otherwise.
        """
        if response:
            # Check if the response is an ICMP port unreachable error
            if response.haslayer(ICMP) and response[ICMP].type == 3:
                # Check if the response has the embedded original IP layer (IPerror in Scapy terms)
                if response.haslayer(IPerror):
                    ip_length = response[IPerror].len  # Extract the total length of the embedded IP response

                    # Compare and determine value
                    if ip_length == 0x148:
                        return "G"  # Good
                    else:
                        return ip_length  # Return the actual value in hexadecimal format
                else:
                    return "None"
            else:
                return "None"
        else:
            return "None"

    def check_returned_ip_id(self, response: IP):
        """
        The RID test.
        Checks if the ID of the embedded IP response is 0x1042.
        :param response: response object of the udp_probe.
        :return: returns 'G' if the ID is 0x1042; the actual value otherwise.
        """
        if response:
            # Check if the response is an ICMP port unreachable error
            if response.haslayer(ICMP) and response[ICMP].type == 3:
                # Check if the response has the embedded original IP layer (IPerror in Scapy terms)
                if response.haslayer(IPerror):
                    ip_id = response[IPerror].id  # Extract the ID of the embedded IP response

                    # Compare and determine value
                    if ip_id == 0x1042:
                        return "G"  # Good
                    else:
                        return ip_id  # Return the actual value in hexadecimal format
                else:
                    return "None"
            else:
                return "None"
        else:
            return "None"

    def check_returned_ip_checksum(self, response: IP):
        """
        The RIPCK test.
        Checks if the checksum of the embedded IP response is valid.
        :param response:  response object of the udp_probe.
        :return: returns 'G' if the checksum is valid; 'Z' if it's zero; 'I' if it's invalid; None otherwise.
        """
        if response:
            # Check if the response is an ICMP port unreachable error
            if response.haslayer(ICMP) and response[ICMP].type == 3:
                # Check if the response has the embedded original IP layer (IPerror in Scapy terms)
                if response.haslayer(IPerror):
                    checksum_received = response[IPerror].chksum
                    original_checksum = response[IP].chksum

                    # Compare and determine value
                    if checksum_received == original_checksum:
                        return "G"  # Good
                    elif checksum_received == 0:
                        return "Z"  # Zero
                    else:
                        return "I"  # Invalid
                else:
                    return "None"
            else:
                return "None"
        else:
            return "None"

    def check_returned_udp_checksum(self, response: IP, original_pkt: IP):
        """
        The RUCK test.
        Checks if the checksum of the embedded UDP response is valid.
        :param response: response object of the udp_probe.
        :return: returns 'G' if the checksum is valid; the actual value otherwise.
        """
        if response:
            # Check if the response is an ICMP port unreachable error
            if response.haslayer(ICMP) and response[ICMP].type == 3:
                # Check if the response has the embedded original UDP layer (UDPerror in Scapy terms)
                if response.haslayer(UDPerror):
                    udp_checksum_received = response[UDPerror].chksum
                    original_udp_checksum = original_pkt[UDP].chksum
                    # Compare and determine value
                    if udp_checksum_received == original_udp_checksum:
                        return "G"  # Good
                    else:
                        return udp_checksum_received
                else:
                    return "None"
            else:
                return "None"
        else:
            return "None"

    def check_returned_udp_data_integrity(self, response: IP):
        """
        The RUD test.
        Checks if the data of the embedded UDP response is intact.
        :param response: response object of the udp_probe.
        :return: returns 'G' if the data is intact; 'I' if it's invalid; None otherwise.
        """
        if response:
            # Check if the response is an ICMP port unreachable error
            if response.haslayer(ICMP) and response[ICMP].type == 3:
                # Check if the response has the embedded original UDP layer (UDPerror in Scapy terms)
                if response.haslayer(UDPerror):
                    udp_payload = bytes(response[UDPerror].payload)  # Get the payload as bytes

                    # Check the payload data
                    if not udp_payload or all(byte == 0x43 for byte in udp_payload):  # No payload data or All payload bytes are 'C' (0x43)
                        return "G"  # Good
                    else:
                        return "I"  # Invalid
                else:
                    return "None"
            else:
                return "None"
        else:
            return "None"

    def icmp_response_code(self, responses: list[IP]):
        """
        The CD test.
        Determine the CD test value based on the ICMP response code.
        :param responses: List of ICMP response objects.
        :return: CD test value ('Z', 'S', hex value of the first packet code in hexadecimal in the <NN> notation,
         or 'O').
        """
        if responses[0] and responses[1]:
            cd_string = ""
            sent_probe_code1 = 9
            sent_probe_code2 = 0
            # Checking if the responses is ICMP echo reply
            if responses[0].haslayer(ICMP) and responses[0][ICMP].type == 0 and responses[1].haslayer(ICMP) and responses[1][ICMP].type == 0:
                code_value1 = responses[0][ICMP].code
                code_value2 = responses[1][ICMP].code

                if code_value1 == 0 and code_value2 == 0:
                    cd_string += "Z"
                elif code_value1 == sent_probe_code1 and code_value2 == sent_probe_code2:
                    cd_string += "S"
                elif code_value1 == code_value2 and code_value1 != 0:
                    cd_string += f"{code_value1:X}"  # NN format
                else:
                    cd_string += "O"
            else:
                return "None"
        else:
            return "None"

        return cd_string
