from helper import HelperFunctions
from scapy.layers.inet import IP, TCP, ICMP, UDP
import math
import statistics

#TODO: ended in TCP initial window size (W, W1–W6) (done) next time start from the R test


class TestMethods:
    def __init__(self):
        pass

    def tcp_isn_gcd(self, responses: list[IP/TCP]):
        """
        Calculate the differences between each of the two consecutive sequences in the give responses and
        compute the GCD value of the differences.

        :param responses: List of SYN ACK responses from the tcp_syn_probe.
        :return: GCD value and the differences array
        """
        differences = []
        previous_isn = None
        if isinstance(responses, list):
            for response in responses:
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

        return None

    def tcp_isn_isr(self, diff: list[int]):
        """
        Calculate the ISR based on the given diff array and the time_intervals.

        :param diff: List of differences between each two consecutive probe responses.
        :return: ISR value
        """
        # Calculate the rate of ISN counter increases per second for each diff1 value
        seq_rates = [diff / 0.1 for diff in zip(diff)]

        # Calculate the average rate
        avg_rate = sum(seq_rates) / len(seq_rates)

        # Calculate ISR based on the average rate
        if avg_rate < 1:
            isr = 0
        else:
            isr = round(8 * math.log2(avg_rate))

        return isr, seq_rates

    def tcp_isn_sp(self, seq_rates: list[int], gcd_value: int):
        """
        Calculate the SP value based on the given seq_rates and the GCD value.

        :param seq_rates: List of rate of ISN counter increases per 0.1 seconds.
        :param gcd_value: GCD value calculated from the diff.
        :return: SP value
        """
        # If GCD value is greater than 9, divide the seq_rates by that value
        if gcd_value > 9:
            seq_rates = [rate / gcd_value for rate in seq_rates]

        # Compute the standard deviation of the seq_rates
        std_dev = statistics.stdev(seq_rates)

        # Calculate SP based on the standard deviation
        if std_dev <= 1:
            sp = 0
        else:
            sp = round(8 * math.log2(std_dev))

        return sp

    def ip_id_sequence(self, responses: list[IP/TCP] | list[IP/ICMP], test_type: str):
        """
        Calculate the IP ID sequence type based on the given ip_ids and the test type.

        :param responses: List of responses from the tcp_syn_probe or icmp_echo_probe.
        :param test_type: Test type ("TI", "CI", or "II").
        :return: IP ID sequence type
        """
        types = ["TI", "CI", "II"]

        if isinstance(responses, list) and test_type in types:
            # TI: needs at least 3 TCP SYN probe
            if test_type == "TI" and len(responses) < 3:
                return None
            # CI: needs at least 2 out of the T5,T6,T7 probe
            if test_type == "CI" and len(responses) < 2:
                return None
            # II: needs exactly 2 ICMP probe
            if test_type == "II" and len(responses) != 2:
                return None
        else:
            return None

        ip_ids = []
        for response in responses:
            if response and response.haslayer(IP):
                ip_ids.append(response[IP].id)

        # Sort the IP ID values
        if not ip_ids:
            return None

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
            return hex(ip_ids[0])

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
        return None

    def shared_ip_id(self, responses: list[IP/TCP], icmp_responses: list[IP/ICMP]):
        """
        Calculate the Shared IP ID sequence Boolean (SS).

        :param responses: List of TCP SYN response objects.
        :param icmp_responses: List of ICMP response objects.
        :return: 'S' if the sequence is shared, 'O' if it is not, and None if the test is not included.
        """

        # Extract IP IDs from the responses
        tcp_ip_ids = []
        icmp_ip_ids = []
        for response in responses:
            if response and response.haslayer(IP):
                tcp_ip_ids.append(response[IP].id)

        for response in icmp_responses:
            if response and response.haslayer(IP):
                icmp_ip_ids.append(response[IP].id)

        # Define the result for IP ID sequence generation algorithm
        def calculate_ip_id_sequence(ip_ids):
            differences = [(ip_ids[i + 1] - ip_ids[i]) % 65536 for i in range(len(ip_ids) - 1)]

            if all(id_val == 0 for id_val in ip_ids):
                return "Z"
            if len(set(ip_ids)) == 1:
                return hex(ip_ids[0])
            if any(diff > 1000 and diff % 256 != 0 for diff in differences):
                return "RI"
            if all(diff % 256 == 0 and diff <= 5120 for diff in differences):
                return "BI"
            if all(diff < 10 for diff in differences):
                return "I"
            return None

        ti_result = calculate_ip_id_sequence(tcp_ip_ids)
        ii_result = calculate_ip_id_sequence(icmp_ip_ids)

        # Check inclusion criteria
        if not (ii_result in ["RI", "BI", "I"] and ti_result == ii_result):
            return None

        # Calculate avg
        avg = (tcp_ip_ids[-1] - tcp_ip_ids[0]) / (len(tcp_ip_ids) - 1)

        # Determine if sequences are shared or not
        if icmp_ip_ids[0] < tcp_ip_ids[-1] + 3 * avg:
            return 'S'
        else:
            return 'O'

    def calculate_ts(self, responses: list[IP/TCP]):
        """
        Calculate the TCP timestamp option algorithm (TS).

        :param responses: List of TCP response objects containing the 'timestamp' field.
        :return: Calculated TS value.
        """

        # Extract TSvals from the responses
        tsvals = []
        tssents = []
        for response in responses:
            tssents.append(response.time)
            if response and response.haslayer(TCP):
                tsvals.append(response[TCP].time)

        # Check for unsupported or zero values
        if None in tsvals:
            return "U"
        if any(val == 0 for val in tsvals):
            return "0"

        # Compute average increments per second
        increments = [(tsvals[i + 1] - tsvals[i]) / (tssents[i + 1] - tssents[i]) for i in range(len(tsvals) - 1)]
        avg_increment = sum(increments) / len(increments)

        # Assign TS value based on avg_increment
        if 0 <= avg_increment <= 5.66:
            return "1"
        elif 70 <= avg_increment <= 150:
            return "7"
        elif 150 <= avg_increment <= 350:
            return "8"
        else:
            return str(round(math.log(avg_increment, 2)))

    def extract_tcp_options(self, responses: list[IP/TCP] | IP/TCP):
        """
        Extract TCP options from the given responses.

        :param responses: List of TCP response objects from tcp_syn_probe.
        :return: List of options strings for each packet respectively.
        """
        options = {"EOL": "L", "NOP": "N", "MSS": "N", "WScale": "W", "Timestamp": "T", "SAckOK": "S"}
        options_string = ""

        if isinstance(responses, list):
            res_list = []
            for response in responses:
                if response and response.haslayer(TCP):
                    option_list = response[TCP].options
                    for option in option_list:
                        options_string += options[option[0]]
                        if option[0] == "Timestamp":
                            options_string += "1" if option[1][0] != 0 else "0"
                            options_string += "1" if option[1][1] != 0 else "0"
                            continue
                        if option[1] is not None:
                            options_string += str(option[1])
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
                        options_string += str(option[1])
            return options_string

    def extract_tcp_window_size(self, responses: list[IP/TCP] | IP/TCP):
        """
        Extract the TCP window size from the packet.

        :param responses: List of TCP response objects from tcp_syn_probe.
        :return: List of window size values for each packet respectively or a single window size value.
        """
        if isinstance(responses, list):
            ws_list = []
            for response in responses:
                if response and response.haslayer(TCP):
                    window_size = response[TCP].window
                    ws_list.append(window_size)
            return ws_list
        else:
            if responses and responses.haslayer(TCP):
                window_size = responses[TCP].window
                return window_size

    def check_responsiveness(self, probe_type: str, response: IP/TCP | IP/ICMP | IP/UDP, has_closed_tcp_port: bool = True):
        """
        Checks the responsiveness of a target to a given probe.

        :param probe_type: The type of the probe. e.g. 'IE', 'U1', 'T5', etc.
        :param response: Whether a response was received for the probe.
        :param has_closed_tcp_port: Default is True. Indicates if there's a closed TCP port for a target.

        Returns:
        :returns 'Y' if the target responded, 'N' otherwise.
        """

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

    def check_dont_fragment_bit(self, response: IP/TCP | IP/ICMP | IP/UDP):
        """
        Checks if the 'don't fragment' bit in the IP header of a packet is set.

        Args:
        :param response: A representation of the IP packet. Assumes the packet has a key 'DF' indicating the state of the 'don't fragment' bit.

        Returns:
        :returns: 'Y' if the 'don't fragment' bit is set, 'N' otherwise.
        """
        if response.haslayer(IP):  # Check if packet has an IP layer
            if (response[IP].flags & 0x2) != 0:
                return "Y"
            else:
                return "N"

    def dfi_test_value(self, response: list[IP/ICMP]):
        """
        Determine the DFI test value based on the DF bits of the two ICMP echo request probe responses.

        :param response: List of ICMP echo request probe responses.
        :return: DFI test value ('N', 'S', 'Y', or 'O')
        """
        if len(response) != 2:
            return None

        df1 = (response[0][IP].flags & 0x2) != 0
        df2 = (response[1][IP].flags & 0x2) != 0

        if not df1 and not df2:
            return 'N'
        elif df1 == df2:
            return 'S'
        elif df1 and df2:
            return 'Y'
        else:
            return 'O'

    def compute_initial_ttl(self, response: IP/TCP | IP/UDP | IP/ICMP, u1_response):
        """
        Compute the initial TTL of the target's response.

        :param response: A response object from the tcp_probe, icmp_echo_probe, tcp_ecn_probe, udp_probe.
        :param u1_response: A response object from the udp_probe.
        :return: Initial TTL value.
        """
        # Determine hop count
        hop_count = u1_response[IP].ttl - u1_response[ICMP].ttl

        # Compute initial TTL of the target's response
        if response.haslayer(TCP):
            initial_ttl = response[TCP].ttl + hop_count
        elif response.haslayer(UDP):
            initial_ttl = response[UDP].ttl + hop_count
        else:
            initial_ttl = response[ICMP].ttl + hop_count

        return initial_ttl

    def ttl_guess_test(self, response: IP/TCP | IP/UDP | IP/ICMP):
        """
        Determine the TTL guess test value based on the TTL value of the target's response.

        :param response: A response object from the tcp_probe, icmp_echo_probe, tcp_ecn_probe, udp_probe.
        :return: TTL guess test value (32, 64, 128, or 255).
        """
        # If there's a response, extract the TTL
        if response.haslayer(TCP):
            received_ttl = response[TCP].ttl
        elif response.haslayer(UDP):
            received_ttl = response[UDP].ttl
        else:
            received_ttl = response[ICMP].ttl

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


    def congestion_control_test(self, response: IP/TCP):
        """
        Extract the ECN-related flags from the TCP layer of the packet and determine
        the CC value.

        :param response: A response object from the tcp_ecn_probe.
        :return: CC value ('Y', 'N', 'S', or 'O').
        """

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


    def check_tcp_quirks(self, response: IP/TCP):
        """
        Extract the TCP quirks from the TCP layer of the packet.
        :param response: Response object from the tcp_probe or tcp_ecn_probe.
        :return: returns a string of TCP quirks and if no quirks are found returns none.
        """
        q_string = ""

        # Check if the reserved field in TCP header is non-zero
        if response[TCP].reserved != 0:
            q_string += "R"

        # Check if the URG flag is not set but urgent pointer field is non-zero
        if not response[TCP].flags.URG and response[TCP].urgptr != 0:
            q_string += "U"

        return q_string or None

    def sequence_test(self, response: IP/TCP, seq_number: int):
        """
        Determine the S test value based on the sequence number and the ack number of the response.

        :param response: Response object from the tcp_probe.
        :param seq_number: the original sequence number of the probe.
        :return: returns the S test value ('Z', 'A', 'A+', or 'O').
        """
        ack_number = response[TCP].ack

        # Check conditions and determine the S test value
        if seq_number == 0:
            return 'Z'
        elif seq_number == ack_number:
            return 'A'
        elif seq_number == ack_number + 1:
            return 'A+'
        else:
            return 'O'
