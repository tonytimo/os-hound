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
