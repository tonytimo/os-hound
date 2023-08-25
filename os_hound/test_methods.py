from helper import HelperFunctions
from scapy.layers.inet import IP, TCP, ICMP, UDP


class TestMethods:
    def __init__(self, response: TCP | ICMP | UDP | list[TCP]):
        self.response = response

    def gcd_diff(self):
        differences = []
        previous_isn = None
        if isinstance(self.response, list):
            for response in self.response:
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
