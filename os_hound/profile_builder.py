from test_methods import TestMethods
from scapy.layers.inet import TCP


class ProfileBuilder:
    def __init__(self, responses: dict):
        self.responses = responses
        self.methods = TestMethods()

    def build_profile(self):
        """
        Build the OS profile by using all the test methods
        based on the responses from all the probes sent.

        :return: returns a dictionary containing the OS profile
        """
        os_dict = {"SEQ": {}, "OPS": {}, "WIN": {}, "ECN": {}, "T1": {}, "T2": {}, "T3": {}, "T4": {}, "T5": {}, "T6": {}, "T7": {}, "U1": {}, "IE": {}}

        # SEQ
        diff1, gcd = self.methods.tcp_isn_gcd(self.responses["SYN"][0])
        isr, seq_rates = self.methods.tcp_isn_isr(diff1)
        os_dict["SEQ"]["SP"] = self.methods.tcp_isn_sp(seq_rates, gcd)
        os_dict["SEQ"]["GCD"] = gcd
        os_dict["SEQ"]["ISR"] = isr
        os_dict["SEQ"]["TI"] = self.methods.ip_id_sequence(self.responses["SYN"][0], "TI")
        os_dict["SEQ"]["CI"] = self.methods.ip_id_sequence([self.responses['T5'][0], self.responses['T6'][0], self.responses['T7'][0]], "CI")
        os_dict["SEQ"]["II"] = self.methods.ip_id_sequence(self.responses["IE"][0], "II")

        opt_ii = ["RI", "BI", "I"]
        if os_dict["SEQ"]["TI"] == os_dict["SEQ"]["II"] and os_dict["SEQ"]["II"] in opt_ii:
            os_dict["SEQ"]["SS"] = self.methods.shared_ip_id(self.responses["SYN"][0], self.responses["IE"][0])
        os_dict["SEQ"]["TS"] = self.methods.calculate_ts(self.responses["SYN"][0])

        # OPS
        op_list = self.methods.extract_tcp_options(self.responses["SYN"][0])
        op_counter = 1
        for op in op_list:
            os_dict["OPS"][f"O{op_counter}"] = op
            op_counter += 1

        # WIN
        ws_list = self.methods.extract_tcp_window_size(self.responses["SYN"][0])
        ws_counter = 1
        for ws in ws_list:
            os_dict["WIN"][f"W{ws_counter}"] = ws
            ws_counter += 1

        # ECN
        os_dict["ECN"]["R"] = self.methods.check_responsiveness("ECN", self.responses["ECN"][0])
        os_dict["ECN"]["DF"] = self.methods.check_dont_fragment_bit(self.responses["ECN"][0])
        os_dict["ECN"]["T"] = self.methods.compute_initial_ttl(self.responses["ECN"][0], self.responses["U1"][0])
        os_dict["ECN"]["TG"] = self.methods.ttl_guess_test(self.responses["ECN"][0])
        os_dict["ECN"]["W"] = self.methods.extract_tcp_window_size(self.responses["ECN"][0])
        os_dict["ECN"]["O"] = self.methods.extract_tcp_options(self.responses["ECN"][0])
        os_dict["ECN"]["CC"] = self.methods.congestion_control_test(self.responses["ECN"][0])
        os_dict["ECN"]["Q"] = self.methods.check_tcp_quirks(self.responses["ECN"][0])

        # T1
        os_dict["T1"]["R"] = self.methods.check_responsiveness("SYN", self.responses["SYN"][0][0])
        os_dict["T1"]["DF"] = self.methods.check_dont_fragment_bit(self.responses["SYN"][0][0])
        os_dict["T1"]["T"] = self.methods.compute_initial_ttl(self.responses["SYN"][0][0], self.responses["U1"][0])
        os_dict["T1"]["TG"] = self.methods.ttl_guess_test(self.responses["SYN"][0][0])
        os_dict["T1"]["S"] = self.methods.sequence_test(self.responses["SYN"][0][0], self.responses["SYN"][1][0])
        os_dict["T1"]["A"] = self.methods.ack_test(self.responses["SYN"][0][0], self.responses["SYN"][1][0])
        os_dict["T1"]["F"] = self.methods.extract_tcp_flags(self.responses["SYN"][0][0])
        os_dict["T1"]["RD"] = self.methods.get_rst_data_checksum(self.responses["SYN"][0][0])
        os_dict["T1"]["Q"] = self.methods.check_tcp_quirks(self.responses["SYN"][0][0])

        # T2
        os_dict["T2"]["R"] = self.methods.check_responsiveness("SYN", self.responses["T2"][0])
        os_dict["T2"]["DF"] = self.methods.check_dont_fragment_bit(self.responses["T2"][0])
        os_dict["T2"]["T"] = self.methods.compute_initial_ttl(self.responses["T2"][0], self.responses["U1"][0])
        os_dict["T2"]["TG"] = self.methods.ttl_guess_test(self.responses["T2"][0])
        os_dict["T2"]["W"] = self.methods.extract_tcp_window_size(self.responses["T2"][0])
        os_dict["T2"]["S"] = self.methods.sequence_test(self.responses["T2"][0], self.responses["T2"][1])
        os_dict["T2"]["A"] = self.methods.ack_test(self.responses["T2"][0], self.responses["T2"][1])
        os_dict["T2"]["F"] = self.methods.extract_tcp_flags(self.responses["T2"][0])
        os_dict["T2"]["RD"] = self.methods.get_rst_data_checksum(self.responses["T2"][0])
        os_dict["T2"]["Q"] = self.methods.check_tcp_quirks(self.responses["T2"][0])

        # T3
        os_dict["T3"]["R"] = self.methods.check_responsiveness("SYN", self.responses["T3"][0])
        os_dict["T3"]["DF"] = self.methods.check_dont_fragment_bit(self.responses["T3"][0])
        os_dict["T3"]["T"] = self.methods.compute_initial_ttl(self.responses["T3"][0], self.responses["U1"][0])
        os_dict["T3"]["TG"] = self.methods.ttl_guess_test(self.responses["T3"][0])
        os_dict["T3"]["W"] = self.methods.extract_tcp_window_size(self.responses["T3"][0])
        os_dict["T3"]["S"] = self.methods.sequence_test(self.responses["T3"][0], self.responses["T3"][1])
        os_dict["T3"]["A"] = self.methods.ack_test(self.responses["T3"][0], self.responses["T3"][1])
        os_dict["T3"]["F"] = self.methods.extract_tcp_flags(self.responses["T3"][0])
        os_dict["T3"]["RD"] = self.methods.get_rst_data_checksum(self.responses["T3"][0])
        os_dict["T3"]["Q"] = self.methods.check_tcp_quirks(self.responses["T3"][0])

        # T4
        os_dict["T4"]["R"] = self.methods.check_responsiveness("SYN", self.responses["T4"][0])
        os_dict["T4"]["DF"] = self.methods.check_dont_fragment_bit(self.responses["T4"][0])
        os_dict["T4"]["T"] = self.methods.compute_initial_ttl(self.responses["T4"][0], self.responses["U1"][0])
        os_dict["T4"]["TG"] = self.methods.ttl_guess_test(self.responses["T4"][0])
        os_dict["T4"]["W"] = self.methods.extract_tcp_window_size(self.responses["T4"][0])
        os_dict["T4"]["S"] = self.methods.sequence_test(self.responses["T4"][0], self.responses["T4"][1])
        os_dict["T4"]["A"] = self.methods.ack_test(self.responses["T4"][0], self.responses["T4"][1])
        os_dict["T4"]["F"] = self.methods.extract_tcp_flags(self.responses["T4"][0])
        os_dict["T4"]["RD"] = self.methods.get_rst_data_checksum(self.responses["T4"][0])
        os_dict["T4"]["Q"] = self.methods.check_tcp_quirks(self.responses["T4"][0])

        # T5
        os_dict["T5"]["R"] = self.methods.check_responsiveness("SYN", self.responses["T5"][0])
        os_dict["T5"]["DF"] = self.methods.check_dont_fragment_bit(self.responses["T5"][0])
        os_dict["T5"]["T"] = self.methods.compute_initial_ttl(self.responses["T5"][0], self.responses["U1"][0])
        os_dict["T5"]["TG"] = self.methods.ttl_guess_test(self.responses["T5"][0])
        os_dict["T5"]["W"] = self.methods.extract_tcp_window_size(self.responses["T5"][0])
        os_dict["T5"]["S"] = self.methods.sequence_test(self.responses["T5"][0], self.responses["T5"][1])
        os_dict["T5"]["A"] = self.methods.ack_test(self.responses["T5"][0], self.responses["T5"][1])
        os_dict["T5"]["F"] = self.methods.extract_tcp_flags(self.responses["T5"][0])
        os_dict["T5"]["RD"] = self.methods.get_rst_data_checksum(self.responses["T5"][0])
        os_dict["T5"]["Q"] = self.methods.check_tcp_quirks(self.responses["T5"][0])

        # T6
        os_dict["T6"]["R"] = self.methods.check_responsiveness("SYN", self.responses["T6"][0])
        os_dict["T6"]["DF"] = self.methods.check_dont_fragment_bit(self.responses["T6"][0])
        os_dict["T6"]["T"] = self.methods.compute_initial_ttl(self.responses["T6"][0], self.responses["U1"][0])
        os_dict["T6"]["TG"] = self.methods.ttl_guess_test(self.responses["T6"][0])
        os_dict["T6"]["W"] = self.methods.extract_tcp_window_size(self.responses["T6"][0])
        os_dict["T6"]["S"] = self.methods.sequence_test(self.responses["T6"][0], self.responses["T6"][1])
        os_dict["T6"]["A"] = self.methods.ack_test(self.responses["T6"][0], self.responses["T6"][1])
        os_dict["T6"]["F"] = self.methods.extract_tcp_flags(self.responses["T6"][0])
        os_dict["T6"]["RD"] = self.methods.get_rst_data_checksum(self.responses["T6"][0])
        os_dict["T6"]["Q"] = self.methods.check_tcp_quirks(self.responses["T6"][0])

        # T7
        os_dict["T7"]["R"] = self.methods.check_responsiveness("SYN", self.responses["T7"][0])
        os_dict["T7"]["DF"] = self.methods.check_dont_fragment_bit(self.responses["T7"][0])
        os_dict["T7"]["T"] = self.methods.compute_initial_ttl(self.responses["T7"][0], self.responses["U1"][0])
        os_dict["T7"]["TG"] = self.methods.ttl_guess_test(self.responses["T7"][0])
        os_dict["T7"]["W"] = self.methods.extract_tcp_window_size(self.responses["T7"][0])
        os_dict["T7"]["S"] = self.methods.sequence_test(self.responses["T7"][0], self.responses["T7"][1])
        os_dict["T7"]["A"] = self.methods.ack_test(self.responses["T7"][0], self.responses["T7"][1])
        os_dict["T7"]["F"] = self.methods.extract_tcp_flags(self.responses["T7"][0])
        os_dict["T7"]["RD"] = self.methods.get_rst_data_checksum(self.responses["T7"][0])
        os_dict["T7"]["Q"] = self.methods.check_tcp_quirks(self.responses["T7"][0])

        # U1
        os_dict["U1"]["R"] = self.methods.check_responsiveness("U1", self.responses["U1"][0])
        os_dict["U1"]["DF"] = self.methods.check_dont_fragment_bit(self.responses["U1"][0])
        os_dict["U1"]["T"] = self.methods.compute_initial_ttl(self.responses["U1"][0], self.responses["U1"][0])
        os_dict["U1"]["TG"] = self.methods.ttl_guess_test(self.responses["U1"][0])
        os_dict["U1"]["IPL"] = self.methods.get_ip_total_length(self.responses["U1"][0])
        os_dict["U1"]["UN"] = self.methods.check_icmp_unused_field(self.responses["U1"][0])
        os_dict["U1"]["RIPL"] = self.methods.check_returned_ip_length(self.responses["U1"][0])
        os_dict["U1"]["RID"] = self.methods.check_returned_ip_id(self.responses["U1"][0])
        os_dict["U1"]["RIPCK"] = self.methods.check_returned_ip_checksum(self.responses["U1"][0])
        os_dict["U1"]["RUCK"] = self.methods.check_returned_udp_checksum(self.responses["U1"][0], self.responses["U1"][1])
        os_dict["U1"]["RUD"] = self.methods.check_returned_udp_data_integrity(self.responses["U1"][0])

        # IE
        r1 = self.methods.check_responsiveness("IE", self.responses["IE"][0][0])
        r2 = self.methods.check_responsiveness("IE", self.responses["IE"][0][1])
        if r1 and r2:
            os_dict["IE"]["R"] = "Y"
        else:
            os_dict["IE"]["R"] = "N"

        os_dict["IE"]["DFI"] = self.methods.dfi_test_value(self.responses["IE"][0])
        os_dict["IE"]["T"] = self.methods.compute_initial_ttl(self.responses["IE"][0][0], self.responses["U1"][0])
        os_dict["IE"]["TG"] = self.methods.ttl_guess_test(self.responses["IE"][0][0])
        os_dict["IE"]["CD"] = self.methods.icmp_response_code(self.responses["IE"][0])

        # Remove None keys
        for key in list(os_dict.keys()):
            for k in list(os_dict[key].keys()):
                if os_dict[key][k] == "None":
                    os_dict[key].pop(k)

        return os_dict
