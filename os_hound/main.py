import sys
from os_hound.db_parser import DbParser
from os_hound.scoring import Scoring
from os_hound.profile_builder import ProfileBuilder
from port_scanner import PortScanner
from probes import Probes


def main():
    try:
        target = input("Enter the IP address to scan: ")
        start = int(input("Enter the start port number: "))
        end = int(input("Enter the end port number: "))

        if start > end or start < 0 or end > 65535:
            raise ValueError("Invalid port range. Ports should be between 0 and 65535.")

    except ValueError as ve:
        print(ve)
        sys.exit(1)

    open_ports = PortScanner().syn_scan(target, start, end)

    if open_ports:
        print(f"Open ports on {target}: {', '.join(map(str, open_ports))}")
    else:
        print(f"No open ports found on {target} between ports {start} and {end}.")

    p = Probes(target, open_ports)
    probes = [p.tcp_syn_probe, p.icmp_echo_probe, p.tcp_ecn_probe, p.tcp_probe, p.tcp_probe, p.tcp_probe, p.tcp_probe, p.tcp_probe, p.tcp_probe, p.udp_probe]
    responses = {}
    for i in range(0, len(probes)):
        if probes[i] == p.tcp_probe:
            response, probe_type, seq = probes[i](f'T{i-1}')
            responses[probe_type] = [response, seq]
            continue
        response, probe_type = probes[i]()
        responses[probe_type] = response

    profile = ProfileBuilder(responses).build_profile()
    os_dicts = DbParser().parse_db()
    results = Scoring().score(profile, os_dicts)
    print(results)


if __name__ == "__main__":
    main()
