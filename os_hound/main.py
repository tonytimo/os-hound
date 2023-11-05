import sys
import re
import questionary
from tabulate import tabulate
from db_parser import DbParser
from scoring import Scoring
from profile_builder import ProfileBuilder
from port_scanner import PortScanner
from probes import Probes


def main():
    common_ports = {
        7: "Echo",
        20: "FTP Data",
        21: "FTP Control",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        42: "WINS Replication",
        53: "DNS",
        67: "DHCP Server",
        68: "DHCP Client",
        69: "TFTP",
        80: "HTTP",
        88: "Kerberos",
        102: "MS Exchange",
        110: "POP3",
        119: "NNTP",
        123: "NTP",
        135: "MS RPC",
        137: "NetBIOS Name Service",
        138: "NetBIOS Datagram Service",
        139: "NetBIOS Session Service",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP Trap",
        179: "BGP",
        389: "LDAP",
        443: "HTTPS",
        444: "Simple Network Paging Protocol",
        445: "MS-DS SMB file sharing",
        464: "Kerberos Change/Set password",
        465: "SMTP over SSL",
        512: "rexec",
        513: "rlogin",
        514: "Syslog",
        515: "LPD/LPR for printing",
        587: "SMTP TLS/SSL",
        636: "LDAP over SSL/TLS",
        771: "Kerberos admin/chpwd",
        953: "DNS over TLS/SSL",
        989: "FTPS Data",
        990: "FTPS Control",
        993: "IMAP4 over TLS/SSL",
        995: "POP3 over TLS/SSL",
        3389: "Microsoft Terminal Service",
        5222: "XMPP Client",
        5269: "XMPP Server",
        5432: "PostgreSQL",
        3306: "MySQL",
        8443: "HTTPS component of Apache and Tomcat",
        6660: "Internet Relay Chat (IRC)",
        6669: "Internet Relay Chat (IRC)"
    }

    title = r""" 
_______________________________________/\\\___________________________________________________________/\\\__        
 ______________________________________\/\\\__________________________________________________________\/\\\__       
  ______________________________________\/\\\__________________________________________________________\/\\\__      
   _____/\\\\\_____/\\\\\\\\\\___________\/\\\_____________/\\\\\_____/\\\____/\\\__/\\/\\\\\\__________\/\\\__     
    ___/\\\///\\\__\/\\\//////____________\/\\\\\\\\\\____/\\\///\\\__\/\\\___\/\\\_\/\\\////\\\____/\\\\\\\\\__    
     __/\\\__\//\\\_\/\\\\\\\\\\___________\/\\\/////\\\__/\\\__\//\\\_\/\\\___\/\\\_\/\\\__\//\\\__/\\\////\\\__   
      _\//\\\__/\\\__\////////\\\___________\/\\\___\/\\\_\//\\\__/\\\__\/\\\___\/\\\_\/\\\___\/\\\_\/\\\__\/\\\__  
       __\///\\\\\/____/\\\\\\\\\\___________\/\\\___\/\\\__\///\\\\\/___\//\\\\\\\\\__\/\\\___\/\\\_\//\\\\\\\/\\_ 
        ____\/////_____\//////////____________\///____\///_____\/////______\/////////___\///____\///___\///////\//__
    """
    print(title)
    print("Welcome to OS Hound!")
    print("OS Hound is a tool that uses fingerprinting to identify the operating system of a target host.")

    # --- Production code ---
    try:
        common_ports_list = None
        start = None
        end = None
        target = questionary.text("Enter the IP address to scan: ").ask()
        match = re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", target)
        if not target:
            raise ValueError("You've entered an empty string this is an invalid IP address.")
        elif target == 'localhost':
            pass
        elif not bool(match):
            raise ValueError("You've entered an Invalid IP address.")
        scan_type = questionary.select("Select a scan type:", choices=["Most common ports", "Port Range", "1000 first ports","All ports"]).ask()
        match scan_type:
            case "1000 first ports":
                start = 1
                end = 1024
            case "Most common ports":
                common_ports_list = list(common_ports.keys())
                ans = questionary.select("Do you want to know what are the most common ports?", choices=["Yes", "No"]).ask()
                if ans == "Yes":
                    print(tabulate(common_ports.items(), headers=["Port", "Service"], tablefmt="grid"))
            case "All ports":
                start = 1
                end = 65535
            case "Port Range":
                start = int(questionary.text("Enter the start port number: ").ask())
                end = int(questionary.text("Enter the end port number: ").ask())
                if start > end or start < 0 or end > 65535:
                    raise ValueError("Invalid port range. Ports should be between 0 and 65535.")
            case _:
                raise ValueError("Invalid scan type.")

    except ValueError as ve:
        print(ve)
        sys.exit(1)

    open_ports = PortScanner().syn_scan(target, start, end, common_ports_list)

    if not open_ports:
        print(f"No open ports found on {target} between ports {start} and {end}.")
        raise SystemExit

    p = Probes(target, open_ports)
    probes = [p.tcp_syn_probe, p.icmp_echo_probe, p.tcp_ecn_probe, p.tcp_probe, p.tcp_probe, p.tcp_probe, p.tcp_probe, p.tcp_probe, p.tcp_probe, p.udp_probe]
    responses = {}
    for i in range(0, len(probes)):
        if probes[i] == p.tcp_probe:
            response, probe_type, original_pkt = probes[i](f'T{i-1}')
            responses[probe_type] = [response, original_pkt]
            continue
        else:
            response, probe_type, original_pkt = probes[i]()
            responses[probe_type] = [response, original_pkt]
            continue

    profile = ProfileBuilder(responses).build_profile()
    os_dicts = DbParser().parse_db()
    results = Scoring().score(profile, os_dicts)
    print("Open Ports: ")
    col_names = ["Port", "Service"]
    data = []
    for k in open_ports:
        if k in common_ports.keys():
            data.append((k, common_ports.get(k)))
        else:
            data.append((k, "not common"))

    print("\n")
    print(tabulate(data, headers=col_names, tablefmt="grid"))
    print("\n")
    print(f"The OS Prediction is:\n {results[0][0]['os_title']}")


if __name__ == "__main__":
    main()
