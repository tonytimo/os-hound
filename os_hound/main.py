import sys
import re
import questionary
from db_parser import DbParser
from scoring import Scoring
from profile_builder import ProfileBuilder
from port_scanner import PortScanner
from probes import Probes

#TODO: Change the most common ports option in the switch to get the dictionary port list
# and add option of the 1000 first ports
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
__________________________________________/\\\_______________________________________________________________/\\\__        
 _________________________________________\/\\\______________________________________________________________\/\\\__       
  _________________________________________\/\\\______________________________________________________________\/\\\__      
   _____/\\\\\______/\\\\\\\\\\_____________\/\\\______________/\\\\\______/\\\____/\\\___/\\/\\\\\\___________\/\\\__     
    ___/\\\///\\\___\/\\\//////______________\/\\\\\\\\\\_____/\\\///\\\___\/\\\___\/\\\__\/\\\////\\\_____/\\\\\\\\\__    
     __/\\\__\//\\\__\/\\\\\\\\\\_____________\/\\\/////\\\___/\\\__\//\\\__\/\\\___\/\\\__\/\\\__\//\\\___/\\\////\\\__   
      _\//\\\__/\\\___\////////\\\_____________\/\\\___\/\\\__\//\\\__/\\\___\/\\\___\/\\\__\/\\\___\/\\\__\/\\\__\/\\\__  
       __\///\\\\\/_____/\\\\\\\\\\_____________\/\\\___\/\\\___\///\\\\\/____\//\\\\\\\\\___\/\\\___\/\\\__\//\\\\\\\/\\_ 
        ____\/////______\//////////______________\///____\///______\/////_______\/////////____\///____\///____\///////\//__
"""
    print(title)
    print("Welcome to OS Hound!")
    print("OS Hound is a tool that uses fingerprinting to identify the operating system of a target host.")

    # --- Production code ---
    try:
        target = questionary.text("Enter the IP address to scan: ").ask()
        match = re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", target)
        if not target:
            raise ValueError("You've entered an empty string this is an invalid IP address.")
        elif target == 'localhost':
            pass
        elif not bool(match):
            raise ValueError("You've entered an Invalid IP address.")
        scan_type = questionary.select("Select a scan type:", choices=["Most common ports", "All ports", "Port Range"]).ask()
        match scan_type:
            case "Most common ports":
                start = 1
                end = 1024
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
    # ---------------------

    # --- Testing code ---
    # try:
    #     target = input("Enter the IP address to scan: ")
    #     start = int(input("Enter the start port number: "))
    #     end = int(input("Enter the end port number: "))
    #
    #     if start > end or start < 0 or end > 65535:
    #         raise ValueError("Invalid port range. Ports should be between 0 and 65535.")
    #
    # except ValueError as ve:
    #     print(ve)
    #     sys.exit(1)
    # ---------------------

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
    print("Open Ports: ")
    print("Port  |  Service")
    for k in open_ports:
        if k in common_ports.keys():
            print(f"{k}        {common_ports.get(k)}")
        else:
            print(f"{k}        not common")
    print(f"The OS Prediction is:\n {results[0][0]['os_title']}")


if __name__ == "__main__":
    main()
