import sys
from port_scanner import PortScanner


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


if __name__ == "__main__":
    main()
