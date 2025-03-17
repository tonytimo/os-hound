<p align="center">
  <img src="https://github.com/tonytimo/os-hound/assets/72600701/ee6f61fd-646c-462d-adff-712d0b581e58" alt= "os-hound-logo2" />
</p>

# OS Hound: OS Fingerprinting Tool

OS Hound is a Python-based tool designed to actively fingerprint the operating system of a target host. By combining network scanning, probe generation, and response analysis, the tool builds a profile of the target’s OS characteristics and then scores the profile against a known database of OS fingerprints (sourced from Nmap’s OS Fingerprinting DB) to determine the most likely operating system.

## Overview

OS Hound performs the following steps:
- **Port Scanning:** Uses a SYN scan (via Scapy) to discover open ports on the target.
- **Probe Generation:** Sends multiple types of probes—TCP SYN probes with varied TCP options and ICMP Echo Requests—to elicit responses from the target.
- **Profile Building:** Processes the responses from probes using various test methods (such as calculating TCP sequence differences, window sizes, and IP ID sequences) to construct an OS fingerprint profile.
- **Scoring:** Compares the constructed profile against a database of OS fingerprints (parsed from the included `nmap-db.txt`) using a weighted scoring algorithm to identify the most likely operating system.

## Project Structure

- **main.py:**  
  The entry point for the tool. It displays a banner, prompts the user for the target IP address, and coordinates the scanning, probing, profiling, and scoring steps.

- **db_parser.py:**  
  Contains the `DbParser` class that reads and parses the Nmap OS fingerprint database (`nmap-db.txt`), converting each entry into a dictionary of OS fingerprint parameters.

- **nmap-db.txt:**  
  A database file containing OS fingerprint data (sourced from Nmap). This file is parsed to extract parameters such as SEQ, OPS, WIN, ECN, and various test fields (T1–T7, U1, IE).

- **port_scanner.py:**  
  Implements the `PortScanner` class which uses a SYN scan technique to detect open ports on the target host. It leverages Scapy for packet crafting and uses multithreading to improve scan speed.

- **probes.py:**  
  Defines the `Probes` class that creates and sends different types of probes:
  - **TCP SYN Probes:** Six variants with differing TCP options.
  - **ICMP Echo Probes:** Two variants with different ICMP options.
  These probes help in gathering response data used later in OS fingerprinting.

- **profile_builder.py:**  
  Uses responses from the probes to build a detailed OS profile. The `ProfileBuilder` class organizes fingerprint parameters (e.g., TCP sequence behavior, window sizes, and flags) into a structured dictionary.

- **scoring.py:**  
  Contains the `Scoring` class which scores the generated profile against each OS fingerprint from the database. Each parameter (SEQ, OPS, WIN, etc.) is weighted, and the OS with the highest score is considered the best match.

- **test_methods.py:**  
  Provides utility functions for analyzing the responses, including:
  - Calculating differences between TCP sequence numbers and their GCD.
  - Assessing TCP options, window sizes, and IP ID patterns.
  - Performing tests to check responsiveness and detect specific TCP/ICMP quirks.

## Installation

### Installing Dependencies
You can install the required packages using pip:

```bash
pip install https://github.com/tonytimo/os-hound/releases/download/v0.1.0/os_hound-0.1.0-py3-none-any.whl

