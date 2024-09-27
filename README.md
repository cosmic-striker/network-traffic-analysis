Here's a simple README file for your Scapy-based packet manipulation script:

---

# Scapy Interactive Script

## Overview

This Python script provides various network utilities using the `Scapy` library. It allows users to sniff packets, craft and send packets, perform ping scans, traceroute, and fuzz packets to test network behavior. The script features an interactive menu for easy selection of tasks.

## Features

1. **Packet Sniffing:** Captures packets on a specified network interface.
2. **Craft and Send Packet:** Crafts a simple IP and TCP packet and sends it to a destination IP.
3. **Ping Scan:** Sends an ICMP packet to check if the target IP is reachable.
4. **Traceroute:** Traces the route to a target IP.
5. **Packet Fuzzing:** Sends a fuzzed packet to a destination IP for testing network behavior.

## Requirements

- **Python 3.x**: Ensure that Python 3.x is installed on your system.
- **Scapy**: Install the Scapy library for packet manipulation.

You can install Scapy using pip:

```bash
pip install scapy
```

### Additional Dependencies

The script also uses the `socket` module, which comes pre-installed with Python.

## Usage

1. **Clone the repository or download the script:**

```bash
git clone https://github.com/cosmic-striker/scapy-interactive-script.git
cd scapy-interactive-script
```

2. **Run the script:**

Ensure you run the script with elevated privileges, as packet sniffing and crafting require root/admin access.

```bash
sudo python3 scapy_script.py
```

3. **Interactive Menu:**

You will be prompted to select an option from the following:

- `1` : Sniff packets on a specific interface (e.g., `eth0`, `wlan0`).
- `2` : Craft and send a packet to a specified target IP address.
- `3` : Perform a ping scan on a specified target IP address.
- `4` : Perform a traceroute to a specified target IP address.
- `5` : Fuzz a packet and send it to a target IP address.
- `6` : Exit the script.

## Example

1. **Packet Sniffing:**

```bash
Enter network interface (e.g., eth0): eth0
```

2. **Craft and Send a Packet:**

```bash
Enter target IP address: 192.168.1.1
```

3. **Ping Scan:**

```bash
Enter target IP address: 192.168.1.1
```

## Error Handling

The script includes error handling for:
- Invalid IP address formats.
- Permission issues when running packet sniffing or crafting tasks without proper privileges.
- General exceptions during network operations.

## Note

Some of the script's functionalities may require administrative privileges to execute properly. Make sure to run the script with elevated privileges (e.g., using `sudo` on Linux or running as Administrator on Windows).

---

This README provides clear instructions and context for users to run and understand the capabilities of the script.
