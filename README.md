# 📡 Scapy Interactive Network Tool

This interactive Python script allows you to perform various network operations using the **Scapy** library. The tool offers functionality such as packet sniffing, crafting and sending packets, ping scanning, tracerouting, fuzzing, ARP scanning, OS fingerprinting, and more!

---

## Features

### 🔍 Packet Sniffing
- Sniff network traffic on a selected interface.
- Option to filter by protocol (TCP, UDP, ICMP, etc.).
- Log captured packets to a file with full packet details and timestamps.

### ✉️ Craft and Send Packets
- Craft and send custom **TCP** or **UDP** packets to a target IP.
- Specify destination port for more customization.

### 📶 Ping Scanning
- Perform a ping scan to check if a single host is up.
- **Continuous Ping Scan** allows you to ping multiple targets in sequence.

### 🛣️ Traceroute
- Perform a traceroute to a specific target IP to trace network routes.

### 🤖 Fuzzing
- Fuzz TCP packets and send them to a target IP to test for vulnerabilities.

### 🌐 ARP Scanning
- Perform an ARP scan on a local network range to discover devices.

### 🖥️ OS Fingerprinting
- Basic OS fingerprinting based on TTL values, detecting if the target is likely **Linux/Unix** or **Windows**.

---

## Requirements

The script depends on the following Python libraries:
- **scapy**
- **netifaces**

### Installation
You can install the required libraries via pip:

```bash
pip install scapy netifaces
```

---

## Usage

Run the script using Python 3:

```bash
python scapy_interactive_tool.py
```

Once the script starts, you will be prompted to choose from a set of options:

### Main Menu Options

1. **Sniff Packets**
   - Choose a network interface.
   - Optionally specify a protocol filter (e.g., `icmp`, `tcp`, `udp`).
   - Set a timeout for how long you want to sniff.
   - Optionally log captured packets to a file.

2. **Craft and Send a Packet**
   - Enter a target IP.
   - Choose between **TCP** or **UDP**.
   - Specify the destination port (default is 80).

3. **Perform a Ping Scan**
   - Enter a target IP address to check if the host is reachable.

4. **Perform a Traceroute**
   - Enter a target IP to trace the network route to the host.

5. **Fuzz a Packet**
   - Enter a target IP to fuzz and send a randomized TCP packet to the target's port 80.

6. **Perform an ARP Scan**
   - Enter a network range (e.g., `192.168.1.0/24`) to discover live hosts on the network.

7. **OS Fingerprinting**
   - Enter a target IP to attempt basic OS detection based on the TTL of the response.

8. **Continuous Ping Scan**
   - Enter a comma-separated list of IPs to perform ping scanning on multiple targets in sequence.

9. **Exit**
   - Exits the script.

---

## Example

### Sniffing Packets

```bash
Select an option:
1. Sniff packets
```

- **Interface**: `eth0`
- **Filter**: `icmp`
- **Duration**: 60 seconds
- **Log File**: `/path/to/log.txt`

The script will sniff ICMP packets on interface `eth0` for 60 seconds and log them to the specified file.

---

## Notes

- Some actions (like packet sniffing and sending) require elevated privileges. If you encounter a permission error, try running the script with `sudo`:
  
  ```bash
  sudo python scapy_interactive_tool.py
  ```

- Always ensure you have permission to perform network operations on your network.

---

## Future Enhancements

Planned features:
- Add support for DNS queries and responses.
- Implement real-time graphical plotting for network response times.
- Integrate multi-threading for faster ARP scans on large networks.

---

## License

This project is licensed under the MIT License. See the LICENSE file for more information.

---

### Author

Developed by Python Copilot 🔨🤖🔧

Feel free to contribute or suggest improvements!

---

This `README.md` provides an overview of the tool, its functionality, and usage instructions. Let me know if you want to add or change anything! 😊
