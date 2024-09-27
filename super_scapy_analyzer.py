import scapy.all as scapy
import socket
import netifaces
from datetime import datetime

# For OS fingerprinting and packet logging
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP

# Packet callback for sniffing
def packet_callback(packet, log_file=None):
    try:
        print(f"\nPacket captured: {packet.summary()}")
        # Display packet details
        packet.show()
        # If logging is enabled, write packet details to the file
        if log_file:
            with open(log_file, "a") as f:
                f.write(f"\nTimestamp: {datetime.now()}\n{packet.summary()}\n{packet.show(dump=True)}\n")
    except Exception as e:
        print(f"Error in packet callback: {e}")

# Sniff packets on an interface with optional filtering and logging
def sniff_packets(interface, timeout=None, filter_protocol=None, log_file=None):
    try:
        print(f"Sniffing on interface {interface} with filter '{filter_protocol}'... (Press Ctrl+C to stop)")
        scapy.sniff(iface=interface, prn=lambda packet: packet_callback(packet, log_file),
                    store=0, timeout=timeout, filter=filter_protocol)
        print("Sniffing complete.")
    except PermissionError:
        print("Error: Permission denied. You may need to run this script with elevated privileges.")
    except Exception as e:
        print(f"An error occurred while sniffing: {e}")

# Craft and send a packet to a specific destination
def craft_and_send_packet(destination_ip, protocol="TCP", dport=80):
    try:
        print(f"Crafting and sending {protocol} packet to {destination_ip} on port {dport}...")
        if protocol == "TCP":
            packet = scapy.IP(dst=destination_ip) / scapy.TCP(dport=dport)
        elif protocol == "UDP":
            packet = scapy.IP(dst=destination_ip) / scapy.UDP(dport=dport)
        scapy.send(packet)
        print("Packet sent.")
    except Exception as e:
        print(f"An error occurred while sending the packet: {e}")

# Perform a ping scan to check if a host is up
def perform_ping_scan(target_ip):
    try:
        socket.inet_pton(socket.AF_INET, target_ip)  # Validate IP address format
        print(f"Performing ping scan to {target_ip}...")
        
        packet = scapy.IP(dst=target_ip) / scapy.ICMP()  # Create ICMP packet
        response = scapy.sr1(packet, timeout=2)  # Send packet
        
        if response:
            print(f"Host {target_ip} is up.")
        else:
            print(f"Host {target_ip} is down.")
    except socket.error:
        print("Error: Invalid IP address format.")
    except Exception as e:
        print(f"An error occurred during the ping scan: {e}")

# Perform continuous ping scanning for multiple targets
def continuous_ping_scan(target_ips):
    for ip in target_ips:
        perform_ping_scan(ip)

# Perform a traceroute to a specific destination
def perform_traceroute(target_ip):
    try:
        print(f"Performing traceroute to {target_ip}...")
        scapy.traceroute(target_ip)
    except Exception as e:
        print(f"An error occurred during traceroute: {e}")

# Fuzz a packet and send it to the destination
def fuzz_packet(destination_ip):
    try:
        print(f"Fuzzing packet to {destination_ip}...")
        packet = scapy.IP(dst=destination_ip) / scapy.TCP(dport=80)
        fuzzed_packet = scapy.fuzz(packet)
        scapy.send(fuzzed_packet)
        print("Fuzzed packet sent.")
    except Exception as e:
        print(f"An error occurred while fuzzing the packet: {e}")

# Perform an ARP scan on a network range
def perform_arp_scan(network_range):
    try:
        print(f"Performing ARP scan on {network_range}...")
        answered, unanswered = scapy.arping(network_range)
        print("ARP scan complete.")
    except Exception as e:
        print(f"An error occurred during the ARP scan: {e}")

# Basic OS fingerprinting based on packet response
def os_fingerprinting(target_ip):
    try:
        print(f"Performing OS fingerprinting on {target_ip}...")
        packet = scapy.IP(dst=target_ip) / scapy.TCP(dport=80)
        response = scapy.sr1(packet, timeout=2)
        if response:
            ttl = response[IP].ttl
            if ttl <= 64:
                print(f"Target {target_ip} is likely running a Linux/Unix-based OS (TTL={ttl}).")
            elif ttl <= 128:
                print(f"Target {target_ip} is likely running a Windows OS (TTL={ttl}).")
            else:
                print(f"Could not determine OS for {target_ip} (TTL={ttl}).")
        else:
            print(f"No response received from {target_ip}. OS fingerprinting failed.")
    except Exception as e:
        print(f"An error occurred during OS fingerprinting: {e}")

# List available network interfaces
def list_interfaces():
    interfaces = netifaces.interfaces()
    print("Available network interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"{idx+1}. {iface}")
    return interfaces

# Main interactive script menu
def main():
    print("Welcome to the Full-Featured Scapy Interactive Script")
    while True:
        print("\nSelect an option:")
        print("1. Sniff packets")
        print("2. Craft and send a packet")
        print("3. Perform a ping scan")
        print("4. Perform a traceroute")
        print("5. Fuzz a packet")
        print("6. Perform an ARP scan")
        print("7. OS Fingerprinting")
        print("8. Continuous Ping Scan")
        print("9. Exit")

        choice = input("Enter your choice (1-9): ")

        if choice == "1":
            interfaces = list_interfaces()
            interface_choice = int(input("Choose a network interface (number): ")) - 1
            filter_protocol = input("Enter a protocol filter (e.g., 'icmp', 'tcp', 'udp'), or press Enter for no filter: ")
            timeout = input("Enter sniffing duration in seconds (or press Enter to sniff indefinitely): ")
            timeout = int(timeout) if timeout else None
            log_file = input("Enter log file path (or press Enter to skip logging): ") or None
            sniff_packets(interfaces[interface_choice], timeout, filter_protocol, log_file)
        elif choice == "2":
            target_ip = input("Enter target IP address: ")
            protocol = input("Enter protocol (TCP/UDP): ").upper()
            dport = int(input("Enter destination port (default 80): ") or 80)
            craft_and_send_packet(target_ip, protocol, dport)
        elif choice == "3":
            target_ip = input("Enter target IP address: ")
            perform_ping_scan(target_ip)
        elif choice == "4":
            target_ip = input("Enter target IP address: ")
            perform_traceroute(target_ip)
        elif choice == "5":
            target_ip = input("Enter target IP address: ")
            fuzz_packet(target_ip)
        elif choice == "6":
            network_range = input("Enter network range (e.g., 192.168.1.0/24): ")
            perform_arp_scan(network_range)
        elif choice == "7":
            target_ip = input("Enter target IP address for OS fingerprinting: ")
            os_fingerprinting(target_ip)
        elif choice == "8":
            target_ips = input("Enter target IP addresses (comma-separated): ").split(',')
            continuous_ping_scan([ip.strip() for ip in target_ips])
        elif choice == "9":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 9.")

if __name__ == "__main__":
    main()

##under development
