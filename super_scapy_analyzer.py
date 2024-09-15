import scapy.all as scapy
import sys

def packet_callback(packet):
    print("\nPacket captured:")
    packet.show()

def sniff_packets(interface):
    try:
        print(f"Sniffing on interface {interface}...")
        scapy.sniff(iface=interface, prn=packet_callback, store=0)
    except PermissionError:
        print("Error: Permission denied. You may need to run this script with elevated privileges.")
    except Exception as e:
        print(f"An error occurred while sniffing: {e}")

def craft_and_send_packet(destination_ip):
    try:
        print(f"Crafting and sending packet to {destination_ip}...")
        packet = scapy.IP(dst=destination_ip) / scapy.TCP(dport=80)
        scapy.send(packet)
        print("Packet sent.")
    except Exception as e:
        print(f"An error occurred while sending the packet: {e}")

def perform_ping_scan(target_ip):
    try:
        print(f"Performing ping scan to {target_ip}...")
        packet = scapy.IP(dst=target_ip) / scapy.ICMP()
        response = scapy.sr1(packet, timeout=2)
        if response:
            print(f"Host {target_ip} is up.")
        else:
            print(f"Host {target_ip} is down.")
    except Exception as e:
        print(f"An error occurred during the ping scan: {e}")

def perform_traceroute(target_ip):
    try:
        print(f"Performing traceroute to {target_ip}...")
        scapy.traceroute(target_ip)
    except Exception as e:
        print(f"An error occurred during traceroute: {e}")

def fuzz_packet(destination_ip):
    try:
        print(f"Fuzzing packet to {destination_ip}...")
        packet = scapy.IP(dst=destination_ip) / scapy.TCP(dport=80)
        fuzzed_packet = scapy.fuzz(packet)
        scapy.send(fuzzed_packet)
        print("Fuzzed packet sent.")
    except Exception as e:
        print(f"An error occurred while fuzzing the packet: {e}")

def main():
    print("Welcome to the Scapy Interactive Script")
    while True:
        print("\nSelect an option:")
        print("1. Sniff packets")
        print("2. Craft and send a packet")
        print("3. Perform a ping scan")
        print("4. Perform a traceroute")
        print("5. Fuzz a packet")
        print("6. Exit")

        choice = input("Enter your choice (1-6): ")

        if choice == "1":
            interface = input("Enter network interface (e.g., eth0): ")
            sniff_packets(interface)
        elif choice == "2":
            target_ip = input("Enter target IP address: ")
            craft_and_send_packet(target_ip)
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
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 6.")

if __name__ == "__main__":
    main()
