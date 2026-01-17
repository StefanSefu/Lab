import subprocess

def enable_ip_forwarding():
    """
    Enable IP forwarding on the system (Linux only).
    """
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        print("[*] IP Forwarding enabled.")
    except Exception as e:
        print(f"[!] Could not enable IP forwarding automatically: {e}")
        print("[!] Please run: echo 1 > /proc/sys/net/ipv4/ip_forward")

def redirect_http_traffic():
    """
    Set iptables to redirect HTTP traffic to port 8080 (Linux only).
    """

    subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", "8080"])
    print("[*] HTTP traffic redirected to port 8080.")

def set_trap_for_forward_packets(queue_num=0):
    """
    Set iptables to trap packets meant for the FORWARD chain into a Netfilter Queue (Linux only).

    :param queue_num: Netfilter Queue number
    """

    # Insert the rule into the FORWARD chain
    subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", str(queue_num)])
    print(f"[*] Packets in FORWARD chain trapped to NFQUEUE number {queue_num}.")

def flush_rules():
    """
    Clear the iptables rules to restore normal network flow (Linux only).
    """
    print("\n[*] Flushing iptables rules...")
    subprocess.run(["iptables", "-t", "nat", "-F"])
    subprocess.run(["iptables", "-F"])
    print("[+] Rules flushed. Network normalized.")