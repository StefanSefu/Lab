# Network Spoofer Toolkit

**Course:** Lab on Offensive Security  
**Status:** Midterm Submission

## Project Overview
This project is a Python-based network interception toolkit designed to demonstrate Man-in-the-Middle (MITM) attacks in a controlled laboratory environment. The current iteration implements two core modalities:

1.  **ARP Cache Poisoning:** Establishes a MITM position by spoofing Address Resolution Protocol (ARP) messages, redirecting traffic between a target victim and the gateway through the attacker's machine.
2.  **DNS Spoofing:** Intercepts DNS queries via `NetfilterQueue` and injects malicious DNS responses to redirect the victim to an arbitrary IP address.

This tool is built using `scapy` for packet manipulation and `netfilterqueue` for interacting with the Linux kernel packet filtering system.

---

## Legal & Ethical Disclaimer
**DO NOT RUN THIS ON PUBLIC NETWORKS.**
This software is for **educational purposes only**. It is intended to be used in a controlled network environment (e.g., Virtual Machines in a private NAT/Host-Only network) to understand network security vulnerabilities. Unauthorized use against networks you do not own or have explicit permission to test is illegal.

---

## Prerequisites

### Operating System
* **Linux** (Kali Linux recommended)
    * *Note: This tool requires root privileges and specific Linux kernel modules (`iptables`, `ip_forward`). It will not work natively on Windows or macOS.*

### System Dependencies
The tool requires the `libnetfilter-queue` development libraries to function.
```bash
sudo apt-get update
sudo apt-get install -y build-essential python3-dev libnetfilter-queue-dev
```

### Python Libraries
Install the required Python modules:
```bash
pip3 install scapy netfilterqueue
```

## Configuration
Currently, the network parameters are defined as constants within the scripts. Before running the tools, you must edit the files to match your lab environment.

### 1. Configure `arp_poison.py`
Open the file and modify the following lines:
```bash
TARGET_IP = "192.168.2.12"      # Replace with your Victim's IP
GATEWAY_IP = "192.168.2.254"    # Replace with your Router/Gateway IP
```

### 2. Configure `dns_spoof.py`
Open the file and modify the following lines:
```bash
TARGET_URL = "bing.com"         # The domain you want to spoof
ATTACKER_IP = "192.168.2.11"    # IP address to redirect the target to
```

## Usage Guide
To perform the attack, you need to run the scripts in two separate terminal windows simultaneously.

### Step 1: Establish the Bridge (ARP Poisoning)
This script handles the MITM connection. It enables IP forwarding on the host machine to ensure the victim maintains internet connectivity, preventing a Denial of Service (DoS).

**Terminal 1**:
```bash
sudo python3 arp_poison.py
```
- **Action**: Sends spoofed ARP replies.

- **Output**: You will see a counter of packets sent.

- **Stop**: Press `CTRL+C` to stop. The script will automatically restore the ARP tables to their original state to avoid breaking the network.

### Step 2: Activate the Trap (DNS Spoofing)
Once ARP poisoning is active, run the DNS spoofer. This script automatically configures `iptables` to trap outgoing packets into a Netfilter Queue.

**Terminal 2**:
```bash
sudo python3 dns_spoof.py
```
- **Action**: Intercepts DNS packets. If a query matches TARGET_URL, it forges a response pointing to ATTACKER_IP.

- **Stop**: Press `CTRL+C` to stop. The script will automatically flush the `iptables` rules to restore normal traffic flow.

## Technical Architecture
### ARP Poisoning (`arp_poison.py`)
- **Layer 2 Attack**: Uses `scapy.Ether` to send ARP packets.

- **Mechanism**: Continuously sends ARP replies to the Victim (mapping Gateway IP to Attacker MAC) and the Gateway (mapping Victim IP to Attacker MAC).

- **Restoration**: Implements a `restore()` function that broadcasts legitimate ARP packets upon program termination.

### DNS Spoofing (`dns_spoof.py`)
- **Kernel Integration**: Uses subprocess to inject an `iptables` rule: `iptables -I FORWARD -j NFQUEUE --queue-num 0`

- **Packet Modification**: Reads packets from the queue using `NetfilterQueue`. It parses the payload with `Scapy`, detects DNSQR (Query Records), modifies the DNSRR (Resource Record/Answer), and `Scapy` automatically recalculates IP/UDP checksums before reinjecting the packet.

- **Restoration**: Clears the `iptables` rules to restore normal network flow upon program termination.

## Future Work
For the final submission, the following features are planned:

- SSL Stripping: Implementation of a transparent proxy to downgrade HTTPS connections to HTTP.

- Command Line Arguments: Using `argparse` to allow dynamic configuration of IPs and Interfaces without editing the code.

- Integrated Interface: A single script to launch and manage all attack vectors.

