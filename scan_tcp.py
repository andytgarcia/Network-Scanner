from scapy.all import *
from scapy.layers.inet import IP, TCP
import argparse

# Argument parser
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP Address")
    options = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify a target IP address, use --help for more info.")
    return options

def os_fingerprint(ip):
    # Send TCP SYN packet to port 80
    syn_packet = IP(dst=ip) / TCP(dport=80, flags="S")

    # Send the packet and wait for a response
    response = sr1(syn_packet, timeout=2, verbose=0)

    if response is None:
        return "No response"

    if response.haslayer(TCP):
        # Analyze TTL (Time To Live)
        ttl = response[IP].ttl

        # Analyze TCP Window Size
        window_size = response[TCP].window

        # Basic OS guessing based on TTL and Window Size
        if 48 <= ttl <= 64:
            if window_size == 65535:
                return "Linux or macOS"
            elif window_size == 65535 and response[TCP].options[2][1] == 1460:
                return "macOS"
        elif 64 <= ttl <= 128:
            if window_size == 65535:
                return "Linux"
            elif window_size == 8192:
                return "Windows"
        elif 128 <= ttl <= 255:
            return "Windows"

    return "Unknown OS"


# Example usage
ip = get_args()
os = os_fingerprint(ip.target)
print(f"Detected OS: {os}")