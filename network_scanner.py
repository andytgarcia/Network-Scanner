from asyncio import timeout
from tabnanny import verbose
from tkinter.ttk import Label

import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse
import argparse
import ipaddress
import threading
from queue import Queue
import socket
import manuf


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP Address/Address Range')
    parser.add_argument('-n', '--num_threads', dest='num_threads', type=int, required=False, default=10, help='Number of threads to use')
    options = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify an IP Address or Addresses, use --help for more info.")
    return options

def determine_manufacturer(mac_addr):
    parsed = manuf.MacParser(update=False)
    if not mac_addr:
        return "Not Found"
    manufacturer = parsed.get_manuf_long(mac_addr)
    return manufacturer if manufacturer else "Unknown"


def os_fingerprinting(ip):
    packet = IP(dst=ip) / TCP(dport=80, flags="S")

    response = scapy.sr1(packet, timeout=2, verbose=False)

    if response is None:
        return "N/A"

    if response.haslayer(TCP):
        ttl = response[IP].ttl
        window_size = response[TCP].window

        if 48 <= ttl <= 64:
            if window_size == 65535:
                return "Linux"
            elif window_size == 65535 and response[TCP].options[2][1] == 1460:
                return "macOS"
        elif 64 <= ttl <= 128:
            if window_size == 65535:
                return "Linux"
            elif window_size == 8192:
                return "Windows"
        elif 128 <= ttl <= 255:
            return "Windows"
        return "Unknown"

def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0]
    except socket.herror:
        return "Unknown"

def get_dhcp_hostname(ip):
    try:
        dhcp_discover = (
            Ether(dst="ff:ff:ff:ff:ff:ff")/
            IP(src="0.0.0.0", dst=ip)/
            UDP(sport=68, dport=67)/
            BOOTP(options=[("message-type", "discover"), ("param_req_list", "pad"), "end"]))
        ans, _ = scapy.srp(dhcp_discover, timeout=3, verbose=False)
        for _, packet in ans:
            if packet.haslayer(DHCP):
                for opt in packet[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == "hostname":
                        return opt[1].decode()
    except:
        pass
    return "Unknown"


def scan_ip(ip, results):
    arp_request = ARP(pdst=str(ip))
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]

    for sent, received in answered_list:
        print("Received: ", received.psrc, received.hwsrc)
        hostname = os_fingerprinting(str(ip))
        manufacturer = determine_manufacturer(received.hwsrc)
        results.append({"ip": received.psrc, "mac": received.hwsrc, "OS": hostname, "Manufacturer": manufacturer})

def threader(q, results):
    while True:
        ip = q.get()
        scan_ip(ip, results)
        q.task_done()

def scan(ip_range, num_threads):
    try:
        ip_network = ipaddress.ip_network(ip_range, strict=False)
        all_hosts = list(ip_network.hosts())
    except ValueError:
        print(f"Invalid IP address or network: {ip_range}")
        return []

    results = []
    q = Queue()

    for _ in range(num_threads):
        t = threading.Thread(target=threader, args=(q, results))
        t.daemon = True
        t.start()

    for ip in all_hosts:
        q.put(ip)

    q.join()
    return results

def print_results(clients):
    print("IP\t\t\tMAC Address\t\t\tOS\t\t\tManufacturer\n------------------------------------------------------------------------------------------------------------------------------")
    for client in clients:
        print(f"{client['ip']}\t\t{client['mac']}\t\t{client['OS']}\t\t\t{client['Manufacturer']}")


if __name__ == '__main__':
    args = get_args()
    scan_results = scan(args.target, args.num_threads)
    print_results(scan_results)
