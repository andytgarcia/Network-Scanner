import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import argparse
import ipaddress
import threading
from queue import Queue

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP Address/Address Range')
    parser.add_argument('-n', '--num_threads', dest='num_threads', type=int, default=10, help='Number of threads to use')
    options = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify an IP Address or Addresses, use --help for more info.")
    return options

def scan_ip(ip, results):
    arp_request = ARP(pdst=str(ip))
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]

    for sent, received in answered_list:
        print("Received: ", received.psrc, received.hwsrc)
        results.append({"ip": received.psrc, "mac": received.hwsrc})

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
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in clients:
        print(f"{client['ip']}\t\t{client['mac']}")


if __name__ == '__main__':
    args = get_args()
    scan_results = scan(args.target, args.num_threads)
    print_results(scan_results)
