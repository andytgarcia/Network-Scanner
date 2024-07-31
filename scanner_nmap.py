#!/usr/bin/python3

import nmap
scanner = nmap.PortScanner()

print("NMAP Automation Tool")
print("-----------------------------------------------------")

ip_addr = input("IP Address: ")
type(ip_addr)

print("Nmap version: ", scanner.nmap_version())
scanner.scan(ip_addr, '1-1024', '-v -sS')
print(scanner.scaninfo())

print("IP Status: ", scanner[ip_addr].state())

print(scanner[ip_addr].all_protocols())




