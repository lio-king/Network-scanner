#!/usr/bin/env python

import scapy.all as scapy
import optparse
from termcolor import colored
import csv
import sqlite3

# Global variable for SQLite database connection
conn = sqlite3.connect('scan_results.db')
c = conn.cursor()

def create_table():
    c.execute('CREATE TABLE IF NOT EXISTS scan_results (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, mac TEXT, ports TEXT)')

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip", help="Enter A Range Of IP Address Example > 192.168.29.1/24.")
    options, arguments = parser.parse_args()

    if not options.ip:
        parser.error("[-] Please Enter An IP Address, Use --help For More Info")
    else:
        return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def scan_ports(ip):
    open_ports = []
    common_ports = {20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
                    110: "POP3", 143: "IMAP", 443: "HTTPS", 3389: "RDP"}
    for port in common_ports.keys():
        syn_packet = scapy.IP(dst=ip) / scapy.TCP(dport=port, flags='S')
        response = scapy.sr1(syn_packet, timeout=1, verbose=False)
        if response and response.haslayer(scapy.TCP) and response[scapy.TCP].flags == 0x12:
            open_ports.append((port, common_ports[port]))
            rst_packet = scapy.IP(dst=ip) / scapy.TCP(dport=port, flags='R')
            scapy.send(rst_packet, verbose=False)
    return open_ports

def load_cve_db(file_path):
    cve_db = {}
    with open(file_path, mode='r', encoding='utf-8', errors='ignore') as file:
        csv_reader = csv.reader(file, delimiter=';')
        for row in csv_reader:
            cve_id, description = row[0], row[1]
            for service in common_ports.values():
                if service.lower() in description.lower():
                    if service not in cve_db:
                        cve_db[service] = []
                    cve_db[service].append(cve_id)
    return cve_db

def get_cve_count(service, cve_db):
    return len(cve_db.get(service, []))

def store_results(ip, mac, ports):
    ports_str = ', '.join([f"{port[0]} ({port[1]})" for port in ports])
    c.execute("INSERT INTO scan_results (ip, mac, ports) VALUES (?, ?, ?)", (ip, mac, ports_str))
    conn.commit()

def retrieve_results():
    c.execute("SELECT * FROM scan_results")
    rows = c.fetchall()
    for row in rows:
        print(row)

def print_result(result_list):
    print("IP Address\t\tMAC Address\t\tOpen Ports\t\tCVE Count")
    print("---------------------------------------------------------------------------------------")
    for result in result_list:
        ip = result["ip"]
        mac = result["mac"]
        ports = result["ports"]
        ports_str = ', '.join([f"{port[0]} ({port[1]})" for port in ports])
        cve_counts = ', '.join([f"{port[0]}: {port[2]}" for port in ports])
        print(f"{ip}\t{mac}\t{ports_str}\t{cve_counts}")
        store_results(ip, mac, ports)

def about():
    print(colored(" _   _      _                      _          _____                                 ", "green"))
    print(colored("| \ | |    | |                    | |        / ____|                                ", "green"))
    print(colored("|  \| | ___| |___      _____  _ __| | __    | (___   ___ __ _ _ __  _ __   ___ _ __ ", "green"))
    print(colored("| . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ /     \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|", "green"))
    print(colored("| |\  |  __/ |_ \ V  V / (_) | |  |   <      ____) | (_| (_| | | | | | | |  __/ |   ", "green"))
    print(colored("|_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\    |_____/ \___\__,_|_| |_|_| |_|\___|_|   \n", "green"))
    print(colored("# Author      :", "white") + " Faizal Azad")
    print(colored("# Title       :", "white") + " Network Scanner")
    print(colored("# Features    :", "white") + " 1.Scan Ip & Mac, 2.Ports & there Services, 3.Cve Detections, 4.Data Storage and Query")
    print(colored("# ========================================================================================================================\n", "green"))

# Define common_ports here so it's accessible in load_cve_db
common_ports = {20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
                110: "POP3", 143: "IMAP", 443: "HTTPS", 3389: "RDP"}

# Create table in SQLite database
create_table()

about()
options = get_arguments()
scan_result = scan(options.ip)
cve_db = load_cve_db('cve.csv')

# Add open ports and CVE counts to the scan results
for client in scan_result:
    client["ports"] = scan_ports(client["ip"])
    for i, port in enumerate(client["ports"]):
        service = port[1]
        cve_count = get_cve_count(service, cve_db)
        client["ports"][i] = (port[0], port[1], cve_count)

print_result(scan_result)

# Option to retrieve stored results
print("\nStored Scan Results:")
retrieve_results()

# Close SQLite connection
conn.close()
