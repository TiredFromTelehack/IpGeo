import pyshark
import requests
import json
import csv
import argparse
from colorama import Fore
from datetime import date
import ipaddress

def read_pcap(pcap_file, output_format):
    ips = []
    try:
        pcap = pyshark.FileCapture(pcap_file)
        print(Fore.GREEN + "[+] Pcap File is valid")
        for packet in pcap:
            if "IP" in packet: 
                ips.append(packet.ip.src) 
                ips.append(packet["ip"].dst)
        
        ips_list(ips, output_format)

    except FileNotFoundError:
        exit(Fore.RED + '[!] Pcap path is incorrect')


def ips_list(ips, output_format):
    ips_lists = []
    aborted_ips = []
    for ip in ips:
        if ip not in ips_lists and ipaddress.ip_address(ip).is_global:
            ips_lists.append(ip)
        elif ip not in aborted_ips and ipaddress.ip_address(ip).is_private:
            aborted_ips.append(ip)
    
    for ip in aborted_ips:
        print(Fore.YELLOW + "[!] Remove " + Fore.RED + ip + Fore.YELLOW + ' From Scanning')
    
    if len(ips_lists) < 1:
        exit(Fore.RED + "[-] No IP to scan.")

    get_ip_info(ips_lists, output_format)


def get_ip_info(list_ip, output_format):
    data = []
    for ip in list_ip:
        print(Fore.YELLOW + "[+] Start analyzing IP : " + ip)
        try:
            req = requests.get("http://ip-api.com/json/" + ip + "?fields=status,message,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query").content.decode()
            if "message" not in req:
                data.append(req)
        except requests.exceptions.ConnectionError:
            exit(Fore.RED + "Check your internet connection and try again ....")
    
    dic_data = []
    for i in data:
        l = json.loads(i)
        dic_data.append(l)

    export_result(dic_data, output_format)


def export_result(data, output_format):
    # Modify this part to export in different formats
    if output_format == 'json':
        with open('scan_result-' + str(date.today()) + '.json', 'w', encoding='UTF8') as f:
            json.dump(data, f, indent=4)
    elif output_format == 'csv':
        fieldnames = data[0].keys()
        with open('scan_result-' + str(date.today()) + '.csv', 'w', encoding='UTF8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
    elif output_format == 'txt':
        with open('scan_result-' + str(date.today()) + '.txt', 'w', encoding='UTF8') as f:
            for item in data:
                f.write(f"{item}\n")
    elif output_format == 'md':
        with open('scan_result-' + str(date.today()) + '.md', 'w', encoding='UTF8') as f:
            for item in data:
                f.write(f"| {' | '.join(f'{key}: {value}' for key, value in item.items())} |\n")

    print(Fore.GREEN + "\n  **Report Exported Successfully!**")


def main():
    parser = argparse.ArgumentParser(description='Extract IP addresses from pcap files and geolocate them.')
    parser.add_argument('pcap', help='Path to the pcap file.')
    parser.add_argument('--format', choices=['json', 'csv', 'txt', 'md'], default='json', help='Output format (default: json).')
    
    args = parser.parse_args()
    
    read_pcap(args.pcap, args.format)

if __name__ == "__main__":
    main()
    
