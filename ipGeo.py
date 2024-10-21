import pyshark
import requests
import json
import csv
import markdown  # For generating markdown files
from colorama import Fore
from datetime import date
import ipaddress
import argparse

def read_pcap(pcap_file):
    ips = []
    try:
        pcap = pyshark.FileCapture(pcap_file)
        print(Fore.GREEN + "[+] Pcap File is valid")
        for packet in pcap:
            if "IP" in packet: 
                ips.append(packet.ip.src) 
                ips.append(packet["ip"].dst)
        
        ips_list(ips)

    except FileNotFoundError:
        exit(Fore.RED + '[!] Pcap path is incorrect')

def ips_list(ips):
    ips_lists = []
    aborted_ips = []
    for ip in ips:
        if ip not in ips_lists and ipaddress.ip_address(ip).is_global:
            ips_lists.append(ip)
        elif ip not in aborted_ips and ipaddress.ip_address(ip).is_private:
            aborted_ips.append(ip)
    for ip in aborted_ips:
        print(Fore.YELLOW + "[!] Remove " + Fore.RED + ip + Fore.YELLOW + ' From Scanning')
    # Call get_ip_info function
    if len(ips_lists) < 1:
        exit(Fore.RED + "[-] No IP to scan.")
    get_ip_info(ips_lists)

def get_ip_info(list_ip):
    data = []
    for ip in list_ip:
        print(Fore.YELLOW + "[+] Start analyzing IP: " + ip)
        try:
            req = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
            )
            # Check if the request was successful
            if req.status_code == 200:
                try:
                    # Attempt to parse the JSON response
                    ip_info = req.json()
                    if ip_info.get("status") == "success":
                        data.append(ip_info)
                    else:
                        print(Fore.RED + f"[!] Failed to get info for {ip}: {ip_info.get('message', 'Unknown error')}")
                except json.JSONDecodeError:
                    print(Fore.RED + f"[!] Invalid JSON response for {ip}: {req.text}")
            else:
                print(Fore.RED + f"[!] Request failed for {ip}: {req.status_code} - {req.text}")
        except requests.exceptions.ConnectionError:
            exit(Fore.RED + "Check your internet connection and try again....")
    
    if data:
        export_result(data)
    else:
        exit(Fore.RED + "[-] No valid IP information retrieved.")

def export_result(data, output_format):
    for i in data:
        i['ip'] = i.pop('query') 
        i.pop('status', None)  # Safely remove 'status' key if it exists
    
    output_file = f'scan_result-{str(date.today())}.{output_format}'

    if output_format == 'json':
        with open(output_file, 'w', encoding='UTF8') as f:
            json.dump(data, f, indent=4)
        print(Fore.GREEN + f"\n** Report Exported Successfully to {output_file}! **")

    elif output_format == 'csv':
        with open(output_file, 'w', encoding='UTF8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        print(Fore.GREEN + f"\n** Report Exported Successfully to {output_file}! **")

    elif output_format == 'txt':
        with open(output_file, 'w', encoding='UTF8') as f:
            for entry in data:
                f.write(json.dumps(entry) + "\n")
        print(Fore.GREEN + f"\n** Report Exported Successfully to {output_file}! **")

    elif output_format == 'md':
        with open(output_file, 'w', encoding='UTF8') as f:
            f.write("# IP Analysis Report\n\n")
            for entry in data:
                f.write(f"## IP: {entry['ip']}\n")
                for key, value in entry.items():
                    if key != 'ip':
                        f.write(f"- **{key}**: {value}\n")
                f.write("\n")
        print(Fore.GREEN + f"\n** Report Exported Successfully to {output_file}! **")

    else:
        print(Fore.RED + "[-] Unsupported format. Please use json, csv, txt, or md.")

def main():
    # Setup argument parser
    parser = argparse.ArgumentParser(description='Analyze IP addresses from a pcap file.')
    parser.add_argument('pcap_file', nargs='?', help='Path to the pcap file (optional, will prompt if not provided)')
    parser.add_argument('--format', choices=['json', 'csv', 'txt', 'md'], default=None,
                        help='Output format (default: will prompt if not provided)')
    
    # Parse the arguments
    args = parser.parse_args()
    
    # Check if pcap_file was provided, if not, prompt the user
    if args.pcap_file:
        pcap_path = args.pcap_file
    else:
        pcap_path = input("[-] Enter pcap file: ")

    # Check output format
    if args.format:
        output_format = args.format
    else:
        output_format = input("[-] Enter output format (json, csv, txt, md): ").strip().lower()
        while output_format not in ['json', 'csv', 'txt', 'md']:
            output_format = input("[-] Invalid format. Please enter json, csv, txt, or md: ").strip().lower()

    read_pcap(pcap_path)

if __name__ == "__main__":
    main()
