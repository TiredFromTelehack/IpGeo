import pyshark
import requests
import json
import csv
import argparse
from colorama import Fore, Style
from datetime import date
import ipaddress
import subprocess


def display_banner():
    """Display a welcome banner."""
    banner = f"""
    {Fore.BLUE + Style.BRIGHT}

$$$$$$$\\  $$$$$$$\\  $$$$$$$$\\  $$$$$$\\  $$$$$$$\\  $$$$$$$$\\ $$\\   $$\\ $$\\       
$$  __$$\\ $$  __$$\\ $$  _____|$$  __$$\\ $$  __$$\\ $$  _____|$$ |  $$ |$$ |      
$$ |  $$ |$$ |  $$ |$$ |      $$ /  $$ |$$ |  $$ |$$ |      $$ |  $$ |$$ |      
$$ |  $$ |$$$$$$$  |$$$$$\\    $$$$$$$$ |$$ |  $$ |$$$$$\\    $$ |  $$ |$$ |      
$$ |  $$ |$$  __$$< $$  __|   $$  __$$ |$$ |  $$ |$$  __|   $$ |  $$ |$$ |      
$$ |  $$ |$$ |  $$ |$$ |      $$ |  $$ |$$ |  $$ |$$ |      $$ |  $$ |$$ |      
$$$$$$$  |$$ |  $$ |$$$$$$$$\\ $$ |  $$ |$$$$$$$  |$$ |      \\$$$$$$  |$$$$$$$$\\ 
\\_______/ \\__|  \\__|\\________|\\__|  \\__|\\_______/ \\__|       \\______/ \\________|

    {Style.RESET_ALL}Welcome to the PCAP IP Extractor and Geolocator!
    """
    print(banner)


def get_local_ips():
    """Retrieve a list of local IPs and their subnets."""
    local_ips = set()
    local_subnets = set()

    # Using 'ifconfig' to get all local IPs
    try:
        output = subprocess.check_output("ifconfig", universal_newlines=True)
        for line in output.splitlines():
            if "inet " in line and not line.strip().startswith("inet6"):
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[1]
                    local_ips.add(ip)
                    # Get the subnet mask
                    netmask_index = line.index("netmask") + len("netmask")
                    netmask = line[netmask_index:line.index(" ", netmask_index)].strip()

                    # Ensure that netmask is a valid value
                    if ip and netmask:
                        # Calculate the subnet and add it to the set
                        try:
                            subnet = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
                            local_subnets.add(subnet)
                        except ValueError as e:
                            print(Fore.RED + f"[!] Error creating subnet for IP {ip} with netmask {netmask}: {str(e)}")

    except Exception as e:
        print(Fore.RED + f"[!] Error fetching local IPs: {str(e)}")

    return local_ips, local_subnets


def read_pcap(pcap_file, output_format):
    ips = set()  # Use a set to avoid duplicates
    try:
        pcap = pyshark.FileCapture(pcap_file)
        print(Fore.GREEN + "[+] Pcap File is valid")
        for packet in pcap:
            if "IP" in packet:
                ips.add(packet.ip.src)  # Add source IP
                ips.add(packet["ip"].dst)  # Add destination IP

        ips_list(ips, output_format)

    except FileNotFoundError:
        exit(Fore.RED + '[!] Pcap path is incorrect')


def ips_list(ips, output_format):
    local_ips, local_subnets = get_local_ips()
    ips_lists = []
    aborted_ips = []
    for ip in ips:
        # Check if IP is private or matches local IPs or subnets
        if ipaddress.ip_address(ip).is_private or ip in local_ips or any(ipaddress.ip_address(ip) in subnet for subnet in local_subnets):
            aborted_ips.append(ip)
            continue

        # Check if IP is global
        if ipaddress.ip_address(ip).is_global:
            ips_lists.append(ip)

    # Inform about removed IPs
    for ip in aborted_ips:
        print(Fore.YELLOW + "[!] Remove " + Fore.RED + ip + Fore.YELLOW + ' From Scanning')

    if len(ips_lists) < 1:
        exit(Fore.RED + "[-] No global IPs to scan.")

    get_ip_info(ips_lists, output_format)


def get_ip_info(list_ip, output_format):
    data = []
    for ip in list_ip:
        print(Fore.YELLOW + "[+] Start analyzing IP : " + ip)
        try:
            req = requests.get("http://ip-api.com/json/" + ip + "?fields=status,message,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query")
            req_content = req.content.decode()

            # Check if the response is valid JSON
            if req.status_code == 200 and req_content:
                try:
                    json_data = json.loads(req_content)
                    if json_data.get("status") == "success":
                        # Skip IPs from hosting providers
                        if json_data.get("isp") and "Hosting" in json_data.get("isp"):
                            print(Fore.YELLOW + f"[!] Skipping hosting IP: {ip} - ISP: {json_data['isp']}")
                            continue

                        data.append(json_data)
                    else:
                        print(Fore.RED + f"[!] Error for IP {ip}: {json_data.get('message', 'Unknown error')}")
                except json.JSONDecodeError:
                    print(Fore.RED + f"[!] Error decoding JSON for IP {ip}. Response content: {req_content}")
            else:
                print(Fore.RED + f"[!] Request failed for IP {ip}: {req_content}")

        except requests.exceptions.ConnectionError:
            exit(Fore.RED + "Check your internet connection and try again ....")

    if data:  # Proceed to export only if data is collected
        export_result(data, output_format)
    else:
        print(Fore.YELLOW + "[-] No valid IP data to export.")


def export_result(data, output_format):
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


def interactive_mode():
    """Run the script in interactive mode."""
    print(Fore.YELLOW + "Interactive Mode: Please enter the path to the pcap file:")
    pcap_file = input("Pcap File Path: ").strip()
    print(Fore.YELLOW + "Choose output format (json, csv, txt, md):")
    output_format = input("Output Format: ").strip().lower()

    if output_format not in ['json', 'csv', 'txt', 'md']:
        print(Fore.RED + "[!] Invalid output format. Defaulting to json.")
        output_format = 'json'

    read_pcap(pcap_file, output_format)


def main():
    display_banner()  # Call the display banner function
    parser = argparse.ArgumentParser(description='Extract IP addresses from pcap files and geolocate them.')
    parser.add_argument('pcap', nargs='?', help='Path to the pcap file.')
    parser.add_argument('--format', choices=['json', 'csv', 'txt', 'md'], default='json', help='Output format (default: json).')

    args = parser.parse_args()

    if args.pcap:
        read_pcap(args.pcap, args.format)
    else:
        interactive_mode()  # Enter interactive mode if no arguments are provided


if __name__ == "__main__":
    main()
