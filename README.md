# IPGeo

**IpGeo** is a Python tool to extract IP addresses from captured network traffic files (pcap/pcapng) and generate reports in various formats (JSON, CSV, TXT, Markdown) containing details about the geolocation of each IP in the packets.

### The report contains:
1. Country
2. Country Code
3. Region
4. Region Name
5. City
6. District
7. Zip
8. Latitude
9. Longitude
10. Timezone
11. ISP
12. Organization
13. IP Address

## Installation

Use the package manager [pip3](https://pip.pypa.io/en/stable/) to install the required modules:

```bash
pip3 install colorama requests pyshark
```

If you are not using Kali or ParrotOs or any other penetration distribution you need to install Tshark.
```bash
sudo apt install tshark
```

## Usage

You can run the script either interactively or by using command-line arguments:

Interactive Mode

```bash
python3 ipGeo.py
```

You will be prompted to enter the captured traffic file path and the desired output format (json, csv, txt, md).

Command-Line Mode

You can also specify the pcap file and output format directly in the command line:

```bash
python3 ipGeo.py <path_to_pcap_file> --format <output_format>
```

Example:
```bash
python3 ipGeo.py /path/to/your/file.pcap --format json
```

## Screenshot from the script
![ipGeo](https://github.com/TiredFromTelehack/IpGeo/blob/304bf033de0b3a67ca0a65336d8ef8ad63247b83/Screenshot_20241021_141901_Termius.jpg)
