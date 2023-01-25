# IPGeo

IpGeo is a python tool to extract IP addresses from captured network  traffic file (pcap/pcapng) and generate  csv report containing details about the geolocation of each ip in the packets.

### The report contains:
1. Country:
2. Country Code.
3. Region
4. Region Name
5. City
6. Zip
7. Latitude
8. Longitude
9. Timezone
10. Isp
11. Org
12. Ip

## Installation

Use the package manager [pip3](https://pip.pypa.io/en/stable/) to install required modules.

```bash
pip3 install colorama
pip3 install requests
pip3 install pyshark
```
If you are not using Kali or ParrotOs or any other penetration distribution you need to install Tshark.
```bash
sudo apt install tshark
```


## Usage

```bash
python3 ipGeo.py
# then you will enter captured traffic file path
```
## Screenshot from the script
![ipGeo](https://user-images.githubusercontent.com/89426041/189775552-78dfb962-23ba-46e7-b1f0-3e31ef54ebd3.png)

