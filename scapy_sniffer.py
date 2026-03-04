from pygments.styles.dracula import yellow
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest,TCP
from colorama import init,Fore

init()
red = Fore.RED
green = Fore.GREEN
blue = Fore.BLUE
reset = Fore.RESET

def sniff_packets(iface):
    if iface:
        sniff(prn = process_packet , iface = iface , store = False)
    else:
        sniff(prn = process_packet, store = False)


def process_packet(packet):
    if packet.hashlayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"{blue}[+] {src_ip} is using port {src_port} to connect to {dst_ip} at port {dst_port} {reset}")

    if packet.hashlayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].path.decode()
        method = packet[HTTPRequest].Method.decode()
        print(f"{green}[+] {src_ip} is making a HTTP request to {url} with method{method}{reset}")
        print(f"[+] HTTP Data :")
        print(f"{yellow} {packet[HTTPRequest].show()}")


    if packet.hashlayer(Raw):
        print(f"{red}[+] useful raw data :{packet.getlayer(Raw).load.decode()}{reset}")


iface = sys.argv[1]
sniff_packets(iface)