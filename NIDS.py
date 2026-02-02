from scapy.all import sniff, IP, TCP, UDP, Raw, ARP, Ether, conf
from collections import defaultdict
import time
import sys
from datetime import datetime
from colorama import Fore, Style, init

# --- GRAPHIC INITIALIZATION ---
# Autoreset=True ensures color resets after every print
init(autoreset=True)

# --- CONFIGURATION ---
THRESHOLD_DDOS = 500  # Packets per second from a single IP to trigger alert
MONITOR_INTERFACE = None # Leave None for auto-detect, or specify (e.g., "Wi-Fi")

# --- GLOBAL VARIABLES ---
packet_counts = defaultdict(int)
start_time = time.time()
arp_table = {} 

def get_time():
    """Returns current time formatted as [HH:MM:SS]"""
    return datetime.now().strftime("%H:%M:%S")

def detect_cleartext_creds(packet):
    """
    Analyzes TCP traffic for cleartext credentials (HTTP POST, FTP, Telnet).
    Ignores HTTPS (Port 443).
    """
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        dest_port = packet[TCP].dport
        
        # Check standard cleartext ports
        if dest_port in [80, 21, 23]: # HTTP, FTP, Telnet
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # Logic: We only care about data LEAVING the client (POST requests)
                is_http_post = (dest_port == 80 and "POST" in payload)
                is_ftp_telnet = (dest_port in [21, 23])

                if is_http_post or is_ftp_telnet:
                    sensitive_patterns = ["password=", "pass=", "username=", "user=", "login=", "pwd="]
                    
                    for pattern in sensitive_patterns:
                        if pattern in payload.lower():
                            # --- CREDENTIAL ALERT DESIGN (YELLOW) ---
                            print(f"\n{Fore.YELLOW}{Style.BRIGHT}[!] [{get_time()}] CREDENTIALS INTERCEPTED!{Style.RESET_ALL}")
                            print(f"{Fore.YELLOW}    ├─ Protocol: {Fore.WHITE}{'HTTP POST' if dest_port == 80 else 'FTP/Telnet'}")
                            print(f"{Fore.YELLOW}    ├─ Server:   {Fore.WHITE}{packet[IP].dst}:{dest_port}")
                            
                            lines = payload.split('\n')
                            for line in lines:
                                if pattern in line.lower():
                                    # Clean up and display only the relevant line
                                    clean_line = line.strip()[:100]
                                    print(f"{Fore.YELLOW}    └─ PAYLOAD:  {Fore.RED}{clean_line}")
                            print("")
                            break
            except:
                pass

def detect_dos(packet):
    """
    Monitors packet volume to detect DoS (Flood) attacks.
    """
    global start_time, packet_counts

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        packet_counts[src_ip] += 1

    current_time = time.time()
    # Reset counter every second
    if current_time - start_time > 1:
        for ip, count in packet_counts.items():
            if count > THRESHOLD_DDOS:
                # --- DOS ALERT DESIGN (RED) ---
                print(f"{Fore.RED}{Style.BRIGHT}[!!!] [{get_time()}] DoS ATTACK DETECTED: {ip} -> {count} pkts/sec!{Style.RESET_ALL}")
        
        packet_counts.clear()
        start_time = current_time

def detect_arp_spoofing(packet):
    """
    Checks ARP packets to detect MITM attempts (IP/MAC mismatches).
    """
    if packet.haslayer(ARP) and packet[ARP].op == 2: # op 2 is "is-at" (Reply)
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc

        if src_ip in arp_table:
            if arp_table[src_ip] != src_mac:
                # --- MITM ALERT DESIGN (MAGENTA) ---
                print(f"\n{Fore.MAGENTA}{Style.BRIGHT}[☠️] [{get_time()}] MITM ATTACK DETECTED (ARP SPOOFING)!{Style.RESET_ALL}")
                print(f"{Fore.MAGENTA}    ├─ Target IP:    {Fore.WHITE}{src_ip}")
                print(f"{Fore.MAGENTA}    ├─ Original MAC: {Fore.GREEN}{arp_table[src_ip]}")
                print(f"{Fore.MAGENTA}    └─ Attacker MAC: {Fore.RED}{src_mac}\n")
                
                arp_table[src_ip] = src_mac
        else:
            arp_table[src_ip] = src_mac

def process_packet(packet):
    detect_dos(packet)
    detect_cleartext_creds(packet)
    detect_arp_spoofing(packet)

if __name__ == "__main__":
    # --- BANNER DESIGN ---
    banner = f"""{Fore.CYAN}{Style.BRIGHT}
    ##########################################
    #           NET_SENTINEL                 #
    #    Python Network Forensics Tool       #
    #               1.0                      #
    ##########################################
    {Style.RESET_ALL}"""
    
    print(banner)
    print(f"{Fore.GREEN}[*] {get_time()} System initialized.")
    print(f"{Fore.GREEN}[*] Monitoring interface for: {Fore.YELLOW}Cleartext Creds{Fore.GREEN}, {Fore.RED}DoS Floods{Fore.GREEN}, {Fore.MAGENTA}ARP Spoofing{Fore.GREEN}...")
    print(f"{Fore.GREEN}[*] Press Ctrl+C to stop.\n")
    
    try:
        sniff(prn=process_packet, store=0)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] {get_time()} Monitoring stopped by user.")
    except PermissionError:
        print(f"\n{Fore.RED}[ERROR] You must run this script as Administrator/Root!")