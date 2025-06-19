import sys
import time
import shutil
import itertools
import threading
import os
import socket
import psutil
import re
from scapy.all import sniff, IP, UDP, TCP
from colorama import init, Fore

# Initialize colorama for colored terminal output
init(autoreset=True)

# ASCII Banner
raw_banner = """
 .s5SSSs.                                              .s5SSSs.                                                      
S;      SS..s5SSSs. .s        .s5SSSs.  .s5SSSs.            SS. .s    s.  s.  .s5SSSs. .s5SSSs. .s5SSSs.  .s5SSSs.  
sS    `:;       SS.                 SS.       SS.     sS    `:;       SS. SS.                         SS.       SS. 
SS        sS    S%S sS        sS    S%S sS    `:;     SS        sSs.  S%S S%S sS       sS       sS    `:; sS    S%S 
SS        SS    S%S SS        SS    S%S `:;;;;.       `:;;;;.   SS `S.S%S S%S SSSs.    SSSs.    SSSs.     SS .sS;:' 
SS        SS    S%S SS        SS    S%S       ;;.           ;;. SS  `sS%S S%S SS       SS       SS        SS    ;,  
SS        SS    `:; SS        SS    `:;       `:;           `:; SS    `:; `:; SS       SS       SS        SS    `:; 
SS    ;,. SS    ;,. SS    ;,. SS    ;,. .,;   ;,.     .,;   ;,. SS    ;,. ;,. SS       SS       SS    ;,. SS    ;,. 
`:;;;;;:' `:;;;;;:' `:;;;;;:' ;;;;;;;:' `:;;;;;:'     `:;;;;;:' :;    ;:' ;:' :;       :;       `:;;;;;:' `:    ;:' 
"""

spinner_stop = False

def get_terminal_width():
    """Gets the current terminal width for centering the spinner."""
    return shutil.get_terminal_size().columns

def spinner():
    """Displays a centered 'Loading' spinner with rotating characters."""
    spin = itertools.cycle(["/", "|", "\\", "—"])
    while not spinner_stop:
        terminal_width = get_terminal_width()
        centered_text = f"Loading {next(spin)}"
        padding = (terminal_width - len(centered_text)) // 2
        sys.stdout.write(f"\r{Fore.LIGHTBLUE_EX}{' ' * padding}{centered_text}")
        sys.stdout.flush()
        time.sleep(0.1)

def get_active_network_interface():
    """Automatically detects the active network adapter."""
    interfaces = psutil.net_if_addrs()
    for iface, addresses in interfaces.items():
        for addr in addresses:
            if addr.family == socket.AF_INET:
                return iface
    return None

def rl_sniffer():
    """Sniffs Rocket League traffic."""
    print(Fore.CYAN + "\n[RL Mode] Sniffing Rocket League Traffic...\n")
    RL_UDP_PORTS = range(7000, 9000)
    RL_TCP_PORT = 443
    seen = set()

    iface = get_active_network_interface()
    if not iface:
        print(Fore.RED + "No active network interface found. Exiting.")
        return

    def callback(packet):
        if IP in packet:
            ip_dst = packet[IP].dst
            if UDP in packet and packet[UDP].dport in RL_UDP_PORTS:
                key = f"{ip_dst}:{packet[UDP].dport}"
                if key not in seen:
                    seen.add(key)
                    print(Fore.LIGHTGREEN_EX + f"[UDP GAME] {key}")
            elif TCP in packet and packet[TCP].dport == RL_TCP_PORT:
                key = f"{ip_dst}:{packet[TCP].dport}"
                if key not in seen:
                    seen.add(key)
                    print(Fore.YELLOW + f"[TCP BACKEND] {key}")

    print(Fore.YELLOW + f"Using network interface: {iface}")
    sniff(iface=iface, prn=callback, store=False)

def get_rl_server_ip():
    """Extracts Rocket League server IP from logs (Updated Option 2)."""
    log_paths = [
        os.path.expanduser("~\\Documents\\My Games\\Rocket League\\TAGame\\Logs\\Launch.log"),
        os.path.expanduser("~\\AppData\\Local\\Rocket League\\Saved\\Logs\\Launch.log")
    ]

    for path in log_paths:
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = reversed(f.readlines())  # Read logs from newest to oldest
                    for line in lines:
                        match = re.search(r'GameURL="([\d\.]+:\d+)"', line)
                        if match:
                            return match.group(1)  # Return first detected server IP
        except Exception as e:
            print(Fore.RED + f"Error reading log file: {e}")

    return None

def mc_sniffer():
    """Sniffs Minecraft traffic."""
    print(Fore.CYAN + "\n[MC Mode] Sniffing Minecraft Traffic...\n")
    JAVA_PORTS = [25565, 25566, 25567]
    BEDROCK_PORT = 19132
    seen = set()

    iface = get_active_network_interface()
    if not iface:
        print(Fore.RED + "No active network interface found. Exiting.")
        return

    def callback(packet):
        if IP in packet:
            ip_dst = packet[IP].dst
            if TCP in packet and packet[TCP].dport in JAVA_PORTS:
                key = f"{ip_dst}:{packet[TCP].dport}"
                if key not in seen:
                    seen.add(key)
                    print(Fore.LIGHTGREEN_EX + f"[JAVA] {key}")
            elif UDP in packet and packet[UDP].dport == BEDROCK_PORT:
                key = f"{ip_dst}:{packet[UDP].dport}"
                if key not in seen:
                    seen.add(key)
                    print(Fore.LIGHTBLUE_EX + f"[BEDROCK] {key}")

    print(Fore.YELLOW + f"Using network interface: {iface}")
    sniff(iface=iface, prn=callback, store=False)

def mc_resolver():
    """Resolves Minecraft server domain and checks connections."""
    print(Fore.CYAN + "\n[MC Resolver Mode]")
    domain = input("Enter server domain (e.g. play.example.com): ").strip()
    try:
        ip = socket.gethostbyname(domain)
        print(Fore.LIGHTCYAN_EX + f"Resolved IP: {ip}")
    except socket.gaierror:
        print(Fore.RED + "Domain could not be resolved.")
        return

    found = False
    print(Fore.YELLOW + "\nChecking active TCP connections...")
    for conn in psutil.net_connections(kind="tcp"):
        if conn.raddr and conn.raddr.ip == ip:
            print(Fore.LIGHTGREEN_EX + f"Connected to {ip}:{conn.raddr.port} (Local: {conn.laddr.port})")
            found = True
    if not found:
        print(Fore.RED + "No active connections to that IP found.")

def main():
    """Main execution logic."""
    global spinner_stop
    print(Fore.CYAN + raw_banner)

    spinner_stop = False
    t = threading.Thread(target=spinner)
    t.start()
    time.sleep(2)
    spinner_stop = True
    t.join()
    sys.stdout.write("\n")

    print(Fore.CYAN + "Choose a mode:")
    print("1 - Rocket League Sniffer")
    print("2 - Rocket League Log Extractor")
    print("3 - Minecraft Sniffer")
    print("4 - Minecraft Domain Resolver")
    choice = input("Enter option (1-4): ").strip()

    if choice == "1":
        rl_sniffer()
    elif choice == "2":
        server_ip = get_rl_server_ip()
        if server_ip:
            print(Fore.LIGHTGREEN_EX + f"Rocket League Server IP: {server_ip}")
        else:
            print(Fore.RED + "No server IP found in logs.")
        
        input(Fore.YELLOW + "\nPress Enter to return to the menu...")  # Prevent immediate exit
    
    elif choice == "3":
        mc_sniffer()
    elif choice == "4":
        mc_resolver()
    else:
        print(Fore.RED + "Invalid selection.")

if __name__ == "__main__":
    main()
