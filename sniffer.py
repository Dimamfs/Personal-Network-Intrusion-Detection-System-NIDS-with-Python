from scapy.all import sniff, TCP, IP
from collections import defaultdict
from datetime import datetime, timedelta
from notifypy import Notify
import os

syn_counts = defaultdict(list)
TIME_WINDOW = timedelta(seconds=10)
THRESHOLD = 10
LOG_FILE = "alerts.log"

def log_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_msg = f"[{timestamp}] {message}\n"
    print(full_msg.strip())
    with open(LOG_FILE, "a") as log:
        log.write(full_msg)

    notification = Notify()
    notification.title = "🚨 Intrusion Alert"
    notification.message = message
    notification.send()

def block_ip(ip_address):
    print(f"🔒 Blocking IP {ip_address} with Windows Firewall...")
    command = f'netsh advfirewall firewall add rule name="Block Port Scanner {ip_address}" dir=in action=block remoteip={ip_address}'
    os.system(command)

def detect_syn_flood(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        ip_src = packet[IP].src
        tcp_flags = packet[TCP].flags

        if tcp_flags == 0x02:
            now = datetime.now()
            syn_counts[ip_src].append(now)
            syn_counts[ip_src] = [t for t in syn_counts[ip_src] if now - t < TIME_WINDOW]

            if len(syn_counts[ip_src]) > THRESHOLD:
                message = (f"🚨 Possible Port Scan Detected from {ip_src} "
                           f"({len(syn_counts[ip_src])} SYNs in last 10s)")
                log_alert(message)
                block_ip(ip_src)

print("🛡️ Monitoring for SYN scan attacks... Logs will be saved to 'alerts.log'")
print("⚠️ Please run this script as Administrator for blocking to work.")
sniff(prn=detect_syn_flood, store=0)
