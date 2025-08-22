from scapy.all import sniff, DNS, DNSQR, IP, IPv6
import time
import os
from dotenv import load_dotenv
import requests
from win10toast import ToastNotifier

load_dotenv()

seen_domains = set()

def check(domain):
    #check
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "accept": "application/json",
        "x-apikey": os.getenv("API_KEY"),
        "content-Type": "application/x-www-form-urlencoded"
    }
    payload = {"url": f"https://{domain}"}

    response = requests.post(api_url, data=payload, headers=headers)
    id_url = response.json()["data"]["links"]["self"]

    #analyse
    #recieve analysis
    headers = {
        "accept": "application/json",
        "x-apikey": os.getenv("API_KEY")
    }
    analyse = requests.get(id_url, headers = headers)
    is_phish = analyse.json()["data"]["attributes"]["stats"]["malicious"] >= 1

    if (is_phish):
        notify(domain)

def notify(domain):
    toaster = ToastNotifier()
    toaster.show_toast(
            "PhishShield",
            f"Checked: {domain}\nResult: {'Phishing ⚠️'}",
            duration=3,
            threaded=True
            )

def dns_logger(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode().rstrip(".")
        
        if query not in seen_domains:
            seen_domains.add(query)
            
            # Grab IP source (IPv4/IPv6 agnostic)
            src = packet[IP].src if packet.haslayer(IP) else (
                packet[IPv6].src if packet.haslayer(IPv6) else "Unknown"
            )
            
            print(f"[DNS Visited : ] {src} → {query}")
            time.sleep(15)
            check(query)

            

print("📡 Logging unique domains...")
sniff(filter="udp port 53", prn=dns_logger, store=0)