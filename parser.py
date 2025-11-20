from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from scapy.layers.tls.all import TLSClientHello
from colorama import Fore, Style
import socket
import re, subprocess

VENDORS = {}
MAC_CACHE = {}

def get_mac(ip):
	try:
		output = subprocess.check_output(f"arp -a {ip}", shell=True, encoding='utf-8')
		m = re.search(r"([0-9a-f]{2}[-:]){5}[0-9a-f]{2}", output.lower())
		if m:
			return m.group(0)
	except Exception:
		pass
	return None

def get_mac_cached(ip):
	if ip in MAC_CACHE:
		return MAC_CACHE[ip]

	m = None
	try:
		output = subprocess.check_output(f"arp -a {ip}", shell=True, encoding='utf-8')
		m = re.search(r"([0-9a-f]{2}[-:]){5}[0-9a-f]{2}", output.lower())
		if m:
			return m.group(0)
	except Exception:
		pass
	MAC_CACHE[ip] = m
	return m

def load_oui(filename="oui.txt"):
	with open(filename, "r", encoding="utf-8") as f:
		for line in f:
			if "(hex)" in line:
				parts = line.split()
				if len(parts) >= 3:
					mac_prefix = parts[0].replace("-", ":").lower()
					vendor = " ".join(parts[2:])
					VENDORS[mac_prefix] = vendor

def lookup_vendor(mac):
	if not mac: return None
	prefix = ":".join(mac.split(":")[:3]).lower()
	return VENDORS.get(prefix)

def color(text, c):
	return c + text + Style.RESET_ALL

def resolve_domain(ip):
	try:
		return socket.gethostbyaddr(ip)[0]
	except:
		return None

def get_direction(pkt, local_ip):
	src = pkt[IP].src
	return "IN" if src != local_ip else "OUT"

def parse_packet(pkt, local_ip, terminal=True):
	if IP not in pkt:
		return None

	src, dst = pkt[IP].src, pkt[IP].dst
	length = len(pkt)
	proto, sport, dport, extra = "OTHER", 0, 0, ""

	if TCP in pkt:
		proto = "TCP"
		sport, dport = pkt[TCP].sport, pkt[TCP].dport
		try:
			if pkt.haslayer(TLSClientHello):
				sni = pkt[TLSClientHello].server_names
				if sni:
					extra = f"SNI: {sni[0].servername.decode()}"
		except Exception:
			pass
	elif UDP in pkt:
		proto = "UDP"
		sport, dport = pkt[UDP].sport, pkt[UDP].dport
		if pkt.haslayer(DNS) and pkt[DNS].qd:
			extra = f"DNS: {pkt[DNS].qd.qname.decode()}"

	# Domain fallback
	if not extra:
		domain = resolve_domain(dst)
		if domain:
			extra = f"Domain: {domain}"

	direction = get_direction(pkt, local_ip)
	direction_c = direction
	proto_c = proto
	alerts = []

	# Color for terminal
	if terminal:
		direction_c = color(direction, Fore.GREEN if direction=="OUT" else Fore.YELLOW)
		if proto=="TCP": proto_c = color(proto, Fore.CYAN)
		elif proto=="UDP": proto_c = color(proto, Fore.BLUE)
		else: proto_c = color(proto, Fore.MAGENTA)

	# Alerts
	if (dport not in [53, 80, 443, 5353] 
			and dport < 49152
			and dport != 0):
		alerts.append("[ALERT] Unusual port {}".format(dport if dport else sport))
		if terminal:
			alerts = [color(a, Fore.RED) for a in alerts]

	# Vendor
	vendor_info = ""
	vendor = lookup_vendor(get_mac(dst if direction == "OUT" else src))
	if vendor:
		vendor_info = f" | Vendor: {vendor}"

	# Table-like output
	line = f"{('['+direction_c+']'):<14} {src:<15} → {dst:<15} | {proto_c} {sport:>5} → {dport:<5} | {length:>6}B"
	if extra: line += f" | {extra}"
	if vendor_info: line += vendor_info

	if alerts:
		line += "\n" + "\n".join(alerts)

	return line