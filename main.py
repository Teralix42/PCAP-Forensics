# main.py
# Safer reader using pydivert (WinDivert)
# Run as admin

import sys, os, re, subprocess, socket, csv
import time
from colorama import Fore, Style, init as colorama_init
from pydivert import WinDivert
from pydivert.consts import Flag, Layer

FLAGS = Flag.SNIFF  # | Flag.RECV_ONLY
LAYER = Layer.NETWORK

LOG_PATH = "logs/capture.log"
if not os.path.exists("logs"):
	os.makedirs("logs")

VENDORS = {}
MAC_CACHE = {}
PORT_LOOKUP = {}

colorama_init()

with open("service-names-port-numbers.csv", newline='', encoding='utf-8') as csvfile:
	reader = csv.DictReader(csvfile)
	for row in reader:
		port_str = row['Port Number']
		proto = row['Transport Protocol'].lower()
		desc = row['Description']

		if '-' in port_str:  # range
			start, end = map(int, port_str.split('-'))
			for p in range(start, end+1):
				PORT_LOOKUP[(p, proto)] = desc
		elif port_str:
			PORT_LOOKUP[(int(port_str), proto)] = desc

with open("oui.txt", "r", encoding="utf-8") as f:
	for line in f:
		if "(hex)" in line:
			parts = line.split()
			if len(parts) >= 3:
				mac_prefix = parts[0].replace("-", ":").lower()
				vendor = " ".join(parts[2:])
				VENDORS[mac_prefix] = vendor

def get_local_ip():
	return socket.gethostbyname(socket.gethostname())

def color(text, col):
	return col + str(text) + Style.RESET_ALL

def format_line(direction, src, dst, proto, sport, dport, length, extra=None, vendor=None, alerts=None):
	dir_col = Fore.GREEN if direction == "OUT" else Fore.YELLOW
	proto_col = Fore.CYAN if proto == "TCP" else Fore.BLUE if proto == "UDP" else Fore.MAGENTA
	sport_desc = PORT_LOOKUP.get((sport, proto.lower()), "Unknown")
	dport_desc = PORT_LOOKUP.get((dport, proto.lower()), "Unknown")

	line = (
		f"{('['+color(direction, dir_col)+']'):<14} "
		f"{src:<15} → {dst:<15} | "
		f"{color(proto, proto_col):<15} "
		f"{f'{sport} ({sport_desc})':>38} → {f'{dport} ({dport_desc})':<38} | "
		f"{length:>6}B"
	)
	if extra:
		line += " | " + extra
	if vendor:
		line += " | distributed by " + vendor
	if alerts:
		line += "\n" + "\n".join(alerts)
	return line

def strip_colors(s):
	import re
	ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
	return ansi_escape.sub('', s)

def get_mac(ip):
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

def lookup_vendor(mac):
	if not mac: return None
	prefix = ":".join(mac.split(":")[:3]).lower()
	return VENDORS.get(prefix)

def resolve_domain(ip):
	try:
		return socket.gethostbyaddr(ip)[0]
	except:
		return None

def run():
	local_ip = get_local_ip()
	print(f"[+] Local IP: {local_ip}")
	filter_str = f"ip and (ip.SrcAddr == {local_ip} or ip.DstAddr == {local_ip})"
	print(f"[+] WinDivert filter: {filter_str}")
	print("[+] Opening WinDivert in sniff mode.")

	try:
		with WinDivert(filter_str, LAYER, 0, FLAGS) as w:
			# TODO: Don't call send(), *never*. Otherwise bye-bye network
			for packet in w:
				try:
					src = getattr(packet, "src_addr", None) or (packet.ipv4 and packet.ipv4.get("src_addr"))
					dst = getattr(packet, "dst_addr", None) or (packet.ipv4 and packet.ipv4.get("dst_addr"))
					sport = getattr(packet, "src_port", 0) or 0
					dport = getattr(packet, "dst_port", 0) or 0

					# protocol detection
					proto = "OTHER"
					if getattr(packet, "tcp", None) is not None:
						proto = "TCP"
					elif getattr(packet, "udp", None) is not None:
						proto = "UDP"
					elif getattr(packet, "icmpv4", None) is not None or getattr(packet, "icmpv6", None) is not None:
						proto = "ICMP"

					# payload length fallback
					payload = getattr(packet, "payload", b"")
					try:
						length = len(payload)
					except Exception:
						# fallback to ipv4 packet_len if available
						ipv4 = getattr(packet, "ipv4", None)
						length = ipv4.get("packet_len") if ipv4 and isinstance(ipv4, dict) and ipv4.get("packet_len") else 0

					direction = "OUT" if getattr(packet, "is_outbound", False) else "IN"

					extra = None

					# Try to find DNS
					raw = bytes(payload)
					if proto == "UDP" and (sport == 53 or dport == 53):
						if len(raw) > 12:
							qname = []
							i = 12
							try:
								length = raw[i]
								while length > 0 and i < len(raw):
									i += 1
									qname.append(raw[i:i+length].decode(errors="ignore"))
									i += length
									length = raw[i]
								if qname:
									extra = "DNS: " + ".".join(qname)
							except Exception:
								extra = "DNS"
					
					if not extra:
						domain = resolve_domain(dst)
						if domain:
							extra = f"Domain: {domain}"
					
					vendor = lookup_vendor(get_mac(dst if direction == "OUT" else src))

					alerts = []

					# Alerts
					if (dport not in [53, 80, 443, 5353] 
							and dport < 49152
							and dport != 0):
						desc = PORT_LOOKUP.get((dport, proto.lower()), "Unknown")
						alerts.append(f"[ALERT] Unusual port {dport} ({desc})")
					if (sport not in [53, 80, 443, 5353] 
							and sport < 49152
							and sport != 0):
						desc = PORT_LOOKUP.get((sport, proto.lower()), "Unknown")
						alerts.append(f"[ALERT] Unusual port {sport} ({desc})")
					
					alerts = [color(a, Fore.RED) for a in alerts]

					line = format_line(direction, src, dst, proto, sport, dport, length, extra, vendor, alerts)
					print(line)

					# remove colors for log
					with open(LOG_PATH, "a", encoding="utf-8") as f:
						f.write(strip_colors(line) + "\n")

				except KeyboardInterrupt:
					print("\n[+] Keyboard interrupt, capture ended.")
					return
				except Exception as e:
					# error for current packet only
					print(color(f"[!] packet parsing error: {e}", Fore.RED))
					continue

	except PermissionError:
		print(color("[!] Permission denied, run as admin.", Fore.RED))
		sys.exit(1)
	except OSError as e:
		print(color(f"[!] Error opening handle: {e}", Fore.RED))
		sys.exit(1)

if __name__ == "__main__":
	try:
		run()
	except KeyboardInterrupt:
		print("\n[+] Keyboard interrupt, capture ended.")