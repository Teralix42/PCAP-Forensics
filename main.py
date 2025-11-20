import scapy.all as scapy
from parser import parse_packet, load_oui
import socket
from scapy.arch.windows import get_windows_if_list
import re, os

def strip_colors(s):
	ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
	return ansi_escape.sub('', s)

def get_local_ip():
	return socket.gethostbyname(socket.gethostname())

def handle_packet(pkt):
	global local_ip
	parsed = parse_packet(pkt, local_ip)
	if parsed:
		print(parsed)
		with open("logs/capture.log", "a", encoding="utf-8") as f:
			f.write(strip_colors(parsed) + "\n")

def main():
	global local_ip
	local_ip = get_local_ip()
	print(f"[+] Local IP : {local_ip}")

	if not os.path.exists("logs"):
		os.makedirs("logs")

	interfaces = get_windows_if_list()
	if not interfaces:
		print("No interfaces found.")
		return

	active = None
	for iface in interfaces:
		if local_ip in iface['ips']:
			active = iface['name']
			break

	if not active:
		print("[!] Aborting, couldn't find interface.")
		return

	print(f"[+] Using interface: {active}")

	try:
		load_oui("oui.txt")
		print("[+] Loaded oui.txt")
	except:
		print("[+] Couldn't load oui.txt")
	print("[+] Starting capture")

	scapy.sniff(
		iface=active,
		prn=handle_packet,
		filter=f"host {local_ip}",
		store=False
	)

if __name__ == "__main__":
	main()