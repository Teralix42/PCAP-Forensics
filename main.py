import scapy.all as scapy
from parser import parse_packet
import socket
from scapy.arch.windows import get_windows_if_list

def get_local_ip():
	return socket.gethostbyname(socket.gethostname())

def handle_packet(pkt):
	parsed = parse_packet(pkt)
	if parsed:
		print(parsed)
		with open("logs/capture.log", "a", encoding="utf-8") as f:
			f.write(parsed + "\n")

def main():
	local_ip = get_local_ip()
	print(f"[+] Local IP : {local_ip}")

	interfaces = get_windows_if_list()
	if not interfaces:
		print("No interfaces found.")
		return

	"""for iface in interfaces:
		print(f"{iface['name']} : {iface['description']} at {iface['ips']}")"""

	# Pick the good interface, which scapy needs for some reason
	active = None
	for iface in interfaces:
		if local_ip in iface['ips']:
			active = iface['name']
			break

	if not active:
		print("[!] Aborting, couldn't find suitable interface.")
		return

	print(f"[+] Using interface: {active}")
	print("[+] Starting capture")

	scapy.sniff(
		iface=active,
		prn=handle_packet,
		filter=f"host {local_ip}",
		store=False
	)

if __name__ == "__main__":
	main()