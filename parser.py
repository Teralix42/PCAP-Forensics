from scapy.layers.inet import IP, TCP, UDP

def parse_packet(pkt):
	if IP not in pkt:
		return None

	src = pkt[IP].src
	dst = pkt[IP].dst
	proto = "OTHER"

	if TCP in pkt:
		proto = f"TCP:{pkt[TCP].sport}->{pkt[TCP].dport}"
	elif UDP in pkt:
		proto = f"UDP:{pkt[UDP].sport}->{pkt[UDP].dport}"

	length = len(pkt)

	return f"{src} -> {dst} | {proto} | {length} bytes"