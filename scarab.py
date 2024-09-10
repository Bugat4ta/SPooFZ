from scapy.all import IP, TCP, send

target_ip = "192.168.1.2"
target_port = 80
spoofed_ip = "192.168.1.100"
source_port = 12345
payload = b"\x90\x90\x90\x90" 

packet = IP(src=spoofed_ip, dst=target_ip) / \
         TCP(sport=source_port, dport=target_port, flags="A") / \
         payload

send(packet, verbose=1)

print("Malicious packet sent")
