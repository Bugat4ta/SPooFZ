import logging
from scapy.all import IP, TCP, send

logging.basicConfig(filename='packet_sender.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    target_ip = "10.71.192.51"
    target_port = 80
    spoofed_ip = "10.71.192.77"
    source_port = 12345
    payload = b"\70\72\69\6E\74\28\22\77\6F\77\22\29" 

    try:
        packet = IP(src=spoofed_ip, dst=target_ip) / \
                 TCP(sport=source_port, dport=target_port, flags="A") / \
                 payload
       
        send(packet, verbose=1)
       
        logging.info("Packet sent successfully")
        print("Malicious packet sent")
    
    except Exception as e:
        logging.error("Failed to send packet", exc_info=True)
        print("Error sending packet. Check the log file for details.")

if __name__ == "__main__":
    main()
