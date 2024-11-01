import sys
import time
from subprocess import call, CalledProcessError
import signal
from itertools import product
import threading

def print_banner():
    banner = """
   ____   _______   __    __  _______ 
  / __ \\ / ____\\ \\ / /   |  |/ ____\\
 | |  | | (___  \\ V /    |  | (___  
 | |  | |\\___ \\  > <     |  |\\___ \\ 
 | |__| |____) / / . \\    |  |____) |
  \\____/_____/ /_/ \\_\\  |_____/  
                           
    """
    print(banner)

def send_can_codes(network, template, delay):
    num_x = template.count("x")
    if num_x == 0:
        print("Error: Template must contain at least one 'x' for the variable part.")
        return

    max_value = 16 ** num_x

    def signal_handler(sig, frame):
        print("\nExecution stopped by user.")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    def generate_hex_values(num_x):
        return [''.join(chars) for chars in product('0123456789abcdef', repeat=num_x)]

    def send_can_message(can_message):
        can_cmd = f"cansend {network} {can_message}"
        print(f"Running {can_cmd} - press Ctrl+C to stop execution.")
        try:
            call(["cansend", network, can_message])
        except CalledProcessError as e:
            print(f"Error sending CAN message: {e}")

    hex_values = generate_hex_values(num_x)
    
    for hex_str in hex_values:
        can_message = template
        for char in hex_str:
            can_message = can_message.replace("x", char, 1)
        # Send messages sequentially
        send_can_message(can_message)
        time.sleep(delay)

def print_syntax():
    print("Syntax: python3 seq.py <network> <template> <delay>")
    print("network: the CAN network to send the messages")
    print("         Example: vcan0")
    print("template: the CAN message to send. Use 'x' as a placeholder for the variable part")
    print("         Example: 19B#0000xx000000")
    print("delay: the delay between messages in seconds")
    print("         Example: 0.1")
    print()
    print("1 x will produce 16 messages. 2 x's will produce 256 messages. 3 x's will produce 4096 messages, etc.")
    print()
    print("Example: python3 seq.py vcan0 19B#0000xx000000 0.1")

if __name__ == "__main__":
    print_banner()
    
    if len(sys.argv) != 4:
        print_syntax()
        sys.exit(1)

    network = sys.argv[1]
    template = sys.argv[2]
    try:
        delay = float(sys.argv[3])
        if delay < 0:
            raise ValueError("Delay must be a non-negative number.")
    except ValueError as e:
        print(f"Invalid delay value: {e}")
        print_syntax()
        sys.exit(1)

    send_can_codes(network, template, delay)
