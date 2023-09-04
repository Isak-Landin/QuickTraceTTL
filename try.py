from scapy.all import *
from scapy.layers.inet import IP, UDP, ICMP


def traceroute_scapy(target, max_hops=255, to_print_all=False):
    for i in range(1, max_hops+1):
        pkt = IP(dst=target, ttl=i) / ICMP()
        reply = sr1(pkt, timeout=20, verbose=0)

        if reply is None:
            if to_print_all:
                print(f"{i}. No reply")
            continue

        if reply.haslayer(ICMP):
            if reply[ICMP].type == 11 and to_print_all:  # ICMP Time Exceeded
                print(f"{i}. Hop: {reply.src}")
            elif reply[ICMP].type == 0:  # ICMP Echo Reply
                print(f"{i}. Destination {reply.src} reached with Echo Reply")
                break
        else:
            print(f"{i}. Unexpected reply from {reply.src}")

        time.sleep(0.1)  # Introduce a slight delay

def run_multiple_traceroutes(target, num_threads=1000):
    threads = []

    for _ in range(num_threads):
        thread = Thread(target=traceroute_scapy, args=(target,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    target_host = "www.australia.gov.au"
    run_multiple_traceroutes(target_host)