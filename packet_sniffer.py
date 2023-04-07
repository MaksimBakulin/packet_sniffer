#!/usr/bin/env python

import scapy.all as scapy

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=procces_sniffed_packet)

def procces_sniffed_packet(packet):
    print(packet)

sniff('eth0')