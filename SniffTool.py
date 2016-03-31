from scapy.all import DNS,sniff
interface=str(raw_input("Interface :"))
def dns_handle(pkt):
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr==0:
        print("Victim  Has Searched For "+pkt.getlayer(DNS).qd.qname)
sniff(iface=interface,prn=dns_handle,filter="udp port 53")