import nmap
def get_ports(ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip,arguments='-sS -Pn --top-ports 1000')
    lport=[]
    for proto in nm[ip].all_protocols():
        lport=list(nm[ip][proto].keys())
        lport.sort()
        for p in lport:
            print("{0} port state {1} \n ".format(p,nm[ip][proto][p]["state"]))
    return lport





