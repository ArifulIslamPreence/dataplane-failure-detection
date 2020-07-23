#!/usr/bin/env python
import sys
import time
from probe_hdrs import *

def main():

    probe_pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=get_if_hwaddr('eth0')) / \
                Probe(hop_cnt=0) / \
                ProbeFwd(egress_spec=4) / \
                ProbeFwd(egress_spec=1) / \
                ProbeFwd(egress_spec=4) / \
                ProbeFwd(egress_spec=1) / \
                ProbeFwd(egress_spec=3) / \
                ProbeFwd(egress_spec=2) / \
                ProbeFwd(egress_spec=3) / \
                ProbeFwd(egress_spec=2) / \
                ProbeFwd(egress_spec=1)
    time.sleep(5)
    while True:
        try:
            sendp(probe_pkt, iface='eth0')
            time.sleep(1)
            print "received. Tag 2 port 2"
            print "packet dropped"
            time.sleep(2)
        except KeyboardInterrupt:
            sys.exit()

if __name__ == '__main__':
    main()
