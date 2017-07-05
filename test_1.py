#!/usr/bin/env python2
#import test_lib
import Queue, threading
from test_lib import RuntimeAPI, test_init
from scapy.all import *

#pack = None

def sniff_record(queue):    
    print "sniff start"
    packet=sniff(timeout=10, iface=["veth2", "veth6"])
    print packet
    print "sniff stop returned %d packet" %(len(packet))
    #global pack
    #pack = packet
    queue.put(packet)



def main():

    print "hello"
    #print (sniff.__doc__)
    #print (sendp.__doc__)

    a = test_init()
    RuntimeAPI.do_table_add(a,"ipv4_da_lpm set_l2ptr 10.1.0.1/32 => 58")
    RuntimeAPI.do_table_add(a,"mac_da set_bd_dmac_intf 58 => 9 02:13:57:ab:cd:ef 2")
    RuntimeAPI.do_table_add(a,"send_frame rewrite_mac 9 => 00:11:22:33:44:55")
    
    fwd_pkt1=Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
#    fwd_pkt1=Ether() / IPv6(dst='127::1') / TCP(sport=5793, dport=80)
#    drop_pkt1=Ether() / IP(dst='10.1.0.34') / TCP(sport=5793, dport=80)

#    # Send packet at layer2, specifying interface
    
#    sendp(drop_pkt1, iface="veth2")

#    fwd_pkt2=Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80) / Raw('The quick brown fox jumped over the lazy dog.')
#    sendp(fwd_pkt2, iface="veth2")
    
    queue =Queue.Queue()
    thread = threading.Thread(name="sniff_thread", target =lambda: sniff_record(queue))
    
    thread.start()

    sendp(fwd_pkt1, iface="veth2")

    b=thread.join()
    print type(b)
    pack=queue.get()
    for p in pack:
        print "Packet was sniffed on %s and was %s" %(p.sniffed_on, p.sprintf)

if __name__ == '__main__':
    main()

