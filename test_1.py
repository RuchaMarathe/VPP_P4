#!/usr/bin/env python2
#import test_lib
import Queue, threading
from test_lib import RuntimeAPI, test_init
from scapy.all import *
from StringIO import StringIO
import sys
from pprint import pprint

#pack = None

def sniff_record(queue, port_interface_mapping):    
    print "sniff start"
    packet=sniff(timeout=1, iface=port_interface_mapping['intf_names'])
#    print packet
#    ip_src = packet[0].summary()
#    print ip_src
    print "sniff stop returned %d packet" %(len(packet))
    #global pack
    #pack = packet
    queue.put(packet)

def  pkt_str(pack):

    old_stdout = sys.stdout
    sys.stdout = mystdout = StringIO()

    # blah blah lots of code ...
    pack.show2()

    sys.stdout = old_stdout

    return mystdout.getvalue()

# def port_veth(veth_c):
#     return {
#         'veth2': 0,
#         'veth4': 1,
#         'veth6': 2,
#         'veth8': 3,
#         'veth10': 4,
#         'veth12': 5,
#         'veth14': 6,
#         'veth16': 7
#     }[veth_c]


def send_pkts_and_capture(port_interface_mapping, port_packet_list):
    
    queue =Queue.Queue()
    thread = threading.Thread(name="sniff_thread", target =lambda: sniff_record(queue,port_interface_mapping))
    
    thread.start()

    #sendp(fwd_pkt1, iface="veth2")
  
    for x in port_packet_list:
       port_num = x['port']
       iface_name = port_interface_mapping['port2intf'][port_num]
       sendp(x['packet'],iface=iface_name)

    b=thread.join()
    #print type(b)
    pack=queue.get()
    Packet_list = []
    for p in pack:
        eth = p.sniffed_on
        port_no=port_interface_mapping['intf_port_names'][eth]
        Packet_list.append({'port': port_no, 'packet': p})
    return Packet_list


def main():
    port_interface_mapping = {
        'port2intf': {0: 'veth2',
                        1: 'veth4',
                        2: 'veth6'}
    }
    # One time, construct a list of all ethernet interface names, which will be used
    # by future calls to sniff.
    intf_names = []
    for port_num in port_interface_mapping['port2intf']:
        intf_names.append(port_interface_mapping['port2intf'][port_num])
    port_interface_mapping['intf_names'] = intf_names

    intf_port_map = {}

    for port_num in port_interface_mapping['port2intf']:
        intf_port_map[port_interface_mapping['port2intf'][port_num]] = port_num
    port_interface_mapping['intf_port_names'] = intf_port_map

    #print (sniff.__doc__)
    #print (sendp.__doc__)
    exp_src_mac = "00:11:22:33:44:55"
    exp_dst_mac = "02:13:57:ab:cd:ef"
    a = test_init()
    RuntimeAPI.do_table_add(a,"ipv4_da_lpm set_l2ptr 10.1.0.1/32 => 58")
    RuntimeAPI.do_table_add(a,"mac_da set_bd_dmac_intf 58 => 9 "+exp_dst_mac+" 2")
    RuntimeAPI.do_table_add(a,"send_frame rewrite_mac 9 => "+exp_src_mac)
    
    fwd_pkt1=Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
#    fwd_pkt1=Ether() / IPv6(dst='127::1') / TCP(sport=5793, dport=80)
#    drop_pkt1=Ether() / IP(dst='10.1.0.34') / TCP(sport=5793, dport=80)
    exp_pkt1=Ether(src=exp_src_mac,dst=exp_dst_mac) / IP(dst='10.1.0.1', ttl=fwd_pkt1[IP].ttl-1) / TCP(sport=5793, dport=80)
    pack = send_pkts_and_capture(port_interface_mapping, [{'port': 0, 'packet': fwd_pkt1}])
    pprint(pack)
#    # Send packet at layer2, specifying interface
    
#    sendp(drop_pkt1, iface="veth2")

#    fwd_pkt2=Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80) / Raw('The quick brown fox jumped over the lazy dog.')
#    sendp(fwd_pkt2, iface="veth2")
    
    
    for p in pack:
        eth = p['port']
        if(eth == 0):
            continue
        #print "type of packet %s" %(type(p))
        #print eth
        print "Packet was sniffed on %d and was %s at %f" %(eth, p['packet'].__repr__(),p['packet'].time)
        #src_mac = p[Ether].src
        #print src_mac
        #if (exp_src_mac ==src_mac):
        #     print "src and dst mac address match"
        # else :
        #     print "not a  match"


        if(pkt_str(p['packet']) == pkt_str(exp_pkt1)):
            print "equal"


        else :
            print "not equal"
            print "P= %s" %(pkt_str(p['packet']))
            print "P= %s" %(pkt_str(exp_pkt1))

            print "Packet not sniffed and was %s at %f" %( exp_pkt1.__repr__(),exp_pkt1.time)
#        print type(p[Ether].src)
    #     if(eth == 'veth2'):
    #         veth2=p.summary()
    #         print veth2
    #     else:
    #         veth6=p.summary()
    #         print veth6
    # if(veth2==veth6):
    #     print "Same packet received"
#        p[0].show()
#        print pack1
#        pack2 = p[1].summary()
        #print pack2
    #print "Packet was sniffed on %s and was %s at %f" %(p.sniffed_on, p.__repr__(),p.time)

if __name__ == '__main__':
    main()