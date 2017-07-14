#!/usr/bin/env python2
#import test_lib
''' test case for P4 '''
import Queue
import threading
from StringIO import StringIO
import sys
import argparse
import subprocess
import time
from scapy.all import *
from scapy.all import TCP, Ether, IP
from test_lib import RuntimeAPI, test_init



def sniff_record(queue, port_interface_mapping):
    '''sniff record module : sniffs the queue for packets'''
    print "sniff start"
    pkt = sniff(timeout=1, iface=port_interface_mapping['intf_names'])
#    print packet
#    ip_src = packet[0].summary()
#    print ip_src
    print "sniff stop returned %d packet" %(len(pkt))

    #global pack
    #pack = packet
    queue.put(pkt)

def  pkt_str(pack):
    '''gets value from packet in the form of str '''
    old_stdout = sys.stdout
    sys.stdout = mystdout = StringIO()
    pack.show2()
    sys.stdout = old_stdout
    return mystdout.getvalue()

def byte_to_hex(byteStr):
    '''converts byte to hex '''
    return ''.join(["%02X " % ord(x) for x in byteStr]).strip()

def split_string(input_packet, expected_packet):
    '''splits the string and compares the expected and output pkt to find the difference. '''
    pack_in_len = len(input_packet)
    #print pack_in_len
    #print type(pack_in_len)
    pack_out_len = len(expected_packet)
    if pack_in_len != pack_out_len:
        return "Not same - packet lengths different"
    pack_in = input_packet.split()
    pack_out = expected_packet.split()
    list_len = len(pack_in)
    for i in range(list_len):
        if pack_in[i] != pack_out[i]:
            return ("Expected packet was different at %s, compared to the packet"
                    " sniffed on port and was suppose to be %s"%(pack_out[i], pack_in[i]))
    return "equal"

def check_exp_outpkt(expected_packets, sniffed_pack, input_ports):
    ''' sniffs packet expected on output '''
    input_list = []
    for j in sniffed_pack:
        num = j['port']
        if num in input_ports:
            continue
        else:
            input_list.append(j)

    list_len = len(input_list)
    print list_len
    for i in range(list_len):
        #list1=str(input_list[i])
        #list2=str(expected_packets[i])
        input_packet = byte_to_hex(str(input_list[i]['packet']))
        #print input_packet
        expected_packet = byte_to_hex(str(expected_packets[i]['packet']))

        #print expected_packet
        result = split_string(input_packet, expected_packet)
        if result == "equal":
            #print "packet as expected"
            continue
        else:
            return result
    return "All packets as expected"

        # diff_string=split_string(input_packet, expected_packet)
        # if input_packet==expected_packet:
        #     print "same"
        # else:
        #     #print input_list[0]['packet'].__repr__()
        #     #print expected_packets[0]['packet'].__repr__()
        #     print "not same"
    #return input_list

def send_pkts_and_capture(port_interface_mapping, port_packet_list):
    ''' sends packets to P4 and captures by sniffing '''
    queue = Queue.Queue()
    thd = threading.Thread(name="sniff_thread",
                           target=lambda: sniff_record(queue, port_interface_mapping))
    thd.start()
    for x in port_packet_list:
        port_num = x['port']
        iface_name = port_interface_mapping['port2intf'][port_num]
        sendp(x['packet'], iface=iface_name)
    thd.join()
    pack = queue.get()
    Packet_list = []
    for p in pack:
        eth = p.sniffed_on
        port_no = port_interface_mapping['intf_port_names'][eth]
        Packet_list.append({'port': port_no, 'packet': p})
    return Packet_list

def interfaceArgs(port_interface_mapping):
    ''' written to start simple switch every time program has to run '''
    result = []
    for port_int in port_interface_mapping['port2intf']:
        eth_name = port_interface_mapping['port2intf'][port_int]
        result.append("-i " + str(port_int) + "@" + eth_name)
    return result


def check_equality(p, exp_pkt1):
    ''' compares 2 packets - expected and packet which came '''
    if pkt_str(p['packet']) == pkt_str(exp_pkt1):
        return "equal"
    # elif pkt_str(p['packet']) == pkt_str(exp_pkt1):
      #  return "equal"
    else:
        return "not equal"
            # The below lines print out the details of the packets
            # print "P= %s" %(pkt_str(p['packet']))
            # print "P= %s" %(pkt_str(exp_pkt1))

def port_intf_mapping(port2intf):

    port_interface_mapping = {
        'port2intf':port2intf
    }

    intf_names = []
    for port_num in port_interface_mapping['port2intf']:
        intf_names.append(port_interface_mapping['port2intf'][port_num])
    port_interface_mapping['intf_names'] = intf_names

    intf_port_map = {}

    for port_num in port_interface_mapping['port2intf']:
        intf_port_map[port_interface_mapping['port2intf'][port_num]] = port_num
    port_interface_mapping['intf_port_names'] = intf_port_map
    return port_interface_mapping

def main():
    '''main block '''
    # parser = argparse.ArgumentParser(description='Use simple switch to run the test case for P4')
    # parser.add_argument('jsonfile', type=str, help='compiled P4 programs json file')
    # args = parser.parse_args()
    # print args.jsonfile

    # One time, construct a list of all ethernet interface names, which will be used
    # by future calls to sniff.
    port_interface_mapping=port_intf_mapping({0: 'veth2',
                                              1: 'veth4',
                                              2: 'veth6'})

    thriftPort = 9090
    # enter the name of the json file which will be created when we compile the P4 code.
    jsonfile = 'demo1.p4_16.json'

    runswitch = ["simple_switch", "--log-file", "log_file_data", "--log-flush", "--thrift-port",
                 str(thriftPort)] + interfaceArgs(port_interface_mapping) + [jsonfile]
    print runswitch
    sw = subprocess.Popen(runswitch, cwd="/home/rucha/p4/p4-guide/demo1")

    time.sleep(2)
    a = test_init()

    #print (sniff.__doc__)
    #print (sendp.__doc__)
    exp_src_mac = "00:11:22:33:44:55"
    exp_dst_mac = "02:13:57:ab:cd:ef"
    RuntimeAPI.do_table_add(a, "ipv4_da_lpm set_l2ptr 10.1.0.1/32 => 58")
    RuntimeAPI.do_table_add(a, "ipv4_da_lpm set_l2ptr 10.1.0.34/32 => 58")
    RuntimeAPI.do_table_add(a, "ipv4_da_lpm set_l2ptr 10.1.0.32/32 => 58")
    RuntimeAPI.do_table_add(a, "mac_da set_bd_dmac_intf 58 => 9 "+exp_dst_mac+" 2")
    RuntimeAPI.do_table_add(a, "send_frame rewrite_mac 9 => "+exp_src_mac)

    fwd_pkt1 = Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2 = Ether() / IP(dst='10.1.0.34') / TCP(sport=5793, dport=80)
    fwd_pkt3 = Ether() / IP(dst='10.1.0.32') / TCP(sport=5793, dport=80)
#    fwd_pkt1=Ether() / IPv6(dst='127::1') / TCP(sport=5793, dport=80)
#    drop_pkt1=Ether() / IP(dst='10.1.0.34') / TCP(sport=5793, dport=80)
    exp_pkt1 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.1', ttl=fwd_pkt1[IP].ttl-1) / TCP(sport=5793, dport=80))
    exp_pkt2 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.34', ttl=fwd_pkt2[IP].ttl-1) / TCP(sport=5793, dport=80))
    exp_pkt3 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.32', ttl=fwd_pkt2[IP].ttl-1) / TCP(sport=5793, dport=80))
    pack = send_pkts_and_capture(port_interface_mapping, [{'port': 0, 'packet': fwd_pkt1},
                                                          {'port': 1, 'packet': fwd_pkt2},
                                                          {'port': 1, 'packet': fwd_pkt3}])
    input_ports = {0, 1}
    output = check_exp_outpkt([{'port': 2, 'packet': exp_pkt1},
                               {'port': 2, 'packet': exp_pkt2},
                               {'port': 2, 'packet': exp_pkt3}], pack, input_ports)
    print output

#    # Send packet at layer2, specifying interface

    # for p in out_pack:
    #     print out_pack[0]['packet'].__repr__()

    # for p in pack:
    #     #print p
    #     #print pack[0]['packet'][IP].ttl
    #     eth = p['port']
        #print eth
        # if eth == 0:
        #     continue
        #print "type of packet %s" %(type(p))
        #print eth
        #packa = p['packet'].__repr__()
        #print pack
        #--------------------------------------------------------------
        # equality = split_pack(packa, eth)
        # print equality
        # if (equality == "same"):
        #     print "packets are: %s" %(equality)
        #     print "veth is %d" %(eth)
        # else:
        #     print "still comparing"
        #--------------------------------------------------------------
        #print type(dst_Add)
        #print pack[0]['packet'].__repr__()
        #print out_pack[0]['packet']

        #if pack[0]['packet']==out_pack[0]['packet']:
        #print "Packet was sniffed on %d and was %s at %f" %(eth,
        # p['packet'].__repr__(), p['packet'].time)

        # src_mac = p[Ether].src
        # print src_mac
        # if(exp_src_mac == src_mac):
        #     print "src and dst mac address match"
        # else :
        #     print "not a  match"
        #result = check_equality(p, exp_pkt1)
        #print result
        #print "Packet not sniffed and was %s at %f" %( exp_pkt1.__repr__(), exp_pkt1.time)
        #print "Packet was sniffed on %d and was %s at %f" %(eth,
        #p['packet'].__repr__(), p['packet'].time)
        # if pkt_str(p['packet']) == pkt_str(exp_pkt1):
        #     print "equal"
        # elif pkt_str(p['packet']) == pkt_str(exp_pkt2)
        #     print "equal"
        # else :
        #     print "not equal"
        #     print "Packet not sniffed and was %s at %f" %( exp_pkt1.__repr__(), exp_pkt1.time)
            # print "P= %s" %(pkt_str(p['packet']))
            # print "P= %s" %(pkt_str(exp_pkt1))
#        print type(p[Ether].src)
    #     if eth == 'veth2':
    #         veth2=p.summary()
    #         print veth2
    #     else:
    #         veth6=p.summary()
    #         print veth6
    # if veth2==veth6 :
    #     print "Same packet received"
#        p[0].show()
#        print pack1
#        pack2 = p[1].summary()
        #print pack2
    #print "Packet was sniffed on %s and was %s at %f" %(p.sniffed_on, p.__repr__(), p.time)
    sw.kill()


if __name__ == '__main__':
    main()