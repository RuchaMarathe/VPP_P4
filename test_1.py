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
from test_lib import RuntimeAPI, test_init, get_parser,PreType



def sniff_record(queue, port_interface_mapping):
    '''sniff record module : sniffs the queue for packets'''
    print "sniff start"
    pkt = sniff(timeout=3, iface=port_interface_mapping['intf_names'])
    print "sniff stop returned %d packet" %(len(pkt))
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

def print_packets(input_packet, expected_packet):
    print ("Input    Packet: %s" %(input_packet))
    print ("Expected Packet: %s" %(expected_packet))


def split_string(input_packet, expected_packet):
    '''splits the string and compares the expected and output pkt to find the difference. '''
    pack_in_len = len(input_packet)
    pack_out_len = len(expected_packet)
    if pack_in_len != pack_out_len:
        print_packets(input_packet, expected_packet)
        return "FAILED: Not same - packet lengths different"
    pack_in = input_packet.split()
    pack_out = expected_packet.split()
    list_len = len(pack_in)
    for i in range(list_len):
        if pack_in[i] != pack_out[i]:
            print_packets(input_packet, expected_packet)
            return "different"
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

    sniffin_len = len(input_list)
    print type(input_list)
    expected_len = len(expected_packets)
    if(sniffin_len < expected_len):
        range_len = sniffin_len
    else:
        range_len = expected_len
    for i in range(range_len):
        input_packet = byte_to_hex(str(input_list[i]['packet']))
        expected_packet = byte_to_hex(str(expected_packets[i]['packet']))

        #print expected_packet
        exp_port = expected_packets[i]['port']
        in_port = input_list[i]['port']
        if(exp_port == in_port):
            result = split_string(input_packet, expected_packet)
            if result == "equal":
                #print "packet as expected"
                continue
            else:
                return result
        else:
            print ("Input port: %d" %(in_port))
            print ("Expected port: %d"%(exp_port))

            return "FAILED: Packet expected on a different port."
    if(sniffin_len == expected_len):
        return "All packets as expected"
    else:
        return "FAILED: Expected %d packets, but the packets sniffed out on output ports are %d"%(expected_len, sniffin_len)

def packets_by_port(packet_list_exp_snif, input_ports):

    sniffed_pkts_by_port = {}
    for j in packet_list_exp_snif:
        num = j['port']
        if num in input_ports:
            continue
        else:
            if num in sniffed_pkts_by_port:
                sniffed_pkts_by_port[num].append(j)
            else:
                sniffed_pkts_by_port[num] = [j]

    return sniffed_pkts_by_port



def create_port_seq_list(expected_packets, sniffed_pack, input_ports):
    ''' sniffs packet expected on output '''
    expected_dict = packets_by_port(expected_packets, input_ports)
    sniffed_dict = packets_by_port(sniffed_pack, input_ports)
    for port in expected_dict:
        if (port not in sniffed_dict):
            sniffed_dict[port] = []

    for port in sniffed_dict:
        if (port not in expected_dict):
            expected_dict[port] = []

    for port_num in expected_dict:

        input_list = sniffed_dict[port_num]
        expected_packets = expected_dict[port_num]
        sniffin_len = len(input_list)
    #print "sniffed output list: %d" %(sniffin_len)
        expected_len = len(expected_packets)
        if(sniffin_len < expected_len):
            range_len = sniffin_len
        #print sniffin_len
        else:
            range_len = expected_len
    #print list_len
        for i in range(range_len):
            input_packet = byte_to_hex(str(input_list[i]['packet']))
            expected_packet = byte_to_hex(str(expected_packets[i]['packet']))

        #print expected_packet
            exp_port = expected_packets[i]['port']
            in_port = input_list[i]['port']
            if(exp_port == in_port):
                result = split_string(input_packet, expected_packet)
                if result == "equal":
                #print "packet as expected"
                    continue
                else:
                    return result
            else:
                print ("Input port: %d" %(in_port))
                print ("Expected port: %d"%(exp_port))

                return "FAILED: Packet expected on a different port."
        if(sniffin_len != expected_len):
            return "FAILED: Expected %d packets on port %d, but the packets sniffed out on output ports are %d"%(expected_len, port_num, sniffin_len)
    return "All packets as expected"


def send_pkts_and_capture(port_interface_mapping, port_packet_list):
    ''' sends packets to P4 and captures by sniffing '''
    queue = Queue.Queue()
    thd = threading.Thread(name="sniff_thread",
                           target=lambda: sniff_record(queue, port_interface_mapping))
    thd.start()
    # gives time for time to start sniffing... so packets are sniffed once sniff call begins
    time.sleep(1)
    for x in port_packet_list:
        port_num = x['port']
        iface_name = port_interface_mapping['port2intf'][port_num]
        sendp(x['packet'], iface=iface_name)
    thd.join()
    pack = queue.get(True)
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
    else:
        return "not equal"

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

def table_entries_unicast(a, exp_src_mac, exp_dst_mac):

    RuntimeAPI.do_table_add(a, "ipv4_da_lpm set_l2ptr 10.1.0.1/32 => 58")
    RuntimeAPI.do_table_add(a, "ipv4_da_lpm set_l2ptr 10.1.0.34/32 => 58")
    RuntimeAPI.do_table_add(a, "ipv4_da_lpm set_l2ptr 10.1.0.32/32 => 45")
    RuntimeAPI.do_table_add(a, "mac_da set_bd_dmac_intf 58 => 9 "+exp_dst_mac+" 2")
    RuntimeAPI.do_table_add(a, "mac_da set_bd_dmac_intf 45 => 7 "+exp_dst_mac+" 3")
    RuntimeAPI.do_table_add(a, "send_frame rewrite_mac 9 => "+exp_src_mac)
    RuntimeAPI.do_table_add(a, "send_frame rewrite_mac 7 => "+exp_src_mac)
    RuntimeAPI.do_table_add(a, "mtu_check assign_mtu 9 => 400")
    RuntimeAPI.do_table_add(a, "mtu_check assign_mtu 7 => 400")


def test_mtu_regular(exp_src_mac, exp_dst_mac, port_interface_mapping, a, create_str):

    fwd_pkt1 = Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2 = Ether() / IP(dst='10.1.0.34') / TCP(sport=5793, dport=80)
    fwd_pkt3 = Ether() / IP(dst='10.1.0.32') / TCP(sport=5793, dport=80) / Raw(create_str)

    exp_pkt1 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.1', ttl=fwd_pkt1[IP].ttl-1) / TCP(sport=5793, dport=80))
    exp_pkt2 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.34', ttl=fwd_pkt2[IP].ttl-1) / TCP(sport=5793, dport=80))
    exp_pkt3 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.32', ttl=fwd_pkt3[IP].ttl-1) / TCP(sport=5793, dport=80) / Raw(create_str))
    pack = send_pkts_and_capture(port_interface_mapping, [{'port': 0, 'packet': fwd_pkt1},
                                                          {'port': 1, 'packet': fwd_pkt2},
                                                          {'port': 1, 'packet': fwd_pkt3}])
    input_ports = {0, 1}
    output = create_port_seq_list([{'port': 2, 'packet': exp_pkt1},
                               {'port': 2, 'packet': exp_pkt2},
                               {'port': 3, 'packet': exp_pkt3}], pack, input_ports)
    return output

def test_mtu_failing(exp_src_mac, exp_dst_mac, port_interface_mapping, a, create_str):

    fwd_pkt1 = Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2 = Ether() / IP(dst='10.1.0.34') / TCP(sport=5793, dport=80)
    fwd_pkt3 = Ether() / IP(dst='10.1.0.32') / TCP(sport=5793, dport=80) / Raw(create_str)

    exp_pkt1 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.1', ttl=fwd_pkt1[IP].ttl-1) / TCP(sport=5793, dport=80))
    exp_pkt2 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.34', ttl=fwd_pkt2[IP].ttl-1) / TCP(sport=5793, dport=80))
    exp_pkt3 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.32', ttl=fwd_pkt3[IP].ttl-1) / TCP(sport=5793, dport=80) / Raw(create_str))
    pack = send_pkts_and_capture(port_interface_mapping, [{'port': 0, 'packet': fwd_pkt1},
                                                          {'port': 1, 'packet': fwd_pkt2},
                                                          {'port': 1, 'packet': fwd_pkt3}])
    input_ports = {0, 1}
    output = create_port_seq_list([{'port': 2, 'packet': exp_pkt1},
                               {'port': 2, 'packet': exp_pkt2},
                               {'port': 3, 'packet': exp_pkt3}], pack, input_ports)
    return output

def test_ttl_cases(exp_src_mac, exp_dst_mac, port_interface_mapping, a):

    fwd_pkt1 = Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2 = Ether() / IP(dst='10.1.0.34', ttl =1) / TCP(sport=5793, dport=80)
    fwd_pkt3 = Ether() / IP(dst='10.1.0.32', ttl=0) / TCP(sport=5793, dport=80)

    exp_pkt1 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.1', ttl=fwd_pkt1[IP].ttl-1) / TCP(sport=5793, dport=80))

    pack = send_pkts_and_capture(port_interface_mapping, [{'port': 0, 'packet': fwd_pkt1},
                                                          {'port': 1, 'packet': fwd_pkt2},
                                                          {'port': 1, 'packet': fwd_pkt3}])
    input_ports = {0, 1}
    output = create_port_seq_list([{'port': 2, 'packet': exp_pkt1}], pack, input_ports)
    return output

def table_entries_multicast(a, exp_src_mac):

    RuntimeAPI.do_table_add(a, "mcgp_sa_da_lookup set_mc_group 10.1.0.3 224.1.0.1 => 2 0 0 1")
    RuntimeAPI.do_table_add(a, "mcgp_da_lookup set_mc_group 224.1.0.1 => 3 1 0 2")

    RuntimeAPI.do_table_add(a, "mcgp_bidirect set_bdir_map 0 1 => 1")
    RuntimeAPI.do_table_add(a, "mcgp_bidirect set_bdir_map 1 2 => 1")

    RuntimeAPI.do_mc_mgrp_create(a, "2")
    RuntimeAPI.do_mc_mgrp_create(a, "3")
    mc_node_value1 = RuntimeAPI.do_mc_node_create(a, "12 2 3")
    mc_node_value2 = RuntimeAPI.do_mc_node_create(a, "24 4 5 6")

    node_handle1 = "2 "+ str(mc_node_value1)
    node_handle2 = "3 "+ str(mc_node_value2)

    RuntimeAPI.do_mc_node_associate(a, node_handle1)
    RuntimeAPI.do_mc_node_associate(a, node_handle2)

    RuntimeAPI.do_table_add(a, "port_bd_rid out_bd_port_match 2 12 => 10")
    RuntimeAPI.do_table_add(a, "port_bd_rid out_bd_port_match 3 12 => 11")
    RuntimeAPI.do_table_add(a, "port_bd_rid out_bd_port_match 4 24 => 12")
    RuntimeAPI.do_table_add(a, "port_bd_rid out_bd_port_match 5 24 => 13")
    RuntimeAPI.do_table_add(a, "port_bd_rid out_bd_port_match 6 24 => 14")

    RuntimeAPI.do_table_add(a, "mtu_check assign_mtu 10 => 400")
    RuntimeAPI.do_table_add(a, "mtu_check assign_mtu 11 => 400")
    RuntimeAPI.do_table_add(a, "mtu_check assign_mtu 12 => 400")
    RuntimeAPI.do_table_add(a, "mtu_check assign_mtu 13 => 400")
    RuntimeAPI.do_table_add(a, "mtu_check assign_mtu 14 => 400")

    RuntimeAPI.do_table_add(a, "send_frame rewrite_mac 10 => "+exp_src_mac)
    RuntimeAPI.do_table_add(a, "send_frame rewrite_mac 11 => "+exp_src_mac)
    RuntimeAPI.do_table_add(a, "send_frame rewrite_mac 12 => "+exp_src_mac)
    RuntimeAPI.do_table_add(a, "send_frame rewrite_mac 13 => "+exp_src_mac)
    RuntimeAPI.do_table_add(a, "send_frame rewrite_mac 14 => "+exp_src_mac)


def test_multicast_sa_da(a, port_interface_mapping, exp_src_mac, exp_dst_mac):

    fwd_pkt1 = Ether() / IP(src='10.1.0.3', dst='224.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2 = Ether() / IP(src='10.1.0.5', dst='224.1.0.1') / TCP(sport=5793, dport=80)

    exp_pkt1 = (Ether(src=exp_src_mac) /
                IP(src='10.1.0.3', dst='224.1.0.1', ttl=fwd_pkt1[IP].ttl-1) / TCP(sport=5793, dport=80))
    exp_pkt2 = (Ether(src=exp_src_mac) /
                IP(src='10.1.0.5',dst='224.1.0.1', ttl=fwd_pkt2[IP].ttl-1) / TCP(sport=5793, dport=80))

    pack = send_pkts_and_capture(port_interface_mapping, [{'port': 0, 'packet': fwd_pkt1},
                                                          {'port': 1, 'packet': fwd_pkt2}])
    input_ports = {0, 1}
    output = create_port_seq_list([{'port': 2, 'packet': exp_pkt1},
                               {'port': 3, 'packet': exp_pkt1},
                               {'port': 4, 'packet': exp_pkt2},
                               {'port': 5, 'packet': exp_pkt2},
                               {'port': 6, 'packet': exp_pkt2}], pack, input_ports)
    return output

def test_multicast_rpf(a, port_interface_mapping, exp_src_mac, exp_dst_mac):

    fwd_pkt1 = Ether() / IP(src='10.1.0.3', dst='224.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2 = Ether() / IP(src='10.1.0.5', dst='224.1.0.1') / TCP(sport=5793, dport=80)

    exp_pkt1 = (Ether(src=exp_src_mac) /
                IP(src='10.1.0.3', dst='224.1.0.1', ttl=fwd_pkt1[IP].ttl-1) / TCP(sport=5793, dport=80))
    exp_pkt2 = (Ether(src=exp_src_mac) /
                IP(src='10.1.0.5',dst='224.1.0.1', ttl=fwd_pkt2[IP].ttl-1) / TCP(sport=5793, dport=80))
    # The ports 1 nad 0 are exchanged to check that the rpf and ingress port are different , 
    # thus dropping the packets
    pack = send_pkts_and_capture(port_interface_mapping, [{'port': 1, 'packet': fwd_pkt1},
                                                          {'port': 0, 'packet': fwd_pkt2}])
    input_ports = {0, 1}
    output = create_port_seq_list([], pack, input_ports)
    return output


def main():
    '''main block '''
    parser = get_parser()
    args = parser.parse_args()
    args.pre = PreType.SimplePreLAG
    # One time, construct a list of all ethernet interface names, which will be used
    # by future calls to sniff.
    port_interface_mapping=port_intf_mapping({0: 'veth2',
                                              1: 'veth4',
                                              2: 'veth6',
                                              3: 'veth8',
                                              4: 'veth10',
                                              5: 'veth12',
                                              6: 'veth14'})

    thriftPort = 9090
    # enter the name of the json file which will be created when we compile the P4 code.

    subprocess.call(["killall", "simple_switch"])
    os.remove("log_file_data.txt")

    runswitch = ["simple_switch", "--log-file", "log_file_data", "--log-flush", "--thrift-port",
                 str(thriftPort)] + interfaceArgs(port_interface_mapping) + [args.json]
    sw = subprocess.Popen(runswitch)

    time.sleep(2)
    a = test_init(args)
    exp_src_mac = "00:11:22:33:44:55"
    exp_dst_mac = "02:13:57:ab:cd:ef"
    n = 80
    create_str = "a" * n

    table_entries_unicast(a, exp_src_mac, exp_dst_mac)
    table_entries_multicast(a, exp_src_mac)

    output1 = test_mtu_regular(exp_src_mac, exp_dst_mac, port_interface_mapping, a, create_str)
    print output1
    output2 = test_mtu_failing(exp_src_mac, exp_dst_mac, port_interface_mapping, a, create_str)
    print output2
    output3 = test_ttl_cases(exp_src_mac, exp_dst_mac, port_interface_mapping, a)
    print output3
    output4 = test_multicast_sa_da(a, port_interface_mapping, exp_src_mac, exp_dst_mac)
    print output4
    output5 = test_multicast_rpf(a, port_interface_mapping, exp_src_mac, exp_dst_mac)
    print output5

    sw.kill()


if __name__ == '__main__':
    main()