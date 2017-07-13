#!/usr/bin/env python2
#import test_lib
import Queue, threading
from test_lib import RuntimeAPI, test_init
from scapy.all import *
from StringIO import StringIO
import sys
from pprint import pprint
from subprocess import call
import time

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
    pack.show2()
    sys.stdout = old_stdout
    return mystdout.getvalue()

#def check_op_packet(pack)

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
def ByteToHex(byteStr):
    return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()

def split_string(input_packet, expected_packet):
    pack_in_len = len(input_packet)
    print pack_in_len
    print type (pack_in_len)
    pack_out_len = len(expected_packet)
    if(pack_in_len!=pack_out_len):
        return "Not same - packet lengths different"
    pack_in = input_packet.split()
    pack_out = expected_packet.split()
    list_len = len(pack_in)
    for i in range(list_len):
        if(pack_in[i]!=pack_out[i]):
            return "Expected packet was different at %s, compared to the packet sniffed on port and was suppose to be %s"%(pack_out[i],pack_in[i])

    return "equal"



        # if(pack_in[i]!=pack_out[i]):
        #     return pack_in[i]
        # elif(pack_in[i]==pack_out[i] and i==pack_in_len-1):
        #     return "equal"
        # else
        #     continue
        

    
       
def sniffedout_packet_list(port_interface_mapping, expected_packets, sniffed_pack, input_ports):
    print "control here"
    input_list = []
    for l in sniffed_pack:
        num = l['port']
        if( num in input_ports):
            continue
        else:
            input_list.append(l)

    list_len = len(input_list)
    print list_len
    for i in range(list_len):
        #list1=str(input_list[i])
        #list2=str(expected_packets[i])
        input_packet = ByteToHex(str(input_list[i]['packet']))
        print input_packet
       
        expected_packet= ByteToHex(str(expected_packets[i]['packet']))

        print expected_packet
        result = split_string(input_packet, expected_packet)
        if(result == "equal"):
            print "packet as expected"
        else:
            print "This is where packet differed: %s" %(result)
    return input_list

        # diff_string=split_string(input_packet, expected_packet)
        # if(input_packet==expected_packet):
        #     print "same"
        # else:
        #     #print input_list[0]['packet'].__repr__()
        #     #print expected_packets[0]['packet'].__repr__()
        #     print "not same"


    #return input_list

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
        #print Packet_list
    return Packet_list

def interfaceArgs(port_interface_mapping):
    result = []
    for port_int in port_interface_mapping['port2intf']:
        eth_name = port_interface_mapping['port2intf'][port_int]
        result.append("-i " + str(port_int) + "@" + eth_name)
    return result

def split_pack(packa, eth):
    print packa
    print eth
    words = packa.split()
    for word in words:
        if(word == "dst=10.1.0.1" and eth ==0):
            dst_word1 = word
            return "continue"
        elif(word == "dst=10.1.0.34" and eth ==1):
            dst_word2 = word
            return "continue"
        if (eth == 2 and word == "dst=10.1.0.1" or word == "dst=10.1.0.34"):
            return "same"

def check_equality (p, exp_pkt1):
    if(pkt_str(p['packet']) == pkt_str(exp_pkt1)):
        return "equal"
    # elif(pkt_str(p['packet']) == pkt_str(exp_pkt1)):
      #  return "equal"
    else :
        return "not equal"
            
            # print "P= %s" %(pkt_str(p['packet']))
            # print "P= %s" %(pkt_str(exp_pkt1))

def main():
    #call(["cd /home/rucha/p4/p4-guide/demo1"])
    #call(["sudo simple_switch --log-console -i 0@veth2 -i 1@veth4 -i 2@veth6 -i 3@veth8 -i 4@veth10 -i 5@veth12 -i 6@veth14 -i 7@veth16 demo1.p4_16.json"]) 

    port_interface_mapping1 = {
        'port2intf': {2: 'veth6'}
    }


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

    thriftPort = 9090
    jsonfile = "demo1.p4_16.json"

    runswitch = ["simple_switch","--log-file", "log_file_data",
                 "--log-flush","--thrift-port", str(thriftPort)] + interfaceArgs(port_interface_mapping) + [jsonfile]
    #print "now here"
    sw = subprocess.Popen(runswitch, cwd= "/home/rucha/p4/p4-guide/demo1")

    time.sleep(2)
    #print " here"
    a = test_init()
    #print "control here"
    #print type(a)
    
    #print (sniff.__doc__)
    #print (sendp.__doc__)
    exp_src_mac = "00:11:22:33:44:55"
    exp_dst_mac = "02:13:57:ab:cd:ef"
    
    RuntimeAPI.do_table_add(a,"ipv4_da_lpm set_l2ptr 10.1.0.1/32 => 58")
    RuntimeAPI.do_table_add(a,"ipv4_da_lpm set_l2ptr 10.1.0.34/32 => 58")
    RuntimeAPI.do_table_add(a,"mac_da set_bd_dmac_intf 58 => 9 "+exp_dst_mac+" 2")
    RuntimeAPI.do_table_add(a,"send_frame rewrite_mac 9 => "+exp_src_mac)
    
    fwd_pkt1=Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2=Ether() / IP(dst='10.1.0.34') / TCP(sport=5793, dport=80)
#    fwd_pkt1=Ether() / IPv6(dst='127::1') / TCP(sport=5793, dport=80)
#    drop_pkt1=Ether() / IP(dst='10.1.0.34') / TCP(sport=5793, dport=80)
    exp_pkt1=Ether(src=exp_src_mac,dst=exp_dst_mac) / IP(dst='10.1.0.1', ttl=fwd_pkt1[IP].ttl-1) / TCP(sport=5793, dport=80)
    exp_pkt2=Ether(src=exp_src_mac,dst=exp_dst_mac) / IP(dst='10.1.0.32', ttl=fwd_pkt2[IP].ttl-1) / TCP(sport=5793, dport=80)
    pack = send_pkts_and_capture(port_interface_mapping, [{'port': 0, 'packet': fwd_pkt1},{'port': 1, 'packet': fwd_pkt2}])
    input_ports = {0, 1}
    expected_out = sniffedout_packet_list(port_interface_mapping1, 
        [{'port': 2, 'packet': exp_pkt1},{'port': 2, 'packet': exp_pkt2}],pack,input_ports)
    

    #pprint(pack)
#    # Send packet at layer2, specifying interface
    
#    sendp(drop_pkt1, iface="veth2")

#    fwd_pkt2=Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80) / Raw('The quick brown fox jumped over the lazy dog.')
#    sendp(fwd_pkt2, iface="veth2")
    # for p in out_pack:
    #     print out_pack[0]['packet'].__repr__()

    
    # for p in pack:
    #     #print p
    #     #print pack[0]['packet'][IP].ttl
    #     eth = p['port']
        #print eth
        # if(eth == 0):
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

        #if(pack[0]['packet']==out_pack[0]['packet']):
        #print "Packet was sniffed on %d and was %s at %f" %(eth, p['packet'].__repr__(),p['packet'].time)
        

        # src_mac = p[Ether].src
        # print src_mac
        # if (exp_src_mac ==src_mac):
        #     print "src and dst mac address match"
        # else :
        #     print "not a  match"
        #result = check_equality(p,exp_pkt1)
        #print result
        #print "Packet not sniffed and was %s at %f" %( exp_pkt1.__repr__(),exp_pkt1.time)
        #print "Packet was sniffed on %d and was %s at %f" %(eth, p['packet'].__repr__(),p['packet'].time)

        #---------------------------------------------------------------------------------------------
        
        # if(pkt_str(p['packet']) == pkt_str(exp_pkt1)):
        #     print "equal"
        # elif(pkt_str(p['packet']) == pkt_str(exp_pkt2)):
        #     print "equal"
        # else :
        #     print "not equal"
        #     print "Packet not sniffed and was %s at %f" %( exp_pkt1.__repr__(),exp_pkt1.time)
            # print "P= %s" %(pkt_str(p['packet']))
            # print "P= %s" %(pkt_str(exp_pkt1))

            
        #---------------------------------------------------------------------------------------------
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

    


    sw.kill()


if __name__ == '__main__':
    main()