/*
Copyright 2017 Cisco Systems, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <core.p4>
#include <v1model.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

struct fwd_metadata_t {
    bit<32> l2ptr;
    bit<24> out_bd;
    bit<14> mtu;
    bit<9> rid;
    bit<9> rpf_intf;
    bit<1> is_bdir;
    bit<4> bdir_index;
    bit<1> setbit_dir;
}

struct metadata {
    fwd_metadata_t fwd_metadata;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

// Why bother creating an action that just does one primitive action?
// That is, why not just use 'mark_to_drop' as one of the possible
// actions when defining a table?  Because the P4_16 compiler does not
// allow primitve actions to be used directly as actions of tables.
// You must use 'compound actions', i.e. ones explicitly defined with
// the 'action' keyword like below.

action my_drop() {
    mark_to_drop();
}

parser ParserImpl(packet_in packet,
                  out headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata)
{
    const bit<16> ETHERTYPE_IPV4 = 16w0x0800;

    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control ingress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata)
{
    action set_l2ptr(bit<32> l2ptr) 
    {
        meta.fwd_metadata.l2ptr = l2ptr;
    }
    table ipv4_da_lpm 
    {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_l2ptr;
            my_drop;
        }
        default_action = my_drop;
    }

    // multicast group match action tables

    action set_mc_group(bit<16> mcgp, bit<9> rpf, bit<1> is_bdir, bit<4> bdir_index) 
    {
        standard_metadata.mcast_grp = mcgp;
        // Reverse path forwading check for multicast case
        meta.fwd_metadata.rpf_intf = rpf;
        meta.fwd_metadata.is_bdir = is_bdir;
        meta.fwd_metadata.bdir_index = bdir_index;
    }
    action noAction(){

    }
    action set_bdir_map(bit<1> setbit_dir)
    {
        meta.fwd_metadata.setbit_dir = setbit_dir;
    }
    table mcgp_sa_da_lookup 
    {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            set_mc_group;
            noAction;
        }
        default_action = noAction();
    }

    table mcgp_da_lookup 
    {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            set_mc_group;
            noAction;
        }
        default_action = noAction();
    }

    table mcgp_bidirect 
    {
        key = {
            standard_metadata.ingress_port: exact;
            meta.fwd_metadata.bdir_index: exact;
        }
        actions = {
            set_bdir_map;
            noAction;
        }
        default_action = noAction();
    }

    action set_bd_dmac_intf(bit<24> bd, bit<48> dmac, bit<9> intf) {
        meta.fwd_metadata.out_bd = bd;
        hdr.ethernet.dstAddr = dmac;
        standard_metadata.egress_spec = intf;
        //meta.fwd_metadata.mtu = mtu;
    }
    table mac_da {
        key = {
            meta.fwd_metadata.l2ptr: exact;
        }
        actions = {
            set_bd_dmac_intf;
            my_drop;
        }
        default_action = my_drop;
    }

    table debug_tab {
        key = {
            standard_metadata.packet_length: exact;
            //meta.fwd_metadata.mtu: exact;
        }
        actions = {
            noAction;
        }
        default_action = noAction();
    }

    apply
    {
        if (hdr.ipv4.ttl == 1 || hdr.ipv4.ttl == 0)
        {
    // for now dropping the packet. To do later: create a special header which will send an ICMP message back.
            my_drop();
            return;
        }
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        if(hdr.ipv4.dstAddr[31:28] == 0xE)
        {
            if(!mcgp_sa_da_lookup.apply().hit)
            {
                mcgp_da_lookup.apply();
            }
            if(standard_metadata.ingress_port == meta.fwd_metadata.rpf_intf)
            {
                if(meta.fwd_metadata.is_bdir == 1)
                {
                    mcgp_bidirect.apply();
                    if(meta.fwd_metadata.setbit_dir != 1)
                    {
                        my_drop();
                        return;
                    }
                }
                else
                {
                    return;
                }
            }
            else
            {
                my_drop();
                return;
            }
        }
        else
        {
            ipv4_da_lpm.apply();
            mac_da.apply();
            debug_tab.apply();
        }
    }
}

control egress(inout headers hdr,
               inout metadata meta,
               inout standard_metadata_t standard_metadata)
{
    action assign_mtu(bit<14> mtu) {
        meta.fwd_metadata.mtu = mtu;
    }
    table mtu_check {
        key = {
            //standard_metadata.egress_port: exact;
            meta.fwd_metadata.out_bd: exact;
        }
        actions = {
            assign_mtu;
            my_drop;
        }
        default_action = my_drop;
    }

    action out_bd_port_match(bit<24> bd) {
        meta.fwd_metadata.out_bd = bd;
    }
    table port_bd_rid {
        key = {
            standard_metadata.egress_port: exact;
            standard_metadata.egress_rid: exact;
        }
        actions = {
            out_bd_port_match;
            my_drop;
        }
        default_action = my_drop;
    }

    action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    table send_frame {
        key = {
            meta.fwd_metadata.out_bd: exact;
        }
        actions = {
            rewrite_mac;
            my_drop;
        }
        default_action = my_drop;
    }

    apply
    {
        if(hdr.ipv4.dstAddr[31:28] == 0xE)
        {
            port_bd_rid.apply();
        }
        mtu_check.apply();
        if((bit<14>)standard_metadata.packet_length > meta.fwd_metadata.mtu)
        {
            // for now dropping the packet. To do later: create a special header which will send an ICMP message back.
            my_drop();
            return;
        } 
        //port_bd_rid.apply();
        send_frame.apply();
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

control verifyChecksum(in headers hdr, inout metadata meta) 
{
    Checksum16() ipv4_checksum;
    apply 
    {
        if ((hdr.ipv4.ihl == 4w5) &&
            (hdr.ipv4.hdrChecksum ==
             ipv4_checksum.get({ hdr.ipv4.version,
                         hdr.ipv4.ihl,
                         hdr.ipv4.diffserv,
                         hdr.ipv4.totalLen,
                         hdr.ipv4.identification,
                         hdr.ipv4.flags,
                         hdr.ipv4.fragOffset,
                         hdr.ipv4.ttl,
                         hdr.ipv4.protocol,
                         hdr.ipv4.srcAddr,
                         hdr.ipv4.dstAddr })))
        {
            mark_to_drop();
        }
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) 
{
    Checksum16() ipv4_checksum;
    apply 
    {
        if (hdr.ipv4.ihl == 4w5) 
        {
            hdr.ipv4.hdrChecksum =
                ipv4_checksum.get({ hdr.ipv4.version,
                            hdr.ipv4.ihl,
                            hdr.ipv4.diffserv,
                            hdr.ipv4.totalLen,
                            hdr.ipv4.identification,
                            hdr.ipv4.flags,
                            hdr.ipv4.fragOffset,
                            hdr.ipv4.ttl,
                            hdr.ipv4.protocol,
                            hdr.ipv4.srcAddr,
                            hdr.ipv4.dstAddr });
        }
    }
}

V1Switch(ParserImpl(),
         verifyChecksum(),
         ingress(),
         egress(),
         computeChecksum(),
         DeparserImpl()) main;
