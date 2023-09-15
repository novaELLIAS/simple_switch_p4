/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP4 = 0x806;
const bit<8>  TYPE_IPV6EXT_ICMP = 58;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>   egressSpec_t;
typedef bit<48>  macAddr_t;
typedef bit<32>  ip4Addr_t;
typedef bit<128> ip6Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv6_t {
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowTable;
    bit<16>   payloadLength;
    bit<8>    nextHeader;
    bit<8>    hopLimit;
    ip6Addr_t srcAddr;
    ip6Addr_t dstAddr;
}

header icmpv6_t {
    bit<8>    type;
    bit<8>    code;
    bit<16>   checksum;
    bit<32>   reserved;
    ip6Addr_t targetAddr;
}

header arpv4_t {
    bit<16> hardwareType;
    bit<16> protocol;
    bit<8>  haddrLen;
    bit<8>  protoLen;
    bit<16> op;
    macAddr_t senderMAC;
    ip4Addr_t senderIP;
    macAddr_t targetMAC;
    ip4Addr_t targetIP;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    arpv4_t      arp;
    ipv4_t       ipv4;
    ipv6_t       ipv6;
    icmpv6_t     icmpv6;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP4: parse_arp;
            default:   accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHeader) {
            TYPE_IPV6EXT_ICMP: parse_icmpv6;
            default: accept;
        }
    }
    
    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action ipv6_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }

    action port_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action arp_proxy_flexback(macAddr_t resMacAddr) {
        macAddr_t senderMAC = hdr.arp.senderMAC;
        ip4Addr_t senderIP  = hdr.arp.senderIP;
        hdr.arp.senderIP  = hdr.arp.targetIP;
        hdr.arp.senderMAC = resMacAddr;
        hdr.arp.targetIP  = senderIP;
        hdr.arp.targetMAC = senderMAC;
        hdr.arp.op = 2;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        hdr.ethernet.srcAddr = resMacAddr;
        hdr.ethernet.dstAddr = senderMAC;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table ipv6_lpm {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }
        actions = {
            ipv6_forward;
            port_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table arp_forward_match {
        key = {
            hdr.arp.targetIP: exact;
        }
        actions = {
            port_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table arp_proxy_match {
        key = {
            hdr.arp.targetIP: exact;
            hdr.arp.op:       exact;
        }
        actions = {
            arp_proxy_flexback;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table ndp_forward_match {
        key = {
            hdr.icmpv6.targetAddr: exact;
        }
        actions = {
            port_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.arp.isValid()) {
            if (arp_proxy_match.apply().hit) {
                NoAction();
            } else {
                arp_forward_match.apply();
            }
        }
        if (hdr.ipv6.isValid()) {
            ipv6_lpm.apply();
        }
        if (hdr.icmpv6.isValid() && hdr.icmpv6.type==136) {
            ndp_forward_match.apply();
        }
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
