/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x86dd;
const bit<16> TYPE_ARP4 = 0x806;
const bit<8>  TYPE_IPV6EXT_ICMP = 58;
const bit<8>  TYPE_IPV6EXT_SRV6 = 43;
const bit<8>  TYPE_ICMP_NDP_NS = 135;
const bit<8>  TYPE_ICMP_NDP_NA = 136;

const bit<1> TEST_CLONE = 1;

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

header srv6_t {
    bit<8>  nextHeader;
    bit<8>  hdrExtLen;
    bit<8>  rtType;
    bit<8>  segLeft;
    bit<8>  lastEntry;
    bit<8>  flag;
    bit<16> tag;
}

header sid_t {
    bit<128> sid;
}

header icmpv6_t {
    bit<8>    type;
    bit<8>    code;
    bit<16>   checksum;
}

header ndp_t {
    bit<1>    router;
    bit<1>    solicited;
    bit<1>    overrid;
    bit<29>   save;
    ip6Addr_t targetIP;
    bit<8>    type;
    bit<8>    len;
    macAddr_t srcAddr;
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

struct postcard_t {
    @field_list(1)
    ip4Addr_t dstIP;
}

struct metadata {
    @field_list(1)
    postcard_t postcard;
    @field_list(1)
    ip4Addr_t dstIP;
}

struct headers {
    ethernet_t   ethernet;
    arpv4_t      arp;
    ipv4_t       ipv4;
    ipv6_t       ipv6;
    srv6_t       srv6;
    sid_t[5]     sidList;
    sid_t        sidLast;
    icmpv6_t     icmpv6;
    ndp_t        ndp;
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
            TYPE_IPV6: parse_ipv6;
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
            TYPE_IPV6EXT_SRV6: parse_srv6;
            default: accept;
        }
    }

    state parse_srv6 {
        packet.extract(hdr.srv6);
        transition select(hdr.srv6.segLeft) {
            0 : parse_sid_last;
            1 : parse_sid_1;
            2 : parse_sid_2;
            3 : parse_sid_3;
            4 : parse_sid_4;
            default: accept;
        }
    }

    state parse_sid_last {
        packet.extract(hdr.sidLast);
        transition accept;
    }

    state parse_sid_1 {
        packet.extract(hdr.sidList[0]);
        transition parse_sid_last;
    }

    state parse_sid_2 {
        packet.extract(hdr.sidList[1]);
        transition parse_sid_1;
    }

    state parse_sid_3 {
        packet.extract(hdr.sidList[2]);
        transition parse_sid_2;
    }

    state parse_sid_4 {
        packet.extract(hdr.sidList[3]);
        transition parse_sid_3;
    }

    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        transition select(hdr.icmpv6.type) {
            TYPE_ICMP_NDP_NS: parse_ndp;
            TYPE_ICMP_NDP_NA: parse_ndp;
            default:          accept;
        }
    }

    state parse_ndp {
        packet.extract(hdr.ndp);
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

    action srv6_end() {
        hdr.srv6.segLeft = hdr.srv6.segLeft - 1;
        hdr.ipv6.dstAddr = hdr.sidList[0].sid;
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

    action clone_cpu() {
        meta.postcard.dstIP = 0x0b04050e;
        meta.dstIP = 0x0b04050e;
        clone_preserving_field_list(CloneType.I2E, 1919, 1);
    }

    action _NoAction() {

    }
    
    table mac_match_exact {
    	key = {
    	    hdr.ethernet.dstAddr: exact;
    	}
    	actions = {
    	    port_forward;
    	    drop;
    	}
    	default_action = drop();
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
            _NoAction;
        }
        default_action = _NoAction();
    }

    table srv6_end_ext {
        key = {
            hdr.sidLast.sid: exact;
        }
        actions = {
            port_forward;
            srv6_end;
            NoAction;
        }
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
            hdr.ndp.targetIP: exact;
        }
        actions = {
            port_forward;
            drop;
        }
        default_action = drop();
    }

    table postcard {
        actions = {clone_cpu;}
        default_action = clone_cpu();
    }

    apply {
        if (hdr.arp.isValid()) {
            if (arp_proxy_match.apply().hit) {
                NoAction();
            } else {
                arp_forward_match.apply();
            }
        }
        if (hdr.ndp.isValid()) {
            if (hdr.icmpv6.type == TYPE_ICMP_NDP_NS) {
            	ndp_forward_match.apply();
            }
            if (hdr.icmpv6.type == TYPE_ICMP_NDP_NA) {
            	mac_match_exact.apply();
            }
        } else if (hdr.ipv6.isValid()) {
            if (hdr.srv6.isValid()) {
                if (srv6_end_ext.apply().hit) {
                    ipv6_lpm.apply();
                } else {
                    ipv6_lpm.apply();
                }
            }
        }
        // if (hdr.ndp.isValid() && hdr.icmpv6.type==135) {
        //     ndp_forward_match.apply();
        // }
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
        if (TEST_CLONE == 1 && hdr.ipv4.isValid()) {
            if (standard_metadata.egress_spec == 2) {
                postcard.apply();
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        if (standard_metadata.instance_type == 1) {
            hdr.ipv4.dstAddr = meta.dstIP;
        }
    }
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
