/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        // Transition based on EtherType
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4; // If IPv4, parse it
            default: accept;       // Otherwise, accept (stop parsing here)
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept; // Finished parsing known headers
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
        // Mark the packet to be dropped
        mark_to_drop(); // Remove parameters to get it to compile
    }

    // Action to forward IPv4 packets
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        // Set the egress port
        standard_metadata.egress_spec = port;
        // Set the destination MAC 
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

        // Rewrite the destination MAC
        hdr.ethernet.dstAddr = dstAddr;

        // Decrement IPv4 TTL. Assuming hdr.ipv4.isValid() and ttl > 0 checked already.
        // If ttl is 1 it becomes 0. If it's 0,  then it wrapped around ( 255),
        // which is why we check for ttl == 0 AFTER this action in the apply block.
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        // Source MAC address (hdr.ethernet.srcAddr) is probably should be rewritten
        // by the egress pipeline on the egress port's MAC address.
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm; // Longest Prefix Match on Destination IP
        }
        actions = {
            ipv4_forward;   // Forward the packet
            drop;           // Drop the packet
            NoAction;       // Do nothing (packet continues)
        }
        size = 1024; // Example size
        // Default action if no entry matches.

        //default_action = NoAction();
        default_action = drop();
    }

    apply {
        // Only process IPv4 packets with the routing table
        if (hdr.ipv4.isValid()) {

            //  Drop the packet if ttl is already 0
            if (hdr.ipv4.ttl == 0) {
                drop();
            } else {
                // Apply the Match table for routing
                ipv4_lpm.apply();

                // If the action ipv4_forward was executed and TTL became 0, drop the packet.
                
                if (hdr.ipv4.ttl == 0) {
                    drop();
                }
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
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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
        // Emit headers in order. Ethernet first.
        packet.emit(hdr.ethernet);
        // Emit IPv4 header.

        packet.emit(hdr.ipv4);
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
