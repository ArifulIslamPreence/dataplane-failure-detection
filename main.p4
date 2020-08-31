/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<32> TYPE_IPV4 = 0x800;
const bit <16> TYPE_PROBE = 10;
const bit<32> INSTANCE_TYPE_NORMAL = 0;
const bit <32> INSTANCE_TYPE_EGRESS_CLONE = 1;


#define REGISTER_LENGTH 255
#define IS_CLONE (standard_metadata) ()



/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9> PortStatus_t;
typedef bit<32> Allports_t;
typedef bit<48> timestamps_t;



header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<32>   etherType;
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

header probe_t {
    bit <2> tag;

}

struct ingress_metadata_t {
    
    bit <48> register_index;
    bit <1> flag ;
 }

struct metadata {
    
    ingress_metadata_t ingress_metadata;
    
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    probe_t      probe;
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
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
            transition accept;
            
    }

    state parse_probe {
        packet.extract (hdr.probe);
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



register <PortStatus_t> (REGISTER_LENGTH) sop_register; //status of port register
PortStatus_t port_status;

register <timestamp_t> (REGISTER_LENGTH) tm_register; // register to store packet ingress time
timestamp_t time_stamp;



    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    //send to the egress port
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    //swap to send back ingress port 

    action ipv4_backward (){
       macAddr_t tmp;
       tmp = hdr.ethernet.srcAddr;
       hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
       hdr.ethernet.dstAddr = tmp;
       standard_metadata.egress_spec = standard_metadata.ingress_port;}


    action change_probe_tag(bit <2> tag){
        hdr.probe.tag = tag;
    }

    action save_port_status(bit <9> port){
        sop_register.write(port_status, port);
    }

    action reset_status_register(){
        sop_register.write(port_status, 0);
    }

    action get_time (){


        meta.ingress_metadata.flag = 0;

        tm_register.write(meta.ingress_metadata.register_index, (bit<32>) standard_metadata.ingress_global_timestamps);
        meta.ingress_metadata.register_index = meta.ingress_metadata.register_index + 1;

        // accessing the register

        if (meta.ingress_metadata.register_index  ){  //problem : accessing the register value one by one
            meta.ingress_metadata.flag = 1;
            return;
        }


    }

     action send_all_ports (egressSpec_t port){
        standard_metadata.egress_spec = port;
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
        default_action = drop;
    }
    table ipv4_backward_lpm {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }

        actions = {
            ipv4_backward;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

apply {
        if (hdr.ipv4.isValid()){
            if (hdr.probe.isValid()){
                if (hdr.probe.tag == 1){
                    change_probe_tag(2);
                    ipv4_backward_lpm.apply();
                }
                else if (hdr.probe.tag == 2){
                    save_port_status(standard_metadata.egress_spec);
                    drop();
                }
                else if (standard_metadata.instance_type == INSTANCE_TYPE_EGRESS_CLONE){
                     get_time(standard_metadata.ingress_global_timestamp);

                    if (meta.ingress_metadata.flag == 1){
                        reset_status_register();
                        send_all_ports(standard_metadata.ingress_port);
                    }
                }
                else {
                    ipv4_lpm.apply();
                }
            }
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
    


    action drop(){
        mark_to_drop(standard_metadata);
    }

    action forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // E2E clone to send the clonned packet to the buffer instead of ingress

    action do_e2e_clone(bit <48> smac){
        hdr.ethernet.srcAddr = smac;
        clone3(CloneType.E2E, (bit<32>) 32w250,standard_metadata);
    }

    action change_probe_tag(bit <2> tag){
        hdr.probe.tag = tag;
    }

    // listing all ports in a register

    action send_all (egressSpec_t port){
        standard_metadata.egress_spec = port;
    }

    action do_recirculate(bit<32> new_ipv4_dstAddr) {
        hdr.ipv4.dstAddr = new_ipv4_dstAddr;
        recirculate(standard_metadata);
    }


    table send_packet {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            do_recirculate;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop;
    }


apply {
    if (hdr.probe.tag == 0){
        if(standard_metadata.instance_type != INSTANCE_TYPE_EGRESS_CLONE){
            
            change_probe_tag(1);  
            do_e2e_clone();
            send_packet.apply();            
                     
        }

        else {
            send_packet.apply();
        }

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
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.probe);
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
